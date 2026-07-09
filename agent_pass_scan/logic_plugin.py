import json
import os
import threading
import time

from agent_pass_scan.exploit_chain import (
    chain_status_from_finding_status,
    exploit_chain_complete,
)
from agent_pass_scan.http_executor import LogicHttpExecutor
from agent_pass_scan.llm_client import LogicLLMClient
from agent_pass_scan.models import LogicTask
from agent_pass_scan.finding_merge import (
    merge_logic_findings,
    stable_logic_finding_key_from_candidate,
    stable_logic_finding_key_from_result,
)
from agent_pass_scan.prompt_builder import SYSTEM_PROMPT, build_candidate_prompt
from agent_pass_scan.registry import default_detectors
from agent_pass_scan.store import FlowStore
from agent_pass_scan.terminal import purple
from agent_pass_scan.traffic_model import trim_text
from pass_scan.reporter import upsert_jsonl, write_html_report
from pass_scan.terminal import red


class LogicAgentScanner:
    name = "logic_agent"
    observer_only = True

    def __init__(self, config=None, report_file=None, vuln_file=None, fingerprint_file=None):
        self.config = config or {}
        self.report_file = report_file or "report.html"
        self.vuln_file = vuln_file or os.path.join("logs", "vulns.jsonl")
        self.fingerprint_file = fingerprint_file
        self.output_file = (
            os.environ.get("PASS_SCAN_LOGIC_FILE")
            or self.config.get("output_file")
            or os.path.join("logs", "logic_vulns.jsonl")
        )
        self.sqlite_file = (
            os.environ.get("PASS_SCAN_LOGIC_DB")
            or self.config.get("sqlite_file")
            or os.path.join("logs", "logic_pass_scan.db")
        )
        self.store = FlowStore(self.sqlite_file)
        self.llm = LogicLLMClient(self.config)
        self.executor = LogicHttpExecutor(self.config)
        self.detectors = default_detectors(self.config)
        self.max_flows_per_endpoint = int(self.config.get("max_flows_per_endpoint", 30))
        self.max_candidates_per_endpoint = int(self.config.get("max_candidates_per_endpoint", 6))
        self.prompt_chars = int(self.config.get("prompt_chars", 50000))
        self.ready_notice_printed = False
        self.enqueue_log_lock = threading.Lock()
        self.printed_enqueue_keys = set()

    def observe(self, context):
        if context.is_skipped:
            return []

        indexed = self.store.ingest_context(context)
        if not indexed.get("sensitive"):
            return []

        if not self.llm.ready:
            if not self.ready_notice_printed:
                print(
                    purple(
                        "[逻辑漏洞][状态] 已启用并写入 SQLite 索引，"
                        "但 LLM 配置不完整，暂不进行 Agent 判断。"
                    ),
                    flush=True,
                )
                self.ready_notice_printed = True
            return []

        if not indexed.get("should_analyze"):
            return []

        return [
            LogicTask(
                endpoint_id=indexed["endpoint_id"],
                signature=indexed["signature"],
                host=context.host,
                method=context.method,
                url=context.url,
            )
        ]

    def interested(self, _context):
        return False

    def dedup_key(self, task):
        return f"{task.endpoint_id}:{task.signature}"

    def task_label(self, task):
        return f"{task.method} {task.url}"

    def enqueue_log_key(self, task):
        return str(task.endpoint_id)

    def should_log_enqueue(self, task):
        key = self.enqueue_log_key(task)
        with self.enqueue_log_lock:
            if key in self.printed_enqueue_keys:
                return False
            self.printed_enqueue_keys.add(key)
            return True

    def check(self, task):
        bundle = self.store.load_endpoint_bundle(
            task.endpoint_id,
            max_flows=self.max_flows_per_endpoint,
        )
        if not bundle:
            return

        candidates = []
        for detector in self.detectors:
            candidates.extend(detector.build_candidates(bundle))
            if len(candidates) >= self.max_candidates_per_endpoint:
                break

        for candidate in candidates[: self.max_candidates_per_endpoint]:
            if self.finding_already_confirmed(candidate):
                self.store.mark_candidate(candidate.key, "skipped_confirmed")
                continue
            if self.store.candidate_seen(candidate.key):
                continue
            self.store.mark_candidate(candidate.key, "started")
            try:
                finding = self.analyze_candidate(candidate, bundle)
            except Exception as error:
                self.store.mark_candidate(candidate.key, "error")
                print(
                    purple(f"[逻辑漏洞][状态] Agent 判断异常: {candidate.title}: {error}"),
                    flush=True,
                )
                continue

            status = finding.get("status", "")
            self.store.mark_candidate(candidate.key, status or "done")
            if status in ("confirmed", "likely", "needs_manual_review"):
                self.emit_finding(finding)

    def analyze_candidate(self, candidate, bundle):
        observations = self.executor.execute_candidate_verification(candidate)
        model_context = {
            "sqlite_file": self.sqlite_file,
            "report_policy": "逻辑漏洞单独进入 report.html 的逻辑漏洞标签页。",
            "endpoint_stats": bundle.get("stats") or {},
            "identity_memory": bundle.get("identity_memory") or {},
        }
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": trim_text(
                    build_candidate_prompt(candidate, observations, model_context),
                    self.prompt_chars,
                ),
            },
        ]
        decision = self.llm.complete_json(messages)
        return self.build_finding(candidate, observations, decision)

    def build_finding(self, candidate, observations, decision):
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        status = str(decision.get("status") or "needs_manual_review").strip().lower()
        if status not in ("confirmed", "likely", "needs_manual_review", "false_positive"):
            status = "needs_manual_review"
        confidence = str(decision.get("confidence") or "medium").strip().lower()
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"
        vuln_type = decision.get("type") or candidate.vuln_type
        endpoint = candidate.endpoint or {}
        finding_key = stable_logic_finding_key_from_candidate(candidate)
        finding = {
            "time": now,
            "finding_key": finding_key,
            "candidate_key": candidate.key,
            "type": vuln_type,
            "detector": candidate.detector,
            "status": status,
            "confidence": confidence,
            "severity": decision.get("severity") or "medium",
            "title": decision.get("title") or candidate.title,
            "summary": decision.get("summary") or "",
            "impact": decision.get("impact") or "",
            "evidence": decision.get("evidence") or candidate.evidence,
            "reproduction": [],
            "remediation": [],
            "verified": bool(decision.get("verified")),
            "safety_notes": decision.get("safety_notes") or "",
            "host": endpoint.get("host") or "",
            "method": endpoint.get("method") or "",
            "endpoint": endpoint.get("normalized_path") or "",
            "url": (candidate.source_flow or {}).get("url") or "",
            "resource": candidate.resource or {},
            "candidate": candidate.to_prompt_dict(),
            "verification_observations": observations,
            "model": self.llm.model,
            "sqlite_file": self.sqlite_file,
        }
        finding["logic_exploit_chain"] = self.build_logic_exploit_chain(
            candidate,
            observations,
            finding,
        )
        finding["logic_chain_packets"] = finding["logic_exploit_chain"].get("steps") or []
        return finding

    def finding_already_confirmed(self, candidate):
        finding_key = stable_logic_finding_key_from_candidate(candidate)
        existing = self.store.load_finding(finding_key)
        return bool(existing and exploit_chain_complete(existing))

    def build_logic_exploit_chain(self, candidate, observations, finding):
        steps = []
        source_flow = candidate.runtime_source_flow or {}
        related_flows = candidate.runtime_related_flows or []
        verification_kind = (candidate.verification or {}).get("kind") or "passive_only"
        status = chain_status_from_finding_status(finding.get("status"))
        vuln_label = self.chain_vuln_label(candidate)
        best_observation = self.best_active_observation(observations)
        related_flow = self.related_flow_for_observation(best_observation, related_flows)

        if source_flow:
            steps.append(
                {
                    "name": "步骤 1: 当前用户原始请求与响应",
                    "role": "source_user_baseline",
                    "proves": self.source_step_proof(candidate),
                    "request": self.render_stored_request(source_flow),
                    "response": self.render_stored_response(source_flow),
                    "flow_id": source_flow.get("id"),
                    "auth_fingerprint": source_flow.get("auth_fingerprint"),
                }
            )

        for index, related_flow in enumerate([related_flow] if related_flow else [], start=1):
            steps.append(
                {
                    "name": f"步骤 {len(steps) + 1}: 其他用户认证来源请求与响应 {index}",
                    "role": "alternate_identity_baseline",
                    "proves": "证明存在另一个认证身份及其正常业务响应，用于后续跨身份差分。",
                    "request": self.render_stored_request(related_flow),
                    "response": self.render_stored_response(related_flow),
                    "flow_id": related_flow.get("id"),
                    "auth_fingerprint": related_flow.get("auth_fingerprint"),
                }
            )

        for observation in ([best_observation] if best_observation else []):
            steps.append(
                {
                    "name": f"步骤 {len(steps) + 1}: {self.observation_packet_title(candidate, observation)}",
                    "role": "active_verification",
                    "proves": self.active_step_proof(candidate),
                    "request": observation.get("request", ""),
                    "response": observation.get("response", ""),
                    "purpose": observation.get("purpose", ""),
                    "status_code": observation.get("status_code"),
                    "baseline_response_excerpt": observation.get("baseline_response_excerpt", ""),
                }
            )

        return {
            "title": f"{vuln_label}利用链",
            "status": status,
            "complete": self.chain_complete(status, verification_kind, steps),
            "verification_kind": verification_kind,
            "summary": finding.get("summary") or "",
            "missing_evidence": self.missing_chain_evidence(status, verification_kind, steps),
            "steps": steps,
        }

    def best_active_observation(self, observations):
        observations = [observation for observation in observations or [] if observation]
        if not observations:
            return None
        return max(observations, key=self.active_observation_score)

    def active_observation_score(self, observation):
        status_code = int(observation.get("status_code") or 0)
        response = observation.get("response") or ""
        request = observation.get("request") or ""
        return (
            1 if not observation.get("blocked") else 0,
            1 if 200 <= status_code < 400 else 0,
            1 if observation.get("ok") else 0,
            min(len(response), 5000),
            min(len(request), 2000),
        )

    def related_flow_for_observation(self, observation, related_flows):
        if not observation:
            return (related_flows or [None])[0]
        related_id = observation.get("related_flow_id")
        related_auth = observation.get("related_auth_fingerprint")
        for flow in related_flows or []:
            if related_id and flow.get("id") == related_id:
                return flow
            if related_auth and flow.get("auth_fingerprint") == related_auth:
                return flow
        return (related_flows or [None])[0]

    def chain_vuln_label(self, candidate):
        labels = {
            "idor": "水平越权/IDOR",
            "tenant_isolation": "租户隔离",
            "unauthorized": "未授权访问",
            "vertical_authz": "垂直越权",
            "workflow_bypass": "流程绕过",
            "mass_assignment": "敏感字段绑定",
        }
        return labels.get(candidate.vuln_type, "逻辑漏洞")

    def source_step_proof(self, candidate):
        if candidate.vuln_type == "unauthorized":
            return "证明认证用户访问该资源时的正常请求与响应基线。"
        if candidate.vuln_type in ("idor", "tenant_isolation"):
            return "证明当前用户、当前资源标识和原始响应内容，作为跨身份访问对照基线。"
        return "证明触发该业务逻辑风险的原始请求、响应和上下文字段。"

    def active_step_proof(self, candidate):
        verification_kind = (candidate.verification or {}).get("kind")
        if verification_kind == "swap_auth":
            return "证明替换为其他用户认证后仍可访问原用户资源，形成跨身份越权证据。"
        if verification_kind == "strip_auth":
            return "证明去除认证信息后仍可访问认证资源，形成未授权访问证据。"
        if verification_kind == "mutate_param":
            return "证明篡改客户端敏感字段后服务端仍接受请求，形成参数篡改/流程绕过证据。"
        return "证明主动差分验证结果。"

    def chain_complete(self, status, verification_kind, steps):
        if status != "confirmed":
            return False
        roles = {step.get("role") for step in steps or []}
        if verification_kind == "swap_auth":
            return {
                "source_user_baseline",
                "alternate_identity_baseline",
                "active_verification",
            }.issubset(roles)
        if verification_kind == "strip_auth":
            return {"source_user_baseline", "active_verification"}.issubset(roles)
        if verification_kind == "same_auth_replay":
            return {"source_user_baseline", "active_verification"}.issubset(roles)
        if verification_kind == "mutate_param":
            return {"source_user_baseline", "active_verification"}.issubset(roles)
        return "source_user_baseline" in roles

    def missing_chain_evidence(self, status, verification_kind, steps):
        if self.chain_complete(status, verification_kind, steps):
            return []

        missing = []
        roles = {step.get("role") for step in steps or []}
        if status != "confirmed":
            missing.append("Agent 结论尚未达到 confirmed，需要继续补充能闭环证明越权/绕过的响应差异或业务上下文。")
        if "source_user_baseline" not in roles:
            missing.append("缺少当前用户原始请求与响应基线。")
        if verification_kind == "swap_auth":
            if "alternate_identity_baseline" not in roles:
                missing.append("缺少其他用户认证来源请求与响应基线。")
            if "active_verification" not in roles:
                missing.append("缺少替换其他用户认证访问原资源的验证请求与响应。")
        elif verification_kind == "strip_auth":
            if "active_verification" not in roles:
                missing.append("缺少去除认证信息后访问原资源的验证请求与响应。")
        elif verification_kind == "same_auth_replay":
            if "active_verification" not in roles:
                missing.append("缺少重放包含敏感业务字段请求后的验证请求与响应。")
        elif verification_kind == "mutate_param":
            if "active_verification" not in roles:
                missing.append("缺少篡改敏感字段后的验证请求与响应。")
        else:
            missing.append("该类风险当前以被动上下文判断为主，确认前需要补充角色、前置步骤或服务端状态变化证据。")
        return missing

    def observation_packet_title(self, candidate, observation):
        verification_kind = (candidate.verification or {}).get("kind")
        if verification_kind == "swap_auth":
            return "替换其他用户认证后访问当前用户资源"
        if verification_kind == "strip_auth":
            return "去除认证信息后访问当前用户资源"
        if verification_kind == "same_auth_replay":
            return "重放包含敏感业务字段的原始请求"
        if verification_kind == "mutate_param":
            mutation = observation.get("mutation") or {}
            name = mutation.get("name") or "敏感字段"
            old_value = mutation.get("old_value")
            new_value = mutation.get("new_value")
            if new_value is not None:
                return f"篡改 {name}={old_value} -> {new_value} 后重放请求"
            return "篡改敏感字段后重放请求"
        return observation.get("purpose") or "主动差分验证请求"

    def render_stored_request(self, flow):
        method = (flow.get("method") or "GET").upper()
        url = flow.get("url") or ""
        headers = flow.get("request_headers") or {}
        body = flow.get("request_body_text") or ""
        lines = [f"{method} {url} HTTP/1.1"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def render_stored_response(self, flow):
        status_code = flow.get("status_code") or 0
        headers = flow.get("response_headers") or {}
        body = flow.get("response_body_text") or ""
        lines = [f"HTTP/1.1 {status_code}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def emit_finding(self, finding):
        existing = self.store.load_finding(finding.get("finding_key"))
        finding = merge_logic_findings(existing, finding)
        self.store.save_finding(finding)
        upsert_jsonl(
            self.output_file,
            finding,
            key_func=stable_logic_finding_key_from_result,
        )
        if hasattr(self, "on_finding"):
            self.on_finding(None)
        print(
            red(
                "[逻辑漏洞][发现] {status} {title} -> {method} {host}{endpoint}".format(
                    status=finding.get("status"),
                    title=finding.get("title"),
                    method=finding.get("method"),
                    host=finding.get("host"),
                    endpoint=finding.get("endpoint"),
                )
            ),
            flush=True,
        )
        write_html_report(
            self.vuln_file,
            self.report_file,
            fingerprint_jsonl_path=self.fingerprint_file,
            logic_jsonl_path=self.output_file,
        )
