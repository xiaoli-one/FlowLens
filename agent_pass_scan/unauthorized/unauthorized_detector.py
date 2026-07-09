from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.traffic_model import SENSITIVE_ACTION_RE
from agent_pass_scan.unauthorized.unauthorized_prompts import DETECTOR_PROMPT


class UnauthorizedDetector(BaseLogicDetector):
    name = "unauthorized"
    vuln_type = "unauthorized"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        candidates = []
        endpoint = bundle.get("endpoint") or {}
        normalized_path = endpoint.get("normalized_path") or ""
        for flow in self.successful_flows(bundle):
            if (flow.get("auth_fingerprint") or "") == "anonymous":
                continue
            if not self.method_allowed_for_active_verification(flow):
                continue
            if not (
                flow.get("resource_refs")
                or flow.get("parameters")
                or SENSITIVE_ACTION_RE.search(normalized_path)
            ):
                continue
            candidates.append(
                self.make_candidate(
                    bundle,
                    flow,
                    "未授权访问风险",
                    "认证接口去除 Cookie/Authorization 后可能仍可访问业务资源。",
                    [
                        "原始请求带认证信息且返回成功状态码。",
                        "接口包含资源标识或业务参数，适合做未授权差分验证。",
                    ],
                    verification={"kind": "strip_auth", "safety": "configured_methods"},
                    resource=(flow.get("resource_refs") or [{}])[0],
                )
            )
            if len(candidates) >= 2:
                break
        return candidates
