# 命令注入（OS Command Injection）检测流程。
#
# 这个文件负责“怎么检测命令注入”，自带一份精简的主动发包逻辑
# （不复用 SQL / XSS 插件，各插件互不影响）。
#
# 三种检测方式，报告里统一归为一种漏洞“命令执行”（type=command_injection，
# method=command_injection），用证据里的“检测方式”字段区分是回显/延时/带外：
#
# 1. 算术回显（检测方式=命令回显）：
#    把一段“能算出唯一乘积”的表达式拼进参数（$((a*b))、expr a \* b、set /a a*b、
#    以及 $() / 反引号 / 分隔符 / 引号逃逸等多种上下文）。只有目标真的执行了命令、
#    并把结果回显到响应，响应里才会出现那个乘积。参数被原样反射只会回显“算式”
#    （含 a、b、运算符），不含乘积，因此能天然区分“命令执行”和“普通反射”，误报极低。
#
# 2. 时间盲注（检测方式=命令延时）：
#    用 sleep / ping / timeout / Start-Sleep 制造稳定延时。control(0 延时) 与
#    delay(N 延时) 成对比较 + 二次确认，覆盖“无任何回显”的盲打场景。逻辑与 SQL
#    时间盲注一致：control 不该慢、delay 要稳定慢过阈值、防止整站变慢误报。
#
# 3. OOB 带外（检测方式=命令带外）：
#    注入向唯一子域发起 DNS/HTTP 请求的命令（nslookup/curl/certutil…），目标执行后
#    回连 interactsh 公共服务（oob.py + tools/interactsh_client.py）。回连是异步到达的，
#    由后台轮询线程关联 token 并写结果。命中即高置信，覆盖完全无回显、无延时的盲打。
#    前提是目标能出网；内网无出网时 OOB 静默，由时间盲注兜底，两者互补。
#    时间盲注是否兜着跑由 time_based_mode 控制（always / fallback / off）。
#
# 流量筛选（先筛后测）：
# - 全局层：ScanContext 已过滤静态资源、二进制响应、无意义方法/状态码。
# - 插件层 interested()：GET/POST + 有可注入参数才进入。默认对全部参数做命令注入检测，
#   不做参数名/值筛选（full_payload_scan 时再额外纳入 Cookie/Header）。
#
# OS 家族记忆：一旦某 host 通过某类命中确认是 unix / windows，后续按该 OS 裁剪
# payload（Linux 不再发 ping -n / set /a），减少无效请求，参考 SQL 的 host_dbms。
#
# tamper 阶段：基础 payload 保持干净（正常空格）；原始 payload 被 WAF 拦截、或开启
# deep_tamper 且未命中时，才按 rules.yaml 的 tamper_profiles 追发空格绕过变形
# （${IFS}/$IFS$9/Tab/${IFS%??}），控制 payload 数量、绕过按需触发。

import os
import socket
import ssl
import threading
import time
from random import Random
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit
from urllib.request import (
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pass_scan.body_paser import decode_body_text, get_header
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context, replace_json_body_parameter
from pass_scan.terminal import red
from pass_scan.command_injection.oob import OOBManager
from pass_scan.command_injection.rules import (
    build_echo_groups,
    build_time_groups,
    echo_random_range,
    max_tampered_payloads_per_probe,
    oob_templates,
    render_oob,
    tamper_profiles,
    time_delay,
    time_threshold,
    waf_detection_rules,
)
from pass_scan.command_injection.tamper import apply_tampers


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

# 单个主动探测请求的超时时间。要大于时间盲注延时 + ping 余量。
TIMEOUT = 15

# 做响应查找/比较时截取的最大长度。
MAX_COMPARE_CHARS = 200000

# 这些 os 是“具体系统”。识别出其一后，带 os 标签的 payload 只发当前系统的版本。
CONCRETE_OS = {"unix", "windows"}

# 连接级 header，不适合照抄到主动重放请求。
HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}


class NoRedirectHandler(HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CommandInjectionScanner:
    """命令注入扫描器。

    接口和 SQLInjectionScanner / XSSScanner / FingerprintScanner 对齐：
    - name
    - interested(context)
    - dedup_key(context)
    - check(context)
    """

    name = "command_injection"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        self.deep_tamper = bool(self.config.get("deep_tamper", True))
        self.deep_tamper_max_profiles = int(self.config.get("deep_tamper_max_profiles", 4))

        self.time_delay = int(self.config.get("time_delay", time_delay()))
        self.time_threshold = float(self.config.get("time_threshold", time_threshold()))
        # 时间盲注策略：always 恒跑；fallback 仅在 OOB 不可用时跑；off 关闭。
        self.time_based_mode = str(self.config.get("time_based_mode", "always")).lower()

        # 内部去重：同一路径下同一参数只主动扫描一次。
        self.scanned = set()
        # OOB 回连可能来自同一参数的多个 payload/token；报告层同一参数只报一次。
        self.reported_oob_findings = set()
        # 每个 host 已识别出的操作系统类型（unix / windows）。
        self.host_os = {}

        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

        # 用固定种子的随机数源生成算术操作数，保证同一次运行可复现、不同参数不同数。
        self.random = Random()

        # OOB 带外：启用后对接 interactsh 公共服务，后台轮询回连。
        # 回连是异步到达的，命中时由 handle_oob_interaction 直接写结果。
        self.oob = OOBManager(
            self.config.get("oob"), on_interaction=self.handle_oob_interaction
        )
        self.oob.start()

        # 不走系统代理，避免主动探测又绕回 Burp/mitmproxy 形成回环。
        # 不校验 HTTPS 证书，方便测试自签名站点。
        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
        )

        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # 调度层接口
    # ------------------------------------------------------------------

    def interested(self, context):
        """轻量判断：命令注入插件是否关心这条流量。不发请求。"""
        if context.is_skipped:
            return False
        if context.method not in ("GET", "POST"):
            return False
        return bool(self.extract_candidates(context))

    def dedup_key(self, context):
        """调度层去重 key：同一 URL 路径 + 同一批参数名，TTL 内只入队一次。"""
        param_shape = tuple(
            (param["place"], param["name"], param.get("index", ""))
            for param in self.extract_candidates(context)
        )
        return (
            self.name,
            context.method,
            context.scheme,
            context.host,
            self.normalize_path_for_dedup(context.path),
            context.request_content_type,
            param_shape,
        )

    def check(self, context, flow=None):
        """命令注入检测入口。"""
        # 兼容旧调用方式 check(record, flow)。
        if flow is not None:
            context = build_scan_context(
                context,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        if not self.interested(context):
            return []

        flow = context.flow
        candidates = self.extract_candidates(context)
        if not candidates:
            return []

        baseline = self.build_baseline(flow)
        if not baseline:
            return []

        findings = []
        for candidate in candidates:
            scan_key = self.make_scan_key(flow, candidate)
            with self.lock:
                if scan_key in self.scanned:
                    continue
                reserved_scan = self.oob.enabled
                if reserved_scan:
                    self.scanned.add(scan_key)

            finding, oob_dispatched = self.check_one_param(flow, baseline, candidate)
            if finding:
                with self.lock:
                    self.scanned.add(scan_key)
                    self.reported_oob_findings.add(scan_key)
            elif oob_dispatched and not reserved_scan:
                with self.lock:
                    self.scanned.add(scan_key)
            elif reserved_scan and not oob_dispatched:
                with self.lock:
                    self.scanned.discard(scan_key)

            if finding:
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # 参数筛选
    # ------------------------------------------------------------------

    def extract_candidates(self, context):
        """从请求中提取可控参数。

        默认对全部参数做命令注入检测，不做“疑似命令参数”筛选：
        - 普通模式：全部 query / form / json。
        - full_payload_scan：额外加 cookie / header。
        """
        normal_places = {"query", "form", "json"}
        params = [p for p in context.parameters if p["place"] in normal_places]

        if self.full_payload_scan:
            params += [p for p in context.parameters if p["place"] in ("cookie", "header")]

        return params

    def normalize_path_for_dedup(self, path):
        """去重用路径归一化：/admin 和 /admin/ 视为同一页面。"""
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    # ------------------------------------------------------------------
    # baseline
    # ------------------------------------------------------------------

    def build_baseline(self, flow):
        """构造 baseline：优先用一次干净重放，退回 mitmproxy 已有响应。"""
        clean = self.send_probe(flow, None, "")
        if clean and not clean.get("timed_out"):
            return clean

        original = self.response_from_flow(flow)
        if original:
            return original
        return None

    def response_from_flow(self, flow):
        """把 mitmproxy 已拿到的原始响应转换成可比较结构。"""
        response = getattr(flow, "response", None)
        if not response:
            return None
        body = response.content or b""
        text, _charset = decode_body_text(body, response.headers)
        return {
            "status_code": response.status_code,
            "length": len(body),
            "elapsed": 0,
            "headers": dict(response.headers.items()),
            "text": text[:MAX_COMPARE_CHARS],
        }

    # ------------------------------------------------------------------
    # 单参数检测
    # ------------------------------------------------------------------

    def check_one_param(self, flow, baseline, candidate):
        """对单个参数依次做算术回显、OOB、时间盲注检测。

        - 回显命中即返回（最快、最确定）。
        - OOB 是异步的：这里只负责“发出带外 payload 并登记”，回连稍后由后台轮询
          线程关联并写结果，不在本函数即时返回。
        - 时间盲注按 time_based_mode 决定是否兜底。
        """
        finding = self.check_echo(flow, baseline, candidate)
        if finding:
            return finding, False

        oob_dispatched = self.fire_oob(flow, candidate)

        if self.should_run_time_based():
            finding = self.check_time(flow, baseline, candidate)
            if finding:
                return finding, oob_dispatched

        return None, oob_dispatched

    def should_run_time_based(self):
        """按 time_based_mode 决定是否跑时间盲注。"""
        if self.time_based_mode == "off":
            return False
        if self.time_based_mode == "fallback":
            # OOB 可用时不跑时间盲注，靠带外覆盖盲打；OOB 不可用才兜底。
            return not self.oob.enabled
        return True  # always

    def check_echo(self, flow, baseline, candidate):
        """算术回显型检测。原始 payload 被拦或 deep_tamper 未命中时追发空格绕过变形。"""
        a, b, product = self.pick_operands(baseline)
        groups = self.filter_groups_by_os(flow, build_echo_groups(candidate["value"], a, b))

        for group in groups:
            for probe in self.send_probe_variants(
                flow, candidate, group["payload"], baseline,
                deep_tamper=self.use_deep_tamper(),
            ):
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue
                if product in probe["text"]:
                    self.record_os(flow, group["os"])
                    return self.build_finding(
                        flow, candidate,
                        {
                            "technique": "命令回显",
                            "message": "arithmetic result computed by the shell appeared in response",
                            "os": group["os"],
                            "payload_group": group["name"],
                            "payload": probe["sent_payload"],
                            "expression": f"{a}*{b}",
                            "product": product,
                            "baseline_status": baseline["status_code"],
                            "probe_status": probe["status_code"],
                            "probe_length": probe["length"],
                            **self.tamper_evidence(probe),
                        },
                        proof_probe=probe,
                    )
        return None

    def check_time(self, flow, baseline, candidate):
        """时间盲注检测。"""
        groups = self.filter_groups_by_os(
            flow, build_time_groups(candidate["value"], self.time_delay)
        )
        for group in groups:
            finding = self.check_delay_pair(flow, baseline, candidate, group)
            if finding:
                return finding
        return None

    def fire_oob(self, flow, candidate):
        """发送带外 payload 并登记 token。返回 True 表示至少发出过一个 payload。"""
        if not self.oob.enabled:
            return False

        value = candidate["value"]
        groups = self.filter_groups_by_os(flow, oob_templates())
        base_info = {
            "scan_key": self.make_scan_key(flow, candidate),
            "url": flow.request.pretty_url,
            "request_method": flow.request.method,
            "param_place": candidate["place"],
            "param_name": candidate["name"],
        }

        sent_any = False
        for entry in groups:
            # 每个上下文发原始 payload；开启 deep_tamper 时再补一个 ${IFS} 变形，
            # 用独立域名以便区分是哪种写法触发了回连。
            variants = [("none", [])]
            if self.use_deep_tamper():
                variants.append(("space2ifs", ["space2ifs"]))

            for profile_name, tampers in variants:
                token, host = self.oob.new_domain()
                if not token:
                    return sent_any
                payload = render_oob(entry["template"], value, host)
                if tampers:
                    payload = apply_tampers(payload, tampers)
                self._send_and_register_oob(
                    flow,
                    candidate,
                    payload,
                    host,
                    token,
                    entry["name"],
                    base_info,
                    {"os": entry.get("os", "any"), "tamper_profile": profile_name},
                )
                sent_any = True
        return sent_any

    def _send_and_register_oob(
        self, flow, candidate, payload, host, token, group_name, base_info, extra_info=None
    ):
        """发送单个带外 payload，并在发包前登记 token 上下文。"""
        info = dict(base_info)
        info.update(extra_info or {})
        info.update(
            {
                "payload_group": group_name,
                "payload": payload,
                "oob_domain": host,
                "request_packet": self.preview_request_packet(flow, candidate, payload),
            }
        )
        self.oob.record(token, info)
        probe = self.send_probe(flow, candidate, payload)
        if probe and probe.get("request_packet"):
            self.oob.record(token, {"request_packet": probe.get("request_packet", "")})

    def preview_request_packet(self, flow, candidate, payload):
        """在真正发包前生成请求包，避免 OOB 回连先到时报告缺少上下文。"""
        request = flow.request
        method = request.method.upper()
        url, body, header_overrides = self.build_probe_request(flow, candidate, payload)
        headers = self.copy_headers(request.headers)
        for name, value in header_overrides.items():
            self.set_header(headers, name, value)
        data = body if method != "GET" else None
        return self.build_request_packet(method, url, headers, data)

    def handle_oob_interaction(self, info, interaction):
        """后台轮询线程回调：收到某注入点的带外回连，生成命令注入漏洞结果。"""
        protocol = (interaction.get("protocol") or "").upper()
        remote = (
            interaction.get("remote-address")
            or interaction.get("remoteAddress")
            or ""
        )
        report_key = self.oob_report_key(info)
        with self.lock:
            if report_key in self.reported_oob_findings:
                return
            self.reported_oob_findings.add(report_key)

        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "command_injection",
            "method": "command_injection",
            "request_method": info.get("request_method", ""),
            "url": info.get("url", ""),
            "param_place": info.get("param_place", ""),
            "param_name": info.get("param_name", ""),
            "evidence": {
                "technique": "命令带外",
                "message": f"out-of-band {protocol} callback received from target",
                "os": info.get("os"),
                "payload_group": info.get("payload_group"),
                "payload": info.get("payload"),
                "oob_protocol": protocol,
                "oob_remote_address": remote,
                "oob_domain": info.get("oob_domain"),
                **({"tamper_profile": info.get("tamper_profile"), "waf_bypass": True}
                   if info.get("tamper_profile") not in (None, "none") else {}),
            },
            "proof": {
                "request": info.get("request_packet", ""),
                "response": self.oob_proof_text(interaction),
            },
            "extra_proofs": [],
        }
        self.write_finding(finding)
        print_finding_once(self, finding)

    def oob_report_key(self, info):
        """同一请求参数的多个 OOB token 只生成一条命令注入报告。"""
        scan_key = info.get("scan_key")
        if scan_key:
            return tuple(scan_key)
        return (
            info.get("request_method", ""),
            info.get("url", ""),
            info.get("param_place", ""),
            info.get("param_name", ""),
            info.get("param_index", ""),
        )

    def oob_proof_text(self, interaction):
        """把一次带外交互整理成可读的“证据”文本，放进报告的响应包位置。"""
        lines = ["[OOB interaction]"]
        for key in ("protocol", "unique-id", "full-id", "remote-address", "timestamp", "q-type"):
            value = interaction.get(key)
            if value:
                lines.append(f"{key}: {value}")
        raw = interaction.get("raw-request") or interaction.get("rawRequest")
        if raw:
            lines.append("")
            lines.append(str(raw))
        return "\n".join(lines)

    def check_delay_pair(self, flow, baseline, candidate, group):
        """control / delay 成对延时验证 + 二次确认。被拦或 deep_tamper 时用同种变形重试。"""
        for control, delayed in self.send_probe_pair_variants(
            flow, candidate, group["control"], group["delay"], baseline,
            deep_tamper=self.use_deep_tamper(),
        ):
            if not control or not delayed:
                continue
            if control.get("waf_blocked") or delayed.get("waf_blocked"):
                continue
            # control 是 0 延时 payload，它本身不该慢。连 control 都超时说明整站在挂，
            # 不是注入引起的延时，跳过避免误报。
            if control.get("timed_out"):
                continue

            first_gap = delayed["elapsed"] - control["elapsed"]
            if first_gap < self.time_threshold:
                continue

            # 二次确认：用同一组已选中的 payload 再发一次。
            control_again, delayed_again = self.send_same_payload_pair(
                flow, candidate, control, delayed, baseline
            )
            if not control_again or not delayed_again:
                continue
            if control_again.get("waf_blocked") or delayed_again.get("waf_blocked"):
                continue
            if control_again.get("timed_out"):
                continue

            second_gap = delayed_again["elapsed"] - control_again["elapsed"]
            if second_gap < self.time_threshold:
                continue

            delay_timed_out = bool(delayed.get("timed_out") and delayed_again.get("timed_out"))

            self.record_os(flow, group["os"])
            return self.build_finding(
                flow, candidate,
                {
                    "technique": "命令延时",
                    "message": "delay payload is consistently slower than control payload",
                    "os": group["os"],
                    "payload_group": group["name"],
                    "control_payload": control["sent_payload"],
                    "delay_payload": delayed["sent_payload"],
                    "delay_seconds": self.time_delay,
                    "first_control_elapsed": round(control["elapsed"], 3),
                    "first_delay_elapsed": round(delayed["elapsed"], 3),
                    "second_control_elapsed": round(control_again["elapsed"], 3),
                    "second_delay_elapsed": round(delayed_again["elapsed"], 3),
                    "first_gap": round(first_gap, 3),
                    "second_gap": round(second_gap, 3),
                    "delay_timed_out": delay_timed_out,
                    **self.tamper_evidence(control),
                },
                proof_probe=delayed,
                extra_probes=[{"name": "control payload", "probe": control}],
            )
        return None

    def pick_operands(self, baseline):
        """生成算术回显用的随机操作数，保证乘积不在 baseline 里、且足够长。"""
        low, high = echo_random_range()
        baseline_text = baseline.get("text", "") if baseline else ""
        a = self.random.randint(low, high)
        b = self.random.randint(low, high)
        product = str(a * b)
        # 乘积太短或恰好出现在 baseline 里，重新抽，最多几次。
        for _ in range(6):
            if len(product) >= 6 and product not in baseline_text:
                break
            a = self.random.randint(low, high)
            b = self.random.randint(low, high)
            product = str(a * b)
        return a, b, product

    # ------------------------------------------------------------------
    # OS 家族记忆
    # ------------------------------------------------------------------

    def host_from_flow(self, flow):
        return urlsplit(flow.request.pretty_url).netloc

    def record_os(self, flow, os_name):
        """记住某 host 已识别出的操作系统类型（只记具体系统）。"""
        if os_name not in CONCRETE_OS:
            return
        host = self.host_from_flow(flow)
        with self.lock:
            if self.host_os.get(host) != os_name:
                self.host_os[host] = os_name

    def known_os(self, flow):
        with self.lock:
            return self.host_os.get(self.host_from_flow(flow))

    def filter_groups_by_os(self, flow, groups):
        """按已识别的 OS 裁剪 payload 组；未识别时全部尝试。"""
        os_name = self.known_os(flow)
        if not os_name:
            return groups
        filtered = [g for g in groups if g.get("os", "any") in (os_name, "any")]
        return filtered or groups

    # ------------------------------------------------------------------
    # 主动发包
    # ------------------------------------------------------------------

    def send_probe(self, flow, candidate, payload):
        """主动发送探测请求。candidate 为 None 表示重放原始请求。"""
        request = flow.request
        method = request.method.upper()
        url, body, header_overrides = self.build_probe_request(flow, candidate, payload)
        host = urlsplit(url).netloc

        if self.waf_state:
            self.waf_state.wait_if_needed(host)

        headers = self.copy_headers(request.headers)
        for name, value in header_overrides.items():
            self.set_header(headers, name, value)

        data = body if method != "GET" else None
        request_packet = self.build_request_packet(method, url, headers, data)
        urllib_request = Request(url, data=data, headers=headers, method=method)

        start_time = time.monotonic()
        try:
            response = self.opener.open(urllib_request, timeout=TIMEOUT)
            response_body = response.read()
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            response_body = error.read()
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError):
            return self.timed_out_probe(request_packet)
        except (URLError, OSError) as error:
            reason = getattr(error, "reason", None)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                return self.timed_out_probe(request_packet)
            return None

        elapsed = time.monotonic() - start_time
        charset = response_headers.get_content_charset() or "utf-8"
        text = response_body.decode(charset, errors="replace")
        response_packet = self.build_response_packet(
            status_code, reason, response_headers, response_body, charset
        )

        return {
            "status_code": status_code,
            "length": len(response_body),
            "elapsed": elapsed,
            "headers": dict(response_headers.items()),
            "text": text[:MAX_COMPARE_CHARS],
            "request_packet": request_packet,
            "response_packet": response_packet,
        }

    def timed_out_probe(self, request_packet=""):
        """构造“请求超时”的探测结果。超时是时间盲注的有效信号，不能当连接失败丢弃。"""
        return {
            "status_code": 0,
            "length": 0,
            "elapsed": float(TIMEOUT),
            "headers": {},
            "text": "",
            "timed_out": True,
            "request_packet": request_packet,
            "response_packet": "",
        }

    def send_probe_variants(self, flow, candidate, payload, baseline=None, deep_tamper=False):
        """发送单个 payload，被 WAF 拦或开启 deep_tamper 时追加 tamper 版本。"""
        probe = self.send_probe(flow, candidate, payload)
        if not probe:
            return

        waf_info = self.detect_waf_block(probe, baseline)
        self.annotate_probe(probe, payload, "none", [], waf_info, [])
        yield probe

        if not waf_info["blocked"] and not deep_tamper:
            return

        original_reasons = waf_info["reasons"]
        profile_limit = None
        is_deep_retry = False
        if not original_reasons:
            profile_limit = self.deep_tamper_profile_limit()
            is_deep_retry = True

        seen = {payload}
        for profile in self.iter_tamper_profiles(candidate, profile_limit):
            tampered = apply_tampers(payload, profile["tampers"])
            if tampered in seen:
                continue
            seen.add(tampered)

            retry = self.send_probe(flow, candidate, tampered)
            if not retry:
                continue
            retry_waf = self.detect_waf_block(retry, baseline)
            self.annotate_probe(
                retry, tampered, profile["name"], profile["tampers"],
                retry_waf, original_reasons, deep_tamper=is_deep_retry,
            )
            yield retry

    def send_probe_pair_variants(
        self, flow, candidate, left_payload, right_payload, baseline=None, deep_tamper=False
    ):
        """发送成对 payload（control/delay），被拦或 deep_tamper 时追加同种变形的成对版本。"""
        left = self.send_probe(flow, candidate, left_payload)
        right = self.send_probe(flow, candidate, right_payload)
        if not left or not right:
            return

        left_waf = self.detect_waf_block(left, baseline)
        right_waf = self.detect_waf_block(right, baseline)
        self.annotate_probe(left, left_payload, "none", [], left_waf, [])
        self.annotate_probe(right, right_payload, "none", [], right_waf, [])
        yield left, right

        if not left_waf["blocked"] and not right_waf["blocked"] and not deep_tamper:
            return

        original_reasons = self.merge_reasons(left_waf["reasons"], right_waf["reasons"])
        profile_limit = None
        is_deep_retry = False
        if not original_reasons:
            profile_limit = self.deep_tamper_profile_limit()
            is_deep_retry = True

        seen = {(left_payload, right_payload)}
        for profile in self.iter_tamper_profiles(candidate, profile_limit):
            t_left = apply_tampers(left_payload, profile["tampers"])
            t_right = apply_tampers(right_payload, profile["tampers"])
            if (t_left, t_right) in seen:
                continue
            seen.add((t_left, t_right))

            left_retry = self.send_probe(flow, candidate, t_left)
            right_retry = self.send_probe(flow, candidate, t_right)
            if not left_retry or not right_retry:
                continue
            left_retry_waf = self.detect_waf_block(left_retry, baseline)
            right_retry_waf = self.detect_waf_block(right_retry, baseline)
            self.annotate_probe(
                left_retry, t_left, profile["name"], profile["tampers"],
                left_retry_waf, original_reasons, deep_tamper=is_deep_retry,
            )
            self.annotate_probe(
                right_retry, t_right, profile["name"], profile["tampers"],
                right_retry_waf, original_reasons, deep_tamper=is_deep_retry,
            )
            yield left_retry, right_retry

    def send_same_payload_pair(self, flow, candidate, left_probe, right_probe, baseline):
        """用同一组已选中的 payload 再发一次，给延时注入做二次确认。"""
        left = self.send_probe(flow, candidate, left_probe["sent_payload"])
        right = self.send_probe(flow, candidate, right_probe["sent_payload"])
        if not left or not right:
            return left, right

        left_waf = self.detect_waf_block(left, baseline)
        right_waf = self.detect_waf_block(right, baseline)
        retry_reasons = left_probe.get("waf_retry_reasons", [])
        self.annotate_probe(
            left, left_probe["sent_payload"], left_probe.get("tamper_profile", "none"),
            left_probe.get("tampers", []), left_waf, retry_reasons,
        )
        self.annotate_probe(
            right, right_probe["sent_payload"], right_probe.get("tamper_profile", "none"),
            right_probe.get("tampers", []), right_waf, retry_reasons,
        )
        return left, right

    # ------------------------------------------------------------------
    # 请求构造
    # ------------------------------------------------------------------

    def build_probe_request(self, flow, candidate, payload):
        """根据参数位置构造新的 URL、body 和 header 覆盖项。"""
        request = flow.request
        url = request.pretty_url
        body = request.content or b""
        header_overrides = {}

        if not candidate:
            return url, body, header_overrides

        place = candidate["place"]
        if place == "query":
            url = self.replace_query_value(url, candidate["index"], payload)
            return url, body, header_overrides

        if place == "cookie":
            cookie_header = get_header(request.headers, "cookie")
            pairs = self.parse_cookie_pairs(cookie_header)
            pairs[candidate["index"]] = (candidate["name"], payload.replace(" ", "${IFS}"))
            header_overrides["Cookie"] = self.build_cookie_header(pairs)
            return url, body, header_overrides

        if place == "header":
            header_overrides[candidate["name"]] = payload
            return url, body, header_overrides

        if place == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            pairs[candidate["index"]] = (candidate["name"], payload)
            charset = candidate.get("charset") or "utf-8"
            body = self.urlencode_pairs(pairs, charset).encode(charset, errors="replace")
            return url, body, header_overrides

        if place == "json":
            body = replace_json_body_parameter(
                body,
                request.headers,
                candidate,
                payload,
            )
            return url, body, header_overrides

        return url, body, header_overrides

    def replace_query_value(self, url, index, new_value):
        """只替换 URL 里第 index 个 query 参数。"""
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs[index] = (pairs[index][0], new_value)
        new_query = self.urlencode_pairs(pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def urlencode_pairs(self, pairs, charset="utf-8"):
        """编码 query/form 参数，保留 payload 里手写的 %xx（如 %0a 换行注入）。"""
        encoded = []
        for name, value in pairs:
            encoded_name = quote_plus(str(name), encoding=charset, errors="replace")
            encoded_value = quote_plus(str(value), safe="%", encoding=charset, errors="replace")
            encoded.append(f"{encoded_name}={encoded_value}")
        return "&".join(encoded)

    def parse_cookie_pairs(self, cookie_header):
        pairs = []
        if not cookie_header:
            return pairs
        for item in cookie_header.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                name, value = item.split("=", 1)
            else:
                name, value = item, ""
            pairs.append((name.strip(), value.strip()))
        return pairs

    def build_cookie_header(self, pairs):
        return "; ".join(f"{name}={value}" for name, value in pairs)

    def build_request_packet(self, method, url, headers, body):
        """把主动探测请求整理成类似 Burp 的原始请求包文本。"""
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        packet_headers = dict(headers)
        if not any(name.lower() == "host" for name in packet_headers):
            packet_headers["Host"] = parts.netloc
        if body:
            packet_headers["Content-Length"] = str(len(body))

        lines = [f"{method} {path} HTTP/1.1"]
        for name, value in packet_headers.items():
            lines.append(f"{name}: {value}")
        request_text = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            request_text += body.decode("utf-8", errors="replace")
        return request_text

    def build_response_packet(self, status_code, reason, headers, body, charset):
        """把主动探测响应整理成类似 Burp 的原始响应包文本。"""
        status_line = f"HTTP/1.1 {status_code} {reason}".rstrip()
        lines = [status_line]
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        response_text = "\r\n".join(lines) + "\r\n\r\n"
        response_text += body.decode(charset or "utf-8", errors="replace")
        return response_text

    def copy_headers(self, headers):
        """复制请求头，移除不适合主动重放的 header，并禁用压缩方便比较。"""
        copied = {}
        for name, value in headers.items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            copied[name] = value
        copied["Accept-Encoding"] = "identity"
        return copied

    def set_header(self, headers, name, value):
        """大小写不敏感地覆盖 header。"""
        for old_name in list(headers.keys()):
            if old_name.lower() == name.lower():
                del headers[old_name]
        headers[name] = value

    # ------------------------------------------------------------------
    # WAF 识别与 tamper
    # ------------------------------------------------------------------

    def detect_waf_block(self, response, baseline=None):
        """判断一次探测响应是否像 WAF 拦截页。"""
        rules = waf_detection_rules()
        reasons = []

        status_codes = {int(code) for code in rules.get("status_codes", [])}
        status_code = int(response.get("status_code", 0))
        baseline_status = baseline.get("status_code") if baseline else None
        if status_code in status_codes and status_code != baseline_status:
            reasons.append(f"status_code:{status_code}")

        headers_text = "\n".join(
            f"{name}: {value}" for name, value in response.get("headers", {}).items()
        ).lower()
        for keyword in rules.get("header_keywords", []):
            if keyword.lower() in headers_text:
                reasons.append(f"header:{keyword}")

        body_text = response.get("text", "")[:8000].lower()
        for keyword in rules.get("body_keywords", []):
            if keyword.lower() in body_text:
                reasons.append(f"body:{keyword}")

        return {"blocked": bool(reasons), "reasons": self.merge_reasons(reasons)}

    def iter_tamper_profiles(self, candidate=None, limit=None):
        """按 rules.yaml 顺序返回有限数量的 tamper 策略。"""
        count = 0
        if limit is None:
            limit = max_tampered_payloads_per_probe()
        if limit <= 0:
            return

        place = candidate.get("place") if candidate else ""
        for profile in tamper_profiles():
            allowed_places = profile.get("places", [])
            if allowed_places and place and place not in allowed_places:
                continue
            tampers = profile.get("tampers", [])
            if not tampers:
                continue
            yield {
                "name": profile.get("name") or "+".join(tampers),
                "tampers": tampers,
                "places": allowed_places,
            }
            count += 1
            if count >= limit:
                break

    def annotate_probe(self, probe, sent_payload, tamper_profile, tampers,
                       waf_info, retry_reasons, deep_tamper=False):
        """给探测响应补充 payload 和 WAF 元信息。"""
        probe["sent_payload"] = sent_payload
        probe["tamper_profile"] = tamper_profile
        probe["tampers"] = list(tampers)
        probe["tamper_used"] = tamper_profile != "none"
        probe["waf_blocked"] = waf_info["blocked"]
        probe["waf_reasons"] = waf_info["reasons"]
        probe["waf_retry"] = bool(retry_reasons)
        probe["waf_retry_reasons"] = self.merge_reasons(retry_reasons)
        probe["deep_tamper"] = bool(deep_tamper)

    def tamper_evidence(self, probe):
        """生成漏洞结果里的 tamper 证据字段。"""
        if probe.get("waf_retry"):
            return {
                "waf_bypass": True,
                "tamper_profile": probe.get("tamper_profile"),
                "tampers": probe.get("tampers", []),
                "waf_reasons": probe.get("waf_retry_reasons", []),
            }
        if probe.get("deep_tamper"):
            return {
                "deep_tamper": True,
                "tamper_profile": probe.get("tamper_profile"),
                "tampers": probe.get("tampers", []),
            }
        return {}

    def use_deep_tamper(self):
        """是否启用 deep tamper（普通 payload 没命中、也没明显 WAF 时追发少量变形）。"""
        if self.full_payload_scan:
            return True
        return self.deep_tamper

    def deep_tamper_profile_limit(self):
        """非 WAF 场景下 deep tamper 的 profile 数量上限。full 模式返回 None = 用 rules 完整上限。"""
        if self.full_payload_scan:
            return None
        return self.deep_tamper_max_profiles

    def merge_reasons(self, *reason_lists):
        merged = []
        for reasons in reason_lists:
            for reason in reasons:
                if reason not in merged:
                    merged.append(reason)
        return merged[:8]

    # ------------------------------------------------------------------
    # 去重与结果
    # ------------------------------------------------------------------

    def make_scan_key(self, flow, candidate):
        request = flow.request
        parts = urlsplit(request.pretty_url)
        return (
            request.method.upper(),
            parts.scheme,
            parts.netloc,
            self.normalize_path_for_dedup(parts.path),
            candidate["place"],
            candidate["name"],
            candidate.get("index", ""),
        )

    def build_finding(self, flow, candidate, evidence, proof_probe=None, extra_probes=None):
        """生成统一漏洞结果结构。

        三种检测方式（回显/延时/带外）统一为一种漏洞：type=method=command_injection，
        报告里显示为“命令执行”，具体是哪种方式看 evidence["technique"]。
        """
        request = flow.request
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "command_injection",
            "method": "command_injection",
            "request_method": request.method,
            "url": request.pretty_url,
            "param_place": candidate["place"],
            "param_name": candidate["name"],
            "evidence": evidence,
            "proof": self.probe_to_proof(proof_probe),
            "extra_proofs": [],
        }
        for extra in extra_probes or []:
            proof = self.probe_to_proof(extra.get("probe"))
            proof["name"] = extra.get("name", "extra")
            finding["extra_proofs"].append(proof)
        return finding

    def probe_to_proof(self, probe):
        if not probe:
            return {"request": "", "response": ""}
        return {
            "request": probe.get("request_packet", ""),
            "response": probe.get("response_packet", ""),
        }

    def write_finding(self, finding):
        """把漏洞结果写入 JSON Lines，并更新 HTML 报告。"""
        write_jsonl(self.vuln_file, finding)
        print_finding_once(self, finding)
        if self.on_finding:
            self.on_finding(finding)
        write_html_report(self.vuln_file, self.report_file)

    def print_finding(self, finding):
        technique = finding.get("evidence", {}).get("technique", "")
        print(
            red(
                "[漏洞] "
                f"检测到命令执行[{technique}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
