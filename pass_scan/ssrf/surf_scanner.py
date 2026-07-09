# SSRF（服务端请求伪造 / Server-Side Request Forgery）检测流程。
#
# 这个文件负责“怎么检测 SSRF”，自带一份精简的主动发包逻辑（不复用 SQL / XSS / RCE / LFI
# 插件，各插件互不影响）。
#
# 检测方式只有一种，也是最通用、覆盖面最广的一种——带外（OOB）确认：
#    把参数替换成指向唯一子域的 URL（http://<host>/、无协议裸主机、协议相对、userinfo 白名单
#    绕过等多种落点写法），服务端一旦去请求（哪怕只做 DNS 解析）就回连 interactsh 公共服务
#    （oob.py + tools/interactsh_client.py）。回连是异步到达的，由后台轮询线程关联 token 并写
#    结果。命中即高置信（服务端真的对外发了请求），且不依赖响应回显，天然覆盖“盲打 SSRF”。
#    回连来源 IP 是目标服务器而非我们，天然证明是“服务端”发起。前提是目标能对外发请求。
#
# 为什么不做“响应回显/云元数据”那一套：那类检测只在“目标恰好在某云 + 应用会把抓取内容
# 回显”时才触发，很窄；而应用一旦回显，OOB 本来就命中了。它并不拓宽“能不能发现 SSRF”，
# 只是危害确认/无出网兜底的小补充，收益低、还要多发一批固定 IP 的请求，因此这里不做，
# 保持插件通用、精简。
#
# 流量筛选（先筛后测，满足“先判断是否要做 SSRF，需要才进入检测”）：
# - 全局层：ScanContext 已过滤静态资源、二进制响应、无意义方法/状态码。
# - 插件层 interested()：仅 GET/POST 且存在可控参数（query/form/json）才进入。
#   不再对参数名/值做“疑似 SSRF 参数”筛选——默认对全部参数做 SSRF 检测，覆盖最全。
#   （full_payload_scan 时再额外纳入 Cookie/Header。）
#
# 绕过策略：按“请求包不多就把绕过并进基础 payload”的思路，多协议、无协议裸主机、协议相对、
# userinfo/路径/片段白名单绕过、子域名拼接击穿、非 http 协议、大小写/URL 编码 scheme 等
# 全部直接写进 rules.yaml 的 OOB 模板，不再单独设 tamper 阶段。基础模板始终发；
# oob_templates_extra 里更激进的绕过在 full_payload_scan / deep_tamper 时追加。

import os
import socket
import ssl
import threading
import time
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
from pass_scan.ssrf.oob import OOBManager
from pass_scan.ssrf.rules import build_oob_templates, render_oob


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

# 单个主动探测请求的超时时间。SSRF 里服务端要去请求外部目标，可能偏慢，给足余量。
TIMEOUT = 15

# 做响应查找/比较时截取的最大长度。
MAX_COMPARE_CHARS = 400000

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


class SSRFScanner:
    """SSRF 扫描器。

    接口和 SQLInjectionScanner / CommandInjectionScanner / PathTraversalScanner / XSSScanner
    对齐：
    - name
    - interested(context)
    - dedup_key(context)
    - check(context)
    """

    name = "ssrf"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        # deep_tamper：开启后追发 oob_templates_extra 里更激进的绕过变体（更广，但每个变体
        # 多占一个带外域名 + 一次请求）。默认开启，追求覆盖面。
        self.deep_tamper = bool(self.config.get("deep_tamper", True))

        # 内部去重：同一路径下同一参数只主动扫描一次。
        self.scanned = set()
        # OOB 回连可能来自同一参数的多个 payload/token；报告层同一参数只报一次。
        self.reported_oob_findings = set()

        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

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
        """轻量判断：SSRF 插件是否关心这条流量。不发请求。

        流量筛选关口：仅 GET/POST 且存在可控参数（query/form/json）就进入。
        不再按“疑似 SSRF 参数”筛选——默认对全部参数做检测。
        """
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
        """SSRF 检测入口。"""
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

        # baseline 只作“目标是否存活”的门槛：一次干净重放都失败、又没有原始响应，
        # 说明目标不可达，没必要再为它消耗带外域名。
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

            result = self.check_one_param(flow, candidate)
            dispatched = bool(result)
            if dispatched and not reserved_scan:
                with self.lock:
                    self.scanned.add(scan_key)
            elif reserved_scan and not dispatched:
                with self.lock:
                    self.scanned.discard(scan_key)

            finding = result if isinstance(result, dict) else None
            if finding:
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # 参数提取（默认全参数，不做疑似筛选）
    # ------------------------------------------------------------------

    def extract_candidates(self, context):
        """从请求中提取可控参数。

        默认对全部参数做 SSRF 检测，不做“疑似 SSRF 参数”筛选：
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

    def check_one_param(self, flow, candidate):
        """对单个参数做 SSRF 检测（带外）。

        OOB 是异步的：这里只负责“发出带外 payload 并登记 token”，服务端回连稍后由后台
        轮询线程关联并写结果。返回 True 表示至少发出过一个 OOB payload。
        """
        return self.fire_oob(flow, candidate)

    def fire_oob(self, flow, candidate):
        """发送带外 payload 并登记 token。返回 True 表示至少发出过一个 payload。"""
        if not self.oob.enabled:
            return False

        value = candidate["value"]
        allow = self.target_host(flow)
        base_info = {
            "scan_key": self.make_scan_key(flow, candidate),
            "url": flow.request.pretty_url,
            "request_method": flow.request.method,
            "param_place": candidate["place"],
            "param_name": candidate["name"],
        }

        # 基础带外变体（已并入主流绕过）；full/deep 时追加额外变体。
        templates = build_oob_templates(extra=self.use_extra_oob())

        sent_any = False
        for entry in templates:
            token, host = self.oob.new_domain()
            if not token:
                return sent_any
            payload = render_oob(entry["template"], host, value=value, allow=allow)
            self._send_and_register_oob(
                flow, candidate, payload, host, token, entry["name"], base_info
            )
            sent_any = True

        # 动态变体：原始值本身就是 URL 时，只把其中的主机换成带外域名、保留 scheme/path。
        # 覆盖“服务端会校验路径或只信任特定 scheme”的场景。
        host_swap = self.build_host_swap_payload(value)
        if host_swap:
            token, host = self.oob.new_domain()
            if token:
                payload = host_swap.replace("__OOB_HOST__", host)
                self._send_and_register_oob(
                    flow, candidate, payload, host, token, "host_in_url", base_info
                )
                sent_any = True
        return sent_any

    def _send_and_register_oob(self, flow, candidate, payload, host, token, group_name, base_info):
        """发送单个带外 payload 并把注入点信息登记到 token 上。"""
        info = dict(base_info)
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

    def build_host_swap_payload(self, value):
        """若参数原值是带主机的 URL，返回把主机替换成占位符 __OOB_HOST__ 的新 URL，否则 None。"""
        value = (value or "").strip()
        if "://" not in value:
            return None
        try:
            parts = urlsplit(value)
        except ValueError:
            return None
        if not parts.scheme or not parts.netloc:
            return None
        swapped = parts._replace(netloc="__OOB_HOST__")
        return urlunsplit(swapped)

    def handle_oob_interaction(self, info, interaction):
        """后台轮询线程回调：收到某注入点的带外回连，生成 SSRF 漏洞结果。

        HTTP 回连说明服务端真的发起了 HTTP 请求，置信度最高；DNS-only 回连说明服务端至少
        解析了我们的域名（也可能是其解析链路/安全设备预解析），置信度稍低，在证据里标注。
        """
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

        confidence = "high" if protocol in ("HTTP", "HTTPS") else "medium"
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "ssrf",
            "method": "ssrf",
            "request_method": info.get("request_method", ""),
            "url": info.get("url", ""),
            "param_place": info.get("param_place", ""),
            "param_name": info.get("param_name", ""),
            "evidence": {
                "technique": "带外请求",
                "message": f"out-of-band {protocol} callback received from target server",
                "payload_group": info.get("payload_group"),
                "payload": info.get("payload"),
                "oob_protocol": protocol,
                "oob_remote_address": remote,
                "oob_domain": info.get("oob_domain"),
                "confidence": confidence,
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
        """同一请求参数的多个 OOB token 只生成一条 SSRF 报告。"""
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

    def target_host(self, flow):
        """目标站点自身主机名，用于 userinfo 白名单绕过 payload（http://<host>@<oob>/）。"""
        return urlsplit(flow.request.pretty_url).hostname or ""

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
        """构造“请求超时”的探测结果。"""
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
            pairs[candidate["index"]] = (candidate["name"], payload)
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
        """编码 query/form 参数，保留 payload 里手写的 %xx（如 enc_scheme 变体里的 %3a/%2f）。"""
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
    # 带外变体范围
    # ------------------------------------------------------------------

    def use_extra_oob(self):
        """是否发送额外带外变体（更多绕过写法）。full_payload_scan 或 deep_tamper 时开启。"""
        return self.full_payload_scan or self.deep_tamper

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
                f"检测到 SSRF[{technique}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
