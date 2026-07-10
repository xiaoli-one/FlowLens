# XSS 检测流程。
#
# 这个文件负责“怎么检测 XSS”，并自带一份精简的主动发包逻辑
# （不复用 SQL 插件，两者互不影响）。
#
# 设计原则：不区分反射/存储/DOM，统一成一个漏洞类型 xss。
# 本质上它们都是同一件事——“我注入的 payload 能不能在某个可执行上下文里
# 以标签形式存活”。区别只是 payload 出现在“哪一次响应”里，这只是元数据，
# 用证据里的 origin 记录（immediate=当次响应命中；persisted=后续页面命中），
# 不该拆成三个独立检测器。
#
# 检测方式（全程 payload 驱动）：
# 1. 注入纯字母数字 locator 定位参数落点，并登记到 MarkerStore 供跨页面回扫。
# 2. 用 context.py 判断落点上下文（HTML 文本/RAWTEXT 标签/属性/JS/注释/URL）。
# 3. 按上下文发带闭合序列的 payload，检查闭合字符是否原样、未被实体编码。
#    只有落在可执行上下文（能直接起标签）且闭合字符未编码，才判 confirmed。
# 4. 对每个 HTML 响应回扫已登记 locator，覆盖“在 A 页面提交、在 B 页面渲染”。
#
# 不做纯 DOM 静态特征匹配：被动代理不执行 JS，无法用 payload 证实纯 DOM XSS，
# 只能靠 innerHTML/location 这类关键字猜测，误报高且违背 payload 驱动原则，故不做。
# 参数反射进 <script> 的那部分本就被 js 上下文的 payload 检测覆盖。
#
# 不做单独的 WAF/tamper 阶段：判定只看结构字符是否原样存活，与状态码、标签名无关。
# 各种绕过/变形（等价标签、通用标签、无空格写法、只闭合引号加事件、闭合 </script>、
# 字符串拼接等）都直接写进 rules.yaml 的基础 payload，主动检测时全部用上。
#
# 流量筛选（和 SQL 插件一样，命中条件才进入 XSS 检测）：
# - 有可注入参数（query/form/json）-> 主动注入，不要求响应是 HTML。
# - 没有可注入参数但响应是 HTML -> 入队做 marker 回扫。

import os
import re
import ssl
import string
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

from pass_scan.body_paser import decode_body_text, get_header, get_media_type
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context, replace_json_body_parameter
from pass_scan.terminal import red
from pass_scan.xss import context as ctx
from pass_scan.xss.marker_store import MarkerStore
from pass_scan.xss.rules import (
    build_reflect_contexts,
    marker_config,
)


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")
MARKER_FILE = os.environ.get("PASS_SCAN_XSS_MARKER_FILE", os.path.join("logs", "xss_markers.jsonl"))

# 单个主动探测请求的超时时间。
TIMEOUT = 10

# 参与反射定位/上下文分析的正文最大长度。
MAX_BODY_CHARS = 200000

# 这些响应类型才可能承载 XSS（会被浏览器当 HTML 解析）。
# 空 content-type 也纳入：一些服务端不设 content-type，但浏览器按 HTML 处理。
HTML_MEDIA_TYPES = ("text/html", "application/xhtml+xml", "")

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


class XSSScanner:
    """XSS 扫描器。

    接口和 SQLInjectionScanner / FingerprintScanner 对齐：
    - name
    - interested(context)
    - dedup_key(context)
    - check(context)
    """

    name = "xss"

    def __init__(self, config=None, vuln_file=None, report_file=None, marker_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        # 是否对每个 HTML 响应回扫已注入的 marker（用于发现“提交后在别处渲染”的 XSS）。
        self.rescan = bool(self.config.get("rescan", self.config.get("stored_rescan", True)))

        # 内部去重：同一路径下同一参数只主动扫描一次。
        self.scanned = set()
        # 命中去重：同一 (marker, 出现URL) 只报一次。
        self.reported = set()

        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

        self.marker_store = MarkerStore(marker_file or MARKER_FILE)

        # 随机 marker 生成器。用固定接口的 Random 实例，
        # 每次 next_marker 产生一段不可预测、baseline 里不可能自带的串。
        self._rand = Random()
        self._marker_cfg = marker_config()

        # 不走系统代理，避免主动请求又绕回 Burp/mitmproxy 形成回环。
        # 不校验 HTTPS 证书，方便测试自签名站点。
        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
        )

        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # 调度接口
    # ------------------------------------------------------------------
    def interested(self, context):
        """快速筛选：XSS 插件是否关心这条流量。

        不发请求，只做便宜判断。和 SQL 插件一样，只有命中条件才入队。

        关键点：能不能做 XSS 检测，取决于“参数值有没有机会被渲染”，
        而不是当前这次响应是不是 HTML。所以分两条路：

        1. 有可注入参数（query/form/json）：只要没被全局过滤（静态资源、
           二进制、HEAD/OPTIONS、204/304 已在 scan_context 挡掉），就入队做注入检测。
           不再要求响应是 HTML——因为：
           - 参数可能被回显进 JSON，再由前端渲染进 DOM。
           - 提交到 JSON/表单接口的内容会被存下来在别的 HTML 页面渲染，
             提交请求本身的响应往往是 JSON 或 302。用响应类型卡死会把注入点漏掉。
        2. 没有可注入参数：只对 HTML 响应入队，用于回扫之前注入的 marker
           （回扫是在“渲染页面”里找 marker，必须是 HTML）。
        """
        if context.is_skipped:
            return False
        if context.method not in ("GET", "POST"):
            return False

        # 有可注入参数 -> 做注入，不看响应类型。
        if self.extract_candidates(context):
            return True

        # 无参数 -> 只有 HTML 响应、且开了回扫才值得入队。
        if not self.is_html_response(context):
            return False
        return self.rescan

    def dedup_key(self, context):
        """调度层去重 key。

        注意区分两种任务，避免“无参数回扫任务”被“有参数注入任务”的去重挡掉：
        - 有可注入参数：按参数形态去重（同 SQL 插件思路）。
        - 无参数（纯回扫）：按 method+host+path 去重，让每个新页面都能被回扫一次。
        """
        candidates = self.extract_candidates(context)
        if candidates:
            param_shape = tuple(
                (param["place"], param["name"], param.get("index", ""))
                for param in candidates
            )
            return (
                self.name,
                "inject",
                context.method,
                context.scheme,
                context.host,
                self.normalize_path(context.path),
                param_shape,
            )
        return (
            self.name,
            "rescan",
            context.scheme,
            context.host,
            self.normalize_path(context.path),
        )

    def check(self, context, flow=None):
        """XSS 检测入口。由后台 worker 调用。"""
        # 兼容旧调用方式 check(record, flow)。
        if flow is not None:
            context = build_scan_context(
                context,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        if context.is_skipped:
            return []

        flow = context.flow
        findings = []
        is_html = self.is_html_response(context)

        # 1. 回扫：只要是 HTML 响应，就检查里面有没有出现之前注入的 marker。
        #    这一步统一覆盖“提交后在别的页面渲染”（过去所谓的存储型）和延迟反射。
        if self.rescan and is_html:
            findings.extend(self.rescan_markers(context))

        # 2. 主动注入：只要有可注入参数就做，不要求响应是 HTML。
        #    JSON/表单接口返回 JSON 或 302 时，注入的内容仍可能在别处以标签形式渲染。
        candidates = self.extract_candidates(context)
        if candidates:
            baseline = self.build_baseline(flow)
            if baseline is not None:
                for candidate in candidates:
                    scan_key = self.make_scan_key(flow, candidate)
                    with self.lock:
                        if scan_key in self.scanned:
                            continue
                        self.scanned.add(scan_key)

                    # 当次注入若立即在本响应命中，作为 origin=immediate 的 XSS 直接报。
                    finding = self.check_injection(flow, baseline, candidate)
                    if finding:
                        findings.append(finding)

        for finding in findings:
            self.write_finding(finding)
            print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # 参数与筛选
    # ------------------------------------------------------------------
    def is_html_response(self, context):
        """响应是否是 HTML（或空 content-type）。"""
        media_type = get_media_type(context.response_content_type or "")
        return media_type in HTML_MEDIA_TYPES

    def extract_candidates(self, context):
        """从请求里提取可注入参数。

        普通模式只扫 query/form/json；
        full_payload_scan 模式额外扫 cookie/header（反射型 XSS 在这些位置较少，
        但确实存在，例如 Referer 被回显在错误页）。
        """
        normal_places = {"query", "form", "json"}
        normal = [p for p in context.parameters if p["place"] in normal_places]
        if not self.full_payload_scan:
            return normal
        extra = [p for p in context.parameters if p["place"] in ("cookie", "header")]
        return normal + extra

    def normalize_path(self, path):
        """去重用路径归一化。/admin 和 /admin/ 视为同一扫描点。"""
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    # ------------------------------------------------------------------
    # 主动注入检测（统一入口，不再区分反射/存储/DOM）
    # ------------------------------------------------------------------
    def check_injection(self, flow, baseline, candidate):
        """对单个参数注入 payload 并检测 XSS。

        本质只有一件事：注入带闭合序列的 payload，看闭合字符能不能在某个
        可执行上下文里原样存活。命中就是 XSS，不关心它是“反射”还是“存储”。

        流程：
        1. 先注入纯字母数字 marker，定位参数值落在响应的什么上下文。
           这个 marker 会同时登记到 MarkerStore，供后续别的页面回扫（覆盖存储型）。
        2. 对命中的每种上下文，发该上下文对应的闭合 payload，验证闭合字符未被编码。
        """
        # 探针一：纯字母数字 marker 定位 + 登记（供跨页面回扫）。
        locator = self.next_marker(self._marker_cfg.get("reflect_prefix", "psr"),
                                   self._marker_cfg.get("reflect_suffix", "xz"))
        probe = self.send_probe(flow, candidate, locator)
        if not probe or probe.get("timed_out"):
            return None

        self.register_marker(flow, candidate, locator)

        positions = ctx.locate_reflections(probe["text"], locator)
        if not positions:
            # 本响应没回显，但可能存起来在别处渲染——已登记，交给回扫。
            return None
        if locator in baseline.get("text", ""):
            return None

        # 收集所有反射点的 (上下文, 外层标签)，去重后逐一验证。
        seen = []
        for index in positions:
            context_name, tag = ctx.classify_context(probe["text"], index, locator)
            key = (context_name, tag)
            if key not in seen:
                seen.append(key)

        # 探针二：对每种命中的上下文，发对应的闭合 payload 并验证。
        for context_name, tag in seen:
            finding = self.verify_context(flow, candidate, context_name, tag, baseline)
            if finding:
                return finding

        return None

    def verify_context(self, flow, candidate, context_name, tag, baseline):
        """针对某个上下文，按顺序尝试该上下文的多条 payload，验证闭合字符是否原样反射。

        命中即停：干净应用只多花一个请求；有过滤时后面的等价 payload 继续覆盖。
        """
        specs = self.reflect_specs_for(context_name)
        if not specs:
            return None

        for spec in specs:
            probe, used = self.send_reflect_probe(flow, candidate, spec, tag, baseline)
            if not probe or probe.get("timed_out"):
                continue

            marker = used["_marker"]
            ok, matched = ctx.chars_reflected_raw(
                probe["text"], marker, used["required_chars"]
            )
            if ok:
                context_label = context_name
                if context_name == "rawtext" and tag:
                    context_label = f"rawtext:{tag}"
                return self.build_xss_finding(
                    flow=flow,
                    url=flow.request.pretty_url,
                    request_method=flow.request.method.upper(),
                    param_place=candidate["place"],
                    param_name=candidate["name"],
                    origin="immediate",
                    context_label=context_label,
                    payload=probe["sent_payload"],
                    matched=matched,
                    sample=used.get("sample", ""),
                    proof_probe=probe,
                    extra_evidence={
                        "baseline_status": baseline.get("status_code"),
                        "probe_status": probe["status_code"],
                    },
                )
        return None

    def reflect_specs_for(self, context_name):
        """按上下文名取对应的所有 payload 规格（展开成逐条 payload）。

        返回 [{method, context, payload, required_chars, sample}, ...]。
        payload 里 {marker}/{tag} 仍是占位符，发送时才替换。
        """
        specs = []
        for group in build_reflect_contexts("{MARKER}", tag="{TAG}"):
            if group["context"] != context_name:
                continue
            for item in group["payloads"]:
                specs.append(
                    {
                        "method": group["method"],
                        "context": group["context"],
                        "payload": item["payload"],
                        "required_chars": item["required_chars"],
                        "sample": item["sample"],
                    }
                )
        return specs

    def send_reflect_probe(self, flow, candidate, spec, tag, baseline):
        """发送一条反射 payload，返回 (probe, used)。

        每次用新的随机 marker，避免不同 payload/页面之间 marker 串扰。
        {TAG} 占位符在这里替换成真实外层标签名（rawtext 闭合用）。
        used 里带本次真实 marker、method、required_chars、sample。

        不再做 WAF 拦截页识别，也不做 tamper 变形重试：
        判定只看结构字符是否原样存活，与状态码、标签名无关；
        各种绕过/变形已直接写进 rules.yaml 的基础 payload 列表，主动检测时全用上。
        """
        marker = self.next_marker(self._marker_cfg.get("reflect_prefix", "psr"),
                                  self._marker_cfg.get("reflect_suffix", "xz"))
        payload = spec["payload"].replace("{MARKER}", marker).replace("{TAG}", tag or "textarea")
        used = dict(spec)
        used["_marker"] = marker

        probe = self.send_probe(flow, candidate, payload)
        if not probe:
            return None, used
        probe["sent_payload"] = payload
        return probe, used

    # ------------------------------------------------------------------
    # marker 登记与跨页面回扫（覆盖“提交后在别处渲染”的场景）
    # ------------------------------------------------------------------
    def register_marker(self, flow, candidate, locator):
        """登记一次注入的 locator，供后续任意 HTML 响应回扫。

        存储型和延迟反射的本质都是“注入的内容之后出现在某个页面”。
        回扫时用 locator（纯字母数字，过滤不掉）定位，再用 context.py
        判断它落在什么上下文、闭合字符有没有被编码——和主动注入用的是同一套判定。
        为了让回扫也能验证闭合字符，登记时额外记录一个带 <x> 的探测串位置约定。
        """
        self.marker_store.register(
            locator,
            {
                "injected_url": flow.request.pretty_url,
                "request_method": flow.request.method.upper(),
                "param_place": candidate["place"],
                "param_name": candidate["name"],
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            },
        )

    def rescan_markers(self, context):
        """回扫：检查当前 HTML 响应里有没有出现之前注入的 locator。

        命中后和主动注入用同一套上下文判定：
        - locator 落在能直接起标签的 HTML 文本区 -> confirmed（可执行）。
        - 落在 textarea/属性/JS 等需额外闭合的位置 -> suspected（需人工确认）。
        注入请求自身响应的即时回显不在这里报（由 check_injection 负责）。
        """
        body = self.body_text_from_flow(context.flow)
        if not body:
            return []

        findings = []
        for info in self.marker_store.find_in_text(body):
            marker = info.get("marker", "")

            # 注入请求自己的响应（同 method+url）属即时命中，不在回扫里重复报。
            if (info.get("request_method", "") == context.method
                    and info.get("injected_url", "") == context.url):
                continue

            dedup = (marker, context.url)
            with self.lock:
                if dedup in self.reported:
                    continue
                self.reported.add(dedup)

            positions = ctx.locate_reflections(body, marker)
            if not positions:
                continue
            context_name, tag = ctx.classify_context(body, positions[0], marker)
            context_label = f"{context_name}:{tag}" if tag else context_name
            chars_ok, matched = ctx.chars_reflected_raw(body, marker, ["<", ">"])
            executable = context_name == "html_text" and chars_ok

            findings.append(
                self.build_xss_finding(
                    flow=context.flow,
                    url=context.url,
                    request_method=context.method,
                    param_place=info.get("param_place", ""),
                    param_name=info.get("param_name", ""),
                    origin="persisted",
                    context_label=context_label,
                    payload=f"{marker}<x>{marker}",
                    matched=matched,
                    sample="",
                    proof_probe=self.passive_proof(context.flow),
                    confirmed=executable,
                    extra_evidence={"injected_url": info.get("injected_url", "")},
                )
            )
        return findings

    # ------------------------------------------------------------------
    # 统一 finding 构造（三类合并：只有一个漏洞类型 xss）
    # ------------------------------------------------------------------
    def build_xss_finding(self, flow, url, request_method, param_place, param_name,
                          origin, context_label, payload, matched, sample,
                          proof_probe, confirmed=True, extra_evidence=None):
        """构造统一的 XSS finding。

        不再区分反射/存储/DOM：method 恒为 "xss"。
        证据里用 origin 记录“出现时机”（immediate=当次响应命中；persisted=后续页面命中），
        用 xss_context 记录落点上下文，confidence 记录是否落在可执行上下文。
        """
        confidence = "confirmed" if confirmed else "suspected"
        if confirmed:
            message = f"payload survived in an executable context ({context_label}) without encoding"
        else:
            message = (
                f"payload rendered on another page but not in a directly "
                f"executable context ({context_label}); needs manual review"
            )
        evidence = {
            "message": message,
            "origin": origin,
            "xss_context": context_label,
            "confidence": confidence,
            "payload": payload,
            "matched_chars": matched,
        }
        if sample:
            evidence["sample_exploit"] = sample
        if extra_evidence:
            evidence.update(extra_evidence)

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "xss",
            "method": "xss",
            "request_method": request_method,
            "url": url,
            "param_place": param_place,
            "param_name": param_name,
            "evidence": evidence,
            "proof": self.probe_to_proof(proof_probe),
            "extra_proofs": [],
        }

    # ------------------------------------------------------------------
    # 主动发包（自带精简实现，不复用 SQL 插件）
    # ------------------------------------------------------------------
    def build_baseline(self, flow):
        """构造 baseline，用于判断 marker 是否本来就在页面里、WAF 判定等。"""
        original = self.response_from_flow(flow)
        active = self.send_probe(flow, None, "")
        if active and not active.get("timed_out"):
            return active
        if original:
            return original
        return None

    def response_from_flow(self, flow):
        """把 mitmproxy 已有的响应转成可比较结构。"""
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
            "text": text[:MAX_BODY_CHARS],
        }

    def body_text_from_flow(self, flow):
        """取响应正文文本（截断），供 DOM 分析和存储回扫使用。"""
        response = getattr(flow, "response", None)
        if not response:
            return ""
        body = response.content or b""
        text, _charset = decode_body_text(body, response.headers)
        return text[:MAX_BODY_CHARS]

    def send_probe(self, flow, candidate, payload):
        """主动发送一次探测请求。

        candidate 为 None 表示重放原始请求；否则只替换当前参数的值。
        """
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
        except (TimeoutError, OSError, URLError):
            return self.timed_out_probe(request_packet)

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
            "text": text[:MAX_BODY_CHARS],
            "request_packet": request_packet,
            "response_packet": response_packet,
        }

    def timed_out_probe(self, request_packet=""):
        """构造一个超时/失败探测结果。"""
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

        if place == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            if candidate["index"] < len(pairs):
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

        if place == "cookie":
            pairs = self.parse_cookie_pairs(get_header(request.headers, "cookie"))
            if candidate["index"] < len(pairs):
                pairs[candidate["index"]] = (candidate["name"], payload)
            header_overrides["Cookie"] = "; ".join(f"{n}={v}" for n, v in pairs)
            return url, body, header_overrides

        if place == "header":
            header_overrides[candidate["name"]] = payload
            return url, body, header_overrides

        return url, body, header_overrides

    def replace_query_value(self, url, index, new_value):
        """只替换 URL 里第 index 个 query 参数的值。"""
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if index < len(pairs):
            pairs[index] = (pairs[index][0], new_value)
        new_query = self.urlencode_pairs(pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def urlencode_pairs(self, pairs, charset="utf-8"):
        """编码 query/form 参数。保留 payload 里手写的 %xx。"""
        encoded = []
        for name, value in pairs:
            encoded_name = quote_plus(str(name), encoding=charset, errors="replace")
            encoded_value = quote_plus(str(value), safe="%", encoding=charset, errors="replace")
            encoded.append(f"{encoded_name}={encoded_value}")
        return "&".join(encoded)

    def parse_cookie_pairs(self, cookie_header):
        """把 Cookie 字符串解析成 [(name, value), ...]。"""
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

    def copy_headers(self, headers):
        """复制请求头，移除不适合主动重放的 header，并禁用压缩。"""
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

    # ------------------------------------------------------------------
    # marker / finding / 输出
    # ------------------------------------------------------------------
    def next_marker(self, prefix, suffix):
        """生成一段随机 marker，baseline 里不可能自带。"""
        middle = "".join(
            self._rand.choice(string.ascii_lowercase + string.digits) for _ in range(6)
        )
        return f"{prefix}{middle}{suffix}"

    def make_scan_key(self, flow, candidate):
        """内部去重 key，避免同一参数反复扫描。"""
        parts = urlsplit(flow.request.pretty_url)
        return (
            flow.request.method.upper(),
            parts.scheme,
            parts.netloc,
            self.normalize_path(parts.path),
            candidate["place"],
            candidate["name"],
            candidate.get("index", ""),
        )

    def passive_proof(self, flow):
        """把原始被动流量整理成报告用的请求/响应包（DOM 型没有主动探测请求）。"""
        request = flow.request
        response = getattr(flow, "response", None)
        req_text = f"{request.method} {request.pretty_url} HTTP/1.1"
        resp_text = ""
        if response:
            body = response.content or b""
            text, charset = decode_body_text(body, response.headers)
            resp_text = self.build_response_packet(
                response.status_code,
                getattr(response, "reason", ""),
                response.headers,
                body,
                charset,
            )
        return {"request": req_text, "response": self.trim_proof(resp_text)}

    def trim_proof(self, text):
        """限制报告里响应包的长度，避免超大页面撑爆报告。"""
        if not text:
            return ""
        limit = 20000
        if len(text) <= limit:
            return text
        return text[:limit] + "\n... [truncated] ..."

    def probe_to_proof(self, probe):
        """从一次主动探测结果里提取报告需要的请求包和响应包。"""
        if not probe:
            return {"request": "", "response": ""}
        # 已经是 {request, response} 结构（被动 proof）直接返回。
        if "request" in probe and "response" in probe and "request_packet" not in probe:
            return {"request": probe.get("request", ""), "response": self.trim_proof(probe.get("response", ""))}
        return {
            "request": probe.get("request_packet", ""),
            "response": self.trim_proof(probe.get("response_packet", "")),
        }

    def write_finding(self, finding):
        """把漏洞结果写入 JSONL，并更新 HTML 报告。"""
        write_jsonl(self.vuln_file, finding)
        print_finding_once(self, finding)
        if self.on_finding:
            self.on_finding(finding)
        write_html_report(self.vuln_file, self.report_file)

    def print_finding(self, finding):
        """终端打印简短提示。"""
        evidence = finding.get("evidence", {})
        confidence = evidence.get("confidence", "confirmed")
        origin = evidence.get("origin", "")
        context_label = evidence.get("xss_context", "")
        tag = "疑似 XSS" if confidence == "suspected" else "XSS"
        param = f"{finding['param_place']}.{finding['param_name']}".strip(".")
        detail = "/".join(x for x in (origin, context_label) if x)
        print(
            red(
                "[漏洞] "
                f"检测到 {tag}"
                + (f" [{detail}]" if detail else "")
                + (f" | {param}" if param else "")
                + f" | 地址: {finding.get('url', '')} | 报告: {self.report_file}"
            ),
            flush=True,
        )
