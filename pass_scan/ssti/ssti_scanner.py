# SSTI（Server-Side Template Injection）检测流程。
#
# 插件边界与其它漏洞保持一致：
# - 独立目录、独立 rules.yaml、独立 tamper.py。
# - 通过 name/interested/dedup_key/check 接入总调度器。
# - ScanQueue 会按 plugin.name 自动创建 SSTI 自己的任务队列和 worker。
#
# 检测思路：
# 1. 流量筛选：只对疑似会进入模板/渲染链路的参数入队，例如模板语法已出现在参数值、
#    参数名/路径像 content/template/preview/message，或原始响应反射了文本值。
# 2. 输出型确认：发送覆盖主流模板语法的算术/字符串转换 payload。预期结果不在 payload
#    本身里，只有服务端模板引擎执行后才会出现在响应中。
# 3. 错误型补充：输出型未命中时，少量发送非法模板语法。响应新增已知模板引擎错误指纹才报。
# 4. tamper：基础 payload 已覆盖主流语法；URL 编码类绕过只在 WAF 拦截或深度扫描时追加。

import html
import os
import re
import socket
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
from pass_scan.ssti.rules import (
    build_error_groups,
    build_probe_groups,
    max_tampered_payloads_per_probe,
    tamper_profiles,
    template_error_patterns,
    waf_detection_rules,
)
from pass_scan.ssti.tamper import apply_tampers
from pass_scan.terminal import red


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 12
MAX_COMPARE_CHARS = 200000
MAX_REFLECTION_CHARS = 60000

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

TEXT_RESPONSE_MEDIA_TYPES = {
    "",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/graphql-response+json",
}

TEMPLATE_DELIMITERS = (
    "{{",
    "}}",
    "{%",
    "%}",
    "{#",
    "${",
    "#{",
    "*{",
    "[[",
    "]]",
    "<%",
    "%>",
    "{math",
    "#set(",
)

TEMPLATE_ENGINE_HINTS = (
    "jinja",
    "twig",
    "freemarker",
    "thymeleaf",
    "velocity",
    "smarty",
    "mako",
    "mustache",
    "handlebars",
    "liquid",
    "razor",
    "ejs",
    "erb",
    "template",
)

PARAM_EXACT_KEYWORDS = {
    "body",
    "comment",
    "content",
    "desc",
    "description",
    "display",
    "email",
    "expr",
    "expression",
    "html",
    "keyword",
    "layout",
    "mail",
    "markdown",
    "md",
    "message",
    "msg",
    "name",
    "notification",
    "page",
    "preview",
    "q",
    "query",
    "render",
    "renderer",
    "search",
    "subject",
    "template",
    "text",
    "theme",
    "title",
    "tpl",
    "view",
}

PARAM_SUBSTRING_KEYWORDS = (
    "comment",
    "content",
    "description",
    "expr",
    "html",
    "layout",
    "markdown",
    "message",
    "preview",
    "render",
    "subject",
    "template",
    "theme",
)

PATH_KEYWORDS = (
    "/cms",
    "/comment",
    "/compose",
    "/email",
    "/mail",
    "/message",
    "/notification",
    "/page",
    "/preview",
    "/render",
    "/report",
    "/search",
    "/template",
    "/theme",
    "/view",
)

_PURE_NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{24,}$", re.I)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-+/=.]{48,}$")
_NAME_SPLIT_RE = re.compile(r"[^a-z0-9]+")


class NoRedirectHandler(HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SSTIScanner:
    """SSTI 扫描器。"""

    name = "ssti"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        self.deep_tamper = bool(self.config.get("deep_tamper", False))
        self.deep_tamper_max_profiles = int(self.config.get("deep_tamper_max_profiles", 2))
        self.error_detection = bool(self.config.get("error_detection", True))
        self.max_candidate_value_length = int(
            self.config.get("max_candidate_value_length", 2000)
        )

        self.scanned = set()
        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE
        self.random = Random()

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
        """轻量判断：SSTI 插件是否关心这条流量。不发请求。"""
        if context.is_skipped:
            return False
        if context.method not in ("GET", "POST"):
            return False
        if not self.is_textual_response(context):
            return False
        return bool(self.extract_candidates(context))

    def dedup_key(self, context):
        """调度层去重 key：同一 URL 路径 + 同一批 SSTI 候选参数，TTL 内只入队一次。"""
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
        """SSTI 检测入口。"""
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
                self.scanned.add(scan_key)

            finding = self.check_one_param(flow, baseline, candidate)
            if finding:
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # 流量筛选与参数提取
    # ------------------------------------------------------------------

    def extract_candidates(self, context):
        """从请求中提取 SSTI 候选参数。

        SSTI 不默认扫描所有参数：先用参数名、参数值、路径、响应反射与模板指纹做筛选。
        full_payload_scan 时额外纳入 Cookie/Header，但仍需通过 SSTI 筛选条件。
        """
        normal_places = {"query", "form", "json"}
        params = [p for p in context.parameters if p["place"] in normal_places]

        if self.full_payload_scan:
            params += [p for p in context.parameters if p["place"] in ("cookie", "header")]

        response_text = self.response_text_preview(context)
        return [
            param for param in params
            if self.candidate_worth_scanning(context, param, response_text)
        ]

    def candidate_worth_scanning(self, context, param, response_text):
        """判断单个参数是否值得做 SSTI 主动探测。"""
        name = str(param.get("name") or "")
        value = str(param.get("value") or "")

        if self.value_contains_template_syntax(value):
            return True

        path_interesting = self.path_looks_template_related(context.path)
        name_interesting = self.param_name_looks_template_related(name)
        reflected = self.response_reflects_value(value, response_text)
        engine_hint = self.response_has_template_hint(context, response_text)

        if not self.value_is_textual(value):
            # 空值也可能是 preview/template 入口，允许强语义参数进入。
            return not value and (name_interesting or path_interesting)

        if name_interesting or path_interesting:
            return True
        if reflected:
            return True
        if engine_hint and self.value_has_user_content_shape(value):
            return True
        return False

    def is_textual_response(self, context):
        media_type = get_media_type(context.response_content_type or "")
        return media_type.startswith("text/") or media_type in TEXT_RESPONSE_MEDIA_TYPES

    def response_text_preview(self, context):
        response = getattr(context.flow, "response", None)
        if not response:
            return ""
        body = response.content or b""
        text, _charset = decode_body_text(body, response.headers)
        return text[:MAX_REFLECTION_CHARS]

    def value_contains_template_syntax(self, value):
        lower = (value or "").lower()
        return any(delimiter.lower() in lower for delimiter in TEMPLATE_DELIMITERS)

    def value_is_textual(self, value):
        value = (value or "").strip()
        if not value:
            return False
        if len(value) > self.max_candidate_value_length:
            return False
        lowered = value.lower()
        if lowered in ("true", "false", "null", "none", "undefined"):
            return False
        if _PURE_NUMBER_RE.match(value):
            return False
        if _UUID_RE.match(value):
            return False
        if _LONG_HEX_RE.match(value):
            return False
        if _TOKEN_RE.match(value) and not any(char.isspace() for char in value):
            return False
        return True

    def value_has_user_content_shape(self, value):
        value = (value or "").strip()
        if not self.value_is_textual(value):
            return False
        if len(value) >= 8:
            return True
        return any(char in value for char in "<>{}$#%@")

    def param_name_looks_template_related(self, name):
        lowered = (name or "").lower()
        if not lowered:
            return False
        tokens = [token for token in _NAME_SPLIT_RE.split(lowered) if token]
        if any(token in PARAM_EXACT_KEYWORDS for token in tokens):
            return True
        return any(keyword in lowered for keyword in PARAM_SUBSTRING_KEYWORDS)

    def path_looks_template_related(self, path):
        lowered = (path or "/").lower()
        return any(keyword in lowered for keyword in PATH_KEYWORDS)

    def response_reflects_value(self, value, response_text):
        value = (value or "").strip()
        if len(value) < 3 or not response_text:
            return False
        if not self.value_is_textual(value):
            return False
        if value in response_text:
            return True
        escaped = html.escape(value, quote=True)
        return escaped != value and escaped in response_text

    def response_has_template_hint(self, context, response_text):
        header_text = "\n".join(
            f"{name}: {value}"
            for name, value in getattr(context.flow.response, "headers", {}).items()
        ).lower() if getattr(context.flow, "response", None) else ""
        sample = (header_text + "\n" + (response_text or "")[:12000]).lower()
        return any(hint in sample for hint in TEMPLATE_ENGINE_HINTS)

    def normalize_path_for_dedup(self, path):
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
        """对单个参数做 SSTI 输出确认，未命中时用模板错误指纹补充。"""
        a, b, marker = self.pick_probe_values(baseline)
        baseline_text = baseline.get("text", "") if baseline else ""

        for group in build_probe_groups(candidate.get("value", ""), a, b, marker):
            for probe in self.send_probe_variants(
                flow,
                candidate,
                group["payload"],
                baseline,
                deep_tamper=self.use_deep_tamper(),
            ):
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue

                matched = self.match_expected_output(group, probe, baseline_text)
                if not matched:
                    continue

                return self.build_finding(
                    flow,
                    candidate,
                    {
                        "technique": self.technique_label(group["technique"]),
                        "message": "server-side template expression was evaluated in the response",
                        "template_family": group.get("family"),
                        "payload_group": group["name"],
                        "payload": probe["sent_payload"],
                        "expected_output": group["expected"],
                        "matched_output": matched,
                        "baseline_status": baseline["status_code"],
                        "probe_status": probe["status_code"],
                        "probe_length": probe["length"],
                        **self.tamper_evidence(probe),
                    },
                    proof_probe=probe,
                )

        if not self.error_detection:
            return None

        for group in build_error_groups(candidate.get("value", ""), marker):
            for probe in self.send_probe_variants(
                flow,
                candidate,
                group["payload"],
                baseline,
                deep_tamper=False,
            ):
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue
                error_hit = self.find_template_error(probe.get("text", ""), baseline_text)
                if not error_hit:
                    continue
                return self.build_finding(
                    flow,
                    candidate,
                    {
                        "technique": "模板错误",
                        "message": "template engine error fingerprint appeared after malformed template syntax",
                        "template_family": error_hit["family"],
                        "payload_group": group["name"],
                        "payload": probe["sent_payload"],
                        "matched_output": error_hit["matched"],
                        "baseline_status": baseline["status_code"],
                        "probe_status": probe["status_code"],
                        "probe_length": probe["length"],
                        **self.tamper_evidence(probe),
                    },
                    proof_probe=probe,
                )

        return None

    def pick_probe_values(self, baseline):
        """生成随机算术操作数和 marker，避开 baseline 中已有内容。"""
        baseline_text = baseline.get("text", "") if baseline else ""

        for _ in range(10):
            a = self.random.randint(1200, 9800)
            b = self.random.randint(1200, 9800)
            product = str(a * b)
            total = str(a + b)
            if product not in baseline_text and total not in baseline_text:
                break

        alphabet = string.ascii_lowercase
        marker = "ssti" + "".join(self.random.choice(alphabet) for _ in range(12))
        for _ in range(10):
            if marker not in baseline_text and marker.upper() not in baseline_text:
                break
            marker = "ssti" + "".join(self.random.choice(alphabet) for _ in range(12))
        return a, b, marker

    def match_expected_output(self, group, probe, baseline_text):
        """判断输出型 payload 是否命中，返回可读证据片段。"""
        expected = str(group.get("expected") or "")
        if not expected:
            return None

        text = probe.get("text", "")
        if expected not in text:
            return None
        if expected in baseline_text:
            return None

        if group.get("technique") == "string_transform":
            if self.looks_like_literal_transform_reflection(text, expected, probe["sent_payload"]):
                return None

        return self.snippet_around(text, expected)

    def looks_like_literal_transform_reflection(self, text, expected, sent_payload):
        """排除“应用把 payload 大写后原样反射”导致的字符串转换误报。"""
        if sent_payload in text:
            return True
        upper_payload = sent_payload.upper()
        if upper_payload in text:
            return True

        index = text.find(expected)
        if index < 0:
            return False
        window = text[max(0, index - 80): index + len(expected) + 80].lower()
        reflection_markers = (
            "{{",
            "}}",
            "${",
            "#{",
            "*{",
            "<%",
            "%>",
            "|upper",
            "upper_case",
            "touppercase",
            "upcase",
            "toupper",
            "#set",
            "{math",
        )
        return any(marker in window for marker in reflection_markers)

    def find_template_error(self, text, baseline_text):
        """查找新增模板错误指纹。"""
        for entry in template_error_patterns():
            pattern = entry.get("pattern") or ""
            try:
                regex = re.compile(pattern)
            except re.error:
                continue
            match = regex.search(text)
            if not match:
                continue
            if regex.search(baseline_text):
                continue
            return {
                "family": entry.get("family", "unknown"),
                "matched": self.snippet_around(text, match.group(0)),
            }
        return None

    def snippet_around(self, text, needle, radius=90):
        index = text.find(needle)
        if index < 0:
            return str(needle)[:160]
        start = max(0, index - radius)
        end = min(len(text), index + len(needle) + radius)
        return text[start:end].replace("\r", " ").replace("\n", " ")[:240]

    def technique_label(self, technique):
        return {
            "arithmetic_echo": "算术回显",
            "string_transform": "字符串转换",
            "template_error": "模板错误",
        }.get(technique, technique or "输出确认")

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
        for profile in self.iter_tamper_profiles(profile_limit):
            tampered = apply_tampers(payload, profile["tampers"])
            if tampered in seen:
                continue
            seen.add(tampered)

            retry = self.send_probe(flow, candidate, tampered)
            if not retry:
                continue
            retry_waf = self.detect_waf_block(retry, baseline)
            self.annotate_probe(
                retry,
                tampered,
                profile["name"],
                profile["tampers"],
                retry_waf,
                original_reasons,
                deep_tamper=is_deep_retry,
            )
            yield retry

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
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs[index] = (pairs[index][0], new_value)
        new_query = self.urlencode_pairs(pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def urlencode_pairs(self, pairs, charset="utf-8"):
        """编码 query/form 参数，保留 payload 里手写的 %xx。"""
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
        status_line = f"HTTP/1.1 {status_code} {reason}".rstrip()
        lines = [status_line]
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        response_text = "\r\n".join(lines) + "\r\n\r\n"
        response_text += body.decode(charset or "utf-8", errors="replace")
        return response_text

    def copy_headers(self, headers):
        copied = {}
        for name, value in headers.items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            copied[name] = value
        copied["Accept-Encoding"] = "identity"
        return copied

    def set_header(self, headers, name, value):
        for old_name in list(headers.keys()):
            if old_name.lower() == name.lower():
                del headers[old_name]
        headers[name] = value

    # ------------------------------------------------------------------
    # WAF 识别与 tamper
    # ------------------------------------------------------------------

    def detect_waf_block(self, response, baseline=None):
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

    def iter_tamper_profiles(self, limit=None):
        count = 0
        if limit is None:
            limit = max_tampered_payloads_per_probe()
        if limit <= 0:
            return

        for profile in tamper_profiles():
            tampers = profile.get("tampers", [])
            if not tampers:
                continue
            yield {
                "name": profile.get("name") or "+".join(tampers),
                "tampers": tampers,
            }
            count += 1
            if count >= limit:
                break

    def annotate_probe(
        self,
        probe,
        sent_payload,
        tamper_profile,
        tampers,
        waf_info,
        retry_reasons,
        deep_tamper=False,
    ):
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
        if self.full_payload_scan:
            return True
        return self.deep_tamper

    def deep_tamper_profile_limit(self):
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
        request = flow.request
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "ssti",
            "method": "ssti",
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
        write_jsonl(self.vuln_file, finding)
        print_finding_once(self, finding)
        if self.on_finding:
            self.on_finding(finding)
        write_html_report(self.vuln_file, self.report_file)

    def print_finding(self, finding):
        technique = finding.get("evidence", {}).get("technique", "")
        family = finding.get("evidence", {}).get("template_family", "")
        print(
            red(
                "[漏洞] "
                f"检测到 SSTI[{technique}/{family}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
