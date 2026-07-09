# 开放重定向 + CRLF/响应头注入检测流程。
#
# 插件名 redir 较短，报告中的 evidence["technique"] 区分具体命中方式：
# - 开放重定向：主动替换 redirect/URL 类参数，不跟随跳转；只有响应 Location/Refresh/meta
#   refresh 解析到唯一 example.com 子域才确认。
# - 响应头注入：主动注入唯一 X-Pass-Scan-* 响应头；只有响应头解析结果里真实出现该 header
#   才确认，普通页面反射不会误报。
#
# 流量筛选：
# - 全局层：ScanContext 已过滤静态资源、二进制响应、无意义方法/状态码。
# - 插件层：只让 redirect/url/header 语义参数、URL/路径形态参数、原始响应头反射参数、
#   或跳转/下载相关路径上的参数进入检测。
# - full_payload_scan 时追加 Cookie/Header 注入点，并启用 extra payload。

import os
import re
import socket
import ssl
import string
import threading
import time
from random import Random
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote_plus, unquote, urljoin, urlsplit, urlunsplit
from urllib.request import (
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pass_scan.body_paser import decode_body_text, get_header
from pass_scan.redir.rules import build_crlf_payloads, build_redirect_payloads
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context, replace_json_body_parameter
from pass_scan.terminal import red


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 10
MAX_COMPARE_CHARS = 200000
MAX_CANDIDATE_VALUE_LENGTH = 2000

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

REDIRECT_STATUS_CODES = set(range(300, 400))

REDIRECT_PARAM_EXACT = {
    "back",
    "callback",
    "callback_url",
    "continue",
    "continue_url",
    "dest",
    "destination",
    "forward",
    "from",
    "go",
    "goto",
    "jump",
    "link",
    "next",
    "next_url",
    "out",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "redirect_url",
    "ref",
    "referer",
    "relaystate",
    "return",
    "return_to",
    "return_url",
    "service",
    "target",
    "to",
    "uri",
    "url",
    "u",
}

REDIRECT_PARAM_SUBSTRINGS = (
    "callback",
    "continue",
    "dest",
    "forward",
    "goto",
    "jump",
    "link",
    "next",
    "redirect",
    "relay",
    "return",
    "service",
    "target",
    "url",
)

HEADER_PARAM_EXACT = {
    "attachment",
    "content_disposition",
    "content-type",
    "content_type",
    "download",
    "file",
    "filename",
    "header",
    "location",
    "mime",
    "response_header",
    "set_cookie",
}

HEADER_PARAM_SUBSTRINGS = (
    "content-disposition",
    "content_type",
    "download",
    "filename",
    "header",
    "location",
    "response_header",
    "set-cookie",
)

PATH_KEYWORDS = (
    "/callback",
    "/download",
    "/export",
    "/file",
    "/forward",
    "/go",
    "/jump",
    "/login",
    "/logout",
    "/oauth",
    "/redirect",
    "/return",
    "/saml",
    "/sso",
)

_NAME_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_DOMAIN_LIKE_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:[/#?].*)?$", re.I)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-+/=.]{48,}$")
_PURE_NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_META_REFRESH_RE = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*content\s*=\s*['\"]([^'\"]+)['\"]",
    re.I,
)


class NoRedirectHandler(HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RedirScanner:
    """开放重定向 + CRLF/响应头注入扫描器。"""

    name = "redir"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        self.deep_tamper = bool(self.config.get("deep_tamper", True))
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
        """轻量判断：redir 插件是否关心这条流量。不发请求。"""
        if context.is_skipped:
            return False
        if context.method not in ("GET", "POST"):
            return False
        return bool(self.extract_candidates(context))

    def dedup_key(self, context):
        """调度层去重 key：同一 URL 路径 + 同一批候选参数名，TTL 内只入队一次。"""
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
        """开放重定向 / 响应头注入检测入口。"""
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

            for finding in self.check_one_param(flow, baseline, candidate):
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # 流量筛选
    # ------------------------------------------------------------------

    def extract_candidates(self, context):
        """从请求中提取 redir 候选参数。

        普通模式只扫 query/form/json；full_payload_scan 额外纳入 Cookie/Header。
        即使 full 模式也保留轻量语义筛选，避免把无关 id/token 全部推入跳转检测。
        """
        normal_places = {"query", "form", "json"}
        params = [p for p in context.parameters if p["place"] in normal_places]

        if self.full_payload_scan:
            params += [p for p in context.parameters if p["place"] in ("cookie", "header")]

        header_text = self.response_headers_text(context)
        return [
            param for param in params
            if self.candidate_worth_scanning(context, param, header_text)
        ]

    def candidate_worth_scanning(self, context, param, header_text):
        name = str(param.get("name") or "")
        value = str(param.get("value") or "")

        if not self.value_is_safe_size(value):
            return False

        if self.param_name_looks_redirect_related(name):
            return True
        if self.param_name_looks_header_related(name):
            return True
        if self.value_looks_redirect_target(value):
            return True
        if self.response_header_reflects_value(value, header_text):
            return True
        if self.response_is_redirect_like(context) and self.value_has_user_shape(value):
            return True
        if self.path_looks_redirect_or_header_related(context.path) and self.value_has_user_shape(value):
            return True
        return False

    def response_headers_text(self, context):
        response = getattr(context.flow, "response", None)
        if not response:
            return ""
        return "\n".join(f"{name}: {value}" for name, value in response.headers.items())

    def response_is_redirect_like(self, context):
        if int(context.status_code or 0) in REDIRECT_STATUS_CODES:
            return True
        header_text = self.response_headers_text(context).lower()
        return "location:" in header_text or "refresh:" in header_text

    def value_is_safe_size(self, value):
        return len(value or "") <= MAX_CANDIDATE_VALUE_LENGTH

    def value_has_user_shape(self, value):
        value = (value or "").strip()
        if not value:
            return True
        if _PURE_NUMBER_RE.match(value):
            return False
        if _TOKEN_RE.match(value) and not any(char in value for char in "/.:_-"):
            return False
        return True

    def value_looks_redirect_target(self, value):
        value = (value or "").strip()
        if not value or not self.value_has_user_shape(value):
            return False
        lowered = value.lower()
        if lowered.startswith(("http://", "https://", "//", "/", "\\\\")):
            return True
        if lowered.startswith(("http%3a", "https%3a", "%2f%2f", "http%253a", "https%253a")):
            return True
        if _DOMAIN_LIKE_RE.match(value):
            return True
        return False

    def response_header_reflects_value(self, value, header_text):
        value = (value or "").strip()
        if len(value) < 3 or not header_text:
            return False
        if _TOKEN_RE.match(value) and len(value) > 80:
            return False
        return value in header_text

    def param_name_looks_redirect_related(self, name):
        lowered = (name or "").lower().strip()
        if not lowered:
            return False
        tokens = [token for token in _NAME_SPLIT_RE.split(lowered) if token]
        if lowered in REDIRECT_PARAM_EXACT:
            return True
        if any(token in REDIRECT_PARAM_EXACT for token in tokens):
            return True
        return any(keyword in lowered for keyword in REDIRECT_PARAM_SUBSTRINGS)

    def param_name_looks_header_related(self, name):
        lowered = (name or "").lower().strip()
        if not lowered:
            return False
        tokens = [token for token in _NAME_SPLIT_RE.split(lowered) if token]
        if lowered in HEADER_PARAM_EXACT:
            return True
        if any(token in HEADER_PARAM_EXACT for token in tokens):
            return True
        return any(keyword in lowered for keyword in HEADER_PARAM_SUBSTRINGS)

    def path_looks_redirect_or_header_related(self, path):
        lowered = (path or "/").lower()
        return any(keyword in lowered for keyword in PATH_KEYWORDS)

    def normalize_path_for_dedup(self, path):
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    # ------------------------------------------------------------------
    # baseline
    # ------------------------------------------------------------------

    def build_baseline(self, flow):
        """构造 baseline：优先干净重放，退回 mitmproxy 已有响应。"""
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
            "header_values": self.collect_header_values(response.headers),
            "text": text[:MAX_COMPARE_CHARS],
        }

    # ------------------------------------------------------------------
    # 单参数检测
    # ------------------------------------------------------------------

    def check_one_param(self, flow, baseline, candidate):
        """同一候选参数上分别尝试开放重定向和 CRLF，二者可同时报告。"""
        findings = []

        redirect_finding = self.check_open_redirect(flow, baseline, candidate)
        if redirect_finding:
            findings.append(redirect_finding)

        crlf_finding = self.check_crlf_header_injection(flow, baseline, candidate)
        if crlf_finding:
            findings.append(crlf_finding)

        return findings

    def check_open_redirect(self, flow, baseline, candidate):
        marker = self.next_marker("psor")
        external_host = f"{marker}.example.com"
        target_url = f"https://{external_host}/{marker}"
        allow_host = self.allow_host_for(flow)

        for group in build_redirect_payloads(
            external_host,
            marker,
            target_url,
            allow_host,
            extra=self.use_extra_payloads(),
        ):
            probe = self.send_probe(flow, candidate, group["payload"])
            if not probe or probe.get("timed_out"):
                continue

            hit = self.match_open_redirect(
                flow.request.pretty_url,
                probe,
                external_host,
                marker,
            )
            if not hit:
                continue

            return self.build_finding(
                flow,
                candidate,
                {
                    "technique": "开放重定向",
                    "message": "response redirects to attacker-controlled external host",
                    "payload_group": group["name"],
                    "payload": probe["sent_payload"],
                    "redirect_sink": hit["sink"],
                    "location": hit["location"],
                    "resolved_url": hit["resolved_url"],
                    "location_resolution": hit["resolution"],
                    "baseline_status": baseline.get("status_code"),
                    "probe_status": probe["status_code"],
                    "confidence": hit["confidence"],
                },
                proof_probe=probe,
            )
        return None

    def check_crlf_header_injection(self, flow, baseline, candidate):
        marker = self.next_marker("pshr")
        external_host = f"{marker}.example.com"
        target_url = f"https://{external_host}/{marker}"
        header_name = f"X-Pass-Scan-{marker}"
        header_value = f"v{marker}"

        for group in build_crlf_payloads(
            candidate.get("value", ""),
            marker,
            target_url,
            header_name,
            header_value,
            extra=self.use_extra_payloads(),
        ):
            payload = group["payload"]
            if not self.payload_safe_for_place(candidate["place"], payload):
                continue

            probe = self.send_probe(flow, candidate, payload)
            if not probe or probe.get("timed_out"):
                continue

            hit = self.match_header_injection(probe, header_name, header_value)
            if not hit:
                continue

            return self.build_finding(
                flow,
                candidate,
                {
                    "technique": "响应头注入",
                    "message": "injected response header appeared in the HTTP response",
                    "payload_group": group["name"],
                    "payload": probe["sent_payload"],
                    "header_name": header_name,
                    "header_value": header_value,
                    "matched": hit,
                    "baseline_status": baseline.get("status_code"),
                    "probe_status": probe["status_code"],
                    "confidence": "high",
                },
                proof_probe=probe,
            )
        return None

    # ------------------------------------------------------------------
    # 命中判定
    # ------------------------------------------------------------------

    def match_open_redirect(self, base_url, probe, expected_host, marker):
        """确认响应是否会把浏览器带到 expected_host。"""
        locations = []
        if int(probe.get("status_code", 0)) in REDIRECT_STATUS_CODES:
            for value in self.get_header_values(probe, "location"):
                locations.append(("Location", value, "high"))

        for value in self.get_header_values(probe, "refresh"):
            refresh_url = self.extract_refresh_url(value)
            if refresh_url:
                locations.append(("Refresh", refresh_url, "high"))

        meta_refresh = self.extract_meta_refresh_url(probe.get("text", ""))
        if meta_refresh:
            locations.append(("meta refresh", meta_refresh, "medium"))

        for sink, location, confidence in locations:
            resolved = self.resolve_redirect_location(base_url, location, expected_host, marker)
            if resolved:
                return {
                    "sink": sink,
                    "location": location,
                    "resolved_url": resolved["url"],
                    "resolution": resolved["resolution"],
                    "confidence": confidence if resolved["resolution"] == "raw" else "medium",
                }
        return None

    def resolve_redirect_location(self, base_url, location, expected_host, marker):
        """按浏览器常见容错方式解析 Location。"""
        for variant, resolution in self.location_variants(location):
            try:
                absolute = urljoin(base_url, variant)
                parts = urlsplit(absolute)
            except ValueError:
                continue
            if (parts.hostname or "").lower() != expected_host.lower():
                continue
            if marker not in absolute and marker not in variant:
                continue
            return {"url": absolute, "resolution": resolution}
        return None

    def location_variants(self, location):
        """生成 raw / URL decode / 反斜杠归一化后的 Location 候选。"""
        raw = (location or "").strip()
        if not raw:
            return

        seen = set()

        def add(value, label):
            if value and value not in seen:
                seen.add(value)
                yield value, label
            slashy = value.replace("\\", "/") if value else value
            if slashy and slashy != value and slashy not in seen:
                seen.add(slashy)
                yield slashy, f"{label}+backslash"
            if slashy and slashy.startswith("///"):
                collapsed = "//" + slashy.lstrip("/")
                if collapsed not in seen:
                    seen.add(collapsed)
                    yield collapsed, f"{label}+slash_collapse"

        yield from add(raw, "raw")
        decoded = raw
        for round_index in range(1, 3):
            new_value = unquote(decoded)
            if new_value == decoded:
                break
            decoded = new_value
            yield from add(decoded, f"url_decode_{round_index}")

    def extract_refresh_url(self, value):
        if not value:
            return ""
        parts = str(value).split(";", 1)
        if len(parts) == 1:
            return ""
        match = re.search(r"url\s*=\s*(.+)$", parts[1], re.I)
        if not match:
            return ""
        return match.group(1).strip().strip("'\"")

    def extract_meta_refresh_url(self, text):
        if not text:
            return ""
        for match in _META_REFRESH_RE.finditer(text[:MAX_COMPARE_CHARS]):
            value = self.extract_refresh_url(match.group(1))
            if value:
                return value
        return ""

    def match_header_injection(self, probe, header_name, header_value):
        """确认自定义 header 是否真实出现在响应头里。"""
        for value in self.get_header_values(probe, header_name):
            if header_value in value:
                return f"{header_name}: {value}"

        response_packet = probe.get("response_packet", "")
        header_block = response_packet.split("\r\n\r\n", 1)[0]
        pattern = re.compile(
            r"^" + re.escape(header_name) + r"\s*:\s*" + re.escape(header_value) + r"\s*$",
            re.I | re.M,
        )
        match = pattern.search(header_block)
        if match:
            return match.group(0)
        return ""

    def get_header_values(self, probe, header_name):
        values = probe.get("header_values", {})
        return values.get(header_name.lower(), [])

    # ------------------------------------------------------------------
    # 主动发包
    # ------------------------------------------------------------------

    def send_probe(self, flow, candidate, payload):
        """主动发送一次探测请求。candidate 为 None 表示重放原始请求。"""
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
            return self.timed_out_probe(request_packet, payload)
        except (URLError, OSError, ValueError):
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
            "header_values": self.collect_header_values(response_headers),
            "text": text[:MAX_COMPARE_CHARS],
            "request_packet": request_packet,
            "response_packet": self.trim_proof(response_packet),
            "sent_payload": payload,
        }

    def timed_out_probe(self, request_packet="", payload=""):
        return {
            "status_code": 0,
            "length": 0,
            "elapsed": float(TIMEOUT),
            "headers": {},
            "header_values": {},
            "text": "",
            "timed_out": True,
            "request_packet": request_packet,
            "response_packet": "",
            "sent_payload": payload,
        }

    # ------------------------------------------------------------------
    # 请求构造
    # ------------------------------------------------------------------

    def build_probe_request(self, flow, candidate, payload):
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
            header_overrides["Cookie"] = self.build_cookie_header(pairs)
            return url, body, header_overrides

        if place == "header":
            header_overrides[candidate["name"]] = payload
            return url, body, header_overrides

        return url, body, header_overrides

    def replace_query_value(self, url, index, new_value):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if index < len(pairs):
            pairs[index] = (pairs[index][0], new_value)
        new_query = self.urlencode_pairs(pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def urlencode_pairs(self, pairs, charset="utf-8"):
        """编码 query/form 参数，保留 payload 中手写的 %xx 绕过。"""
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

    def payload_safe_for_place(self, place, payload):
        """urllib 不允许请求头/Cookie 值里出现真实 CR/LF，header 类注入只发编码版本。"""
        if place not in ("header", "cookie"):
            return True
        return "\r" not in payload and "\n" not in payload

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

    def collect_header_values(self, headers):
        """把 HTTP headers 整理成 {lower_name: [values...]}。"""
        values = {}
        if not headers:
            return values

        names = []
        try:
            names = list(headers.keys())
        except AttributeError:
            names = [name for name, _value in headers.items()]

        for name in names:
            lower = str(name).lower()
            if lower in values:
                continue
            if hasattr(headers, "get_all"):
                raw_values = headers.get_all(name) or []
            else:
                raw_values = [value for item_name, value in headers.items() if item_name.lower() == lower]
            values[lower] = [str(value) for value in raw_values]
        return values

    # ------------------------------------------------------------------
    # 工具与结果
    # ------------------------------------------------------------------

    def use_extra_payloads(self):
        """extra payload 等价于其它插件的 deep tamper：请求数可控，默认开启追求覆盖面。"""
        return self.full_payload_scan or self.deep_tamper

    def allow_host_for(self, flow):
        parts = urlsplit(flow.request.pretty_url)
        host = parts.hostname or "localhost"
        safe_host = re.sub(r"[^A-Za-z0-9.-]+", "-", host).strip(".-")
        return safe_host or "localhost"

    def next_marker(self, prefix):
        middle = "".join(
            self.random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
        )
        return f"{prefix}{middle}"

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

    def build_finding(self, flow, candidate, evidence, proof_probe=None):
        request = flow.request
        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "redir",
            "method": "redir",
            "request_method": request.method,
            "url": request.pretty_url,
            "param_place": candidate["place"],
            "param_name": candidate["name"],
            "evidence": evidence,
            "proof": self.probe_to_proof(proof_probe),
            "extra_proofs": [],
        }

    def probe_to_proof(self, probe):
        if not probe:
            return {"request": "", "response": ""}
        return {
            "request": probe.get("request_packet", ""),
            "response": self.trim_proof(probe.get("response_packet", "")),
        }

    def trim_proof(self, text):
        if not text:
            return ""
        limit = 20000
        if len(text) <= limit:
            return text
        return text[:limit] + "\n... [truncated] ..."

    def write_finding(self, finding):
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
                f"检测到跳转/响应头注入[{technique}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
