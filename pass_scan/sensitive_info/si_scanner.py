# 敏感信息泄漏检测插件。
#
# 设计目标：
# 1. 被动优先：直接扫描当前响应正文/响应头，覆盖 JS、JSON、HTML、报错页和配置文本。
# 2. 轻量主动探测：每个 host + 应用路径段只探一次常见泄漏端点（目录列出/.git/.svn/.env/.DS_Store/Swagger/actuator），
#    由本插件自己的 ScanQueue worker 执行，不占用其它漏洞队列。
# 3. 低误报：云密钥、API key 等规则都做基础占位符/上下文过滤。

import gzip
import html
import hashlib
import os
import re
import socket
import ssl
import threading
import time
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from pass_scan.body_paser import decode_body_text, get_header, get_media_type
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context
from pass_scan.terminal import red


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 8
MAX_SCAN_CHARS = 300000
MAX_ACTIVE_BODY_BYTES = 262144
MAX_SAMPLE_PER_TYPE = 6

DIRECTORY_LISTING_ENDPOINT = "/"
GIT_DIRECTORY_ENDPOINT = ".git/"
SVN_DIRECTORY_ENDPOINT = ".svn/"

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

TEXT_STATIC_SUFFIXES = (
    ".js",
    ".mjs",
    ".map",
    ".json",
    ".txt",
    ".xml",
    ".yml",
    ".yaml",
    ".properties",
    ".ini",
    ".conf",
    ".config",
    ".env",
    ".log",
)

TEXT_MEDIA_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/x-javascript",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
    "application/x-www-form-urlencoded",
}

BINARY_MEDIA_PREFIXES = ("audio/", "font/", "image/", "video/")

ACTIVE_ENDPOINTS = (
    DIRECTORY_LISTING_ENDPOINT,
    GIT_DIRECTORY_ENDPOINT,
    SVN_DIRECTORY_ENDPOINT,
    ".env",
    ".env.local",
    ".env.production",
    ".env.bak",
    ".env.backup",
    "config/.env",
    ".DS_Store",
    "application.properties",
    "application.yml",
    "application.yaml",
    "bootstrap.properties",
    "bootstrap.yml",
    "bootstrap.yaml",
    "config/application.properties",
    "config/application.yml",
    "config/application.yaml",
    "config/bootstrap.properties",
    "config/bootstrap.yml",
    "WEB-INF/classes/application.properties",
    "WEB-INF/classes/application.yml",
    "WEB-INF/classes/bootstrap.properties",
    "WEB-INF/classes/bootstrap.yml",
    "WEB-INF/web.xml",
    "swagger-ui.html",
    "swagger-ui/",
    "swagger/",
    "api-docs",
    "v2/api-docs",
    "v3/api-docs",
    "swagger-resources",
    "swagger.json",
    "swagger.yaml",
    "openapi.json",
    "openapi.yaml",
    "docs/swagger.json",
    "docs/openapi.json",
    "doc.html",
    "docs",
    "redoc",
    "actuator",
)

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    re.I,
)

CLOUD_ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      (?:aws[_-]?)?access[_-]?key[_-]?id
      |(?:aws[_-]?)?secret[_-]?access[_-]?key
      |accessKeyId
      |accessKeySecret
      |secretAccessKey
      |secretId
      |secretKey
      |ossAccessKeyId
      |ossAccessKeySecret
      |aliyun[_-]?access[_-]?key[_-]?id
      |aliyun[_-]?access[_-]?key[_-]?secret
      |tencentcloud[_-]?secret[_-]?id
      |tencentcloud[_-]?secret[_-]?key
    )
    ["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9/+=._-]{16,120})
    """,
    re.I | re.X,
)

AWS_AK_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
ALIYUN_AK_RE = re.compile(r"\bLTAI[0-9A-Za-z]{12,30}\b")
TENCENT_AK_RE = re.compile(r"\bAKID[0-9A-Za-z]{13,50}\b")

API_ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      api[_-]?key
      |apikey
      |x-api-key
      |apiKey
      |access[_-]?token
      |refresh[_-]?token
      |auth[_-]?token
      |id[_-]?token
      |client[_-]?secret
      |app[_-]?secret
      |bearer
      |authorization
    )
    ["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9][A-Za-z0-9._~+/=-]{19,300})
    """,
    re.I | re.X,
)

SPECIFIC_API_TOKEN_RES = (
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bghp_[0-9A-Za-z_]{36}\b"),
    re.compile(r"\bgithub_pat_[0-9A-Za-z_]{80,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{32,}\b"),
)

MAP_KEY_RE = re.compile(
    r"""
    (?P<label>
      (?:amap|gaode|baidu|bmap|tencent|qqmap|mapbox|maptiler|google[_-]?maps?)
      [A-Za-z0-9_-]*
      (?:key|ak|token|access[_-]?token)
      |(?:key|ak|token|access[_-]?token)
    )
    ["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9._-]{20,200})
    """,
    re.I | re.X,
)

MAP_CONTEXT_KEYWORDS = (
    "amap",
    "gaode",
    "高德",
    "webapi.amap.com",
    "restapi.amap.com",
    "baidu",
    "bmap",
    "百度",
    "api.map.baidu.com",
    "tencent",
    "qqmap",
    "腾讯地图",
    "apis.map.qq.com",
    "maps.googleapis.com",
    "google.maps",
    "google map",
    "googlemap",
    "mapbox",
    "mapboxgl",
    "api.mapbox.com",
    "maptiler",
    "api.maptiler.com",
)

DB_URL_RE = re.compile(
    r"""
    \b
    (?:
      jdbc:
    )?
    (?:
      mysql|postgresql|postgres|mongodb(?:\+srv)?|redis|amqp|rabbitmq
    )
    ://[^\s'"<>]{8,300}
    """,
    re.I | re.X,
)

ENV_LINE_RE = re.compile(
    r"(?m)^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]{2,})\s*=\s*(?P<value>[^\r\n#]{1,300})"
)

ACTUATOR_RES = (
    re.compile(r'"_links"\s*:\s*\{.*?(?:actuator|self|health|env|metrics)', re.I | re.S),
    re.compile(r'"propertySources"\s*:\s*\[', re.I),
    re.compile(r'"activeProfiles"\s*:\s*\[', re.I),
    re.compile(r'"contexts"\s*:\s*\{', re.I),
    re.compile(r'"beans"\s*:\s*\{', re.I),
    re.compile(r'"mappings"\s*:\s*\{', re.I),
    re.compile(r"management\.endpoints\.web\.exposure", re.I),
)

CONFIG_FILE_SUFFIXES = (
    "application.properties",
    "application.yml",
    "application.yaml",
    "bootstrap.properties",
    "bootstrap.yml",
    "bootstrap.yaml",
    "web-inf/web.xml",
)

CONFIG_PROPERTIES_RE = re.compile(
    r"(?m)^\s*(?:spring|server|management|logging|datasource|mybatis|redis|eureka|dubbo)(?:\.[A-Za-z0-9_-]+)+\s*[:=]",
    re.I,
)
CONFIG_YAML_ROOT_RE = re.compile(
    r"(?m)^\s*(?:spring|server|management|logging|datasource|mybatis|redis|eureka|dubbo)\s*:",
    re.I,
)
CONFIG_YAML_NESTED_RE = re.compile(r"(?m)^\s{2,}[A-Za-z0-9_-]+\s*:")
CONFIG_WEB_XML_RE = re.compile(
    r"<web-app[\s>]|<servlet[\s>]|<context-param[\s>]",
    re.I,
)

DIRECTORY_LISTING_TITLE_RE = re.compile(
    r"""
    <title[^>]*>\s*
    (?P<label>
      Index\s+of\s+[^<]{0,200}
      |Directory\s+listing\s+for\s+[^<]{0,200}
      |Directory\s+Listing\s+For\s+[^<]{0,200}
      |Directory\s+Listing\s+--\s+[^<]{0,200}
    )
    \s*</title>
    """,
    re.I | re.X,
)
DIRECTORY_LISTING_HEADING_RE = re.compile(
    r"""
    <h[1-3][^>]*>\s*
    (?P<label>
      Index\s+of\s+[^<]{0,200}
      |Directory\s+listing\s+for\s+[^<]{0,200}
      |Directory\s+Listing\s+For\s+[^<]{0,200}
      |Directory\s+Listing\s+--\s+[^<]{0,200}
    )
    \s*</h[1-3]>
    """,
    re.I | re.X,
)
DIRECTORY_PARENT_LINK_RE = re.compile(
    r"""
    <a\b[^>]*href\s*=\s*["'][^"']*(?:\.\./?|/)[^"']*["'][^>]*>
    \s*(?:Parent\s+Directory|\[To\s+Parent\s+Directory\]|\.\./?)\s*
    </a>
    """,
    re.I | re.X,
)
DIRECTORY_HREF_RE = re.compile(r"""href\s*=\s*["'](?P<href>[^"'<>]+)["']""", re.I)
DIRECTORY_DATED_ENTRY_RE = re.compile(
    r"""
    (?mi)
    (?:^|\n)\s*
    [^\n<>]{1,160}?
    \s+
    (?:\d{2}-[A-Za-z]{3}-\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})
    \s+
    \d{1,2}:\d{2}(?:\s*[AP]M)?
    \s+
    (?:-|[0-9][0-9,.]*(?:\s?[KMGTPE]?B?)?)
    """,
    re.X,
)

SENSITIVE_ENV_KEYS = (
    "APP_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "DATABASE_URL",
    "DB_",
    "MYSQL_",
    "POSTGRES_",
    "REDIS_",
    "MONGO_",
    "AWS_",
    "ALIYUN_",
    "TENCENT",
    "OSS_",
    "MAIL_",
    "SMTP_",
)

PLACEHOLDER_VALUES = {
    "",
    "null",
    "none",
    "undefined",
    "false",
    "true",
    "changeme",
    "change_me",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "your_api_key",
    "your-api-key",
    "your_secret",
    "example",
    "sample",
    "demo",
    "test",
}


class SensitiveInfoScanner:
    """敏感信息泄漏扫描器。"""

    name = "sensitive_info"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.active_probe = bool(self.config.get("active_probe", True))
        self.path_segment_depth = max(1, int(self.config.get("path_segment_depth", 1)))
        self.max_active_body_bytes = int(
            self.config.get("max_active_body_bytes", MAX_ACTIVE_BODY_BYTES)
        )
        self.max_scan_chars = int(self.config.get("max_scan_chars", MAX_SCAN_CHARS))
        self.active_endpoints = tuple(
            self.config.get("active_endpoints") or ACTIVE_ENDPOINTS
        )
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE
        self.lock = threading.Lock()
        self.active_scanned = set()
        self.reported = set()
        self.waf_state = None
        self.on_finding = None

        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
        )

        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # 调度层接口
    # ------------------------------------------------------------------

    def interested(self, context):
        """轻量判断：是否需要把这条流量交给敏感信息插件。"""
        if not context.host:
            return False
        if context.method in ("HEAD", "OPTIONS"):
            return False

        if self.response_can_be_scanned(context):
            return True

        if self.active_probe and self.has_unscanned_active_base(context):
            return True

        return False

    def dedup_key(self, context):
        """敏感信息被动扫描按 URL 去重；主动探测在插件内部按 host+路径段去重。"""
        return (
            self.name,
            context.method,
            context.scheme,
            context.host,
            context.url,
        )

    def check(self, context, flow=None):
        """敏感信息检测入口。"""
        if flow is not None:
            context = build_scan_context(
                context,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        findings = []

        if self.response_can_be_scanned(context):
            findings.extend(self.scan_passive_response(context))

        if self.active_probe:
            findings.extend(self.scan_active_endpoints(context))

        written = []
        for finding in findings:
            if self.write_finding_once(finding):
                written.append(finding)

        return written

    # ------------------------------------------------------------------
    # 被动检测
    # ------------------------------------------------------------------

    def scan_passive_response(self, context):
        response = getattr(context.flow, "response", None)
        if not response:
            return []

        body = response.content or b""
        text, _charset = self.decode_http_body(body, response.headers)
        headers_text = self.headers_to_text(response.headers)
        proof = self.passive_proof(context.flow)

        return self.findings_for_artifact(
            url=context.url,
            request_method=context.method,
            status_code=response.status_code,
            headers=response.headers,
            body=body,
            body_text=text,
            headers_text=headers_text,
            proof=proof,
            technique="被动响应检测",
            context_host=context.host,
        )

    def response_can_be_scanned(self, context):
        response = getattr(context.flow, "response", None)
        if not response:
            return False
        if int(getattr(response, "status_code", 0) or 0) in (204, 304):
            return False
        if (context.path or "").lower().endswith(".ds_store"):
            return True

        content_type = get_header(response.headers, "content-type")
        media_type = get_media_type(content_type)
        if media_type.startswith(BINARY_MEDIA_PREFIXES):
            return False
        if media_type.startswith("text/"):
            return True
        if (
            media_type in TEXT_MEDIA_TYPES
            or media_type.endswith("+json")
            or media_type.endswith("+xml")
        ):
            return True
        if (context.path or "").lower().endswith(TEXT_STATIC_SUFFIXES):
            return True

        body = response.content or b""
        if not body:
            return False
        return self.looks_like_text(body[:4096], response.headers)

    def looks_like_text(self, body, headers):
        text, _charset = self.decode_http_body(body, headers)
        if not text:
            return True
        bad = 0
        for char in text[:4096]:
            if char in "\n\r\t":
                continue
            if ord(char) < 32:
                bad += 1
        return bad / max(1, min(len(text), 4096)) < 0.05

    # ------------------------------------------------------------------
    # 主动端点探测
    # ------------------------------------------------------------------

    def has_unscanned_active_base(self, context):
        with self.lock:
            return any(
                (context.scheme, context.host, base_path) not in self.active_scanned
                for base_path in self.base_paths_for(context.path)
            )

    def scan_active_endpoints(self, context):
        findings = []
        base_paths = self.claim_active_base_paths(context)
        if not base_paths:
            return findings

        for base_path in base_paths:
            for endpoint in self.active_endpoints:
                url = self.build_endpoint_url(context, base_path, endpoint)
                probe = self.fetch_url(context.flow, url)
                if not probe:
                    continue

                endpoint_findings = self.findings_for_artifact(
                    url=url,
                    request_method="GET",
                    status_code=probe["status_code"],
                    headers=probe["headers"],
                    body=probe["body"],
                    body_text=probe["text"],
                    headers_text=probe["headers_text"],
                    proof={
                        "request": probe["request_packet"],
                        "response": self.trim_proof(probe["response_packet"]),
                    },
                    technique="主动端点探测",
                    context_host=context.host,
                )
                findings.extend(endpoint_findings)

        return findings

    def claim_active_base_paths(self, context):
        claimed = []
        with self.lock:
            for base_path in self.base_paths_for(context.path):
                key = (context.scheme, context.host, base_path)
                if key in self.active_scanned:
                    continue
                self.active_scanned.add(key)
                claimed.append(base_path)
        return claimed

    def base_paths_for(self, path):
        parts = [part for part in (path or "/").split("/") if part]
        bases = ["/"]
        if parts:
            depth = min(self.path_segment_depth, len(parts))
            bases.append("/" + "/".join(parts[:depth]))
        return tuple(dict.fromkeys(bases))

    def build_endpoint_url(self, context, base_path, endpoint):
        endpoint_text = str(endpoint)
        path_parts = []
        if base_path and base_path != "/":
            path_parts.append(base_path.strip("/"))
        path_parts.append(endpoint_text.strip("/"))
        path = "/" + "/".join(part for part in path_parts if part)
        if endpoint_text.endswith("/") and not path.endswith("/"):
            path += "/"
        return f"{context.scheme}://{context.host}{path}"

    def fetch_url(self, flow, url):
        request = getattr(flow, "request", None)
        headers = self.copy_headers(getattr(request, "headers", {}) if request else {})
        headers["Accept-Encoding"] = "identity"
        urllib_request = Request(url, headers=headers, method="GET")
        request_packet = self.build_request_packet("GET", url, headers, None)

        host = urlsplit(url).netloc
        if self.waf_state:
            self.waf_state.wait_if_needed(host)

        try:
            response = self.opener.open(urllib_request, timeout=TIMEOUT)
            body = response.read(self.max_active_body_bytes + 1)
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            body = error.read(self.max_active_body_bytes + 1)
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError, URLError, OSError, ValueError):
            return None

        text, charset = self.decode_http_body(body, response_headers)
        response_packet = self.build_response_packet(
            status_code,
            reason,
            response_headers,
            body,
            charset,
        )
        return {
            "status_code": status_code,
            "headers": response_headers,
            "headers_text": self.headers_to_text(response_headers),
            "body": body,
            "text": text,
            "request_packet": request_packet,
            "response_packet": response_packet,
        }

    # ------------------------------------------------------------------
    # 规则引擎
    # ------------------------------------------------------------------

    def findings_for_artifact(
        self,
        url,
        request_method,
        status_code,
        headers,
        body,
        body_text,
        headers_text,
        proof,
        technique,
        context_host,
    ):
        matches = []
        body_text = (body_text or "")[: self.max_scan_chars]
        headers_text = (headers_text or "")[: self.max_scan_chars]

        matches.extend(
            self.detect_in_text(
                body_text,
                source="response.body",
                url=url,
                status_code=status_code,
                body=body,
                context_host=context_host,
            )
        )
        matches.extend(
            self.detect_in_text(
                headers_text,
                source="response.headers",
                url=url,
                status_code=status_code,
                body=b"",
                context_host=context_host,
            )
        )

        grouped = self.group_matches(matches)
        findings = []
        for sensitive_type, info in grouped.items():
            evidence = {
                "technique": technique,
                "sensitive_type": sensitive_type,
                "message": f"响应中出现敏感信息: {sensitive_type}",
                "matched": info["samples"],
                "sources": info["sources"],
                "match_count": info["count"],
                "confidence": info["confidence"],
            }
            if info["subtypes"]:
                evidence["subtypes"] = info["subtypes"]
            if status_code:
                evidence["probe_status"] = status_code
            dedup_keys = info.get("dedup_keys") or []

            finding = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "type": "sensitive_info",
                "method": "sensitive_info",
                "request_method": request_method,
                "url": url,
                "param_place": "response",
                "param_name": "body",
                "evidence": evidence,
                "proof": proof,
                "extra_proofs": [],
            }
            if dedup_keys:
                finding["_dedup_keys"] = dedup_keys
            findings.append(finding)

        return findings

    def detect_in_text(self, text, source, url, status_code, body, context_host):
        if not text and not body:
            return []

        matches = []
        matches.extend(self.detect_private_keys(text, source))
        matches.extend(self.detect_cloud_keys(text, source))
        matches.extend(self.detect_map_keys(text, source))
        matches.extend(self.detect_api_keys(text, source))
        matches.extend(self.detect_database_urls(text, source))
        if source == "response.body":
            matches.extend(self.detect_env(text, source, url, status_code))
            matches.extend(self.detect_config_file(text, source, url, status_code))
            matches.extend(self.detect_ds_store(text, source, url, status_code, body))
            matches.extend(self.detect_directory_listing(text, source, url, status_code))
            matches.extend(self.detect_git(text, source, url, status_code, body))
            matches.extend(self.detect_svn(text, source, url, status_code, body))
            matches.extend(self.detect_swagger(text, source, url, status_code))
            matches.extend(self.detect_actuator(text, source, url, status_code))
        return matches

    def detect_config_file(self, text, source, url, status_code):
        if source != "response.body":
            return []
        if int(status_code or 0) >= 400:
            return []
        value = text or ""
        if not value:
            return []

        path = urlsplit(url).path.lower()
        if not path.endswith(CONFIG_FILE_SUFFIXES):
            return []
        if self.looks_like_html_document(value):
            return []

        sample = self.config_file_sample(value, path)
        if not sample:
            return []

        matches = []
        self.add_match(
            matches,
            "配置文件泄露",
            self.config_file_subtype(path),
            sample,
            source,
            fingerprint=self.config_file_fingerprint(value),
        )
        return matches

    def config_file_sample(self, text, path):
        if path.endswith(".properties"):
            match = CONFIG_PROPERTIES_RE.search(text)
            return self.clean_sample(match.group(0)) if match else ""

        if path.endswith((".yml", ".yaml")):
            dotted_match = CONFIG_PROPERTIES_RE.search(text)
            if dotted_match:
                return self.clean_sample(dotted_match.group(0))

            root_match = CONFIG_YAML_ROOT_RE.search(text)
            if not root_match:
                return ""
            if not CONFIG_YAML_NESTED_RE.search(text):
                return ""
            return self.clean_sample(root_match.group(0))

        if path.endswith("web-inf/web.xml"):
            if not re.search(r"<web-app[\s>]", text or "", re.I):
                return ""
            match = CONFIG_WEB_XML_RE.search(text)
            return self.clean_sample(match.group(0)) if match else ""

        return ""

    def config_file_subtype(self, path):
        if path.endswith(".properties"):
            return "Java properties"
        if path.endswith((".yml", ".yaml")):
            return "YAML config"
        if path.endswith("web-inf/web.xml"):
            return "Java web.xml"
        return "application/bootstrap/web.xml"

    def config_file_fingerprint(self, text):
        normalized_lines = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped:
                normalized_lines.append(stripped)
        return "\n".join(normalized_lines)[:20000]

    def looks_like_html_document(self, text):
        head = (text or "")[:2048].lower()
        return any(
            token in head
            for token in ("<!doctype html", "<html", "<head", "<body", "<script")
        )

    def add_match(
        self,
        matches,
        category,
        subtype,
        sample,
        source,
        confidence="high",
        fingerprint=None,
    ):
        sample = self.clean_sample(sample)
        if not sample:
            return
        match = {
            "category": category,
            "subtype": subtype,
            "sample": sample,
            "source": source,
            "confidence": confidence,
        }
        if fingerprint:
            match["dedup_key"] = self.match_dedup_key(category, fingerprint)
        matches.append(match)

    def detect_private_keys(self, text, source):
        matches = []
        for match in PRIVATE_KEY_RE.finditer(text or ""):
            value = match.group(0)
            self.add_match(
                matches,
                "私钥",
                "PEM private key",
                value,
                source,
                fingerprint=value,
            )
        return matches

    def detect_cloud_keys(self, text, source):
        matches = []
        for match in CLOUD_ASSIGN_RE.finditer(text or ""):
            key = match.group("key")
            value = self.strip_secret_value(match.group("value"))
            if not self.looks_like_secret(value, min_length=16, allow_words=True):
                continue
            self.add_match(
                matches,
                "AK/SK",
                key,
                f"{key}={self.mask_secret(value)}",
                source,
                fingerprint=value,
            )

        for regex, subtype in (
            (AWS_AK_RE, "AWS Access Key ID"),
            (ALIYUN_AK_RE, "Aliyun AccessKeyId"),
            (TENCENT_AK_RE, "Tencent SecretId"),
        ):
            for match in regex.finditer(text or ""):
                value = match.group(0)
                self.add_match(
                    matches,
                    "AK/SK",
                    subtype,
                    self.mask_secret(value),
                    source,
                    fingerprint=value,
                )

        return matches

    def detect_api_keys(self, text, source):
        matches = []
        for regex in SPECIFIC_API_TOKEN_RES:
            for match in regex.finditer(text or ""):
                value = match.group(0)
                if self.is_placeholder(value):
                    continue
                if self.has_map_context(text, match.start(), match.end()):
                    continue
                self.add_match(
                    matches,
                    "API key",
                    self.specific_token_subtype(value),
                    self.mask_secret(value),
                    source,
                    fingerprint=value,
                )

        for match in API_ASSIGN_RE.finditer(text or ""):
            key = match.group("key")
            value = self.strip_secret_value(match.group("value"))
            if not self.looks_like_secret(value, min_length=20):
                continue
            if self.has_map_context(text, match.start(), match.end(), key):
                continue
            self.add_match(
                matches,
                "API key",
                key,
                f"{key}={self.mask_secret(value)}",
                source,
                fingerprint=value,
            )
        return matches

    def detect_map_keys(self, text, source):
        matches = []
        seen = set()
        for match in MAP_KEY_RE.finditer(text or ""):
            label = match.group("label")
            value = self.strip_secret_value(match.group("value"))
            if not self.looks_like_secret(value, min_length=20):
                continue
            if not self.has_map_context(text, match.start(), match.end(), label):
                continue
            if value in seen:
                continue
            seen.add(value)
            self.add_match(
                matches,
                "地图 key",
                self.map_key_provider(text, match.start(), match.end(), label),
                f"{label}={self.mask_secret(value)}",
                source,
                fingerprint=value,
            )
        return matches

    def detect_database_urls(self, text, source):
        matches = []
        for match in DB_URL_RE.finditer(text or ""):
            value = match.group(0)
            lowered = value.lower()
            if "@" not in value and "password=" not in lowered and "passwd=" not in lowered:
                continue
            self.add_match(
                matches,
                "数据库连接串",
                "connection string",
                self.mask_connection_string(value),
                source,
                fingerprint=value,
            )
        return matches

    def detect_env(self, text, source, url, status_code):
        if int(status_code or 0) >= 400:
            return []

        env_matches = []
        for match in ENV_LINE_RE.finditer(text or ""):
            key = match.group("key").strip()
            value = self.strip_secret_value(match.group("value"))
            if not self.env_key_is_sensitive(key):
                continue
            if not value or self.is_placeholder(value):
                continue
            env_matches.append((key, value))

        if not env_matches:
            return []

        path = urlsplit(url).path.lower()
        strong_path = "/.env" in path or path.endswith(".env")
        if strong_path and self.looks_like_html_document(text):
            return []
        uppercase_env_count = sum(1 for key, _value in env_matches if key == key.upper())
        dotenv_marker = any(
            key.upper() in ("APP_ENV", "APP_KEY", "DATABASE_URL")
            or key.upper().startswith(("DB_", "MYSQL_", "POSTGRES_", "REDIS_"))
            for key, _value in env_matches
        )
        if not strong_path and (
            len(env_matches) < 3 or uppercase_env_count < 3 or not dotenv_marker
        ):
            return []

        matches = []
        for key, value in env_matches[:MAX_SAMPLE_PER_TYPE]:
            self.add_match(
                matches,
                ".env 泄露",
                key,
                f"{key}={self.mask_secret(value)}",
                source,
                fingerprint=f"{key}={value}",
            )
        return matches

    def detect_ds_store(self, text, source, url, status_code, body):
        if int(status_code or 0) >= 400:
            return []
        path = urlsplit(url).path.lower()
        if not path.endswith("/.ds_store"):
            return []

        prefix = body[:16] if body else b""
        if not (prefix.startswith(b"\x00\x00\x00\x01Bud1") or b"Bud1" in prefix[:8]):
            return []

        return [
            {
                "category": ".DS_Store 泄露",
                "subtype": "Apple Desktop Services Store",
                "sample": ".DS_Store binary header: Bud1",
                "source": source,
                "confidence": "high",
            }
        ]

    def detect_directory_listing(self, text, source, url, status_code):
        if source != "response.body":
            return []
        if int(status_code or 0) >= 400:
            return []

        value = text or ""
        if not value:
            return []

        path = urlsplit(url).path.lower()
        if "/.git/" in path or path.endswith("/.git"):
            return []
        if "/.svn/" in path or path.endswith("/.svn"):
            return []

        artifact = self.directory_listing_artifact(value)
        if not artifact:
            return []

        matches = []
        self.add_match(
            matches,
            "目录列出",
            artifact["subtype"],
            artifact["sample"],
            source,
            confidence=artifact["confidence"],
            fingerprint=f"{urlsplit(url).netloc}{path}:{artifact['fingerprint']}",
        )
        return matches

    def directory_listing_artifact(self, text):
        value = text or ""
        title_match = DIRECTORY_LISTING_TITLE_RE.search(value)
        heading_match = DIRECTORY_LISTING_HEADING_RE.search(value)
        label_match = title_match or heading_match
        label = label_match.group("label") if label_match else ""

        plain = self.html_to_plain_text(value)
        plain_head = plain[:6000].lower()
        has_table_header = self.has_directory_listing_table_header(plain_head)
        has_parent_link = bool(DIRECTORY_PARENT_LINK_RE.search(value))
        has_sort_links = bool(re.search(r"\?C=[NMSD];O=[AD]", value, re.I))
        dated_entries = len(DIRECTORY_DATED_ENTRY_RE.findall(plain[:12000]))
        entry_names = self.directory_listing_entry_names(value)
        entry_count = len(entry_names)

        strong_structure = (
            has_table_header
            or has_sort_links
            or has_parent_link
            or dated_entries >= 1
            or entry_count >= 2
        )
        fallback_structure = (
            (has_table_header and (has_parent_link or dated_entries >= 1 or entry_count >= 2))
            or (has_sort_links and (has_parent_link or entry_count >= 2))
            or (has_parent_link and dated_entries >= 2)
        )

        if (
            label_match
            and self.directory_listing_label_looks_like_path(label)
            and strong_structure
        ):
            sample = self.directory_listing_sample(label, entry_names)
            return {
                "subtype": "Directory index",
                "sample": sample,
                "confidence": "high",
                "fingerprint": f"{label}:{','.join(entry_names[:6])}",
            }

        if fallback_structure:
            sample = self.directory_listing_sample("Directory listing", entry_names)
            return {
                "subtype": "Directory index",
                "sample": sample,
                "confidence": "medium",
                "fingerprint": f"fallback:{','.join(entry_names[:6])}:{dated_entries}",
            }

        return None

    def directory_listing_label_looks_like_path(self, label):
        value = re.sub(
            r"(?i)^(?:index\s+of|directory\s+listing\s+for|directory\s+listing\s+--)\s*",
            "",
            label or "",
        ).strip()
        if not value:
            return True
        return "/" in value or "\\" in value or value in (".", "..")

    def html_to_plain_text(self, text):
        value = re.sub(r"(?is)<(?:script|style)\b.*?</(?:script|style)>", " ", text or "")
        value = re.sub(r"(?is)<br\s*/?>|</(?:tr|p|li|div|h[1-6]|pre)>", "\n", value)
        value = re.sub(r"(?s)<[^>]+>", " ", value)
        value = html.unescape(value)
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r"\n\s+", "\n", value)
        return value

    def has_directory_listing_table_header(self, plain_head):
        value = re.sub(r"\s+", " ", plain_head or "")
        return bool(
            re.search(r"\bname\b\s+(?:last\s+modified|modified)\s+\bsize\b", value)
            or re.search(r"\bname\b\s+\bsize\b\s+(?:last\s+modified|modified)", value)
            or ("[ico]" in value and "parent directory" in value)
        )

    def directory_listing_entry_names(self, text):
        entries = []
        seen = set()
        for match in DIRECTORY_HREF_RE.finditer(text or ""):
            href = html.unescape(match.group("href")).strip()
            name = self.directory_listing_href_name(href)
            if not name or name in seen:
                continue
            seen.add(name)
            entries.append(name)
            if len(entries) >= MAX_SAMPLE_PER_TYPE:
                break
        return entries

    def directory_listing_href_name(self, href):
        value = (href or "").strip()
        if not value:
            return ""

        lowered = value.lower()
        if lowered.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return ""
        if lowered.startswith(("http://", "https://", "//")):
            return ""
        if lowered.startswith("?") or "?c=" in lowered:
            return ""

        value = value.split("#", 1)[0].split("?", 1)[0]
        value = value.strip()
        if value in ("", ".", "./", "..", "../", "/"):
            return ""
        if len(value) > 200 or re.search(r"\s", value):
            return ""

        name = value.rstrip("/").rsplit("/", 1)[-1]
        if not name or name in (".", ".."):
            return ""
        if not re.search(r"[A-Za-z0-9_.-]", name):
            return ""

        if value.endswith("/") or re.search(r"\.[A-Za-z0-9][A-Za-z0-9_-]{0,15}$", name):
            return name + ("/" if value.endswith("/") else "")
        return ""

    def directory_listing_sample(self, label, entry_names):
        sample = self.clean_sample(label)
        if entry_names:
            sample = f"{sample}; entries: {', '.join(entry_names[:3])}"
        return self.clean_sample(sample)

    def detect_git(self, text, source, url, status_code, body):
        if int(status_code or 0) >= 400:
            return []
        path = urlsplit(url).path.lower()
        if "/.git/" not in path and not path.endswith("/.git"):
            return []

        sample = ""
        if body and body.startswith(b"DIRC"):
            sample = "Git index: DIRC"
        elif self.looks_like_git_directory_listing(text, path):
            sample = "Git directory listing: /.git/"
        elif re.search(r"(?m)^ref:\s+refs/(?:heads|tags)/", text or ""):
            sample = "ref: refs/heads/..."
        elif "[core]" in (text or "") and "repositoryformatversion" in (text or ""):
            sample = "[core] repositoryformatversion"
        elif re.search(r"(?m)^#\s*pack-refs with:", text or ""):
            sample = "packed-refs"
        elif re.search(r"(?m)^[0-9a-f]{40}\s+refs/(?:heads|tags|remotes)/", text or ""):
            sample = "info/refs or packed refs"
        elif re.fullmatch(r"\s*[0-9a-f]{40}\s*", text or ""):
            sample = "git ref object id"
        elif re.search(r"(?m)^P\s+pack-[0-9a-f]{40}\.pack$", text or ""):
            sample = "objects/info/packs"
        elif re.search(r"(?m)^[0-9a-f]{40}\s+[0-9a-f]{40}\s+", text or ""):
            sample = "git logs/HEAD"

        matches = []
        if sample:
            self.add_match(matches, ".git 泄露", "Git metadata", sample, source)
        return matches

    def looks_like_git_directory_listing(self, text, path):
        if not (path.endswith("/.git/") or path.endswith("/.git")):
            return False
        value = (text or "").lower()
        if not value:
            return False

        git_entries = (
            "head",
            "config",
            "objects/",
            "refs/",
            "packed-refs",
            "branches/",
            "hooks/",
            "info/",
        )
        hit_count = sum(1 for entry in git_entries if entry in value)
        if hit_count < 2:
            return False

        has_listing_title = (
            ("index of" in value or "directory listing" in value)
            and ".git" in value
        )
        has_git_links = re.search(
            r"href=[\"'](?:\.?/)?(?:head|config|objects/?|refs/?)[\"']",
            value,
        )
        return bool(has_listing_title or (has_git_links and hit_count >= 3))

    def detect_svn(self, text, source, url, status_code, body):
        if int(status_code or 0) >= 400:
            return []
        path = urlsplit(url).path.lower()
        if "/.svn/" not in path and not path.endswith("/.svn"):
            return []

        sample = ""
        if body and body.startswith(b"SQLite format 3"):
            sample = "SQLite wc.db"
        elif self.looks_like_svn_directory_listing(text, path):
            sample = "SVN directory listing: /.svn/"
        elif "svn:" in (text or "") and "<wc-entries" in (text or ""):
            sample = "svn wc-entries"
        elif re.search(r"(?m)^\s*(?:8|9|10|11|12)\s*$", text or "") and (
            path.endswith("/.svn/format") or "dir" in (text or "")
        ):
            sample = ".svn/entries"
        elif "svn:this_dir" in (text or "") or "svn:wc:ra_dav" in (text or ""):
            sample = ".svn wc props"
        elif "svn://" in (text or ""):
            sample = ".svn metadata"

        matches = []
        if sample:
            self.add_match(matches, ".svn 泄露", "SVN metadata", sample, source)
        return matches

    def looks_like_svn_directory_listing(self, text, path):
        if not (path.endswith("/.svn/") or path.endswith("/.svn")):
            return False
        value = (text or "").lower()
        if not value:
            return False

        svn_entries = (
            "entries",
            "wc.db",
            "format",
            "pristine/",
            "props/",
            "text-base/",
            "all-wcprops",
        )
        hit_count = sum(1 for entry in svn_entries if entry in value)
        if hit_count < 2:
            return False

        has_listing_title = (
            ("index of" in value or "directory listing" in value)
            and ".svn" in value
        )
        has_svn_links = re.search(
            r"href=[\"'](?:\.?/)?(?:entries|wc\.db|format|pristine/?|props/?|text-base/?)[\"']",
            value,
        )
        return bool(has_listing_title or (has_svn_links and hit_count >= 3))

    def detect_swagger(self, text, source, url, status_code):
        if int(status_code or 0) >= 400:
            return []
        value = text or ""
        if not value:
            return []
        path = urlsplit(url).path.lower()
        sample = self.swagger_artifact_sample(value, path)
        if sample:
            return [
                {
                    "category": "Swagger 泄露",
                    "subtype": "OpenAPI/Swagger",
                    "sample": sample,
                    "source": source,
                    "confidence": "high",
                }
            ]
        return []

    def swagger_artifact_sample(self, value, path):
        for regex in (
            re.compile(r'"swagger"\s*:\s*"2\.0"', re.I),
            re.compile(r'"openapi"\s*:\s*"3\.', re.I),
            re.compile(r"(?mi)^\s*swagger\s*:\s*['\"]?2\.0"),
            re.compile(r"(?mi)^\s*openapi\s*:\s*['\"]?3\."),
        ):
            match = regex.search(value)
            if match:
                return self.clean_sample(match.group(0))

        if "swagger-resources" in path:
            swagger_version = re.search(r'"swaggerVersion"\s*:', value, re.I)
            resource_url = re.search(r'"url"\s*:\s*"[^"]*(?:api-docs|swagger|openapi)', value, re.I)
            if swagger_version and resource_url:
                return "swagger-resources with swaggerVersion and url"

        swagger_ui_path = any(
            token in path
            for token in ("swagger-ui", "swagger/", "doc.html", "docs", "redoc")
        )
        if not swagger_ui_path:
            return ""

        ui_marker = re.search(r"\b(?:Swagger UI|Knife4j|ReDoc)\b", value, re.I)
        api_loader = re.search(
            r"(?:api-docs|swagger\.json|swagger\.yaml|openapi\.json|openapi\.yaml|swagger-ui-bundle|knife4j|redoc)",
            value,
            re.I,
        )
        if ui_marker and api_loader:
            return self.clean_sample(ui_marker.group(0))
        return ""

    def detect_actuator(self, text, source, url, status_code):
        if int(status_code or 0) >= 400:
            return []
        value = text or ""
        if not value:
            return []
        if self.looks_like_html_document(value):
            return []
        path = urlsplit(url).path.lower()
        if "actuator" not in path and not any(regex.search(value) for regex in ACTUATOR_RES[:3]):
            return []

        for regex in ACTUATOR_RES:
            match = regex.search(value)
            if match:
                return [
                    {
                        "category": "actuator 泄露",
                        "subtype": "Spring Boot actuator",
                        "sample": self.clean_sample(match.group(0)),
                        "source": source,
                        "confidence": "high",
                    }
                ]
        return []

    def group_matches(self, matches):
        grouped = {}
        confidence_rank = {"low": 1, "medium": 2, "high": 3}
        for match in matches:
            category = match["category"]
            item = grouped.setdefault(
                category,
                {
                    "samples": [],
                    "sample_seen": set(),
                    "sources": [],
                    "source_seen": set(),
                    "subtypes": [],
                    "subtype_seen": set(),
                    "dedup_keys": [],
                    "dedup_key_seen": set(),
                    "count": 0,
                    "confidence": "low",
                },
            )
            item["count"] += 1
            sample = match.get("sample", "")
            if sample and sample not in item["sample_seen"] and len(item["samples"]) < MAX_SAMPLE_PER_TYPE:
                item["sample_seen"].add(sample)
                item["samples"].append(sample)
            source = match.get("source", "")
            if source and source not in item["source_seen"]:
                item["source_seen"].add(source)
                item["sources"].append(source)
            subtype = match.get("subtype", "")
            if subtype and subtype not in item["subtype_seen"]:
                item["subtype_seen"].add(subtype)
                item["subtypes"].append(subtype)
            dedup_key = match.get("dedup_key", "")
            if dedup_key and dedup_key not in item["dedup_key_seen"]:
                item["dedup_key_seen"].add(dedup_key)
                item["dedup_keys"].append(dedup_key)
            if confidence_rank.get(match.get("confidence", "low"), 1) > confidence_rank.get(item["confidence"], 1):
                item["confidence"] = match.get("confidence", "low")

        for item in grouped.values():
            item.pop("sample_seen", None)
            item.pop("source_seen", None)
            item.pop("subtype_seen", None)
            item.pop("dedup_key_seen", None)

        return grouped

    # ------------------------------------------------------------------
    # 结果输出
    # ------------------------------------------------------------------

    def write_finding_once(self, finding):
        sensitive_type = finding.get("evidence", {}).get("sensitive_type", "")
        dedup_keys = finding.get("_dedup_keys") or []
        with self.lock:
            if dedup_keys:
                scoped_keys = [(sensitive_type, dedup_key) for dedup_key in dedup_keys]
                if all(key in self.reported for key in scoped_keys):
                    return False
                for key in scoped_keys:
                    self.reported.add(key)
            else:
                key = (finding.get("url", ""), sensitive_type)
                if key in self.reported:
                    return False
                self.reported.add(key)

        stored_finding = dict(finding)
        stored_finding.pop("_dedup_keys", None)
        write_jsonl(self.vuln_file, stored_finding)
        print_finding_once(self, stored_finding)
        if self.on_finding:
            self.on_finding(stored_finding)
        write_html_report(self.vuln_file, self.report_file)
        return True

    def print_finding(self, finding):
        sensitive_type = finding.get("evidence", {}).get("sensitive_type", "")
        print(
            red(
                "[漏洞] "
                f"检测到敏感信息[{sensitive_type}] | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )

    # ------------------------------------------------------------------
    # HTTP proof / decode 工具
    # ------------------------------------------------------------------

    def passive_proof(self, flow):
        request = flow.request
        response = getattr(flow, "response", None)
        request_text = self.build_request_packet(
            request.method,
            request.pretty_url,
            dict(request.headers.items()),
            request.content or b"",
        )
        response_text = ""
        if response:
            body = response.content or b""
            text, charset = self.decode_http_body(body, response.headers)
            response_text = self.build_response_packet(
                response.status_code,
                getattr(response, "reason", ""),
                response.headers,
                text.encode(charset or "utf-8", errors="replace"),
                charset,
            )
        return {"request": self.trim_proof(request_text), "response": self.trim_proof(response_text)}

    def build_request_packet(self, method, url, headers, body):
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        packet_headers = dict(headers or {})
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

    def decode_http_body(self, body, headers):
        body = body or b""
        decoded_body = self.decompress_body(body, headers)
        try:
            return decode_body_text(decoded_body, headers)
        except Exception:
            return decoded_body.decode("utf-8", errors="replace"), "utf-8"

    def decompress_body(self, body, headers):
        encoding = (get_header(headers, "content-encoding") or "").lower()
        if not body:
            return body
        try:
            if "gzip" in encoding:
                return gzip.decompress(body)
            if "deflate" in encoding:
                try:
                    return zlib.decompress(body)
                except zlib.error:
                    return zlib.decompress(body, -zlib.MAX_WBITS)
        except Exception:
            return body
        return body

    def headers_to_text(self, headers):
        if not headers:
            return ""
        return "\n".join(f"{name}: {value}" for name, value in headers.items())

    def copy_headers(self, headers):
        copied = {}
        for name, value in (headers or {}).items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            copied[name] = value
        return copied

    def trim_proof(self, text):
        if not text:
            return ""
        limit = 20000
        if len(text) <= limit:
            return text
        return text[:limit] + "\n... [truncated] ..."

    # ------------------------------------------------------------------
    # 过滤 / 格式化工具
    # ------------------------------------------------------------------

    def strip_secret_value(self, value):
        value = str(value or "").strip()
        value = value.strip("\"'`")
        value = value.rstrip(".,;)")
        return value

    def looks_like_secret(self, value, min_length=16, allow_words=False):
        value = self.strip_secret_value(value)
        if len(value) < min_length:
            return False
        if self.is_placeholder(value):
            return False
        if value.lower().startswith(("http://", "https://", "file://")):
            return False
        if not allow_words and re.fullmatch(r"[A-Za-z_-]+", value):
            return False
        if re.fullmatch(r"\d+", value) and len(value) < 18:
            return False
        if len(set(value)) < min(8, len(value)):
            return False
        return True

    def is_placeholder(self, value):
        value = self.strip_secret_value(value)
        lowered = value.lower()
        if lowered in PLACEHOLDER_VALUES:
            return True
        if any(token in lowered for token in ("example", "your_", "your-", "<", ">", "xxxx", "****")):
            return True
        if re.fullmatch(r"(?:0+|1+|1234567890|123456|abcdef|qwerty)", lowered):
            return True
        return False

    def mask_secret(self, value):
        value = self.strip_secret_value(value)
        if len(value) <= 10:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"

    def mask_connection_string(self, value):
        return re.sub(r"(://[^:/@\s]+:)([^@\s]+)(@)", r"\1****\3", value)

    def clean_sample(self, sample):
        sample = re.sub(r"\s+", " ", str(sample or "")).strip()
        if len(sample) > 180:
            sample = sample[:180] + "..."
        return sample

    def match_dedup_key(self, category, value):
        digest = hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()
        return f"{category}:{digest[:24]}"

    def specific_token_subtype(self, value):
        if value.startswith("AIza"):
            return "Google API key"
        if value.startswith("ghp_") or value.startswith("github_pat_"):
            return "GitHub token"
        if value.startswith("xox"):
            return "Slack token"
        if value.startswith(("sk_live_", "rk_live_")):
            return "Stripe live key"
        if value.startswith("SG."):
            return "SendGrid API key"
        return "token"

    def has_map_context(self, text, start, end, label=""):
        value = text or ""
        window = value[max(0, start - 160): min(len(value), end + 160)].lower()
        haystack = f"{label or ''} {window}".lower()
        return any(keyword.lower() in haystack for keyword in MAP_CONTEXT_KEYWORDS)

    def map_key_provider(self, text, start, end, label=""):
        providers = (
            ("高德地图 key", ("amap", "gaode", "高德", "webapi.amap.com", "restapi.amap.com")),
            ("百度地图 key", ("baidu", "bmap", "百度", "api.map.baidu.com")),
            ("腾讯地图 key", ("tencent", "qqmap", "腾讯地图", "apis.map.qq.com")),
            ("Google Maps key", ("maps.googleapis.com", "google.maps", "google map", "googlemap")),
            ("Mapbox token", ("mapbox", "mapboxgl", "api.mapbox.com")),
            ("MapTiler key", ("maptiler", "api.maptiler.com")),
        )

        label_text = (label or "").lower()
        for provider, tokens in providers:
            if any(token in label_text for token in tokens):
                return provider

        value = text or ""
        before_start = max(0, start - 160)
        before_window = value[before_start:start].lower()
        best_before = None
        for provider, tokens in providers:
            for token in tokens:
                token = token.lower()
                index = before_window.find(token)
                while index != -1:
                    absolute_index = before_start + index
                    distance = start - absolute_index
                    if best_before is None or distance < best_before[0]:
                        best_before = (distance, provider)
                    index = before_window.find(token, index + 1)
        if best_before:
            return best_before[1]

        window_start = max(0, start - 160)
        window = value[window_start: min(len(value), end + 160)].lower()
        center = (start + end) // 2
        best = None
        for provider, tokens in providers:
            for token in tokens:
                token = token.lower()
                index = window.find(token)
                while index != -1:
                    absolute_index = window_start + index
                    distance = abs(absolute_index - center)
                    if best is None or distance < best[0]:
                        best = (distance, provider)
                    index = window.find(token, index + 1)

        if best:
            return best[1]
        return "地图服务 key"

    def env_key_is_sensitive(self, key):
        upper = (key or "").upper()
        return any(upper == prefix.rstrip("_") or upper.startswith(prefix) or prefix in upper for prefix in SENSITIVE_ENV_KEYS)
