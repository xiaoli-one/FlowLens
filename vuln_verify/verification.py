# 主动漏洞验证队列。
#
# 这个模块只在 run.py --verify 开启后工作。它把检测插件产出的 finding
# 交给 LLM agent 做下一步决策，再由本地受控 HTTP 执行器发包，最后写入
# logs/verifications.jsonl 并刷新 report.html 的“验证”标签页。

import hashlib
import json
import os
import queue
import re
import ssl
import string
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from pass_scan.llm_client import LLMClient
from pass_scan.reporter import verification_path_for, write_html_report, write_jsonl
from pass_scan.terminal import green, red, yellow
from vuln_verify.prompts import (
    build_initial_prompt,
    build_json_repair_prompt,
    build_observation_prompt,
    build_system_prompt,
)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ENV_FILE = os.path.join(PROJECT_ROOT, ".env")
DEFAULT_VERIFY_FILE = os.path.join("logs", "verifications.jsonl")
ALLOWED_VERIFICATION_STATUSES = {
    "confirmed",
    "likely",
    "false_positive",
    "needs_manual_review",
}
ALLOWED_CONFIDENCES = {"high", "medium", "low"}

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

DESTRUCTIVE_PATTERNS = (
    re.compile(r"\bdelete\s+from\b", re.I),
    re.compile(r"\bupdate\s+\S+\s+set\b", re.I),
    re.compile(r"\binsert\s+into\b", re.I),
    re.compile(r"\bdrop\s+(table|database|schema|index|user)\b", re.I),
    re.compile(r"\btruncate\s+table\b", re.I),
    re.compile(r"\balter\s+(table|database|schema|user)\b", re.I),
    re.compile(r"\bshutdown\b", re.I),
    re.compile(r"\breboot\b", re.I),
    re.compile(r"\brm\s+-[^\s]*r[^\s]*f\b", re.I),
    re.compile(r"\bmkfs(?:\.\w+)?\b", re.I),
    re.compile(r"\bdd\s+if=", re.I),
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*;", re.I),
)

def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def load_dotenv(path):
    values = {}
    if not path or not os.path.exists(path):
        return values

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
            if key:
                values[key] = os.environ.get(key, value)
    return values


def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def resolve_project_path(path):
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def finding_key(finding):
    """对漏洞位置和核心证据做稳定哈希，用于验证去重和报告关联。"""
    evidence = finding.get("evidence", {}) or {}
    payloads = {
        key: evidence.get(key)
        for key in (
            "payload",
            "true_payload",
            "false_payload",
            "control_payload",
            "delay_payload",
            "technique",
            "matched",
            "marker",
        )
        if evidence.get(key)
    }
    material = {
        "type": finding.get("type"),
        "method": finding.get("method"),
        "request_method": finding.get("request_method"),
        "url": finding.get("url"),
        "param_place": finding.get("param_place"),
        "param_name": finding.get("param_name"),
        "payloads": payloads,
    }
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def redact_headers(headers):
    redacted = {}
    for key, value in (headers or {}).items():
        if key.lower() in SENSITIVE_HEADERS:
            redacted[key] = "<redacted>"
        else:
            redacted[key] = value
    return redacted


def redact_packet(packet):
    if not packet:
        return ""

    lines = str(packet).splitlines()
    redacted = []
    in_headers = True
    for line in lines:
        if in_headers and not line.strip():
            in_headers = False
            redacted.append(line)
            continue
        if in_headers and ":" in line:
            name, value = line.split(":", 1)
            if name.strip().lower() in SENSITIVE_HEADERS:
                redacted.append(f"{name}: <redacted>")
                continue
        redacted.append(line)
    return "\n".join(redacted)


def trim_text(value, limit):
    value = "" if value is None else str(value)
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"


def get_header(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return ""


def set_header(headers, name, value):
    for key in list(headers or {}):
        if key.lower() == name.lower():
            headers[key] = value
            return
    headers[name] = value


def remove_header(headers, name):
    for key in list(headers or {}):
        if key.lower() == name.lower():
            headers.pop(key, None)


def safe_json_loads(text):
    if isinstance(text, dict):
        return text

    text = str(text or "").strip()
    if not text:
        raise ValueError("empty json")

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
        text = re.sub(r"```$", "", text).strip()

    candidates = [text]
    match = re.search(r"\{.*\}", text, re.S)
    if match and match.group(0) != text:
        candidates.append(match.group(0))

    last_error = None
    for candidate in candidates:
        for repaired in (candidate, escape_invalid_json_backslashes(candidate)):
            try:
                return json.loads(repaired)
            except json.JSONDecodeError as error:
                last_error = error

    if last_error:
        raise last_error
    raise ValueError("invalid json")


def escape_invalid_json_backslashes(text):
    """修复 LLM 常见的非法 JSON 反斜杠，例如 \\.、\\e、C:\\path。"""
    valid_escapes = {'"', "\\", "/", "b", "f", "n", "r", "t"}
    hex_digits = set(string.hexdigits)
    chars = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            chars.append(char)
            index += 1
            continue

        next_char = text[index + 1] if index + 1 < len(text) else ""
        if next_char in valid_escapes:
            chars.append(char)
            index += 1
            continue
        if next_char == "u":
            seq = text[index + 2:index + 6]
            if len(seq) == 4 and all(item in hex_digits for item in seq):
                chars.append(char)
            else:
                chars.append("\\\\")
            index += 1
            continue

        chars.append("\\\\")
        index += 1
    return "".join(chars)


class RawHttpRequest:
    def __init__(self, method, url, headers=None, body=""):
        self.method = (method or "GET").upper()
        self.url = url
        self.headers = headers or {}
        self.body = body or ""

    @classmethod
    def from_packet(cls, packet, fallback_url):
        packet = packet or ""
        parts = packet.split("\r\n\r\n", 1)
        if len(parts) == 1:
            parts = packet.split("\n\n", 1)
        head = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        lines = head.replace("\r\n", "\n").split("\n")
        request_line = lines[0] if lines else ""
        method = "GET"
        target = fallback_url
        pieces = request_line.split()
        if len(pieces) >= 2:
            method = pieces[0].upper()
            target = pieces[1]

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

        fallback_parts = urlsplit(fallback_url)
        host = headers.get("Host") or headers.get("host") or fallback_parts.netloc
        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            base = f"{fallback_parts.scheme or 'http'}://{host}"
            url = urljoin(base, target or fallback_parts.path or "/")

        return cls(method, url, headers, body)

    @classmethod
    def from_finding(cls, finding):
        proof = finding.get("proof", {}) or {}
        packet = proof.get("request") or ""
        fallback_url = finding.get("url") or ""
        if packet:
            return cls.from_packet(packet, fallback_url)
        request_method = finding.get("request_method") or "GET"
        return cls(request_method, fallback_url, {}, "")

    def copy(self):
        return RawHttpRequest(self.method, self.url, dict(self.headers), self.body)

    def as_packet(self, redacted=False):
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        lines = [f"{self.method} {path} HTTP/1.1"]
        headers = redact_headers(self.headers) if redacted else self.headers
        if not any(name.lower() == "host" for name in headers):
            lines.append(f"Host: {parts.netloc}")
        for name, value in headers.items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            lines.append(f"{name}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + (self.body or "")


class VerificationOOBClient:
    """验证阶段使用的 OOB 客户端，复用命令执行插件的 OOB 配置。"""

    def __init__(self, config):
        self.config = config or {}
        self.oob_config = dict(self.config.get("command_injection_oob") or {})
        self.enabled = truthy(self.oob_config.get("enabled", False))
        self.poll_interval = float(self.oob_config.get("poll_interval", 2))
        self.wait_seconds = float(
            self.config.get(
                "oob_wait_seconds",
                max(float(self.oob_config.get("poll_interval", 15)) + 5, 20),
            )
        )
        self.timeout = int(self.oob_config.get("timeout", 15))
        self.client = None
        self.lock = threading.Lock()

    def ensure_client(self):
        if not self.enabled:
            return None
        with self.lock:
            if self.client and self.client.registered:
                return self.client

            try:
                from tools.interactsh_client import DEFAULT_SERVERS, InteractshClient
            except Exception:
                self.enabled = False
                return None

            configured = self.oob_config.get("server")
            servers = [configured] if configured else list(DEFAULT_SERVERS)
            token = self.oob_config.get("token", "")
            for server in servers:
                client = InteractshClient(
                    server=server,
                    token=token,
                    timeout=self.timeout,
                )
                if client.register():
                    self.client = client
                    return self.client

            self.enabled = False
            return None

    def new_domain(self):
        client = self.ensure_client()
        if not client:
            return None, ""
        return client.new_domain()

    def poll_for_token(self, token):
        client = self.ensure_client()
        if not client or not token:
            return []

        deadline = time.time() + self.wait_seconds
        hits = []
        seen = set()
        while time.time() <= deadline:
            for interaction in client.poll():
                interaction_token = client.token_of(interaction)
                if interaction_token != token:
                    continue
                key = (
                    interaction.get("protocol", ""),
                    interaction.get("full-id")
                    or interaction.get("unique-id")
                    or interaction.get("uniqueId")
                    or "",
                    interaction.get("timestamp", ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                hits.append(interaction)
            if hits:
                return hits
            time.sleep(max(0.5, min(self.poll_interval, 3)))
        return hits


class NoRedirectHandler(HTTPRedirectHandler):
    """保留 3xx 响应本身，避免开放重定向证据被自动跳转吞掉。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpExecutor:
    def __init__(self, config):
        self.config = config or {}
        self.timeout = float(self.config.get("request_timeout_seconds", 12))
        self.max_body_bytes = int(self.config.get("max_response_body_bytes", 262144))
        self.observation_chars = int(self.config.get("observation_chars", 12000))
        self.allowed_methods = {
            method.upper()
            for method in self.config.get("allowed_methods", ["GET", "POST", "HEAD", "PUT"])
        }

        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler(),
        )
        self.oob = VerificationOOBClient(self.config)

    def execute_action(self, finding, action):
        action_type = str(action.get("type") or action.get("action") or "").strip()
        if action_type == "send_mutation":
            request_template = RawHttpRequest.from_finding(finding)
            request_template = self.apply_mutation(finding, request_template, action)
            return self.send(request_template, action)

        if action_type == "send_oob_mutation":
            return self.execute_oob_mutation(finding, action)

        if action_type == "send_request":
            url = self.normalize_action_url(action.get("url") or finding.get("url") or "", finding)
            request_template = RawHttpRequest(
                action.get("method") or "GET",
                url,
                self.action_headers(finding, action, url),
                action.get("body") or "",
            )
            return self.send(request_template, action)

        if action_type == "send_raw":
            request_template = RawHttpRequest.from_packet(
                action.get("raw_request") or "",
                finding.get("url") or "",
            )
            return self.send(request_template, action)

        return {
            "action_id": action.get("id") or "",
            "ok": False,
            "blocked": True,
            "error": f"unsupported action type: {action_type}",
            "purpose": action.get("purpose", ""),
            "chain_step": action.get("chain_step", ""),
            "bypass_strategy": action.get("bypass_strategy", ""),
            "payload": action.get("payload", ""),
        }

    def execute_oob_mutation(self, finding, action):
        token, domain = self.oob.new_domain()
        if not token or not domain:
            return {
                "action_id": action.get("id") or "",
                "ok": False,
                "blocked": True,
                "error": "OOB is not available; check command_injection.oob config or interactsh connectivity",
                "purpose": action.get("purpose", ""),
                "chain_step": action.get("chain_step", ""),
                "bypass_strategy": action.get("bypass_strategy", ""),
                "payload": action.get("payload") or action.get("value") or "",
            }

        rendered_action = self.render_oob_action(action, domain)
        if rendered_action.get("raw_request"):
            request_template = RawHttpRequest.from_packet(
                rendered_action.get("raw_request") or "",
                finding.get("url") or "",
            )
        elif rendered_action.get("url") and not (
            rendered_action.get("param_name") or rendered_action.get("param_place")
        ):
            url = self.normalize_action_url(rendered_action.get("url"), finding)
            request_template = RawHttpRequest(
                rendered_action.get("method") or "GET",
                url,
                self.action_headers(finding, rendered_action, url),
                rendered_action.get("body") or "",
            )
        else:
            request_template = RawHttpRequest.from_finding(finding)
            request_template = self.apply_mutation(finding, request_template, rendered_action)
        observation = self.send(request_template, rendered_action)
        observation["oob_domain"] = domain
        observation["oob_token"] = token
        interactions = self.oob.poll_for_token(token)
        observation["oob_hit"] = bool(interactions)
        observation["oob_interactions"] = interactions
        if interactions:
            observation["ok"] = True
            observation["response"] = self.oob_interaction_proof(interactions)
            observation["response_excerpt"] = self.oob_interaction_proof(interactions)
        return observation

    def render_oob_action(self, action, domain):
        rendered = dict(action)
        for key in ("value", "payload", "url", "body", "raw_request"):
            if key in rendered and rendered[key] is not None:
                rendered[key] = str(rendered[key]).replace("{domain}", domain)
        headers = rendered.get("headers")
        if isinstance(headers, dict):
            rendered["headers"] = {
                name: str(value).replace("{domain}", domain)
                for name, value in headers.items()
            }
        return rendered

    def normalize_action_url(self, url, finding):
        url = str(url or "")
        if url.startswith("http://") or url.startswith("https://"):
            return url
        base_url = finding.get("url") or ""
        return urljoin(base_url, url or base_url)

    def action_headers(self, finding, action, url):
        explicit_headers = dict(action.get("headers") or {})
        inherit = action.get("inherit_headers")
        if inherit is not None and not truthy(inherit):
            return explicit_headers

        original = RawHttpRequest.from_finding(finding)
        inherited = {}
        same_origin = self.same_origin(original.url, url)
        for name, value in original.headers.items():
            lower = name.lower()
            if lower in HOP_BY_HOP_HEADERS:
                continue
            if lower in SENSITIVE_HEADERS and not same_origin:
                continue
            inherited[name] = value

        for name, value in explicit_headers.items():
            set_header(inherited, name, value)
        return inherited

    def same_origin(self, left_url, right_url):
        left = urlsplit(left_url or "")
        right = urlsplit(right_url or "")
        return bool(
            left.scheme
            and right.scheme
            and left.scheme.lower() == right.scheme.lower()
            and left.netloc.lower() == right.netloc.lower()
        )

    def oob_interaction_proof(self, interactions):
        lines = ["[OOB interactions]"]
        for index, interaction in enumerate(interactions, start=1):
            lines.append(f"#{index}")
            for key in (
                "protocol",
                "full-id",
                "unique-id",
                "remote-address",
                "remoteAddress",
                "timestamp",
            ):
                value = interaction.get(key)
                if value:
                    lines.append(f"{key}: {value}")
            raw = interaction.get("raw-request") or interaction.get("rawRequest")
            if raw:
                lines.append("raw-request:")
                lines.append(str(raw))
        return "\n".join(lines)

    def apply_mutation(self, finding, template, action):
        request_template = template.copy()
        place = action.get("param_place") or finding.get("param_place") or "query"
        name = action.get("param_name") or finding.get("param_name") or ""
        value = str(action.get("value") if action.get("value") is not None else action.get("payload") or "")

        if place == "query":
            request_template.url = self.replace_query_param(request_template.url, name, value)
            return request_template

        if place == "form":
            body = request_template.body or ""
            pairs = parse_qsl(body, keep_blank_values=True)
            request_template.body = urlencode(self.replace_pairs(pairs, name, value), doseq=True)
            request_template.method = "POST"
            request_template.headers["Content-Type"] = "application/x-www-form-urlencoded"
            return request_template

        if place == "cookie":
            cookie = request_template.headers.get("Cookie") or request_template.headers.get("cookie") or ""
            request_template.headers["Cookie"] = self.replace_cookie(cookie, name, value)
            return request_template

        if place == "header":
            request_template.headers[name] = value
            return request_template

        if place == "json":
            try:
                data = json.loads(request_template.body or "{}")
                if isinstance(data, dict):
                    data[name] = value
                    request_template.body = json.dumps(data, ensure_ascii=False)
                    request_template.method = "POST"
                    request_template.headers["Content-Type"] = "application/json"
                    return request_template
            except json.JSONDecodeError:
                pass

        if place == "multipart":
            if self.apply_multipart_mutation(request_template, action, name, value):
                return request_template

        if place == "body":
            request_template.body = value
            if action.get("content_type"):
                set_header(request_template.headers, "Content-Type", action.get("content_type"))
            if request_template.method == "GET":
                request_template.method = "POST"
            return request_template

        request_template.url = self.replace_query_param(request_template.url, name, value)
        return request_template

    def apply_multipart_mutation(self, request_template, action, name, value):
        content_type = get_header(request_template.headers, "Content-Type")
        if "multipart/" not in (content_type or "").lower():
            return False

        parts = self.parse_multipart_parts(request_template.body or "", content_type)
        if not parts:
            return False

        target_index = action.get("part_index")
        if target_index is not None:
            try:
                target_index = int(target_index)
            except (TypeError, ValueError):
                target_index = None

        matched = False
        boundary = f"----passscanverify{uuid.uuid4().hex}"
        chunks = []
        for part in parts:
            replace_part = (
                target_index is not None
                and part.get("index") == target_index
            ) or (
                target_index is None
                and name
                and part.get("name") == name
            )
            if replace_part:
                matched = True
            chunks.append(f"--{boundary}\r\n")
            headers, body = self.multipart_replacement(part, action, name, value) if replace_part else (
                part.get("headers") or [],
                part.get("body") or "",
            )
            for header_name, header_value in headers:
                if header_name.lower() == "content-length":
                    continue
                chunks.append(f"{header_name}: {header_value}\r\n")
            chunks.append("\r\n")
            chunks.append(body)
            chunks.append("\r\n")

        if not matched and name:
            chunks.append(f"--{boundary}\r\n")
            filename = action.get("filename")
            content_type_value = action.get("content_type") or "text/plain"
            if filename:
                disposition = (
                    f'form-data; name="{self.quote_header_value(name)}"; '
                    f'filename="{self.quote_header_value(filename)}"'
                )
            else:
                disposition = f'form-data; name="{self.quote_header_value(name)}"'
            chunks.append(f"Content-Disposition: {disposition}\r\n")
            if filename:
                chunks.append(f"Content-Type: {content_type_value}\r\n")
            chunks.append("\r\n")
            chunks.append(value)
            chunks.append("\r\n")
            matched = True

        chunks.append(f"--{boundary}--\r\n")
        request_template.body = "".join(chunks)
        set_header(request_template.headers, "Content-Type", f"multipart/form-data; boundary={boundary}")
        remove_header(request_template.headers, "Content-Length")
        request_template.method = "POST"
        return matched

    def parse_multipart_parts(self, body, content_type):
        message_bytes = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
            + str(body or "").encode("utf-8", errors="replace")
        )
        try:
            message = BytesParser(policy=policy.default).parsebytes(message_bytes)
        except Exception:
            return []

        if not message.is_multipart():
            return []

        parts = []
        for index, part in enumerate(message.iter_parts()):
            disposition = part.get("Content-Disposition", "")
            params = dict(part.get_params(header="content-disposition") or [])
            payload = part.get_payload(decode=True)
            if payload is None:
                payload_text = part.get_content()
            else:
                charset = part.get_content_charset() or "utf-8"
                payload_text = payload.decode(charset, errors="replace")
            parts.append({
                "index": index,
                "name": params.get("name", ""),
                "filename": params.get("filename", ""),
                "content_disposition": disposition,
                "content_type": part.get_content_type() or "",
                "headers": [(header_name, header_value) for header_name, header_value in part.items()],
                "body": payload_text,
            })
        return parts

    def multipart_replacement(self, part, action, name, value):
        part_name = name or part.get("name") or "file"
        filename = action.get("filename")
        content_type = action.get("content_type") or part.get("content_type") or "text/plain"
        body = action.get("body")
        if body is None:
            body = value

        if filename is None and part.get("filename"):
            filename = part.get("filename")

        if filename:
            disposition = (
                f'form-data; name="{self.quote_header_value(part_name)}"; '
                f'filename="{self.quote_header_value(filename)}"'
            )
            headers = [
                ("Content-Disposition", disposition),
                ("Content-Type", content_type),
            ]
        else:
            headers = [
                ("Content-Disposition", f'form-data; name="{self.quote_header_value(part_name)}"'),
            ]
            if action.get("content_type"):
                headers.append(("Content-Type", content_type))
        return headers, str(body or "")

    def quote_header_value(self, value):
        return str(value or "").replace("\\", "\\\\").replace('"', '\\"')

    def replace_query_param(self, url, name, value):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = urlencode(self.replace_pairs(pairs, name, value), doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment))

    def replace_pairs(self, pairs, name, value):
        replaced = False
        new_pairs = []
        for key, old_value in pairs:
            if key == name:
                new_pairs.append((key, value))
                replaced = True
            else:
                new_pairs.append((key, old_value))
        if not replaced and name:
            new_pairs.append((name, value))
        return new_pairs

    def replace_cookie(self, cookie, name, value):
        items = []
        replaced = False
        for item in cookie.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                key, old_value = item.split("=", 1)
            else:
                key, old_value = item, ""
            if key.strip() == name:
                items.append(f"{key.strip()}={value}")
                replaced = True
            else:
                items.append(f"{key.strip()}={old_value}")
        if not replaced and name:
            items.append(f"{name}={value}")
        return "; ".join(items)

    def send(self, request_template, action):
        action_id = action.get("id") or action.get("name") or ""
        safety_error = self.safety_error(request_template, action)
        if safety_error:
            return {
                "action_id": action_id,
                "ok": False,
                "blocked": True,
                "error": safety_error,
                "purpose": action.get("purpose", ""),
                "chain_step": action.get("chain_step", ""),
                "bypass_strategy": action.get("bypass_strategy", ""),
                "payload": action.get("payload") or action.get("value") or "",
                "request": request_template.as_packet(redacted=True),
            }

        headers = {
            name: value
            for name, value in request_template.headers.items()
            if name.lower() not in HOP_BY_HOP_HEADERS
        }
        headers.setdefault("Accept-Encoding", "identity")
        data = None
        if request_template.method not in ("GET", "HEAD") and request_template.body:
            data = request_template.body.encode("utf-8", errors="replace")

        started = time.time()
        status_code = 0
        reason = ""
        response_headers = {}
        body = b""
        error = ""

        try:
            urllib_request = Request(
                request_template.url,
                data=data,
                headers=headers,
                method=request_template.method,
            )
            response = self.opener.open(urllib_request, timeout=self.timeout)
            status_code = response.getcode() or 0
            reason = getattr(response, "reason", "") or ""
            response_headers = dict(response.headers.items())
            body = response.read(self.max_body_bytes)
        except HTTPError as exc:
            status_code = exc.code
            reason = getattr(exc, "reason", "") or ""
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                body = exc.read(self.max_body_bytes)
            except Exception:
                body = b""
        except (URLError, TimeoutError, OSError) as exc:
            error = str(exc)

        elapsed_ms = int((time.time() - started) * 1000)
        text = body.decode(self.detect_charset(response_headers), errors="replace")
        response_packet = self.build_response_packet(status_code, reason, response_headers, text)
        return {
            "action_id": action_id,
            "ok": not error,
            "blocked": False,
            "error": error,
            "purpose": action.get("purpose", ""),
            "chain_step": action.get("chain_step", ""),
            "bypass_strategy": action.get("bypass_strategy", ""),
            "payload": action.get("payload") or action.get("value") or "",
            "method": request_template.method,
            "url": request_template.url,
            "status_code": status_code,
            "elapsed_ms": elapsed_ms,
            "request": request_template.as_packet(redacted=True),
            "response": trim_text(response_packet, self.observation_chars),
            "response_excerpt": trim_text(text, self.observation_chars),
        }

    def safety_error(self, request_template, action):
        if request_template.method not in self.allowed_methods:
            return f"HTTP method not allowed for verification: {request_template.method}"

        if request_template.method == "PUT" and not self.is_canary_write(request_template, action):
            return "PUT is only allowed for canary verification objects/files"

        checks = [
            str(action.get("payload") or ""),
            str(action.get("value") or ""),
            str(action.get("raw_request") or ""),
            str(request_template.url or ""),
            "\n".join(f"{name}: {value}" for name, value in request_template.headers.items()),
            request_template.body or "",
        ]
        text = "\n".join(checks)
        for pattern in DESTRUCTIVE_PATTERNS:
            if pattern.search(text):
                return f"blocked destructive pattern: {pattern.pattern}"
        return ""

    def is_canary_write(self, request_template, action):
        marker_text = "\n".join(
            str(value or "")
            for value in (
                request_template.url,
                request_template.body,
                action.get("payload"),
                action.get("value"),
                action.get("filename"),
                action.get("canary_marker"),
            )
        ).lower()
        has_canary_name = any(
            marker in marker_text
            for marker in ("pass-scan", "passscan", "canary", "verify")
        )
        return truthy(action.get("canary")) and has_canary_name

    def detect_charset(self, headers):
        content_type = ""
        for key, value in (headers or {}).items():
            if key.lower() == "content-type":
                content_type = value
                break
        match = re.search(r"charset=([\w.-]+)", content_type, re.I)
        return match.group(1) if match else "utf-8"

    def build_response_packet(self, status_code, reason, headers, body_text):
        status = status_code or 0
        reason = reason or ""
        lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
        for name, value in (headers or {}).items():
            if name.lower() in SENSITIVE_HEADERS:
                value = "<redacted>"
            lines.append(f"{name}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + (body_text or "")


class LLMVerificationAgent:
    def __init__(self, config):
        self.config = config or {}
        self.env_file = resolve_project_path(self.config.get("env_file", DEFAULT_ENV_FILE))
        self.llm = LLMClient(self.config)
        self.model = self.llm.model
        self.protocol = self.llm.protocol
        self.max_rounds = int(self.config.get("max_rounds", 10))
        self.max_requests = int(self.config.get("max_requests_per_finding", 80))
        self.prompt_chars = int(self.config.get("prompt_chars", 50000))
        self.executor = HttpExecutor(self.config)

    @property
    def ready(self):
        return self.llm.ready

    def verify(self, finding):
        key = finding_key(finding)
        observations = []
        messages = [
            {"role": "system", "content": self.system_prompt()},
            {"role": "user", "content": self.initial_prompt(finding)},
        ]
        requests_sent = 0
        final = None

        for round_index in range(1, self.max_rounds + 1):
            content = self.chat(messages)
            decision = self.parse_decision(content, messages)
            actions = decision.get("actions") or []
            if decision.get("final"):
                final = decision.get("final") or {}
                break

            if not actions:
                final = {
                    "status": "needs_manual_review",
                    "confidence": "low",
                    "exploitability": "not_reached",
                    "summary": "Agent did not request more actions and did not provide a final conclusion.",
                    "exploit_chain": [],
                    "payloads": [],
                }
                break

            round_observations = []
            for action in actions:
                if requests_sent >= self.max_requests:
                    round_observations.append({
                        "action_id": action.get("id") or "",
                        "ok": False,
                        "blocked": True,
                        "error": "max_requests_per_finding reached",
                    })
                    continue
                observation = self.executor.execute_action(finding, action)
                requests_sent += 0 if observation.get("blocked") else 1
                observations.append(observation)
                round_observations.append(observation)

            messages.append({
                "role": "assistant",
                "content": json.dumps(decision, ensure_ascii=False),
            })
            messages.append({
                "role": "user",
                "content": build_observation_prompt(
                    json.dumps(
                        self.compact_observations(round_observations),
                        ensure_ascii=False,
                        indent=2,
                    )
                ),
            })

        if final is None:
            final = {
                "status": "needs_manual_review",
                "confidence": "medium" if observations else "low",
                "exploitability": "partial",
                "summary": "达到最大验证轮次，已保留当前主动发包证据。",
                "exploit_chain": [],
                "payloads": [],
            }

        return self.build_result(key, finding, final, observations, requests_sent)

    def system_prompt(self):
        return build_system_prompt()

    def initial_prompt(self, finding):
        vuln_type = finding.get("type") or finding.get("method") or "unknown"
        method = finding.get("method") or ""
        safe_finding = self.sanitize_finding_for_prompt(finding)
        return trim_text(
            build_initial_prompt(
                vuln_type,
                method,
                json.dumps(safe_finding, ensure_ascii=False, indent=2),
            ),
            self.prompt_chars,
        )

    def sanitize_finding_for_prompt(self, finding):
        safe_finding = json.loads(json.dumps(finding, ensure_ascii=False))
        proof = safe_finding.get("proof") or {}
        if proof.get("request"):
            proof["request"] = redact_packet(trim_text(proof.get("request"), 20000))
        if proof.get("response"):
            proof["response"] = trim_text(proof.get("response"), 25000)
        for proof_item in safe_finding.get("extra_proofs") or []:
            if proof_item.get("request"):
                proof_item["request"] = redact_packet(trim_text(proof_item.get("request"), 12000))
            if proof_item.get("response"):
                proof_item["response"] = trim_text(proof_item.get("response"), 16000)
        return safe_finding

    def chat(self, messages):
        return self.llm.chat(messages)

    def parse_decision(self, content, messages):
        try:
            return safe_json_loads(content)
        except Exception as first_error:
            repair_messages = list(messages)
            repair_messages.append({
                "role": "assistant",
                "content": trim_text(content, 12000),
            })
            repair_messages.append({
                "role": "user",
                "content": build_json_repair_prompt(str(first_error)),
            })
            repaired_content = self.chat(repair_messages)
            try:
                return safe_json_loads(repaired_content)
            except Exception as second_error:
                raise ValueError(
                    "LLM output is not valid JSON after repair retry: "
                    f"{second_error}; first error: {first_error}; "
                    f"raw: {trim_text(content, 1200)}"
                ) from second_error

    def compact_observations(self, observations):
        compact = []
        for item in observations:
            compact.append({
                "action_id": item.get("action_id"),
                "ok": item.get("ok"),
                "blocked": item.get("blocked"),
                "error": item.get("error"),
                "purpose": item.get("purpose"),
                "chain_step": item.get("chain_step"),
                "bypass_strategy": item.get("bypass_strategy"),
                "payload": item.get("payload"),
                "method": item.get("method"),
                "url": item.get("url"),
                "status_code": item.get("status_code"),
                "elapsed_ms": item.get("elapsed_ms"),
                "oob_hit": item.get("oob_hit"),
                "oob_domain": item.get("oob_domain"),
                "oob_interactions": item.get("oob_interactions"),
                "response_excerpt": trim_text(item.get("response_excerpt"), 8000),
            })
        return compact

    def build_result(self, key, finding, final, observations, requests_sent):
        source = {
            "type": finding.get("type"),
            "method": finding.get("method"),
            "request_method": finding.get("request_method"),
            "url": finding.get("url"),
            "param_place": finding.get("param_place"),
            "param_name": finding.get("param_name"),
            "time": finding.get("time"),
        }
        successful_request_ids = self.normalize_string_list(final.get("successful_request_ids"))
        successful_requests = self.select_successful_requests(
            observations,
            successful_request_ids,
        )
        status = str(final.get("status") or "needs_manual_review").strip().lower()
        confidence = str(final.get("confidence") or "medium").strip().lower()
        validation_warnings = []
        if status not in ALLOWED_VERIFICATION_STATUSES:
            validation_warnings.append(f"未知验证状态: {status}")
            status = "needs_manual_review"
        if confidence not in ALLOWED_CONFIDENCES:
            validation_warnings.append(f"未知置信度: {confidence}")
            confidence = "medium"
        validation_warnings = self.validation_warnings(
            status,
            successful_request_ids,
            successful_requests,
        ) + validation_warnings
        summary = final.get("summary") or ""
        if validation_warnings:
            if status in ("confirmed", "likely"):
                status = "needs_manual_review"
                confidence = "low"
            summary = self.append_validation_summary(summary, validation_warnings)

        return {
            "time": now_text(),
            "finding_key": key,
            "source": source,
            "status": status,
            "confidence": confidence,
            "exploitability": final.get("exploitability") or "partial",
            "depth": final.get("depth") or "",
            "endpoint": final.get("endpoint") or "",
            "summary": summary,
            "impact": final.get("impact") or "",
            "safety_notes": final.get("safety_notes") or "",
            "exploit_chain": final.get("exploit_chain") or [],
            "payloads": final.get("payloads") or [],
            "successful_request_ids": successful_request_ids,
            "successful_requests": successful_requests,
            "validation_warnings": validation_warnings,
            "reproduction": final.get("reproduction") or [],
            "requests": observations,
            "request_count": requests_sent,
            "model": self.model,
        }

    def validation_warnings(self, status, successful_request_ids, successful_requests):
        if status not in ("confirmed", "likely"):
            return []

        warnings = []
        if not successful_request_ids:
            warnings.append("confirmed/likely 结果缺少 successful_request_ids")
        elif len(successful_requests) != len(successful_request_ids):
            found_ids = {item.get("action_id") for item in successful_requests}
            missing = [
                action_id
                for action_id in successful_request_ids
                if action_id not in found_ids
            ]
            if missing:
                warnings.append(
                    "successful_request_ids 中存在未执行或未记录的 action id: "
                    + ", ".join(missing)
                )
        return warnings

    def append_validation_summary(self, summary, warnings):
        suffix = "结果已降级为需人工复核：" + "；".join(warnings)
        if not summary:
            return suffix
        return f"{summary} {suffix}"

    def normalize_string_list(self, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value if item is not None and str(item)]
        return [str(value)]

    def select_successful_requests(self, observations, successful_request_ids):
        if not successful_request_ids:
            return []
        by_id = {item.get("action_id"): item for item in observations if item.get("action_id")}
        selected = []
        for action_id in successful_request_ids:
            item = by_id.get(action_id)
            if item:
                selected.append(item)
        return selected


class VerificationQueue:
    def __init__(self, config, vuln_file, report_file, fingerprint_file=None):
        root_config = config or {}
        self.config = dict(root_config.get("verification", {}))
        plugin_config = root_config.get("plugins", {})
        command_injection_config = plugin_config.get("command_injection", {})
        self.config["command_injection_oob"] = command_injection_config.get("oob", {})
        self.enabled = truthy(self.config.get("enabled", False)) or truthy(os.environ.get("PASS_SCAN_VERIFY"))
        self.vuln_file = vuln_file
        self.report_file = report_file
        self.fingerprint_file = fingerprint_file
        self.output_file = (
            os.environ.get("PASS_SCAN_VERIFY_FILE")
            or self.config.get("output_file")
            or verification_path_for(vuln_file)
        )
        self.queue_size = int(self.config.get("queue_size", 100))
        self.worker_count = max(1, int(self.config.get("worker_count", 2)))
        self.tasks = queue.Queue(maxsize=max(1, self.queue_size))
        self.seen = set()
        self.lock = threading.Lock()
        self.agent = LLMVerificationAgent(self.config)

        if not self.enabled:
            return

        if not self.agent.ready:
            self.enabled = False
            print(
                yellow(
                    "[验证] 已请求启用漏洞验证，但 LLM 配置不完整，"
                    "跳过验证 agent"
                ),
                flush=True,
            )
            return

        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        for index in range(self.worker_count):
            worker = threading.Thread(
                target=self.worker_loop,
                name=f"pass-scan-verifier-{index + 1}",
                daemon=True,
            )
            worker.start()

        print(
            green(
                f"[验证] 主动验证 agent 已启用 | worker: {self.worker_count} | "
                f"结果: {self.output_file}"
            ),
            flush=True,
        )

    def enqueue(self, plugin_name, finding):
        if not self.enabled or not finding:
            return False
        if (
            plugin_name == "fingerprint"
            or finding.get("type") == "fingerprint"
            or finding.get("method") == "fingerprint"
        ):
            return False

        key = finding_key(finding)
        with self.lock:
            if key in self.seen:
                return False
            self.seen.add(key)

        try:
            self.tasks.put_nowait({
                "plugin_name": plugin_name,
                "finding": finding,
                "finding_key": key,
            })
            print(
                yellow(
                    f"[验证] 已入队: {plugin_name} | "
                    f"{finding.get('param_place', '')}.{finding.get('param_name', '')} | "
                    f"{finding.get('url', '')}"
                ),
                flush=True,
            )
            return True
        except queue.Full:
            print(yellow(f"[验证] 队列已满，丢弃验证任务: {finding.get('url', '')}"), flush=True)
            return False

    def worker_loop(self):
        while True:
            task = self.tasks.get()
            try:
                finding = task["finding"]
                result = self.agent.verify(finding)
                write_jsonl(self.output_file, result)
                if self.report_file:
                    write_html_report(
                        self.vuln_file,
                        self.report_file,
                        self.fingerprint_file,
                        self.output_file,
                    )
                self.print_result(result)
            except Exception as error:
                finding = task.get("finding", {})
                result = {
                    "time": now_text(),
                    "finding_key": task.get("finding_key", ""),
                    "source": {
                        "type": finding.get("type"),
                        "method": finding.get("method"),
                        "request_method": finding.get("request_method"),
                        "url": finding.get("url"),
                        "param_place": finding.get("param_place"),
                        "param_name": finding.get("param_name"),
                        "time": finding.get("time"),
                    },
                    "status": "error",
                    "confidence": "low",
                    "exploitability": "none",
                    "summary": str(error),
                    "exploit_chain": [],
                    "payloads": [],
                    "successful_request_ids": [],
                    "successful_requests": [],
                    "requests": [],
                    "model": self.agent.model,
                }
                write_jsonl(self.output_file, result)
                print(red(f"[验证] 任务异常: {error}"), flush=True)
            finally:
                self.tasks.task_done()

    def print_result(self, result):
        source = result.get("source", {}) or {}
        print(
            green(
                f"[验证] {result.get('status')} | {source.get('type')} | "
                f"{result.get('exploitability')} | {source.get('url')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
