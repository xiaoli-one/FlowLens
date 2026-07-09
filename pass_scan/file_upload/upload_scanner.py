# File upload vulnerability scanner.
#
# Detection strategy:
# - Only upload-looking traffic is queued.
# - A harmless canary upload discovers where files land.
# - Dangerous extensions, active content, bypass filenames, and .htaccess are
#   tested with per-request markers.
# - A finding is written only when the upload response or follow-up access gives
#   concrete evidence for the uploaded file.

import base64
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, quote_plus, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from pass_scan.body_paser import decode_body_text, get_header, get_media_type, get_part_body
from pass_scan.file_upload.rules import (
    active_content_extensions,
    binary_media_prefixes,
    binary_media_types,
    common_upload_dirs,
    failure_keywords,
    script_bypass_filenames,
    script_extensions,
    success_keywords,
    upload_name_keywords,
    upload_path_keywords,
    url_json_keys,
)
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context, replace_json_body_parameter
from pass_scan.terminal import red


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 10
VERIFY_TIMEOUT = 3
MAX_RESPONSE_BYTES = 262144
MAX_PROOF_CHARS = 24000
MAX_BODY_PREVIEW_BYTES = 12000

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

UPLOAD_METHODS = {"POST", "PUT", "PATCH"}
TEXTISH_MEDIA_TYPES = {
    "application/json",
    "application/problem+json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "application/javascript",
    "text/html",
    "text/plain",
}

URL_RE = re.compile(
    r"""
    (?P<url>
      (?:(?:https?:)?//)
      [A-Za-z0-9._~!$&'()*+,;=:%-]+
      (?:/[^\s"'<>\\]*)?
    )
    """,
    re.I | re.X,
)

PATH_RE = re.compile(
    r"""(?P<path>/[A-Za-z0-9._~%!$&'()*+,;=:@/?#-]+)""",
    re.I,
)

NAME_SPLIT_RE = re.compile(r"[^a-z0-9]+")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")
URL_UNSAFE_RE = re.compile(r"[\x00-\x20\x7f]")


@dataclass
class UploadPayload:
    name: str
    kind: str
    filename: str
    content_type: str
    body: bytes
    marker: str
    expected: str
    technique: str
    payload_group: str
    polyglot_marker: str = ""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FileUploadScanner:
    """File upload scanner with its own ScanQueue queue."""

    name = "file_upload"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        self.deep_tamper = bool(self.config.get("deep_tamper", True))
        self.max_original_body_bytes = int(
            self.config.get("max_original_body_bytes", 5 * 1024 * 1024)
        )
        self.max_payloads_per_candidate = int(
            self.config.get("max_payloads_per_candidate", 30)
        )
        self.max_verify_urls = int(self.config.get("max_verify_urls", 24))
        self.upload_timeout = float(self.config.get("upload_timeout_seconds", TIMEOUT))
        self.verify_timeout = float(self.config.get("verify_timeout_seconds", VERIFY_TIMEOUT))
        self.allow_external_verification = bool(
            self.config.get("allow_external_verification", True)
        )
        self.cleanup_uploaded_files = bool(
            self.config.get("cleanup_uploaded_files", True)
        )
        self.pending = []
        self.scanned = set()
        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
        )

        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    # ------------------------------------------------------------------
    # Queue interface
    # ------------------------------------------------------------------

    def interested(self, context):
        if context.method not in UPLOAD_METHODS:
            return False
        if context.skip_reason in ("method_not_useful", "static_resource"):
            return False
        return bool(self.extract_candidates(context))

    def dedup_key(self, context):
        shape = tuple(
            (
                candidate["place"],
                candidate["name"],
                candidate.get("index", ""),
            )
            for candidate in self.extract_candidates(context)
        )
        return (
            self.name,
            context.method,
            context.scheme,
            context.host,
            self.normalize_path_for_dedup(context.path),
            self.dedup_content_type(context.request_content_type),
            shape,
        )

    def observe(self, context):
        """Find delayed upload evidence in later browsing traffic."""
        if not self.pending:
            return []

        response = getattr(context.flow, "response", None)
        if not response:
            return []

        body = response.content or b""
        if not body:
            return []

        text, _charset = decode_body_text(body, response.headers)
        with self.lock:
            pending = list(self.pending)

        for item in pending:
            if item["marker"] not in text and item["filename"] not in text:
                continue

            finding = self.build_finding(
                item["flow"],
                item["candidate"],
                {
                    "technique": "延迟上传结果发现",
                    "message": "uploaded marker or filename appeared in a later response",
                    "filename": item["filename"],
                    "marker": item["marker"],
                    "trigger_url": context.url,
                    "confidence": "medium",
                },
                proof_probe=self.passive_proof(context.flow),
            )
            self.write_finding(finding)
            print_finding_once(self, finding)

            with self.lock:
                self.pending = [p for p in self.pending if p is not item]

        return []

    def check(self, context, flow=None):
        if flow is not None:
            context = build_scan_context(
                context,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        if not self.interested(context):
            return []

        findings = []
        for candidate in self.extract_candidates(context):
            scan_key = self.make_scan_key(context.flow, candidate)
            with self.lock:
                if scan_key in self.scanned:
                    continue
                self.scanned.add(scan_key)

            for finding in self.check_candidate(context.flow, candidate):
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # Candidate extraction
    # ------------------------------------------------------------------

    def extract_candidates(self, context):
        request = context.flow.request
        body = request.content or b""
        if len(body) > self.max_original_body_bytes:
            return []

        content_type = get_header(request.headers, "content-type")
        media_type = get_media_type(content_type)

        if media_type.startswith("multipart/"):
            return self.extract_multipart_candidates(context, body, content_type)

        if self.raw_body_worth_scanning(context, media_type, body):
            return [
                {
                    "place": "body",
                    "name": "$body",
                    "index": 0,
                    "filename": self.filename_from_path(context.path) or "body.bin",
                    "content_type": content_type,
                }
            ]

        return self.extract_encoded_body_candidates(context)

    def extract_multipart_candidates(self, context, body, content_type):
        parts = self.parse_multipart_parts(body, content_type)
        file_parts = [part for part in parts if part.get("filename")]
        if file_parts:
            parts = file_parts

        candidates = []
        for part in parts:
            if not self.part_worth_scanning(context, part):
                continue
            candidates.append(
                {
                    "place": "multipart",
                    "name": part.get("name") or f"part_{part['index']}",
                    "index": part["index"],
                    "filename": part.get("filename", ""),
                    "content_type": part.get("content_type", ""),
                }
            )
        return candidates[:4]

    def parse_multipart_parts(self, body, content_type):
        message_bytes = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
            + body
        )
        try:
            message = BytesParser(policy=policy.default).parsebytes(message_bytes)
        except Exception:
            return []

        if not message.is_multipart():
            return []

        parts = []
        for index, part in enumerate(message.iter_parts()):
            headers = [(name, value) for name, value in part.items()]
            body = get_part_body(part)
            parts.append(
                {
                    "index": index,
                    "headers": headers,
                    "name": part.get_param("name", header="content-disposition") or "",
                    "filename": part.get_filename() or "",
                    "content_type": part.get_content_type() or "",
                    "body": body,
                }
            )
        return parts

    def part_worth_scanning(self, context, part):
        if part.get("filename"):
            return True
        name = part.get("name", "")
        content_type = part.get("content_type", "")
        if self.name_looks_upload_related(name):
            return True
        if self.media_type_looks_file(get_media_type(content_type)):
            return True
        return self.path_looks_upload_related(context.path) and len(part.get("body") or b"") > 0

    def raw_body_worth_scanning(self, context, media_type, body):
        if not body or context.method not in ("PUT", "PATCH", "POST"):
            return False
        if self.media_type_looks_file(media_type):
            return True
        if context.method in ("PUT", "PATCH") and self.path_looks_upload_related(context.path):
            return True
        return False

    def extract_encoded_body_candidates(self, context):
        media_type = get_media_type(context.request_content_type)
        if media_type not in TEXTISH_MEDIA_TYPES and not media_type.endswith("+json"):
            return []

        candidates = []
        for parameter in context.parameters:
            if parameter.get("place") not in ("form", "json"):
                continue
            if self.encoded_param_worth_scanning(context, parameter):
                candidate = dict(parameter)
                candidate["filename"] = f"{self.safe_stem('psup')}.txt"
                candidates.append(candidate)
        return candidates[:4]

    def encoded_param_worth_scanning(self, context, parameter):
        name = parameter.get("name", "")
        value = str(parameter.get("value", ""))
        if self.name_looks_upload_related(name) and self.value_looks_file_payload(value):
            return True
        if self.path_looks_upload_related(context.path) and self.value_looks_file_payload(value):
            return True
        return False

    def value_looks_file_payload(self, value):
        value = (value or "").strip()
        if value.startswith("data:") and ";base64," in value[:120].lower():
            return True
        if len(value) < 32 or len(value) > 200000:
            return False
        if not BASE64_RE.match(value):
            return False
        normalized = value.replace("-", "+").replace("_", "/")
        normalized += "=" * (-len(normalized) % 4)
        try:
            decoded = base64.b64decode(normalized, validate=False)
        except Exception:
            return False
        return len(decoded) >= 16

    def media_type_looks_file(self, media_type):
        media_type = (media_type or "").lower()
        return (
            media_type in binary_media_types()
            or media_type.startswith(binary_media_prefixes())
            or media_type.startswith("application/")
            and media_type not in TEXTISH_MEDIA_TYPES
        )

    def name_looks_upload_related(self, name):
        lowered = (name or "").lower()
        if not lowered:
            return False
        tokens = [token for token in NAME_SPLIT_RE.split(lowered) if token]
        keywords = {keyword.lower() for keyword in upload_name_keywords()}
        return any(token in keywords for token in tokens) or any(
            keyword in lowered for keyword in keywords
        )

    def path_looks_upload_related(self, path):
        lowered = (path or "/").lower()
        return any(keyword.lower() in lowered for keyword in upload_path_keywords())

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def check_candidate(self, flow, candidate):
        findings = []
        marker = self.next_marker()
        canary = self.text_canary_payload(marker)
        baseline_probe = self.send_upload(flow, candidate, canary)
        if not baseline_probe:
            return []

        baseline_urls = self.urls_for_probe(flow, baseline_probe, canary, [])
        baseline_accesses = self.verify_payload_urls(flow, baseline_urls, canary)
        verified_dirs = self.base_dirs_from_accesses(baseline_accesses, canary.marker)

        if not self.baseline_confirmed(baseline_probe, baseline_accesses, canary):
            self.remember_pending(flow, candidate, canary)

        reported_kinds = set()
        for payload in self.test_payloads(marker):
            if len(reported_kinds) >= 4:
                break
            if payload.kind in reported_kinds and payload.kind != "script":
                continue

            probe = self.send_upload(flow, candidate, payload)
            if not probe:
                continue

            urls = self.urls_for_probe(flow, probe, payload, verified_dirs)
            accesses = self.verify_payload_urls(flow, urls, payload)
            finding = self.match_payload(flow, candidate, payload, probe, accesses)
            self.cleanup_urls(flow, accesses, self.cleanup_marker_for(payload))

            if not finding:
                self.remember_pending(flow, candidate, payload)
                continue

            technique = finding["evidence"].get("technique")
            if technique == "危险扩展文件可上传":
                if "dangerous_stored" in reported_kinds:
                    continue
                reported_kinds.add("dangerous_stored")

            findings.append(finding)
            if payload.kind != "script":
                reported_kinds.add(payload.kind)
            if technique in ("脚本文件执行", "中间件解析执行"):
                reported_kinds.add("script")
                reported_kinds.add("dangerous_stored")

        finding = self.check_active_htaccess_chain(flow, candidate, verified_dirs)
        if finding:
            findings.append(finding)

        self.cleanup_urls(flow, baseline_accesses, canary.marker)
        return findings

    def baseline_confirmed(self, probe, accesses, payload):
        if any(self.access_contains_marker(access, payload.marker) for access in accesses):
            return True
        return self.response_accepts_upload(probe, payload)

    def match_payload(self, flow, candidate, payload, upload_probe, access_probes):
        if payload.kind == "script":
            executed = self.first_execution_hit(access_probes, payload)
            if executed:
                parser_bypass = self.parser_bypass_execution(executed, payload)
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    executed,
                    "中间件解析执行" if parser_bypass else "脚本文件执行",
                    (
                        "middleware/runtime parser handled the uploaded file as executable code"
                        if parser_bypass
                        else "uploaded server-side script executed and returned the marker"
                    ),
                    "high",
                )

            stored = self.first_marker_hit(access_probes, payload.marker)
            if stored:
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    stored,
                    "危险扩展文件可上传",
                    "dangerous extension was stored and could be fetched back",
                    "medium",
                )
            return None

        if payload.kind == "active_content":
            hit = self.first_inline_active_content_hit(access_probes, payload)
            if hit:
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    hit,
                    "主动内容文件可上传",
                    "HTML/SVG content was stored and served inline",
                    "high",
                )
            return None

        if payload.kind == "image_polyglot":
            executed = self.first_execution_hit(access_probes, payload)
            if executed:
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    executed,
                    "图片马脚本执行",
                    "valid image polyglot executed as server-side script",
                    "high",
                )

            stored = self.first_polyglot_marker_hit(access_probes, payload)
            if stored:
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    stored,
                    "图片马可上传",
                    "valid image polyglot containing PHP code was stored and could be fetched back",
                    "medium",
                )

            if self.response_accepts_upload(upload_probe, payload):
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    None,
                    "图片马上传接受",
                    "upload response indicates that a valid image polyglot was accepted",
                    "medium",
                )
            return None

        if payload.kind == "htaccess":
            hit = self.first_marker_hit(access_probes, payload.marker)
            if hit:
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    hit,
                    ".htaccess 文件可上传",
                    ".htaccess canary was stored and could be fetched back",
                    "medium",
                )

            if self.response_accepts_upload(upload_probe, payload):
                return self.build_upload_finding(
                    flow,
                    candidate,
                    payload,
                    upload_probe,
                    None,
                    ".htaccess 文件上传接受",
                    "upload response indicates that .htaccess was accepted",
                    "medium",
                )
            return None

        return None

    def parser_bypass_execution(self, access_probe, payload):
        group = (payload.payload_group or "").lower()
        if group.startswith("middleware_") or group == "script_bypass":
            return True

        url = (access_probe or {}).get("url", "")
        path = urlsplit(url).path.lower()
        filename = quote(payload.filename).lower()
        if filename and not path.endswith("/" + filename) and not path.endswith(filename):
            return True
        return any(token in path for token in (";.jpg", ";.png", "%2f", "%00", ".php.jpg", ".jsp.jpg", ".asp;."))

    def check_active_htaccess_chain(self, flow, candidate, base_dirs):
        marker = self.next_marker()
        extension = f"ps{uuid.uuid4().hex[:8]}"
        htaccess = self.htaccess_handler_payload(marker, extension)
        htaccess_probe = self.send_upload(flow, candidate, htaccess)
        if not htaccess_probe or not self.upload_maybe_accepted(htaccess_probe):
            return None

        payload = self.php_payload(marker, filename=f"pass-scan-{marker}.{extension}")
        probe = self.send_upload(flow, candidate, payload)
        if not probe:
            return None

        urls = self.urls_for_probe(flow, probe, payload, base_dirs)
        accesses = self.verify_payload_urls(flow, urls, payload)
        executed = self.first_execution_hit(accesses, payload)
        self.cleanup_urls(flow, accesses, payload.marker)
        if not executed:
            return None

        finding = self.build_upload_finding(
            flow,
            candidate,
            payload,
            probe,
            executed,
            ".htaccess 解析绕过",
            ".htaccess AddType/AddHandler made a random extension execute as PHP",
            "high",
        )
        finding["extra_proofs"].append(
            {
                "name": ".htaccess upload",
                **self.probe_to_proof(htaccess_probe),
            }
        )
        finding["evidence"]["htaccess_filename"] = htaccess.filename
        finding["evidence"]["handler_extension"] = extension
        return finding

    # ------------------------------------------------------------------
    # Payloads
    # ------------------------------------------------------------------

    def text_canary_payload(self, marker):
        body = f"pass-scan upload canary\nmarker={marker}\n".encode("utf-8")
        return UploadPayload(
            name="txt_canary",
            kind="canary",
            filename=f"pass-scan-{marker}.txt",
            content_type="text/plain",
            body=body,
            marker=marker,
            expected=marker,
            technique="基线文件上传",
            payload_group="txt_canary",
        )

    def test_payloads(self, marker):
        payloads = []
        for extension in script_extensions():
            payloads.append(self.script_payload(marker, extension))

        for extension in active_content_extensions():
            payloads.append(self.active_content_payload(marker, extension))

        payloads.extend(self.image_polyglot_payloads(marker))

        payloads.append(self.htaccess_canary_payload(marker))

        payloads.extend(self.middleware_parser_payloads(marker))

        stem = f"pass-scan-{marker}"
        for template in script_bypass_filenames():
            filename = template.format(stem=stem)
            payloads.append(self.script_filename_payload(marker, filename, "script_bypass"))

        limit = self.max_payloads_per_candidate
        if self.full_payload_scan:
            limit = max(limit, len(payloads))
        return payloads[:limit]

    def image_polyglot_payloads(self, marker):
        return [
            self.image_polyglot_payload(marker, "gif", self.gif_1x1_bytes(), "image/gif"),
            self.image_polyglot_payload(marker, "png", self.png_1x1_bytes(), "image/png"),
            self.image_polyglot_payload(marker, "jpg", self.jpeg_sof_1x1_bytes(), "image/jpeg"),
        ]

    def image_polyglot_payload(self, marker, extension, image_bytes, content_type):
        polyglot_marker = f"psupimg{marker}"
        php = self.php_marker_code(marker)
        body = (
            image_bytes
            + b"\n"
            + f"/*{polyglot_marker}*/\n".encode("utf-8")
            + php
        )
        return UploadPayload(
            name=f"{extension}_polyglot",
            kind="image_polyglot",
            filename=f"pass-scan-{marker}.{extension}",
            content_type=content_type,
            body=body,
            marker=marker,
            expected=marker,
            technique="图片马可上传",
            payload_group=f"image_polyglot_{extension}",
            polyglot_marker=polyglot_marker,
        )

    def php_marker_code(self, marker):
        left, right = self.marker_parts(marker)
        return (
            "<?php $m='" + left + "'.'" + right + "'; echo $m; ?>"
        ).encode("utf-8")

    def gif_1x1_bytes(self):
        return (
            b"GIF89a"
            b"\x01\x00\x01\x00\x80\x00\x00"
            b"\x00\x00\x00\xff\xff\xff"
            b"!\xf9\x04\x01\x00\x00\x00\x00"
            b",\x00\x00\x00\x00\x01\x00\x01\x00\x00"
            b"\x02\x02D\x01\x00;"
        )

    def png_1x1_bytes(self):
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
        )

    def jpeg_sof_1x1_bytes(self):
        return (
            b"\xff\xd8"
            b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xc0\x00\x11\x08\x00\x01\x00\x01\x03"
            b"\x01\x11\x00\x02\x11\x00\x03\x11\x00"
            b"\xff\xd9"
        )

    def middleware_parser_payloads(self, marker):
        stem = f"pass-scan-{marker}"
        return [
            self.php_payload(
                marker,
                filename=f"{stem}.jpg",
                group="middleware_php_fpm_pathinfo",
                content_type="image/jpeg",
            ),
            self.php_payload(
                marker,
                filename=f"{stem}.gif",
                group="middleware_php_fpm_pathinfo",
                content_type="image/gif",
            ),
            self.aspnet_payload(
                marker,
                "asp",
                filename=f"{stem}.asp;.jpg",
                group="middleware_iis_semicolon",
            ),
            self.aspnet_payload(
                marker,
                "aspx",
                filename=f"{stem}.aspx;.jpg",
                group="middleware_iis_semicolon",
            ),
            self.aspnet_payload(
                marker,
                "asp",
                filename=f"{stem}.asp/{stem}.jpg",
                group="middleware_iis_directory",
            ),
            self.jsp_payload(
                marker,
                "jsp",
                filename=f"{stem}.jsp;.jpg",
                group="middleware_tomcat_semicolon",
            ),
            self.jsp_payload(
                marker,
                "jsp",
                filename=f"{stem}.jsp/{stem}.jpg",
                group="middleware_tomcat_directory",
            ),
        ]

    def script_filename_payload(self, marker, filename, group):
        lowered = filename.lower()
        if ".jspx" in lowered:
            return self.jsp_payload(marker, "jspx", filename=filename, group=group)
        if ".jsp" in lowered:
            return self.jsp_payload(marker, "jsp", filename=filename, group=group)
        if ".aspx" in lowered:
            return self.aspnet_payload(marker, "aspx", filename=filename, group=group)
        if ".ashx" in lowered:
            return self.aspnet_payload(marker, "ashx", filename=filename, group=group)
        if ".asp" in lowered:
            return self.aspnet_payload(marker, "asp", filename=filename, group=group)
        return self.php_payload(marker, filename=filename, group=group)

    def script_payload(self, marker, extension):
        extension = extension.lower().lstrip(".")
        if extension in ("php", "phtml", "php5"):
            return self.php_payload(marker, filename=f"pass-scan-{marker}.{extension}")
        if extension in ("jsp", "jspx"):
            return self.jsp_payload(marker, extension)
        if extension in ("asp", "aspx", "ashx"):
            return self.aspnet_payload(marker, extension)
        return self.php_payload(marker, filename=f"pass-scan-{marker}.{extension}")

    def php_payload(self, marker, filename, group="script_direct", content_type="image/gif"):
        body = (
            "GIF89a\n"
        ).encode("utf-8") + self.php_marker_code(marker)
        return UploadPayload(
            name="php",
            kind="script",
            filename=filename,
            content_type=content_type,
            body=body,
            marker=marker,
            expected=marker,
            technique="脚本文件执行",
            payload_group=group,
        )

    def jsp_payload(self, marker, extension, filename=None, group="script_direct"):
        left, right = self.marker_parts(marker)
        body = (
            '<% String m = "' + left + '" + "' + right + '"; out.print(m); %>'
        ).encode("utf-8")
        return UploadPayload(
            name=extension,
            kind="script",
            filename=filename or f"pass-scan-{marker}.{extension}",
            content_type="image/jpeg",
            body=body,
            marker=marker,
            expected=marker,
            technique="脚本文件执行",
            payload_group=group,
        )

    def aspnet_payload(self, marker, extension, filename=None, group="script_direct"):
        left, right = self.marker_parts(marker)
        if extension == "asp":
            source = '<% Response.Write "' + left + '" & "' + right + '" %>'
        else:
            source = (
                '<%@ Page Language="C#" %><% string m = "'
                + left
                + '" + "'
                + right
                + '"; Response.Write(m); %>'
            )
        return UploadPayload(
            name=extension,
            kind="script",
            filename=filename or f"pass-scan-{marker}.{extension}",
            content_type="image/jpeg",
            body=source.encode("utf-8"),
            marker=marker,
            expected=marker,
            technique="脚本文件执行",
            payload_group=group,
        )

    def active_content_payload(self, marker, extension):
        extension = extension.lower().lstrip(".")
        if extension == "svg":
            body = (
                '<svg xmlns="http://www.w3.org/2000/svg">'
                f"<text>{marker}</text><script>window.name='{marker}'</script></svg>"
            ).encode("utf-8")
            content_type = "image/svg+xml"
        else:
            body = (
                "<!doctype html><html><body>"
                f"<h1>{marker}</h1><script>window.name='{marker}'</script>"
                "</body></html>"
            ).encode("utf-8")
            content_type = "text/html"

        return UploadPayload(
            name=extension,
            kind="active_content",
            filename=f"pass-scan-{marker}.{extension}",
            content_type=content_type,
            body=body,
            marker=marker,
            expected=marker,
            technique="主动内容文件可上传",
            payload_group="active_content",
        )

    def htaccess_canary_payload(self, marker):
        body = (
            "# pass-scan inert htaccess canary\n"
            f"# marker {marker}\n"
        ).encode("utf-8")
        return UploadPayload(
            name="htaccess",
            kind="htaccess",
            filename=".htaccess",
            content_type="text/plain",
            body=body,
            marker=marker,
            expected=marker,
            technique=".htaccess 文件上传",
            payload_group="htaccess_canary",
        )

    def htaccess_handler_payload(self, marker, extension):
        body = (
            "# pass-scan scoped handler canary\n"
            f"# marker {marker}\n"
            f"AddType application/x-httpd-php .{extension}\n"
            f"AddHandler application/x-httpd-php .{extension}\n"
        ).encode("utf-8")
        return UploadPayload(
            name="htaccess_handler",
            kind="htaccess",
            filename=".htaccess",
            content_type="text/plain",
            body=body,
            marker=marker,
            expected=marker,
            technique=".htaccess 解析绕过",
            payload_group="htaccess_handler",
        )

    def marker_parts(self, marker):
        index = max(1, len(marker) // 2)
        return marker[:index], marker[index:]

    # ------------------------------------------------------------------
    # Active HTTP
    # ------------------------------------------------------------------

    def send_upload(self, flow, candidate, payload):
        request = flow.request
        method = request.method.upper()
        url, body, overrides = self.build_upload_request(flow, candidate, payload)
        host = urlsplit(url).netloc

        if self.waf_state:
            self.waf_state.wait_if_needed(host)

        headers = self.copy_headers(request.headers)
        for name, value in overrides.items():
            self.set_header(headers, name, value)

        data = body if method != "GET" else None
        request_packet = self.build_request_packet(method, url, headers, data)
        urllib_request = Request(url, data=data, headers=headers, method=method)

        start_time = time.monotonic()
        try:
            response = self.opener.open(urllib_request, timeout=self.upload_timeout)
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            response_body = error.read(MAX_RESPONSE_BYTES + 1)
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError):
            return self.timed_out_probe(request_packet, payload)
        except (URLError, OSError, ValueError):
            return None

        elapsed = time.monotonic() - start_time
        truncated = len(response_body) > MAX_RESPONSE_BYTES
        response_body = response_body[:MAX_RESPONSE_BYTES]
        charset = response_headers.get_content_charset() or "utf-8"
        text = response_body.decode(charset, errors="replace")
        response_packet = self.build_response_packet(
            status_code, reason, response_headers, response_body, charset, truncated
        )

        return {
            "status_code": status_code,
            "length": len(response_body),
            "elapsed": elapsed,
            "headers": dict(response_headers.items()),
            "header_values": self.collect_header_values(response_headers),
            "text": text,
            "body": response_body,
            "request_packet": request_packet,
            "response_packet": self.trim_proof(response_packet),
            "sent_payload": payload.filename,
        }

    def send_get(self, flow, url):
        request = flow.request
        headers = self.copy_headers(request.headers)
        self.set_header(headers, "Accept-Encoding", "identity")
        request_packet = self.build_request_packet("GET", url, headers, None)

        try:
            response = self.opener.open(
                Request(url, headers=headers, method="GET"),
                timeout=self.verify_timeout,
            )
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            response_body = error.read(MAX_RESPONSE_BYTES + 1)
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError):
            probe = self.timed_out_probe(request_packet, None)
            probe["url"] = url
            return probe
        except (URLError, OSError, ValueError):
            return None

        truncated = len(response_body) > MAX_RESPONSE_BYTES
        response_body = response_body[:MAX_RESPONSE_BYTES]
        charset = response_headers.get_content_charset() or "utf-8"
        text = response_body.decode(charset, errors="replace")
        response_packet = self.build_response_packet(
            status_code, reason, response_headers, response_body, charset, truncated
        )
        return {
            "url": url,
            "status_code": status_code,
            "length": len(response_body),
            "headers": dict(response_headers.items()),
            "header_values": self.collect_header_values(response_headers),
            "text": text,
            "body": response_body,
            "request_packet": request_packet,
            "response_packet": self.trim_proof(response_packet),
        }

    def cleanup_urls(self, flow, access_probes, marker=""):
        if not self.cleanup_uploaded_files:
            return
        for probe in access_probes or []:
            url = probe.get("url")
            if not url:
                continue
            if marker and not self.access_contains_marker(probe, marker):
                continue
            try:
                headers = self.copy_headers(flow.request.headers)
                self.opener.open(Request(url, headers=headers, method="DELETE"), timeout=4)
            except Exception:
                pass

    def cleanup_marker_for(self, payload):
        return payload.polyglot_marker or payload.marker

    def timed_out_probe(self, request_packet="", payload=None):
        filename = getattr(payload, "filename", "") if payload else ""
        return {
            "status_code": 0,
            "length": 0,
            "headers": {},
            "header_values": {},
            "text": "",
            "body": b"",
            "timed_out": True,
            "request_packet": request_packet,
            "response_packet": "",
            "sent_payload": filename,
        }

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def build_upload_request(self, flow, candidate, payload):
        request = flow.request
        url = request.pretty_url
        body = request.content or b""
        overrides = {}
        place = candidate["place"]

        if place == "multipart":
            body, content_type = self.build_multipart_body(
                body,
                get_header(request.headers, "content-type"),
                candidate,
                payload,
            )
            overrides["Content-Type"] = content_type
            return url, body, overrides

        if place == "body":
            overrides["Content-Type"] = payload.content_type
            return url, payload.body, overrides

        if place == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            if candidate["index"] < len(pairs):
                pairs[candidate["index"]] = (
                    candidate["name"],
                    self.encoded_payload_value(candidate, payload),
                )
            charset = candidate.get("charset") or "utf-8"
            body = self.urlencode_pairs(pairs, charset).encode(charset, errors="replace")
            return url, body, overrides

        if place == "json":
            body = replace_json_body_parameter(
                body,
                request.headers,
                candidate,
                self.encoded_payload_value(candidate, payload),
            )
            return url, body, overrides

        return url, body, overrides

    def build_multipart_body(self, original_body, content_type, candidate, payload):
        parts = self.parse_multipart_parts(original_body, content_type)
        boundary = f"----passscan{uuid.uuid4().hex}"
        chunks = []
        for part in parts:
            chunks.append(f"--{boundary}\r\n".encode("ascii"))
            if part["index"] == candidate["index"]:
                name = part.get("name") or candidate.get("name") or "file"
                headers = [
                    (
                        "Content-Disposition",
                        f'form-data; name="{self.quote_header_value(name)}"; '
                        f'filename="{self.quote_header_value(payload.filename)}"',
                    ),
                    ("Content-Type", payload.content_type),
                ]
                body = payload.body
            else:
                headers = part.get("headers", [])
                body = part.get("body", b"")

            for name, value in headers:
                if name.lower() == "content-length":
                    continue
                chunks.append(f"{name}: {value}\r\n".encode("utf-8", errors="replace"))
            chunks.append(b"\r\n")
            chunks.append(body)
            chunks.append(b"\r\n")

        chunks.append(f"--{boundary}--\r\n".encode("ascii"))
        return b"".join(chunks), f"multipart/form-data; boundary={boundary}"

    def encoded_payload_value(self, candidate, payload):
        original = str(candidate.get("value", ""))
        encoded = base64.b64encode(payload.body).decode("ascii")
        if original.strip().lower().startswith("data:"):
            return f"data:{payload.content_type};base64,{encoded}"
        return encoded

    def quote_header_value(self, value):
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    def urlencode_pairs(self, pairs, charset="utf-8"):
        encoded = []
        for name, value in pairs:
            encoded_name = quote_plus(str(name), encoding=charset, errors="replace")
            encoded_value = quote_plus(
                str(value),
                safe="%",
                encoding=charset,
                errors="replace",
            )
            encoded.append(f"{encoded_name}={encoded_value}")
        return "&".join(encoded)

    # ------------------------------------------------------------------
    # Upload location discovery and verification
    # ------------------------------------------------------------------

    def urls_for_probe(self, flow, probe, payload, base_dirs):
        urls = []
        urls.extend(self.urls_from_response(flow.request.pretty_url, probe, payload.filename))
        for directory in base_dirs or []:
            urls.append(urljoin(directory.rstrip("/") + "/", quote(payload.filename)))

        if not urls and self.response_mentions_filename(probe, payload.filename):
            urls.extend(self.common_candidate_urls(flow.request.pretty_url, payload.filename))

        direct_urls = self.normalize_urls(flow.request.pretty_url, urls)
        derived_urls = self.parser_bypass_urls(direct_urls, payload)
        return self.normalize_urls(flow.request.pretty_url, direct_urls + derived_urls)

    def parser_bypass_urls(self, urls, payload):
        """Generate middleware/runtime parser bypass access paths.

        These are follow-up GET URLs only. A finding is still reported only when
        the response returns the per-request execution marker.
        """
        if payload.kind != "script":
            return []

        derived = []
        for url in urls:
            if not self.location_mentions_filename(url, payload.filename):
                continue

            parts = urlsplit(url)
            path = parts.path or "/"
            lower_name = payload.filename.lower()

            if self.payload_looks_php(payload):
                derived.extend(
                    self.url_with_path(parts, variant)
                    for variant in self.php_parser_path_variants(path)
                )

            if self.payload_looks_asp(payload):
                derived.extend(
                    self.url_with_path(parts, variant)
                    for variant in self.asp_parser_path_variants(path)
                )

            if self.payload_looks_jsp(payload):
                derived.extend(
                    self.url_with_path(parts, variant)
                    for variant in self.jsp_parser_path_variants(path)
                )

            if any(ext in lower_name for ext in (".php", ".phtml", ".php5", ".asp", ".aspx", ".jsp", ".jspx")):
                derived.extend(
                    self.url_with_path(parts, variant)
                    for variant in self.generic_suffix_path_variants(path)
                )

        return list(dict.fromkeys(derived))

    def php_parser_path_variants(self, path):
        marker_name = path.rsplit("/", 1)[-1].split(".", 1)[0] or "index"
        return [
            f"{path}/.php",
            f"{path}/index.php",
            f"{path}/{marker_name}.php",
            f"{path}%2f.php",
            f"{path}%2findex.php",
        ]

    def asp_parser_path_variants(self, path):
        return [
            f"{path};.jpg",
            f"{path};.png",
            f"{path}/",
            f"{path}/default.jpg",
        ]

    def jsp_parser_path_variants(self, path):
        return [
            f"{path};.jpg",
            f"{path};.png",
            f"{path}/",
            f"{path}/index.jpg",
        ]

    def generic_suffix_path_variants(self, path):
        return [
            f"{path}.",
            f"{path}%20",
            f"{path}%2e",
            f"{path}%00.jpg",
        ]

    def url_with_path(self, parts, path):
        return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))

    def payload_looks_php(self, payload):
        value = f"{payload.name} {payload.filename} {payload.payload_group}".lower()
        return any(token in value for token in ("php", "phtml", "php5", "php_fpm"))

    def payload_looks_asp(self, payload):
        value = f"{payload.name} {payload.filename} {payload.payload_group}".lower()
        return any(token in value for token in ("asp", "aspx", "ashx", "iis"))

    def payload_looks_jsp(self, payload):
        value = f"{payload.name} {payload.filename} {payload.payload_group}".lower()
        return any(token in value for token in ("jsp", "jspx", "tomcat"))

    def urls_from_response(self, base_url, probe, filename):
        urls = []
        for header_name in ("location", "content-location"):
            for value in self.get_header_values(probe, header_name):
                urls.append(value)

        text = probe.get("text", "")
        urls.extend(self.json_string_locations(text, filename))
        urls.extend(
            match.group("url")
            for match in URL_RE.finditer(text)
            if self.location_mentions_filename(match.group("url"), filename)
        )
        urls.extend(self.path_locations(text, filename))
        urls.extend(self.quoted_filename_locations(text, filename))
        return [self.resolve_location(base_url, value) for value in urls]

    def json_string_locations(self, text, filename):
        try:
            data = json.loads(text)
        except Exception:
            return []

        values = []

        def walk(value, key=""):
            if isinstance(value, dict):
                for child_key, child in value.items():
                    walk(child, child_key)
            elif isinstance(value, list):
                for child in value:
                    walk(child, key)
            elif isinstance(value, str):
                lowered_key = key.lower()
                if filename in value or lowered_key in {k.lower() for k in url_json_keys()}:
                    values.append(value)

        walk(data)
        return values

    def path_locations(self, text, filename):
        values = []
        for match in PATH_RE.finditer(text):
            value = unescape(match.group("path"))
            if self.location_mentions_filename(value, filename):
                values.append(value)
        return values

    def location_mentions_filename(self, value, filename):
        if not value or not filename:
            return False

        value = str(value).lower()
        filename = str(filename).lower()
        basename = filename.rsplit("/", 1)[-1]
        quoted_keep_path = quote(filename, safe="/.;%").lower()
        quoted_strict = quote(filename, safe="").lower()
        quoted_basename = quote(basename, safe=".;%").lower()

        return any(
            item and item in value
            for item in (
                filename,
                basename,
                quoted_keep_path,
                quoted_strict,
                quoted_basename,
            )
        )

    def quoted_filename_locations(self, text, filename):
        pattern = re.compile(
            r"""["'](?P<value>[^"']*"""
            + re.escape(filename)
            + r"""[^"']*)["']""",
            re.I,
        )
        return [match.group("value") for match in pattern.finditer(text)]

    def common_candidate_urls(self, base_url, filename):
        urls = []
        for directory in common_upload_dirs():
            urls.append(urljoin(base_url, directory.lstrip("/") + quote(filename)))

        parts = urlsplit(base_url)
        path_dir = parts.path.rsplit("/", 1)[0].rstrip("/") + "/"
        urls.append(urlunsplit((parts.scheme, parts.netloc, path_dir + quote(filename), "", "")))
        return urls

    def normalize_urls(self, base_url, values):
        normalized = []
        seen = set()
        base_host = urlsplit(base_url).netloc
        for value in values:
            url = self.resolve_location(base_url, value)
            if not url:
                continue
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                continue
            if not self.allow_external_verification and parts.netloc != base_host:
                continue
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            if url in seen:
                continue
            seen.add(url)
            normalized.append(url)
            if len(normalized) >= self.max_verify_urls:
                break
        return normalized

    def resolve_location(self, base_url, value):
        if not value:
            return ""
        value = unescape(str(value).strip().strip("\"'"))
        if not value:
            return ""
        if URL_UNSAFE_RE.search(value):
            return ""
        if value.startswith("//"):
            return f"{urlsplit(base_url).scheme}:{value}"
        return urljoin(base_url, value)

    def verify_payload_urls(self, flow, urls, payload):
        probes = []
        for url in urls[: self.max_verify_urls]:
            probe = self.send_get(flow, url)
            if not probe:
                continue
            probes.append(probe)
            if payload.kind in ("script", "active_content") and payload.expected in probe.get("text", ""):
                break
        return probes

    def base_dirs_from_accesses(self, accesses, marker=""):
        dirs = []
        for access in accesses or []:
            if marker and not self.access_contains_marker(access, marker):
                continue
            if not marker and access.get("status_code") not in (200, 201, 206):
                continue
            url = access.get("url", "")
            if not url:
                continue
            parts = urlsplit(url)
            directory = parts.path.rsplit("/", 1)[0] + "/"
            dirs.append(urlunsplit((parts.scheme, parts.netloc, directory, "", "")))
        return list(dict.fromkeys(dirs))

    # ------------------------------------------------------------------
    # Evidence matching
    # ------------------------------------------------------------------

    def first_execution_hit(self, access_probes, payload):
        source_text = payload.body.decode("utf-8", errors="replace")
        for probe in access_probes or []:
            text = probe.get("text", "")
            if payload.expected not in text:
                continue
            if payload.expected in source_text:
                continue
            if int(probe.get("status_code", 0)) not in (200, 201, 202, 206):
                continue
            return probe
        return None

    def first_marker_hit(self, access_probes, marker):
        for probe in access_probes or []:
            if self.access_contains_marker(probe, marker):
                return probe
        return None

    def first_polyglot_marker_hit(self, access_probes, payload):
        marker = payload.polyglot_marker or payload.marker
        marker_bytes = marker.encode("utf-8")
        for probe in access_probes or []:
            if marker in probe.get("text", ""):
                return probe
            if marker_bytes in (probe.get("body") or b""):
                return probe
        return None

    def access_contains_marker(self, probe, marker):
        if not marker:
            return int(probe.get("status_code", 0)) in (200, 201, 202, 206)
        if marker in probe.get("text", ""):
            return True
        return marker.encode("utf-8") in (probe.get("body") or b"")

    def first_inline_active_content_hit(self, access_probes, payload):
        for probe in access_probes or []:
            if not self.access_contains_marker(probe, payload.marker):
                continue
            if self.response_is_attachment(probe):
                continue
            content_type = self.content_type_for_probe(probe).lower()
            if (
                content_type.startswith("text/html")
                or content_type.startswith("image/svg")
                or content_type in ("", "application/xhtml+xml")
            ):
                return probe
        return None

    def response_is_attachment(self, probe):
        for value in self.get_header_values(probe, "content-disposition"):
            if "attachment" in value.lower():
                return True
        return False

    def response_accepts_upload(self, probe, payload):
        status = int(probe.get("status_code", 0))
        if status < 200 or status >= 400:
            return False
        text = (probe.get("text") or "").lower()
        if any(keyword.lower() in text for keyword in failure_keywords()):
            return False
        filename = payload.filename.lower()
        if filename and filename in text:
            return True
        if payload.marker.lower() in text:
            return True
        return any(keyword.lower() in text for keyword in success_keywords())

    def upload_maybe_accepted(self, probe):
        status = int(probe.get("status_code", 0))
        if status < 200 or status >= 400:
            return False
        text = (probe.get("text") or "").lower()
        return not any(keyword.lower() in text for keyword in failure_keywords())

    def response_mentions_filename(self, probe, filename):
        text = probe.get("text", "")
        if filename in text:
            return True
        headers = "\n".join(f"{k}: {v}" for k, v in probe.get("headers", {}).items())
        return filename in headers

    # ------------------------------------------------------------------
    # Proof and output
    # ------------------------------------------------------------------

    def build_upload_finding(
        self,
        flow,
        candidate,
        payload,
        upload_probe,
        access_probe,
        technique,
        message,
        confidence,
    ):
        evidence = {
            "technique": technique,
            "message": message,
            "filename": payload.filename,
            "content_type": payload.content_type,
            "payload_group": payload.payload_group,
            "marker": payload.marker,
            "upload_status": upload_probe.get("status_code"),
            "confidence": confidence,
        }
        if access_probe:
            evidence["verified_url"] = access_probe.get("url")
            evidence["access_status"] = access_probe.get("status_code")
            evidence["access_content_type"] = self.content_type_for_probe(access_probe)
        if payload.kind == "image_polyglot":
            evidence["polyglot_marker"] = payload.polyglot_marker
            evidence["image_type"] = payload.name.replace("_polyglot", "")

        finding = self.build_finding(
            flow,
            candidate,
            evidence,
            proof_probe=upload_probe,
        )
        if access_probe:
            proof = self.probe_to_proof(access_probe)
            proof["name"] = "access verification"
            finding["extra_proofs"].append(proof)
        return finding

    def build_finding(self, flow, candidate, evidence, proof_probe=None):
        request = flow.request
        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "file_upload",
            "method": "file_upload",
            "request_method": request.method,
            "url": request.pretty_url,
            "param_place": candidate.get("place", ""),
            "param_name": candidate.get("name", ""),
            "evidence": evidence,
            "proof": self.probe_to_proof(proof_probe),
            "extra_proofs": [],
        }

    def passive_proof(self, flow):
        request = flow.request
        response = flow.response
        req_text = self.build_request_packet(
            request.method.upper(),
            request.pretty_url,
            self.copy_headers(request.headers),
            request.content or b"",
        )
        resp_text = self.build_response_packet(
            response.status_code,
            response.reason,
            response.headers,
            response.content or b"",
            "utf-8",
            False,
        )
        return {"request": req_text, "response": self.trim_proof(resp_text)}

    def probe_to_proof(self, probe):
        if not probe:
            return {"request": "", "response": ""}
        if "request" in probe or "response" in probe:
            return {
                "request": probe.get("request", ""),
                "response": self.trim_proof(probe.get("response", "")),
            }
        return {
            "request": self.trim_proof(probe.get("request_packet", "")),
            "response": self.trim_proof(probe.get("response_packet", "")),
        }

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
                f"检测到文件上传漏洞[{technique}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )

    def remember_pending(self, flow, candidate, payload):
        if payload.kind == "canary":
            return
        with self.lock:
            if len(self.pending) >= 200:
                self.pending = self.pending[-100:]
            self.pending.append(
                {
                    "flow": flow,
                    "candidate": dict(candidate),
                    "filename": payload.filename,
                    "marker": payload.marker,
                    "time": time.time(),
                }
            )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

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
                raw_values = [
                    value for item_name, value in headers.items()
                    if item_name.lower() == lower
                ]
            values[lower] = [str(value) for value in raw_values]
        return values

    def get_header_values(self, probe, header_name):
        return (probe.get("header_values") or {}).get(header_name.lower(), [])

    def content_type_for_probe(self, probe):
        values = self.get_header_values(probe, "content-type")
        if values:
            return values[0]
        return probe.get("headers", {}).get("Content-Type", "")

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
            request_text += self.body_preview(body)
        return request_text

    def build_response_packet(self, status_code, reason, headers, body, charset, truncated):
        status_line = f"HTTP/1.1 {status_code} {reason}".rstrip()
        lines = [status_line]
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        response_text = "\r\n".join(lines) + "\r\n\r\n"
        response_text += self.body_preview(body, charset)
        if truncated:
            response_text += "\n... [truncated] ..."
        return response_text

    def body_preview(self, body, charset="utf-8"):
        if not body:
            return ""
        body = body[:MAX_BODY_PREVIEW_BYTES]
        return body.decode(charset or "utf-8", errors="replace")

    def trim_proof(self, text):
        if not text:
            return ""
        if len(text) <= MAX_PROOF_CHARS:
            return text
        return text[:MAX_PROOF_CHARS] + "\n... [truncated] ..."

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def next_marker(self):
        return f"psup{uuid.uuid4().hex[:12]}"

    def make_scan_key(self, flow, candidate):
        request = flow.request
        parts = urlsplit(request.pretty_url)
        return (
            request.method.upper(),
            parts.scheme,
            parts.netloc,
            self.normalize_path_for_dedup(parts.path),
            self.dedup_content_type(get_header(request.headers, "content-type")),
            candidate.get("place", ""),
            candidate.get("name", ""),
            candidate.get("index", ""),
        )

    def dedup_content_type(self, content_type):
        return get_media_type(content_type or "")

    def normalize_path_for_dedup(self, path):
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    def filename_from_path(self, path):
        name = (path or "").rsplit("/", 1)[-1]
        if "." in name:
            return name
        return ""

    def safe_stem(self, prefix):
        return f"{prefix}-{uuid.uuid4().hex[:8]}"
