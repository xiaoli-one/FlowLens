# Object storage bucket discovery and vulnerability checks.
#
# The plugin has two phases:
# 1. observe(context): collect domains and bucket-looking endpoints from passive
#    traffic, verify them immediately with short GET requests, and report
#    confirmed buckets. This phase is intentionally not scheduled through the
#    global ScanQueue.
# 2. check(target): run bucket vulnerability checks for confirmed buckets from
#    the object_storage queue.

import gzip
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
import zlib
from dataclasses import dataclass
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from xml.etree import ElementTree

from pass_scan.body_paser import decode_body_text, get_header, get_media_type
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context
from pass_scan.terminal import red


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

TIMEOUT = 8
MAX_SCAN_CHARS = 400000
MAX_ACTIVE_BODY_BYTES = 262144
MAX_TEXT_OBJECT_BYTES = 262144
MAX_CREDENTIAL_SAMPLES = 8

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
    ".csv",
    ".tsv",
    ".html",
    ".htm",
)

BINARY_OBJECT_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".avif",
    ".mp4",
    ".mp3",
    ".wav",
    ".avi",
    ".mov",
    ".mkv",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

TEXT_MEDIA_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/x-javascript",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
}

BINARY_MEDIA_PREFIXES = ("audio/", "font/", "image/", "video/")

NO_BUCKET_CODES = {
    "NoSuchBucket",
    "NoSuchContainer",
    "BucketNotFound",
    "ContainerNotFound",
}

OBJECT_NOT_FOUND_CODES = {
    "NoSuchKey",
    "BlobNotFound",
    "NoSuchObject",
}

BUCKET_CONFIRM_CODES = {
    "AccessDenied",
    "AllAccessDisabled",
    "AnonymousAccessDenied",
    "InvalidAccessKeyId",
    "InvalidBucketName",
    "InvalidURI",
    "MethodNotAllowed",
    "PermanentRedirect",
    "RequestTimeTooSkewed",
    "SignatureDoesNotMatch",
}

PROVIDER_LABELS = {
    "aliyun_oss": "Aliyun OSS",
    "aws_s3": "AWS S3/S3-compatible",
    "tencent_cos": "Tencent COS",
    "huawei_obs": "Huawei OBS",
    "google_gcs": "Google Cloud Storage",
    "azure_blob": "Azure Blob",
    "baidu_bos": "Baidu BOS",
    "volcengine_tos": "Volcengine TOS",
    "qiniu_kodo": "Qiniu Kodo",
    "upyun": "Upyun",
    "jdcloud_oss": "JDCloud OSS",
    "ucloud_ufile": "UCloud UFile",
    "kingsoft_ks3": "Kingsoft KS3",
    "s3_compatible": "S3-compatible",
    "object_storage": "Object Storage",
}

METHOD_LABELS = {
    "object_storage_bucket": "存在存储桶",
    "object_storage_listable": "OSS 遍历",
    "object_storage_upload": "OSS 任意文件上传",
    "object_storage_overwrite": "OSS 任意文件覆盖",
    "object_storage_credential": "OSS AK/SK 泄露",
}

URL_RE = re.compile(
    r"""
    (?P<url>
      (?:(?:https?:)?//)
      [A-Za-z0-9._~!$&'()*+,;=:-]+
      (?:/[^\s"'<>\\]*)?
    )
    """,
    re.I | re.X,
)

DOMAIN_RE = re.compile(
    r"""
    (?<![@A-Za-z0-9_-])
    (?P<host>
      (?:[A-Za-z0-9][A-Za-z0-9-]{0,62}\.)+
      (?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})
      (?::\d{1,5})?
    )
    (?P<path>/[A-Za-z0-9._~%!$&'()*+,;=:@/?#-]*)?
    """,
    re.X,
)

ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      bucket(?:Name)?
      |bucket_name
      |ossBucket(?:Name)?
      |oss_bucket
      |s3Bucket(?:Name)?
      |cosBucket(?:Name)?
      |obsBucket(?:Name)?
      |gcsBucket(?:Name)?
      |container(?:Name)?
    )
    ["']?\s*[:=]\s*["'](?P<value>[A-Za-z0-9][A-Za-z0-9._-]{1,126})["']
    """,
    re.I | re.X,
)

ENDPOINT_ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      endpoint
      |endPoint
      |ossEndpoint
      |oss_endpoint
      |s3Endpoint
      |cosEndpoint
      |obsEndpoint
      |gcsEndpoint
      |uploadHost
      |uploadUrl
      |baseUrl
      |baseURL
    )
    ["']?\s*[:=]\s*["'](?P<value>(?:https?:)?//[^"'\s<>]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?)["']
    """,
    re.I | re.X,
)

ACCESS_KEY_ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      (?:aws[_-]?)?access[_-]?key[_-]?id
      |accessKeyId
      |AccessKeyId
      |ossAccessKeyId
      |aliyun[_-]?access[_-]?key[_-]?id
      |secretId
      |SecretId
      |tencentcloud[_-]?secret[_-]?id
    )
    ["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9._/-]{12,80})
    """,
    re.I | re.X,
)

SECRET_KEY_ASSIGN_RE = re.compile(
    r"""
    ["']?
    (?P<key>
      (?:aws[_-]?)?secret[_-]?access[_-]?key
      |SecretAccessKey
      |secretAccessKey
      |accessKeySecret
      |AccessKeySecret
      |ossAccessKeySecret
      |aliyun[_-]?access[_-]?key[_-]?secret
      |secretKey
      |SecretKey
      |tencentcloud[_-]?secret[_-]?key
    )
    ["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9/+=._-]{20,160})
    """,
    re.I | re.X,
)

AWS_AK_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
ALIYUN_AK_RE = re.compile(r"\bLTAI[0-9A-Za-z]{12,30}\b")
TENCENT_AK_RE = re.compile(r"\bAKID[0-9A-Za-z]{13,50}\b")


@dataclass
class DomainCandidate:
    url: str
    source: str


@dataclass
class ObjectStorageTarget:
    provider: str
    bucket: str
    base_url: str
    source: str
    original_url: str = ""
    region: str = ""
    verified_url: str = ""
    marker: str = ""
    status_code: int = 0
    host: str = ""
    method: str = "GET"

    def __post_init__(self):
        if not self.host:
            self.host = urlsplit(self.base_url).netloc

    @property
    def url(self):
        return self.base_url


class ObjectStorageScanner:
    """OSS/object storage scanner."""

    name = "object_storage"
    observer_only = True

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.active_probe = bool(self.config.get("active_probe", True))
        self.active_write_probe = bool(self.config.get("active_write_probe", False))
        self.scan_listed_objects = bool(self.config.get("scan_listed_objects", True))
        self.max_scan_chars = int(self.config.get("max_scan_chars", MAX_SCAN_CHARS))
        self.max_active_body_bytes = int(
            self.config.get("max_active_body_bytes", MAX_ACTIVE_BODY_BYTES)
        )
        self.max_buckets_per_context = int(self.config.get("max_buckets_per_context", 8))
        self.max_domains_per_context = int(self.config.get("max_domains_per_context", 40))
        self.max_listed_objects_scan = int(
            self.config.get("max_listed_objects_scan", 12)
        )
        self.discovery_timeout = float(self.config.get("discovery_timeout", 4))
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE
        self.lock = threading.Lock()
        self.discovery_scanned = set()
        self.confirmed_buckets = set()
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
    # Scheduler interface
    # ------------------------------------------------------------------

    def observe(self, context):
        """Discover buckets immediately and return confirmed bucket tasks."""
        if not context.host:
            return []

        self.scan_passive_credentials(context)

        tasks = []
        for target, proof_probe in self.discover_targets(context):
            if not self.claim_confirmed_bucket(target):
                continue

            finding = self.bucket_finding(target, proof_probe)
            if self.write_finding_once(finding):
                print_finding_once(self, finding)
            tasks.append(target)

        return tasks

    def interested(self, _context):
        """Object storage discovery is handled by observe()."""
        return False

    def dedup_key(self, target):
        return (
            "bucket",
            getattr(target, "provider", ""),
            getattr(target, "bucket", ""),
            getattr(target, "base_url", getattr(target, "url", "")),
        )

    def check(self, target, flow=None):
        """Run vulnerability checks for one confirmed bucket."""
        if flow is not None:
            target = build_scan_context(
                target,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        if not isinstance(target, ObjectStorageTarget):
            return []

        written = []
        if self.active_probe:
            listing_result = self.check_bucket_listing(target)
            written.extend(listing_result.get("findings", []))

            if self.scan_listed_objects:
                written.extend(
                    self.scan_public_objects_for_credentials(
                        target,
                        listing_result.get("keys", []),
                    )
                )

        if self.active_write_probe:
            written.extend(self.check_anonymous_write(target))

        return written

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover_targets(self, context):
        direct_targets = []
        candidates = []
        artifacts = list(self.text_artifacts(context))

        direct_targets.extend(self.targets_from_url(context.url, "request.url"))
        candidates.append(DomainCandidate(context.url, "request.url"))

        for source, text in artifacts:
            direct_targets.extend(self.targets_from_assignments(text, source))
            for url in self.urls_from_text(text):
                direct_targets.extend(self.targets_from_url(url, source))
                candidates.append(DomainCandidate(url, source))
            for domain_url in self.domain_urls_from_text(text):
                candidates.append(DomainCandidate(domain_url, source))

        results = []
        seen_targets = set()
        for target in direct_targets:
            key = self.target_key(target)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            confirmed = self.verify_target_once(target, context)
            if confirmed:
                results.append(confirmed)
                if len(results) >= self.max_buckets_per_context:
                    return results

        seen_candidates = set()
        for candidate in candidates[: self.max_domains_per_context]:
            candidate_url = self.normalize_url(candidate.url)
            if not candidate_url:
                continue
            key = self.discovery_key(candidate_url)
            if key in seen_candidates:
                continue
            seen_candidates.add(key)

            candidate_targets = self.targets_from_url(candidate_url, candidate.source)
            if candidate_targets:
                for target in candidate_targets:
                    target.source = candidate.source
                    confirmed = self.verify_target_once(target, context)
                    if confirmed:
                        results.append(confirmed)
                        if len(results) >= self.max_buckets_per_context:
                            return results
                continue

            confirmed = self.verify_custom_domain_once(
                DomainCandidate(candidate_url, candidate.source),
                context,
            )
            if confirmed:
                results.append(confirmed)
                if len(results) >= self.max_buckets_per_context:
                    return results

        return results

    def verify_target_once(self, target, context):
        key = self.discovery_key(target.base_url)
        with self.lock:
            if key in self.discovery_scanned:
                return None
            self.discovery_scanned.add(key)

        probe_urls = []
        if target.original_url and self.normalize_url(target.original_url):
            probe_urls.append(self.normalize_url(target.original_url))
        probe_urls.append(target.base_url)
        probe_urls = list(dict.fromkeys(probe_urls))

        for url in probe_urls:
            probe = self.fetch_url(
                getattr(context, "flow", None),
                url,
                method="GET",
                timeout=self.discovery_timeout,
            )
            if not probe:
                continue

            verdict = self.bucket_verdict_from_probe(
                probe,
                expected_provider=target.provider,
            )
            if not verdict.get("confirmed"):
                continue

            provider = verdict.get("provider") or target.provider
            if target.provider and target.provider != "object_storage":
                provider = target.provider
            target.provider = provider or "object_storage"
            target.verified_url = url
            target.marker = verdict.get("marker", "")
            target.status_code = int(probe.get("status_code") or 0)
            return target, probe

        return None

    def verify_custom_domain_once(self, candidate, context):
        key = self.discovery_key(candidate.url)
        with self.lock:
            if key in self.discovery_scanned:
                return None
            self.discovery_scanned.add(key)

        probe = self.fetch_url(
            getattr(context, "flow", None),
            candidate.url,
            method="GET",
            timeout=self.discovery_timeout,
        )
        if not probe:
            return None

        verdict = self.bucket_verdict_from_probe(probe)
        if not verdict.get("confirmed"):
            return None

        parts = urlsplit(candidate.url)
        provider = verdict.get("provider") or "object_storage"
        bucket = self.bucket_from_custom_url(candidate.url, provider)
        target = ObjectStorageTarget(
            provider=provider,
            bucket=bucket,
            base_url=self.base_url_from_candidate(candidate.url, provider),
            source=candidate.source,
            original_url=candidate.url,
            verified_url=candidate.url,
            marker=verdict.get("marker", ""),
            status_code=int(probe.get("status_code") or 0),
            host=parts.netloc,
        )
        return target, probe

    def claim_confirmed_bucket(self, target):
        key = self.target_key(target)
        with self.lock:
            if key in self.confirmed_buckets:
                return False
            self.confirmed_buckets.add(key)
            return True

    def target_key(self, target):
        return (
            (target.provider or "").lower(),
            (target.bucket or "").lower(),
            self.discovery_key(target.base_url),
        )

    def discovery_key(self, url):
        parts = urlsplit(self.normalize_url(url) or url)
        path = parts.path.rstrip("/") or "/"
        return (
            parts.scheme.lower() or "https",
            parts.netloc.lower(),
            path,
        )

    # ------------------------------------------------------------------
    # Target extraction
    # ------------------------------------------------------------------

    def targets_from_url(self, url, source):
        url = self.normalize_url(url)
        if not url:
            return []

        parts = urlsplit(url)
        host = self.host_without_port(parts.netloc).lower()
        scheme = parts.scheme or "https"
        path_parts = [part for part in parts.path.split("/") if part]
        targets = []

        def add(provider, bucket, base_url, region=""):
            if not bucket or not base_url:
                return
            targets.append(
                ObjectStorageTarget(
                    provider=provider,
                    bucket=bucket,
                    base_url=base_url.rstrip("/"),
                    source=source,
                    original_url=url,
                    region=region,
                )
            )

        match = re.match(
            r"^(?P<bucket>.+)\.oss(?:-(?P<region>[a-z0-9-]+))?(?:-internal)?\.aliyuncs\.com(?:\.cn)?$",
            host,
            re.I,
        )
        if match:
            add("aliyun_oss", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region") or "")
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.s3(?:[.-](?P<region>[a-z0-9-]+))?\.amazonaws\.com(?:\.cn)?$",
            host,
            re.I,
        )
        if match:
            add("aws_s3", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region") or "")
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.s3(?:-accelerate)?(?:\.dualstack\.(?P<region>[a-z0-9-]+))?\.amazonaws\.com(?:\.cn)?$",
            host,
            re.I,
        )
        if match:
            add("aws_s3", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region") or "")
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.s3-website[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$",
            host,
            re.I,
        )
        if match:
            add("aws_s3", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region") or "")
            return targets

        if re.match(r"^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$", host, re.I):
            if path_parts:
                bucket = path_parts[0]
                add("aws_s3", bucket, f"{scheme}://{parts.netloc}/{bucket}")
                return targets

        match = re.match(
            r"^(?P<bucket>.+)\.cos\.(?P<region>[a-z0-9-]+)\.myqcloud\.com$",
            host,
            re.I,
        )
        if match:
            add("tencent_cos", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.obs[.-](?P<region>[a-z0-9-]+)\.myhuaweicloud\.com(?:\.cn)?$",
            host,
            re.I,
        )
        if match:
            add("huawei_obs", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(r"^(?P<bucket>.+)\.storage\.googleapis\.com$", host, re.I)
        if match:
            add("google_gcs", match.group("bucket"), f"{scheme}://{parts.netloc}")
            return targets

        if host == "storage.googleapis.com" and path_parts:
            bucket = path_parts[0]
            add("google_gcs", bucket, f"{scheme}://{parts.netloc}/{bucket}")
            return targets

        match = re.match(r"^(?P<account>[a-z0-9-]+)\.blob\.core\.windows\.net$", host, re.I)
        if match and path_parts:
            container = path_parts[0]
            add(
                "azure_blob",
                f"{match.group('account')}/{container}",
                f"{scheme}://{parts.netloc}/{container}",
            )
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.(?:(?P<region>[a-z0-9-]+)\.)?bcebos\.com$",
            host,
            re.I,
        )
        if match:
            add("baidu_bos", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region") or "")
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.bos[.-](?P<region>[a-z0-9-]+)\.baidubce\.com$",
            host,
            re.I,
        )
        if match:
            add("baidu_bos", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.tos(?:-s3)?[.-](?P<region>[a-z0-9-]+)\.volces\.com$",
            host,
            re.I,
        )
        if match:
            add("volcengine_tos", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.(?:kodo-[a-z0-9-]+|qiniucs|qiniup|qbox)\.com$",
            host,
            re.I,
        )
        if match:
            add("qiniu_kodo", match.group("bucket"), f"{scheme}://{parts.netloc}")
            return targets

        match = re.match(r"^(?P<bucket>.+)\.b0\.upaiyun\.com$", host, re.I)
        if match:
            add("upyun", match.group("bucket"), f"{scheme}://{parts.netloc}")
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.(?:s3\.)?(?P<region>cn-[a-z0-9-]+)\.jdcloud-oss\.com$",
            host,
            re.I,
        )
        if match:
            add("jdcloud_oss", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.(?P<region>[a-z0-9-]+)\.ufileos\.com$",
            host,
            re.I,
        )
        if match:
            add("ucloud_ufile", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))
            return targets

        match = re.match(
            r"^(?P<bucket>.+)\.ks3-(?P<region>[a-z0-9-]+)\.ksyuncs\.com$",
            host,
            re.I,
        )
        if match:
            add("kingsoft_ks3", match.group("bucket"), f"{scheme}://{parts.netloc}", match.group("region"))

        return targets

    def targets_from_assignments(self, text, source):
        text = (text or "")[: self.max_scan_chars]
        buckets = []
        endpoints = []

        for match in ASSIGN_RE.finditer(text):
            bucket = match.group("value").strip()
            if self.looks_like_bucket_name(bucket):
                buckets.append(bucket)

        for match in ENDPOINT_ASSIGN_RE.finditer(text):
            endpoint = self.normalize_url(match.group("value"))
            if endpoint:
                endpoints.append(endpoint)

        targets = []
        seen = set()
        for bucket in buckets[:8]:
            for endpoint in endpoints[:8]:
                target = self.target_from_bucket_endpoint(bucket, endpoint, source)
                if not target:
                    continue
                key = self.target_key(target)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(target)

        return targets

    def target_from_bucket_endpoint(self, bucket, endpoint, source):
        endpoint = self.normalize_url(endpoint)
        if not endpoint or not self.looks_like_bucket_name(bucket):
            return None

        parts = urlsplit(endpoint)
        host = self.host_without_port(parts.netloc).lower()
        scheme = parts.scheme or "https"
        provider = self.provider_from_endpoint_host(host)

        if "{bucket}" in endpoint:
            base_url = endpoint.replace("{bucket}", bucket).rstrip("/")
            return ObjectStorageTarget(provider or "object_storage", bucket, base_url, source)

        if provider == "google_gcs" and host == "storage.googleapis.com":
            return ObjectStorageTarget(
                "google_gcs",
                bucket,
                f"{scheme}://{parts.netloc}/{bucket}",
                source,
            )

        if provider == "azure_blob":
            account = host.split(".", 1)[0]
            return ObjectStorageTarget(
                "azure_blob",
                f"{account}/{bucket}",
                f"{scheme}://{parts.netloc}/{bucket}",
                source,
            )

        if provider:
            return ObjectStorageTarget(
                provider,
                bucket,
                f"{scheme}://{bucket}.{parts.netloc}",
                source,
                region=self.region_from_host(host),
            )

        return None

    def provider_from_endpoint_host(self, host):
        host = (host or "").lower()
        if re.match(r"^oss(?:-[a-z0-9-]+)?(?:-internal)?\.aliyuncs\.com(?:\.cn)?$", host):
            return "aliyun_oss"
        if re.match(r"^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$", host):
            return "aws_s3"
        if re.match(r"^cos\.[a-z0-9-]+\.myqcloud\.com$", host):
            return "tencent_cos"
        if re.match(r"^obs[.-][a-z0-9-]+\.myhuaweicloud\.com(?:\.cn)?$", host):
            return "huawei_obs"
        if host == "storage.googleapis.com":
            return "google_gcs"
        if host.endswith(".blob.core.windows.net"):
            return "azure_blob"
        if re.match(r"^(?:[a-z0-9-]+\.)?bcebos\.com$", host):
            return "baidu_bos"
        if re.match(r"^tos(?:-s3)?[.-][a-z0-9-]+\.volces\.com$", host):
            return "volcengine_tos"
        return ""

    def region_from_host(self, host):
        patterns = (
            r"oss-(?P<region>[a-z0-9-]+)",
            r"s3[.-](?P<region>[a-z0-9-]+)",
            r"cos\.(?P<region>[a-z0-9-]+)",
            r"obs[.-](?P<region>[a-z0-9-]+)",
            r"tos(?:-s3)?[.-](?P<region>[a-z0-9-]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, host or "", re.I)
            if match:
                return match.group("region")
        return ""

    # ------------------------------------------------------------------
    # Bucket verification and listing detection
    # ------------------------------------------------------------------

    def provider_hint_from_headers(self, headers):
        lowered = self.lower_headers(headers)
        server = lowered.get("server", "").lower()

        if "cloudfront" in server or "x-amz-cf-id" in lowered or "x-amz-cf-pop" in lowered:
            return ""
        if any(name.startswith("x-oss-") for name in lowered) or "aliyunoss" in server:
            return "aliyun_oss"
        if (
            "x-amz-request-id" in lowered
            or "x-amz-id-2" in lowered
            or "x-amz-bucket-region" in lowered
            or "amazons3" in server
        ):
            return "aws_s3"
        if any(name.startswith("x-cos-") for name in lowered):
            return "tencent_cos"
        if any(name.startswith("x-obs-") for name in lowered):
            return "huawei_obs"
        if any(name.startswith("x-goog-") for name in lowered) or "x-guploader-uploadid" in lowered:
            return "google_gcs"
        if (
            "x-ms-request-id" in lowered
            or "x-ms-version" in lowered
            or "x-ms-blob-type" in lowered
            or "windows-azure-blob" in server
        ):
            return "azure_blob"
        if any(name.startswith("x-bce-") for name in lowered):
            return "baidu_bos"
        if any(name.startswith("x-tos-") for name in lowered):
            return "volcengine_tos"
        if any(name.startswith("x-qiniu-") for name in lowered) or "x-qiniu-zone" in lowered:
            return "qiniu_kodo"
        if any(name.startswith("x-upyun-") for name in lowered):
            return "upyun"
        return ""

    def bucket_verdict_from_probe(self, probe, expected_provider=""):
        status_code = int(probe.get("status_code") or 0)
        headers = probe.get("headers") or {}
        text = (probe.get("text") or "")[:50000]
        provider = self.provider_hint_from_headers(headers)
        code = self.extract_error_code(text)

        if code in NO_BUCKET_CODES:
            return {"confirmed": False, "provider": provider or expected_provider, "marker": code}

        if code in OBJECT_NOT_FOUND_CODES and (provider or expected_provider):
            return {
                "confirmed": True,
                "provider": provider or expected_provider,
                "marker": code,
            }

        if self.is_listing_text(text):
            return {
                "confirmed": True,
                "provider": provider or expected_provider or self.provider_from_listing(text),
                "marker": "ListBucketResult",
            }

        if provider:
            marker = code or self.storage_header_marker(headers) or "object-storage-header"
            if status_code in (200, 201, 204, 206, 301, 302, 304, 307, 308, 400, 403, 405, 409):
                return {"confirmed": True, "provider": provider, "marker": marker}

        if expected_provider and code in BUCKET_CONFIRM_CODES:
            return {
                "confirmed": True,
                "provider": expected_provider,
                "marker": code,
            }

        return {"confirmed": False, "provider": provider or expected_provider, "marker": code or ""}

    def is_bucket_listable(self, probe, target=None):
        if int(probe.get("status_code") or 0) != 200:
            return False
        text = probe.get("text") or ""
        if self.extract_error_code(text) in NO_BUCKET_CODES | BUCKET_CONFIRM_CODES:
            return False
        return self.is_listing_text(text)

    def is_listing_text(self, text):
        value = text or ""
        lowered = value.lower()
        if "<listbucketresult" in lowered and "<contents" in lowered:
            return True
        if "<enumerationresults" in lowered and "<blobs" in lowered:
            return True
        if "<listallmybucketsresult" in lowered:
            return True
        if "<bucketlist" in lowered and "<object" in lowered:
            return True
        if '"items"' in lowered and '"name"' in lowered and ("storage#objects" in lowered or '"kind"' in lowered):
            return True
        return False

    def provider_from_listing(self, text):
        lowered = (text or "").lower()
        if "<enumerationresults" in lowered:
            return "azure_blob"
        if "storage#objects" in lowered:
            return "google_gcs"
        return "s3_compatible"

    def extract_error_code(self, text):
        value = text or ""
        patterns = (
            r"<Code>\s*([^<\s]+)\s*</Code>",
            r"<code>\s*([^<\s]+)\s*</code>",
            r'"Code"\s*:\s*"([^"]+)"',
            r'"code"\s*:\s*"([^"]+)"',
            r"<ErrorCode>\s*([^<\s]+)\s*</ErrorCode>",
        )
        for pattern in patterns:
            match = re.search(pattern, value, re.I)
            if match:
                return match.group(1).strip()
        for code in NO_BUCKET_CODES | OBJECT_NOT_FOUND_CODES | BUCKET_CONFIRM_CODES:
            if re.search(rf"\b{re.escape(code)}\b", value):
                return code
        return ""

    def storage_header_marker(self, headers):
        for name, _value in self.header_items(headers):
            lower = name.lower()
            if lower.startswith(("x-oss-", "x-amz-", "x-cos-", "x-obs-", "x-goog-", "x-ms-", "x-bce-", "x-tos-", "x-qiniu-", "x-upyun-")):
                return name
        return ""

    def extract_object_keys_from_listing(self, text):
        keys = []
        value = text or ""

        try:
            root = ElementTree.fromstring(value.encode("utf-8"))
            for contents in root.iter():
                if self.xml_tag_name(contents.tag) != "Contents":
                    continue
                for child in contents:
                    if self.xml_tag_name(child.tag) == "Key" and child.text:
                        keys.append(unescape(child.text.strip()))

            for blob in root.iter():
                if self.xml_tag_name(blob.tag) != "Blob":
                    continue
                for child in blob:
                    if self.xml_tag_name(child.tag) == "Name" and child.text:
                        keys.append(unescape(child.text.strip()))
        except ElementTree.ParseError:
            pass

        if not keys:
            keys.extend(unescape(item.strip()) for item in re.findall(r"<Key>\s*([^<]+)\s*</Key>", value, re.I))
            keys.extend(
                unescape(item.strip())
                for item in re.findall(r"<Blob>\s*<Name>\s*([^<]+)\s*</Name>", value, re.I | re.S)
            )

        if not keys:
            try:
                data = json.loads(value)
                items = data.get("items", []) if isinstance(data, dict) else []
                for item in items:
                    if isinstance(item, dict) and item.get("name"):
                        keys.append(str(item["name"]))
            except json.JSONDecodeError:
                pass

        return list(dict.fromkeys(key for key in keys if key))[:100]

    def xml_tag_name(self, tag):
        return str(tag).rsplit("}", 1)[-1]

    # ------------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------------

    def check_bucket_listing(self, target):
        findings = []
        keys = []
        for url in self.list_probe_urls(target):
            probe = self.fetch_url(None, url, method="GET", timeout=TIMEOUT)
            if not probe:
                continue
            if not self.is_bucket_listable(probe, target):
                continue

            keys = self.extract_object_keys_from_listing(probe.get("text", ""))
            finding = self.listable_finding(target, url, probe, keys)
            if self.write_finding_once(finding):
                print_finding_once(self, finding)
                findings.append(finding)
            break

        return {"findings": findings, "keys": keys}

    def list_probe_urls(self, target):
        if target.provider == "azure_blob":
            queries = ("restype=container&comp=list&maxresults=100",)
        else:
            queries = (
                "list-type=2&max-keys=100",
                "max-keys=100",
                "delimiter=/&max-keys=100",
            )
        return [self.url_with_query(target.base_url, query) for query in queries]

    def scan_public_objects_for_credentials(self, target, keys):
        findings = []
        scanned = 0
        for key in keys:
            if scanned >= self.max_listed_objects_scan:
                break
            if not self.object_key_is_text(key):
                continue
            scanned += 1
            url = self.object_url(target, key)
            probe = self.fetch_url(
                None,
                url,
                method="GET",
                timeout=TIMEOUT,
                max_body_bytes=MAX_TEXT_OBJECT_BYTES,
            )
            if not probe or int(probe.get("status_code") or 0) >= 400:
                continue
            if not self.response_looks_text(probe):
                continue

            matches = self.detect_credentials(probe.get("text", ""), "listed_object.body")
            if not matches:
                continue

            finding = self.credential_finding(
                url=url,
                request_method="GET",
                source="listed_object.body",
                matches=matches,
                proof={
                    "request": probe.get("request_packet", ""),
                    "response": self.trim_proof(probe.get("response_packet", "")),
                },
                target=target,
                object_key=key,
            )
            if self.write_finding_once(finding):
                print_finding_once(self, finding)
                findings.append(finding)

        return findings

    def check_anonymous_write(self, target):
        findings = []
        marker = uuid.uuid4().hex
        key = f"pass-scan-canary/{marker}.txt"
        object_url = self.object_url(target, key)
        body1 = f"pass-scan-canary:{marker}:1\n".encode("utf-8")
        body2 = f"pass-scan-canary:{marker}:2\n".encode("utf-8")
        headers = {"Content-Type": "text/plain"}
        if target.provider == "azure_blob":
            headers["x-ms-blob-type"] = "BlockBlob"

        put1 = self.fetch_url(
            None,
            object_url,
            method="PUT",
            body=body1,
            headers=headers,
            timeout=TIMEOUT,
        )
        if not self.write_succeeded(put1, target.provider):
            return findings

        get1 = self.fetch_url(None, object_url, method="GET", timeout=TIMEOUT)
        verified_upload = bool(get1 and body1.decode("utf-8") in (get1.get("text") or ""))
        upload_finding = self.write_finding(
            target,
            "object_storage_upload",
            object_url,
            key,
            put1,
            verified_upload,
            "匿名 PUT canary 对象成功",
        )
        if self.write_finding_once(upload_finding):
            print_finding_once(self, upload_finding)
            findings.append(upload_finding)

        put2 = self.fetch_url(
            None,
            object_url,
            method="PUT",
            body=body2,
            headers=headers,
            timeout=TIMEOUT,
        )
        if self.write_succeeded(put2, target.provider):
            get2 = self.fetch_url(None, object_url, method="GET", timeout=TIMEOUT)
            verified_overwrite = bool(
                get2 and body2.decode("utf-8") in (get2.get("text") or "")
            )
            overwrite_finding = self.write_finding(
                target,
                "object_storage_overwrite",
                object_url,
                key,
                put2,
                verified_overwrite,
                "匿名 PUT 同一路径 canary 对象成功",
            )
            if self.write_finding_once(overwrite_finding):
                print_finding_once(self, overwrite_finding)
                findings.append(overwrite_finding)

        self.fetch_url(None, object_url, method="DELETE", timeout=TIMEOUT)
        return findings

    def write_succeeded(self, probe, provider):
        if not probe:
            return False
        status_code = int(probe.get("status_code") or 0)
        if status_code not in (200, 201, 202, 204):
            return False
        hint = self.provider_hint_from_headers(probe.get("headers") or {})
        return bool(hint or provider)

    # ------------------------------------------------------------------
    # Credential detection
    # ------------------------------------------------------------------

    def scan_passive_credentials(self, context):
        proof = self.passive_proof(getattr(context, "flow", None))
        written = []
        for source, text in self.text_artifacts(context):
            matches = self.detect_credentials(text, source)
            if not matches:
                continue
            finding = self.credential_finding(
                url=context.url,
                request_method=context.method,
                source=source,
                matches=matches,
                proof=proof,
                target=None,
            )
            if self.write_finding_once(finding):
                print_finding_once(self, finding)
                written.append(finding)
        return written

    def detect_credentials(self, text, source):
        text = text or ""
        matches = []

        for regex, category, subtype in (
            (ACCESS_KEY_ASSIGN_RE, "AccessKeyId", "assignment"),
            (SECRET_KEY_ASSIGN_RE, "SecretAccessKey", "assignment"),
        ):
            for match in regex.finditer(text):
                key = match.group("key")
                value = self.strip_secret_value(match.group("value"))
                if not self.looks_like_secret(value, min_length=12 if category == "AccessKeyId" else 20):
                    continue
                matches.append(
                    {
                        "category": category,
                        "subtype": key,
                        "sample": f"{key}={self.mask_secret(value)}",
                        "source": source,
                    }
                )

        for regex, category, subtype in (
            (AWS_AK_RE, "AccessKeyId", "AWS Access Key ID"),
            (ALIYUN_AK_RE, "AccessKeyId", "Aliyun AccessKeyId"),
            (TENCENT_AK_RE, "AccessKeyId", "Tencent SecretId"),
        ):
            for match in regex.finditer(text):
                value = match.group(0)
                if not self.looks_like_secret(value, min_length=16):
                    continue
                matches.append(
                    {
                        "category": category,
                        "subtype": subtype,
                        "sample": self.mask_secret(value),
                        "source": source,
                    }
                )

        return self.dedupe_matches(matches)[:MAX_CREDENTIAL_SAMPLES]

    def dedupe_matches(self, matches):
        seen = set()
        result = []
        for match in matches:
            key = (match.get("category"), match.get("subtype"), match.get("sample"), match.get("source"))
            if key in seen:
                continue
            seen.add(key)
            result.append(match)
        return result

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def bucket_finding(self, target, probe):
        evidence = {
            "technique": "域名访问确认",
            "provider": PROVIDER_LABELS.get(target.provider, target.provider),
            "bucket": target.bucket,
            "endpoint": target.base_url,
            "bucket_source": target.source,
            "verified_url": target.verified_url or target.base_url,
            "probe_status": target.status_code or probe.get("status_code"),
            "message": f"访问域名后出现对象存储特征: {target.marker or 'storage marker'}",
            "confidence": "high",
        }
        if target.region:
            evidence["region"] = target.region
        if target.marker:
            evidence["matched"] = target.marker

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "object_storage",
            "method": "object_storage_bucket",
            "request_method": "GET",
            "url": target.verified_url or target.base_url,
            "param_place": "domain",
            "param_name": target.host,
            "evidence": evidence,
            "proof": {
                "request": probe.get("request_packet", ""),
                "response": self.trim_proof(probe.get("response_packet", "")),
            },
            "extra_proofs": [],
        }

    def listable_finding(self, target, url, probe, keys):
        evidence = {
            "technique": "匿名列举",
            "provider": PROVIDER_LABELS.get(target.provider, target.provider),
            "bucket": target.bucket,
            "endpoint": target.base_url,
            "list_url": url,
            "object_count": len(keys),
            "object_samples": keys[:10],
            "probe_status": probe.get("status_code"),
            "message": "匿名访问桶列举接口返回对象列表",
            "confidence": "high",
        }
        if target.region:
            evidence["region"] = target.region

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "object_storage",
            "method": "object_storage_listable",
            "request_method": "GET",
            "url": url,
            "param_place": "bucket",
            "param_name": target.bucket,
            "evidence": evidence,
            "proof": {
                "request": probe.get("request_packet", ""),
                "response": self.trim_proof(probe.get("response_packet", "")),
            },
            "extra_proofs": [],
        }

    def write_finding(self, target, method, object_url, key, probe, verified, message):
        evidence = {
            "technique": "匿名写入 canary 对象",
            "provider": PROVIDER_LABELS.get(target.provider, target.provider),
            "bucket": target.bucket,
            "endpoint": target.base_url,
            "object_key": key,
            "object_url": object_url,
            "probe_status": probe.get("status_code") if probe else "",
            "verified": verified,
            "message": message,
            "confidence": "high" if verified else "medium",
        }
        if target.region:
            evidence["region"] = target.region

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "object_storage",
            "method": method,
            "request_method": "PUT",
            "url": object_url,
            "param_place": "bucket",
            "param_name": target.bucket,
            "evidence": evidence,
            "proof": {
                "request": probe.get("request_packet", "") if probe else "",
                "response": self.trim_proof(probe.get("response_packet", "")) if probe else "",
            },
            "extra_proofs": [],
        }

    def credential_finding(
        self,
        url,
        request_method,
        source,
        matches,
        proof,
        target=None,
        object_key="",
    ):
        categories = []
        samples = []
        sources = []
        subtypes = []
        for match in matches:
            if match["category"] not in categories:
                categories.append(match["category"])
            if match["sample"] not in samples:
                samples.append(match["sample"])
            if match["source"] not in sources:
                sources.append(match["source"])
            if match["subtype"] not in subtypes:
                subtypes.append(match["subtype"])

        evidence = {
            "technique": "AK/SK 正则匹配",
            "sensitive_type": "AK/SK",
            "matched": samples[:MAX_CREDENTIAL_SAMPLES],
            "sources": sources,
            "subtypes": categories + [item for item in subtypes if item not in categories],
            "match_count": len(matches),
            "message": "发现对象存储访问密钥特征",
            "confidence": "high",
        }
        if target:
            evidence.update(
                {
                    "provider": PROVIDER_LABELS.get(target.provider, target.provider),
                    "bucket": target.bucket,
                    "endpoint": target.base_url,
                }
            )
        if object_key:
            evidence["object_key"] = object_key

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "object_storage",
            "method": "object_storage_credential",
            "request_method": request_method,
            "url": url,
            "param_place": "response",
            "param_name": source,
            "evidence": evidence,
            "proof": proof,
            "extra_proofs": [],
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
        return True

    def finding_key(self, finding):
        evidence = finding.get("evidence", {})
        matched = evidence.get("matched", [])
        if isinstance(matched, list):
            matched = tuple(matched)
        return (
            finding.get("method", ""),
            finding.get("url", ""),
            evidence.get("bucket", ""),
            evidence.get("object_key", ""),
            evidence.get("list_url", ""),
            matched,
        )

    def print_finding(self, finding):
        method = finding.get("method", "")
        label = METHOD_LABELS.get(method, method)
        print(
            red(
                "[漏洞] "
                f"检测到{label} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )

    # ------------------------------------------------------------------
    # HTTP and proof helpers
    # ------------------------------------------------------------------

    def fetch_url(
        self,
        flow,
        url,
        method="GET",
        body=None,
        headers=None,
        timeout=TIMEOUT,
        max_body_bytes=None,
    ):
        url = self.normalize_url(url)
        if not url:
            return None

        request_headers = {}
        request = getattr(flow, "request", None) if flow is not None else None
        if request is not None:
            request_headers.update(self.copy_headers(getattr(request, "headers", {})))
        request_headers.update(headers or {})
        request_headers.setdefault("User-Agent", "pass_scan-object-storage/1.0")
        request_headers["Accept-Encoding"] = "identity"

        data = body if body is None or isinstance(body, bytes) else str(body).encode("utf-8")
        urllib_request = Request(url, data=data, headers=request_headers, method=method)
        request_packet = self.build_request_packet(method, url, request_headers, data)

        host = urlsplit(url).netloc
        if self.waf_state:
            self.waf_state.wait_if_needed(host)

        try:
            response = self.opener.open(urllib_request, timeout=timeout)
            limit = int(max_body_bytes or self.max_active_body_bytes)
            raw_body = response.read(limit + 1)
            status_code = response.status
            reason = getattr(response, "reason", "")
            response_headers = response.headers
        except HTTPError as error:
            limit = int(max_body_bytes or self.max_active_body_bytes)
            raw_body = error.read(limit + 1)
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError, URLError, OSError, ValueError):
            return None

        body_bytes = raw_body[: int(max_body_bytes or self.max_active_body_bytes)]
        text, charset = self.decode_http_body(body_bytes, response_headers)
        response_packet = self.build_response_packet(
            status_code,
            reason,
            response_headers,
            body_bytes,
            charset,
        )
        return {
            "status_code": status_code,
            "headers": response_headers,
            "headers_text": self.headers_to_text(response_headers),
            "body": body_bytes,
            "text": text,
            "request_packet": request_packet,
            "response_packet": response_packet,
        }

    def passive_proof(self, flow):
        if flow is None:
            return {"request": "", "response": ""}
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)
        request_text = ""
        response_text = ""
        if request:
            request_text = self.build_request_packet(
                request.method,
                request.pretty_url,
                dict(request.headers.items()),
                request.content or b"",
            )
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
        for name, value in self.header_items(headers):
            lines.append(f"{name}: {value}")
        response_text = "\r\n".join(lines) + "\r\n\r\n"
        response_text += (body or b"").decode(charset or "utf-8", errors="replace")
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

    # ------------------------------------------------------------------
    # Text/domain helpers
    # ------------------------------------------------------------------

    def text_artifacts(self, context):
        flow = getattr(context, "flow", None)
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)

        yield "request.url", context.url or ""

        if request is not None:
            yield "request.headers", self.headers_to_text(getattr(request, "headers", {}))
            body = request.content or b""
            if body and self.body_looks_text(body, request.headers):
                text, _charset = self.decode_http_body(body, request.headers)
                yield "request.body", text[: self.max_scan_chars]

        if response is not None:
            yield "response.headers", self.headers_to_text(getattr(response, "headers", {}))
            body = response.content or b""
            if body and self.body_looks_text(body, response.headers):
                text, _charset = self.decode_http_body(body, response.headers)
                yield "response.body", text[: self.max_scan_chars]

    def urls_from_text(self, text):
        urls = []
        for match in URL_RE.finditer(text or ""):
            url = self.normalize_url(match.group("url"))
            if url:
                urls.append(url)
        return list(dict.fromkeys(urls))

    def domain_urls_from_text(self, text):
        urls = []
        for match in DOMAIN_RE.finditer(text or ""):
            host = match.group("host")
            path = match.group("path") or "/"
            if not self.is_probable_host(host):
                continue
            url = self.normalize_url(f"https://{host}{path}")
            if url:
                urls.append(url)
        return list(dict.fromkeys(urls))

    def normalize_url(self, url):
        value = str(url or "").strip().strip("\"'`<>()[]{}")
        if not value:
            return ""
        value = value.rstrip(".,;")
        if value.startswith("//"):
            value = "https:" + value
        elif not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
            value = "https://" + value
        try:
            parts = urlsplit(value)
        except ValueError:
            return ""
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return ""
        if not self.is_probable_host(parts.netloc):
            return ""
        path = parts.path or "/"
        return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))

    def is_probable_host(self, netloc):
        host = self.host_without_port(netloc).lower()
        if not host or "/" in host or "\\" in host:
            return False
        if host in ("localhost", "0.0.0.0"):
            return False
        if len(host) > 253:
            return False
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            return True
        return "." in host and not host.startswith(".") and not host.endswith(".")

    def host_without_port(self, netloc):
        value = str(netloc or "")
        if "@" in value:
            value = value.rsplit("@", 1)[-1]
        if value.startswith("["):
            return value.strip("[]")
        return value.split(":", 1)[0]

    def base_url_from_candidate(self, url, provider):
        parts = urlsplit(url)
        if provider == "azure_blob":
            path_parts = [part for part in parts.path.split("/") if part]
            if path_parts:
                return f"{parts.scheme}://{parts.netloc}/{path_parts[0]}"
        return f"{parts.scheme}://{parts.netloc}"

    def bucket_from_custom_url(self, url, provider):
        parts = urlsplit(url)
        if provider == "azure_blob":
            path_parts = [part for part in parts.path.split("/") if part]
            if path_parts:
                account = self.host_without_port(parts.netloc).split(".", 1)[0]
                return f"{account}/{path_parts[0]}"
        return parts.netloc

    def looks_like_bucket_name(self, value):
        value = str(value or "")
        if len(value) < 2 or len(value) > 128:
            return False
        if any(token in value.lower() for token in ("example", "your_", "your-", "<", ">")):
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]", value))

    def body_looks_text(self, body, headers):
        content_type = get_header(headers, "content-type")
        media_type = get_media_type(content_type)
        if media_type.startswith(BINARY_MEDIA_PREFIXES):
            return False
        if (
            media_type.startswith("text/")
            or media_type in TEXT_MEDIA_TYPES
            or media_type.endswith("+json")
            or media_type.endswith("+xml")
        ):
            return True

        text, _charset = self.decode_http_body((body or b"")[:4096], headers)
        bad = 0
        for char in text:
            if char in "\n\r\t":
                continue
            if ord(char) < 32:
                bad += 1
        return bad / max(1, len(text)) < 0.05

    def response_looks_text(self, probe):
        headers = probe.get("headers") or {}
        body = probe.get("body") or b""
        return self.body_looks_text(body, headers)

    def object_key_is_text(self, key):
        lowered = (key or "").lower().split("?", 1)[0]
        if lowered.endswith(BINARY_OBJECT_SUFFIXES):
            return False
        if lowered.endswith(TEXT_STATIC_SUFFIXES):
            return True
        return "." not in lowered.rsplit("/", 1)[-1]

    def object_url(self, target, key):
        quoted_key = quote(str(key).lstrip("/"), safe="/~!$&'()*+,;=:@")
        return f"{target.base_url.rstrip('/')}/{quoted_key}"

    def url_with_query(self, url, query):
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{query}"

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def lower_headers(self, headers):
        return {name.lower(): str(value) for name, value in self.header_items(headers)}

    def header_items(self, headers):
        if not headers:
            return []
        try:
            return list(headers.items())
        except AttributeError:
            return list(dict(headers).items())

    def headers_to_text(self, headers):
        return "\n".join(f"{name}: {value}" for name, value in self.header_items(headers))

    def copy_headers(self, headers):
        copied = {}
        for name, value in self.header_items(headers):
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

    def strip_secret_value(self, value):
        value = str(value or "").strip()
        value = value.strip("\"'`")
        value = value.rstrip(".,;)")
        return value

    def looks_like_secret(self, value, min_length=16):
        value = self.strip_secret_value(value)
        if len(value) < min_length:
            return False
        lowered = value.lower()
        if any(token in lowered for token in ("example", "your_", "your-", "xxxx", "****", "accesskeyid", "secretaccesskey")):
            return False
        if re.fullmatch(r"(?:0+|1+|1234567890|123456|abcdef|qwerty)", lowered):
            return False
        if re.fullmatch(r"[A-Za-z_-]+", value) and len(value) < 32:
            return False
        if len(set(value)) < min(8, len(value)):
            return False
        return True

    def mask_secret(self, value):
        value = self.strip_secret_value(value)
        if len(value) <= 10:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"
