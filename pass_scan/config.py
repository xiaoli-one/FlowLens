# 扫描器配置加载。
#
# config.yaml 控制全局调度行为，例如 worker 数、队列大小、去重时间等。

import os

import yaml


DEFAULT_IGNORED_HOSTS = [
    # Firefox 后台服务。
    "aus5.mozilla.org",
    "ads.mozilla.org",
    "push.services.mozilla.com",
    "firefox.settings.services.mozilla.com",
    "classify-client.services.mozilla.com",
    "contile.services.mozilla.com",
    "*.services.mozilla.com",
    "detectportal.firefox.com",
    "location.services.mozilla.com",
    "shavar.services.mozilla.com",
    "remote-settings.mozilla.org",
    "versioncheck.addons.mozilla.org",
    "crash-reports.mozilla.com",
    "telemetry.mozilla.org",
    "*.telemetry.mozilla.org",
    "cdn.mozilla.net",
    "*.cdn.mozilla.net",
    "mozilla-ohttp.fastly-edge.com",
    "mozilla.cloudflare-dns.com",

    # Chrome/Chromium 后台服务。
    "clients*.google.com",
    "safebrowsing.googleapis.com",
    "update.googleapis.com",
    "variations.google.com",
    "optimizationguide-pa.googleapis.com",
    "redirector.gvt1.com",
    "edgedl.me.gvt1.com",
    "dl.google.com",
    "mtalk.google.com",

    # Edge / Windows 浏览器后台服务。
    "edge.microsoft.com",
    "*.edge.microsoft.com",
    "msedge.api.cdp.microsoft.com",
    "iecvlist.microsoft.com",
    "nav-edge.smartscreen.microsoft.com",
    "browser.events.data.msn.com",
    "browser.pipe.aria.microsoft.com",
    "ntp.msn.com",
    "self.events.data.microsoft.com",
    "*.events.data.microsoft.com",
    "v10.events.data.microsoft.com",

    # Safari / Apple 后台服务。
    "configuration.apple.com",
    "configuration.ls.apple.com",
    "gsp-ssl.ls.apple.com",
    "mesu.apple.com",
    "swscan.apple.com",
    "swcdn.apple.com",
    "xp.apple.com",
    "ocsp.apple.com",
    "ocsp2.apple.com",
    "valid.apple.com",
    "safebrowsing.apple.com",
    "api.smoot.apple.com",

    # Brave 后台服务。
    "variations.brave.com",
    "componentupdater.brave.com",
    "go-updater.brave.com",
    "laptop-updates.brave.com",
    "safe-browsing.brave.com",
    "p3a.brave.com",
    "p3a-json.brave.com",
    "ads-serve.brave.com",
    "static.ads.brave.com",
    "grant.rewards.brave.com",

    # Opera 后台服务。
    "autoupdate.opera.com",
    "autoupdate.geo.opera.com",
    "features.opera-api.com",
    "sitecheck2.opera.com",
    "speeddials.opera.com",
    "news.opera-api.com",
    "crashreports.operacdn.com",

    # Vivaldi 后台服务。
    "update.vivaldi.com",
    "bifrost.vivaldi.com",

    # 系统网络探测/门户检测。
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
]


CONFIG_FILE = os.environ.get(
    "PASS_SCAN_CONFIG_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml"),
)


DEFAULT_CONFIG = {
    "scan": {
        "mode": "normal",
        "worker_count": 3,
        "queue_size": 200,
        "dedup_ttl_seconds": 1800,
        "per_host_interval_seconds": 0.2,
        "max_params_per_request": 8,
        "status_interval_seconds": 3,
        "full_payload_scan": False,
        "waf_backoff_seconds": 1800,
        "waf_max_block_attempts": 3,
        "ignored_hosts": DEFAULT_IGNORED_HOSTS,
    },
    "report": {
        "html_file": "report.html",
    },
    "verification": {
        "enabled": False,
        "worker_count": 2,
        "queue_size": 100,
        "output_file": os.path.join("logs", "verifications.jsonl"),
        "env_file": ".env",
        "llm_protocol": "openai",
        "max_rounds": 10,
        "max_requests_per_finding": 80,
        "request_timeout_seconds": 12,
        "llm_timeout_seconds": 60,
        "llm_max_tokens": 4096,
        "oob_wait_seconds": 30,
        "max_response_body_bytes": 262144,
        "observation_chars": 12000,
        "prompt_chars": 50000,
        "allowed_methods": ["GET", "POST", "HEAD", "PUT"],
    },
    "plugins": {
        "sql_injection": {
            "enabled": True,
            "deep_tamper": True,
            "deep_tamper_max_profiles": 4,
            "deep_tamper_methods": [
                "error_based",
                "boolean_based",
                "inline_query",
                "union_based",
                "stacked_query",
                "time_based",
            ],
        },
        "fingerprint": {
            "enabled": True,
            "path_segment_depth": 1,
            "max_paths_per_host": 25,
            "active_probe": True,
            "fetch_favicon": True,
            "output_file": os.path.join("logs", "fingerprints.jsonl"),
            "unknown_file": os.path.join("logs", "fingerprints_unknown.jsonl"),
        },
        "xss": {
            "enabled": True,
            "rescan": True,
        },
        "ssrf": {
            "enabled": True,
            "deep_tamper": True,
            "oob": {
                "enabled": True,
                "poll_interval": 15,
            },
        },
        "ssti": {
            "enabled": True,
            "deep_tamper": False,
            "deep_tamper_max_profiles": 2,
            "error_detection": True,
            "max_candidate_value_length": 2000,
        },
        "redir": {
            "enabled": True,
            "deep_tamper": True,
        },
        "sensitive_info": {
            "enabled": True,
            "active_probe": True,
            "path_segment_depth": 1,
            "max_scan_chars": 300000,
            "max_active_body_bytes": 262144,
        },
        "object_storage": {
            "enabled": True,
            "active_probe": True,
            "active_write_probe": True,
            "scan_listed_objects": True,
            "max_scan_chars": 400000,
            "max_active_body_bytes": 262144,
            "max_buckets_per_context": 8,
            "max_domains_per_context": 40,
            "max_listed_objects_scan": 12,
            "discovery_timeout": 4,
        },
        "file_upload": {
            "enabled": True,
            "deep_tamper": True,
            "max_original_body_bytes": 5242880,
            "max_payloads_per_candidate": 30,
            "max_verify_urls": 24,
            "upload_timeout_seconds": 10,
            "verify_timeout_seconds": 3,
            "allow_external_verification": True,
            "cleanup_uploaded_files": True,
        },
        "jwt": {
            "enabled": True,
            "active_probe": True,
            "weak_secret_scan": True,
            "claim_tamper": False,
            "algorithm_confusion_scan": False,
            "embedded_jwk_scan": False,
            "kid_injection_scan": False,
            "remote_key_fetch_scan": False,
            "jwks_discovery": False,
            "max_scan_chars": 400000,
            "max_tokens_per_context": 12,
            "max_secret_candidates": 160,
            "oob": {
                "enabled": False,
                "poll_interval": 15,
            },
        },
        "logic_agent": {
            "enabled": False,
            "worker_count": 1,
            "queue_size": 50,
            "output_file": os.path.join("logs", "logic_vulns.jsonl"),
            "sqlite_file": os.path.join("logs", "logic_pass_scan.db"),
            "env_file": ".env",
            "llm_protocol": "openai",
            "temperature": 0.1,
            "llm_timeout_seconds": 60,
            "llm_max_tokens": 4096,
            "request_timeout_seconds": 12,
            "max_response_body_bytes": 262144,
            "prompt_chars": 50000,
            "max_flows_per_endpoint": 30,
            "max_candidates_per_endpoint": 12,
            "max_http_requests_per_endpoint": 18,
            "max_candidates_per_detector": 2,
            "max_alternate_identities_per_candidate": 3,
            "max_agent_steps": 10,
            "max_http_requests_per_candidate": 6,
            "max_write_requests_per_candidate": 1,
            "max_investigation_seconds": 90,
            "postcondition_readback": True,
            "max_postcondition_checks_per_candidate": 2,
            "active_verification_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        },
    },
}


def deep_merge(base, override):
    """递归合并配置，用户只写想覆盖的字段即可。"""
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    """读取 config.yaml。文件不存在时使用默认配置。"""
    if not os.path.exists(CONFIG_FILE):
        config = deep_merge(DEFAULT_CONFIG, {})
    else:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            user_config = yaml.safe_load(file) or {}

        config = deep_merge(DEFAULT_CONFIG, user_config)

    env_full_payload_scan = os.environ.get("PASS_SCAN_FULL_PAYLOAD_SCAN")
    if env_full_payload_scan is not None:
        config["scan"]["full_payload_scan"] = env_full_payload_scan.lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

    return config
