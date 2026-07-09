# 漏洞报告输出。
#
# 扫描器发现漏洞后会先写 JSON Lines，方便程序继续处理；
# 同时重写一个静态 HTML 报告，方便直接用浏览器查看。

import html
import hashlib
import json
import os
import threading
from collections import Counter
from urllib.parse import urlsplit

from agent_pass_scan.finding_merge import merge_logic_result_list


METHOD_LABELS = {
    "error_based": "报错注入",
    "boolean_based": "布尔盲注",
    "inline_query": "内联查询",
    "union_based": "UNION 查询",
    "stacked_query": "堆叠查询",
    "time_based": "时间盲注",
    # XSS：三类合并为一个类型，用证据里的 origin/context/confidence 描述细节。
    "xss": "XSS",
    # 命令执行：回显/延时/带外三种检测方式合并为一种漏洞，用证据里的 technique 区分。
    "command_injection": "命令执行",
    # 任意文件读取：目录遍历 + 文件内容回显 + PHP 源码读取合并为一种漏洞，用 technique 区分。
    "path_traversal": "任意文件读取",
    # SSRF：只做带外（OOB）确认，用证据里的 technique（带外请求）与 confidence 描述。
    "ssrf": "SSRF",
    # XXE：带内文件读取 + 带外解析合并为一种漏洞，用证据里的 technique 区分。
    "xxe": "XXE",
    # SSTI：算术回显 / 字符串转换 / 模板错误合并为一种漏洞，用 technique 区分。
    "ssti": "SSTI",
    # redir：开放重定向 + CRLF/响应头注入合并为一种漏洞，用 technique 区分。
    "redir": "跳转/响应头注入",
    # sensitive_info：被动响应匹配 + 主动端点探测合并为一种漏洞，用 sensitive_type 区分。
    "sensitive_info": "敏感信息泄漏",
    # object_storage：桶发现 + 匿名列举/写入 + AK/SK 泄露。
    "object_storage_bucket": "存在存储桶",
    "object_storage_listable": "OSS 遍历",
    "object_storage_upload": "OSS 任意文件上传",
    "object_storage_overwrite": "OSS 任意文件覆盖",
    "object_storage_credential": "OSS AK/SK 泄露",
    # file_upload：脚本执行 / 危险扩展 / 主动内容 / .htaccess 统一为一种漏洞。
    "file_upload": "文件上传",
    # jwt：发现、配置风险、签名绕过、密钥/claim/远程 key 问题。
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

TYPE_LABELS = {
    "sql_injection": "SQL注入",
    "xss": "XSS",
    "command_injection": "命令执行",
    "path_traversal": "任意文件读取",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "ssti": "SSTI",
    "redir": "跳转/响应头注入",
    "sensitive_info": "敏感信息泄漏",
    "object_storage": "对象存储",
    "file_upload": "文件上传",
    "jwt": "JWT",
    "unauthorized": "未授权访问",
    "idor": "水平越权/IDOR",
    "vertical_authz": "垂直越权",
    "tenant_isolation": "租户隔离",
    "workflow_bypass": "流程绕过",
    "mass_assignment": "敏感字段绑定",
    "other_logic": "业务逻辑漏洞",
}

XSS_ORIGIN_LABELS = {
    "immediate": "反射型 XSS",
    "persisted": "存储型 XSS",
    "dom": "DOM 型 XSS",
}

# 这些漏洞类型本身是大类，具体命中方式写在 evidence.technique。
TECHNIQUE_DETAIL_TYPES = {
    "command_injection",
    "path_traversal",
    "ssrf",
    "xxe",
    "ssti",
    "redir",
    "file_upload",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "严重": "critical",
    "紧急": "critical",
    "高危": "high",
    "high": "high",
    "中危": "medium",
    "medium": "medium",
    "med": "medium",
    "低危": "low",
    "low": "low",
    "info": "info",
    "informational": "info",
    "信息": "info",
    "提示": "info",
}

DETAIL_SEVERITIES = {
    # SQL 注入小类。
    "报错注入": "high",
    "布尔盲注": "high",
    "内联查询": "high",
    "UNION 查询": "high",
    "堆叠查询": "high",
    "时间盲注": "high",
    # XSS 小类。
    "存储型 XSS": "high",
    "反射型 XSS": "medium",
    "DOM 型 XSS": "medium",
    # 命令执行 / SSTI。
    "命令回显": "critical",
    "命令延时": "critical",
    "命令带外": "critical",
    "算术回显": "critical",
    "字符串转换": "high",
    "模板错误": "low",
    # 文件读取 / SSRF / XXE。
    "文件内容回显": "high",
    "PHP 源码读取": "high",
    "带外请求": "high",
    "带内文件读取": "high",
    "带外解析": "high",
    # 跳转 / 响应头。
    "响应头注入": "medium",
    "开放重定向": "low",
    # 敏感信息。
    "配置文件泄露": "high",
    "AK/SK": "high",
    "地图 key": "medium",
    # 对象存储。
    "存在存储桶": "info",
    "OSS 遍历": "medium",
    "OSS 任意文件上传": "high",
    "OSS 任意文件覆盖": "high",
    "OSS AK/SK 泄露": "high",
    # 文件上传。
    "脚本文件执行": "critical",
    "中间件解析执行": "critical",
    ".htaccess 解析绕过": "critical",
    "危险扩展文件可上传": "high",
    ".htaccess 文件上传接受": "high",
    "主动内容文件可上传": "medium",
    "图片马可上传": "medium",
    "图片马上传接受": "medium",
    "基线文件上传": "low",
    "延迟上传结果发现": "low",
    # JWT。
    "JWT 敏感信息泄露": "high",
    "JWT 暴露风险": "medium",
    "JWT alg=none": "high",
    "JWT 签名未校验": "high",
    "JWT 弱 HMAC 密钥": "high",
    "JWT 算法混淆": "high",
    "JWT JWK 头信任": "high",
    "JWT 远程密钥获取": "medium",
    "JWT kid 注入": "high",
    "JWT Claim 篡改": "high",
    "JWT 时间 Claim 校验缺失": "medium",
    "JWT iss/aud 校验缺失": "medium",
}

EVIDENCE_LABELS = {
    "message": "判断依据",
    "payload": "命中 payload",
    "true_payload": "True payload",
    "false_payload": "False payload",
    "control_payload": "Control payload",
    "delay_payload": "Delay payload",
    "dbms": "数据库",
    "matched": "匹配指纹",
    "marker": "Marker",
    "payload_group": "Payload 组",
    "baseline_status": "Baseline 状态码",
    "probe_status": "探测状态码",
    "baseline_length": "Baseline 长度",
    "probe_length": "探测长度",
    "true_similarity": "True 相似度",
    "false_similarity": "False 相似度",
    "true_false_similarity": "True/False 相似度",
    "first_control_elapsed": "首次控制耗时",
    "first_delay_elapsed": "首次延时耗时",
    "second_control_elapsed": "二次控制耗时",
    "second_delay_elapsed": "二次延时耗时",
    "first_gap": "首次延时差",
    "second_gap": "二次延时差",
    "waf_bypass": "WAF 绕过",
    "tamper_profile": "Tamper 策略",
    "tampers": "Tamper 函数",
    "waf_reasons": "WAF 原因",
    # XSS 相关证据。
    "origin": "出现时机",
    "xss_context": "落点上下文",
    "matched_chars": "命中字符",
    "sample_exploit": "利用示例",
    "confidence": "置信度",
    "injected_url": "注入点 URL",
    "trigger_url": "触发点 URL",
    # 命令执行相关证据。
    "technique": "检测方式",
    "os": "操作系统",
    "expression": "算术表达式",
    "product": "期望乘积",
    "delay_seconds": "延时秒数",
    "delay_timed_out": "延时至超时",
    "oob_protocol": "带外协议",
    "oob_remote_address": "回连来源 IP",
    "oob_domain": "带外域名",
    # 任意文件读取相关证据。
    "target_file": "目标文件",
    "matched_content": "命中内容",
    # 开放重定向 / 响应头注入相关证据。
    "redirect_sink": "跳转位置",
    "location": "Location/Refresh",
    "resolved_url": "解析后 URL",
    "location_resolution": "解析方式",
    "header_name": "注入响应头",
    "header_value": "响应头值",
    # SSTI 相关证据。
    "template_family": "模板家族",
    "expected_output": "预期输出",
    "matched_output": "命中输出",
    "deep_tamper": "深度 Tamper",
    # 敏感信息泄漏相关证据。
    "sensitive_type": "敏感信息类型",
    "sources": "命中位置",
    "match_count": "命中数量",
    "subtypes": "细分类别",
    # 对象存储相关证据。
    "provider": "存储服务",
    "bucket": "存储桶",
    "endpoint": "桶地址",
    "bucket_source": "发现位置",
    "verified_url": "确认 URL",
    "region": "区域",
    "list_url": "列举 URL",
    "object_count": "对象数量",
    "object_samples": "对象样例",
    "object_key": "对象 Key",
    "object_url": "对象 URL",
    "verified": "内容校验",
    # 文件上传相关证据。
    "filename": "文件名",
    "content_type": "上传 Content-Type",
    "upload_status": "上传状态码",
    "access_status": "访问状态码",
    "access_content_type": "访问 Content-Type",
    "polyglot_marker": "图片马 Marker",
    "image_type": "图片类型",
    "htaccess_filename": ".htaccess 文件名",
    "handler_extension": "随机解析扩展",
    # JWT 相关证据。
    "jwt_location": "JWT 位置",
    "jwt_token_type": "Token 类型",
    "jwt_alg": "JWT alg",
    "jwt_original_alg": "原始 alg",
    "jwt_kid": "JWT kid",
    "jwt_typ": "JWT typ",
    "jwt_claims": "JWT Claims",
    "jwt_sensitive_claims": "敏感 Claim",
    "jwt_exposure": "暴露风险",
    "jwt_secret": "命中 Secret",
    "jwt_header_param": "Header 参数",
    "jwt_modified_claims": "篡改 Claim",
    "jwt_exp": "exp",
    "jwt_nbf": "nbf",
    "jwt_now": "当前时间",
    "control_status": "控制状态码",
}

PAYLOAD_KEYS = (
    "payload",
    "true_payload",
    "false_payload",
    "control_payload",
    "delay_payload",
)

REPORT_WRITE_LOCK = threading.Lock()

VERIFICATION_STATUS_LABELS = {
    "confirmed": "已确认",
    "likely": "基本确认",
    "false_positive": "疑似误报",
    "needs_manual_review": "需人工复核",
    "error": "验证异常",
}

VERIFICATION_CONFIDENCE_LABELS = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

LOGIC_STATUS_LABELS = {
    "confirmed": "已确认",
    "likely": "基本确认",
    "needs_manual_review": "需人工复核",
    "false_positive": "疑似误报",
    "error": "检测异常",
}


def write_jsonl(path, finding):
    """追加写入一条漏洞 JSON。"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as file:
        file.write(json.dumps(finding, ensure_ascii=False) + "\n")


def upsert_jsonl(path, record, key_field="finding_key", key_func=None):
    """按稳定 key 更新 JSONL；没有旧记录时追加。"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = key_func(record) if key_func else record.get(key_field)
    if not key:
        write_jsonl(path, record)
        return

    records = read_findings(path)
    replaced = False
    updated = []
    for item in records:
        item_key = key_func(item) if key_func and isinstance(item, dict) else item.get(key_field)
        if isinstance(item, dict) and item_key == key:
            if not replaced:
                updated.append(record)
                replaced = True
            continue
        updated.append(item)
    if not replaced:
        updated.append(record)

    with open(path, "w", encoding="utf-8") as file:
        for item in updated:
            file.write(json.dumps(item, ensure_ascii=False) + "\n")


def print_finding_once(scanner, finding):
    """同一个 finding 只打印一次，保证漏洞日志先于验证入队日志。"""
    if not finding or finding.get("_pass_scan_printed"):
        return False
    finding["_pass_scan_printed"] = True
    scanner.print_finding(finding)
    return True


def read_findings(path):
    """读取历史漏洞结果。"""
    findings = []
    if not os.path.exists(path):
        return findings

    def append_record(record):
        if isinstance(record, dict):
            findings.append(record)
            return
        if isinstance(record, list):
            for item in record:
                append_record(item)

    with open(path, "r", encoding="utf-8") as file:
        content = file.read()

    stripped = content.strip()
    if not stripped:
        return findings

    if stripped.startswith("["):
        try:
            append_record(json.loads(stripped))
            return findings
        except json.JSONDecodeError:
            pass

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            append_record(json.loads(line))
        except json.JSONDecodeError:
            continue

    return findings


def escape(value):
    if value is None:
        value = ""
    return html.escape(str(value), quote=True)


def method_label(method):
    return METHOD_LABELS.get(method, method or "未知方法")


def type_label(vuln_type):
    return TYPE_LABELS.get(vuln_type, method_label(vuln_type))


def finding_detail_label(finding):
    """详情卡片标题用的小分类；没有小分类时回退到漏洞大类。"""
    evidence = finding.get("evidence", {}) or {}
    method = finding.get("method", "")
    vuln_type = finding.get("type", "")

    if method and method != vuln_type:
        return method_label(method)

    if vuln_type == "sensitive_info":
        return evidence.get("sensitive_type") or type_label(vuln_type)

    if vuln_type == "xss":
        return XSS_ORIGIN_LABELS.get(evidence.get("origin")) or type_label(vuln_type)

    if vuln_type in TECHNIQUE_DETAIL_TYPES:
        return evidence.get("technique") or type_label(vuln_type)

    return type_label(vuln_type or method)


def normalize_severity(value):
    if value is None:
        return ""
    return SEVERITY_ALIASES.get(str(value).strip().lower(), "")


def finding_severity(finding):
    """报告用危害等级；优先读 finding 显式字段，没有则按小分类推断。"""
    evidence = finding.get("evidence", {}) or {}
    for key in ("severity", "risk"):
        severity = normalize_severity(finding.get(key))
        if severity:
            return severity
        severity = normalize_severity(evidence.get(key))
        if severity:
            return severity

    vuln_type = finding.get("type", "")
    method = finding.get("method", "")
    detail_label = finding_detail_label(finding)
    if detail_label in DETAIL_SEVERITIES:
        return DETAIL_SEVERITIES[detail_label]

    technique = str(evidence.get("technique", ""))
    sensitive_type = str(evidence.get("sensitive_type", ""))
    for value in (technique, sensitive_type):
        if value in DETAIL_SEVERITIES:
            return DETAIL_SEVERITIES[value]

    # 兜底逻辑只在没有可识别小分类时使用。
    if vuln_type in ("command_injection", "ssti"):
        return "critical"
    if vuln_type in ("sql_injection", "path_traversal", "ssrf", "xxe"):
        return "high"

    if vuln_type == "file_upload":
        if any(word in technique for word in ("执行", "解析绕过")):
            return "critical"
        if any(word in technique for word in ("危险扩展", ".htaccess")):
            return "high"
        if any(word in technique for word in ("主动内容", "图片马")):
            return "medium"
        return "medium"

    if vuln_type == "jwt":
        if method in (
            "jwt_none_alg",
            "jwt_signature_bypass",
            "jwt_weak_secret",
            "jwt_algorithm_confusion",
            "jwt_embedded_jwk",
            "jwt_kid_injection",
            "jwt_claim_tamper",
        ):
            return "high"
        if method in ("jwt_remote_key_fetch", "jwt_time_claim", "jwt_issuer_audience"):
            return "medium"
        return "medium"

    if vuln_type == "xss":
        if evidence.get("origin") == "persisted":
            return "high"
        if evidence.get("confidence") == "suspected":
            return "low"
        return "medium"

    if vuln_type == "sensitive_info":
        if any(word in sensitive_type for word in ("AK/SK", "密钥", "Secret", "Token", "配置")):
            return "high"
        return "medium"

    if vuln_type == "object_storage":
        return "info"

    if vuln_type == "redir":
        if technique == "响应头注入":
            return "medium"
        return "low"

    return "medium"


def host_for(finding):
    return urlsplit(finding.get("url", "")).netloc or "unknown"


def path_for(finding):
    parts = urlsplit(finding.get("url", ""))
    path = parts.path or "/"
    if parts.query:
        return f"{path}?{parts.query}"
    return path


def primary_payload(evidence):
    for key in PAYLOAD_KEYS:
        value = evidence.get(key)
        if value:
            return str(value)
    return ""


def report_finding_key(finding):
    """与主动验证队列一致的漏洞稳定 key，用于报告内跳转关联。"""
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


def fallback_finding_match_key(finding):
    """旧验证记录可能没有完整 evidence，退化用漏洞位置字段做报告内关联。"""
    material = {
        "type": finding.get("type"),
        "method": finding.get("method"),
        "request_method": finding.get("request_method"),
        "url": finding.get("url"),
        "param_place": finding.get("param_place"),
        "param_name": finding.get("param_name"),
    }
    if not any(value not in (None, "") for value in material.values()):
        return ""
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def render_value(value):
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "-"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    if value is None or value == "":
        return "-"
    return str(value)


def render_pre(value, element_id=""):
    """把文本安全地放进 HTML pre 标签。"""
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2)
    value = printable_report_text(value)
    id_attr = f' id="{escape(element_id)}"' if element_id else ""
    return f"<pre{id_attr}>{escape(value)}</pre>"


def printable_report_text(value):
    """HTML 报告展示层保留内容，但把不可显示控制字符转成可读转义。"""
    chars = []
    for char in str(value):
        code = ord(char)
        if char in "\n\r\t":
            chars.append(char)
            continue
        if code >= 32 and code != 127 and not 128 <= code <= 159:
            chars.append(char)
            continue
        chars.append(f"\\x{code:02x}")
    return "".join(chars)


def split_http_message(message):
    message = "" if message is None else str(message)
    if "\r\n\r\n" in message:
        return message.split("\r\n\r\n", 1)
    if "\n\n" in message:
        return message.split("\n\n", 1)
    return message, ""


def looks_like_legacy_compressed_response(message):
    head, body = split_http_message(message)
    if "content-encoding:" not in head.lower():
        return False
    if not any(
        marker in head.lower()
        for marker in ("content-encoding: gzip", "content-encoding: deflate", "content-encoding: br")
    ):
        return False
    if "\ufffd" in body or body.startswith("\x1f"):
        return True

    if not body:
        return False
    bad_chars = sum(
        1
        for char in body[:1000]
        if char not in "\n\r\t" and (ord(char) < 32 or ord(char) == 127)
    )
    return bad_chars / min(len(body), 1000) > 0.05


def render_logic_observation_response(observation):
    response = observation.get("response", "") if observation else ""
    if not looks_like_legacy_compressed_response(response):
        return response

    head, _body = split_http_message(response)
    baseline = observation.get("baseline_response_excerpt") or ""
    notice = (
        "[历史记录提示] 这条响应体是在旧版本中以压缩字节写入 JSONL 的，"
        "原始字节已被替换字符破坏，无法从现有日志精确恢复。"
        "当前版本已修复主动验证响应解压与 charset 解码；重新运行逻辑验证后会显示完整响应体。"
    )
    if baseline:
        return f"{head}\r\n\r\n{notice}\r\n\r\n[基线响应预览]\r\n{baseline}"
    return f"{head}\r\n\r\n{notice}"


def render_logic_packet_chain(packets, item_id):
    packet_html = []
    for packet_index, packet in enumerate(packets or [], start=1):
        title = packet.get("name") or packet.get("purpose") or f"利用链数据包 {packet_index}"
        proof = {
            "request": packet.get("request", ""),
            "response": render_logic_observation_response(packet),
        }
        packet_html.append(
            render_proof(
                title,
                proof,
                f"{item_id}-chain-{packet_index}",
            )
        )
    return "".join(packet_html)


def logic_exploit_chain_for(result):
    chain = result.get("logic_exploit_chain") or {}
    if isinstance(chain, dict) and chain:
        return chain
    packets = result.get("logic_chain_packets") or []
    if not packets:
        return {}
    return {
        "title": "历史利用链数据包",
        "status": "confirmed" if result.get("status") == "confirmed" else "partial",
        "complete": result.get("status") == "confirmed",
        "summary": result.get("summary") or "",
        "missing_evidence": [] if result.get("status") == "confirmed" else ["历史记录缺少结构化链路状态，需结合数据包人工确认。"],
        "steps": packets,
    }


def render_logic_chain_status(chain):
    status = chain.get("status") or "partial"
    if chain.get("complete") and status == "confirmed":
        return "已确认"
    labels = {
        "confirmed": "已确认",
        "likely": "基本确认",
        "partial": "证据不足",
        "needs_manual_review": "证据不足",
        "false_positive": "非漏洞",
    }
    return labels.get(status, status)


def render_logic_exploit_chain(chain, item_id):
    if not chain:
        return ""

    missing = chain.get("missing_evidence") or []
    steps = chain.get("steps") or []
    missing_html = ""
    if missing:
        missing_html = f"""
        <h3>待补强证据</h3>
        {render_list(missing)}
        """

    return f"""
    <section class="logic-chain-box">
      <dl class="meta-grid">
        <div><dt>利用链状态</dt><dd>{escape(render_logic_chain_status(chain))}</dd></div>
        <div><dt>链路完整</dt><dd>{escape('是' if chain.get('complete') else '否')}</dd></div>
        <div><dt>验证方式</dt><dd>{escape(chain.get('verification_kind') or '-')}</dd></div>
      </dl>
      {('<p class="verification-summary">' + escape(chain.get('summary') or '') + '</p>') if chain.get('summary') else ''}
      {missing_html}
      <h3>链路数据包</h3>
      {render_logic_packet_chain(steps, item_id) or '<p class="muted">暂无链路数据包。</p>'}
    </section>
    """


def render_evidence(evidence):
    if not evidence:
        return '<p class="muted">暂无结构化证据。</p>'

    rows = []
    for key, value in evidence.items():
        rows.append(
            "<tr>"
            f"<th>{escape(EVIDENCE_LABELS.get(key, key))}</th>"
            f"<td>{escape(render_value(value))}</td>"
            "</tr>"
        )

    return f"""
    <table class="evidence">
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def render_proof(title, proof, proof_id):
    request_id = f"{proof_id}-request"
    response_id = f"{proof_id}-response"
    request_text = proof.get("request", "") if proof else ""
    response_text = proof.get("response", "") if proof else ""

    return f"""
    <details class="proof">
      <summary>
        <span>{escape(title)}</span>
        <span class="proof-actions">
          <button type="button" data-copy="{escape(request_id)}">复制请求</button>
          <button type="button" data-copy="{escape(response_id)}">复制响应</button>
        </span>
      </summary>
      <div class="proof-grid">
        <section>
          <h4>请求包</h4>
          {render_pre(request_text, request_id)}
        </section>
        <section>
          <h4>响应包</h4>
          {render_pre(response_text, response_id)}
        </section>
      </div>
    </details>
    """


def render_finding(finding, index, verification_lookup=None):
    """渲染单个漏洞块。"""
    evidence = finding.get("evidence", {})
    method = finding.get("method", "")
    vuln_type = finding.get("type", "")
    detail_label = finding_detail_label(finding)
    severity = finding_severity(finding)
    parameter = f"{finding.get('param_place', '')}.{finding.get('param_name', '')}"
    payload = primary_payload(evidence)
    proof = finding.get("proof", {})
    extra_proofs = finding.get("extra_proofs", [])
    item_id = f"finding-{index}"
    finding_key = report_finding_key(finding)
    match_key = fallback_finding_match_key(finding)
    verification_key = verification_link_key_for(finding, verification_lookup or set())

    payload_html = ""
    if payload:
        payload_html = f"""
        <div class="payload">
          <span>Payload</span>
          <code>{escape(payload)}</code>
        </div>
        """

    extra_html = []
    for extra_index, extra in enumerate(extra_proofs, start=1):
        extra_html.append(
            render_proof(
                extra.get("name", "补充证据"),
                extra,
                f"{item_id}-extra-{extra_index}",
            )
        )

    if verification_key:
        verification_link_html = (
            f'<a class="verify-link" href="#verify:{escape(verification_key)}" '
            f'data-open-verification="{escape(verification_key)}">查看验证详情</a>'
        )
    else:
        verification_link_html = '<span class="verify-link verify-link-muted">暂无验证结果</span>'

    return f"""
    <details class="finding" data-type="{escape(vuln_type)}" data-host="{escape(host_for(finding))}" data-finding-key="{escape(finding_key)}" data-match-key="{escape(match_key)}">
      <summary class="finding-head">
        <div>
          <div class="badges">
            <span class="badge risk risk-{escape(severity)}">{escape(SEVERITY_LABELS[severity])}</span>
            <span class="badge method">{escape(detail_label)}</span>
            <span class="badge param">{escape(parameter)}</span>
          </div>
          <h2>#{index} {escape(type_label(vuln_type))}</h2>
          <p class="target">
            <span class="target-method">{escape(finding.get('request_method', ''))}</span>
            <span class="target-host">{escape(host_for(finding))}</span><span class="target-path">{escape(path_for(finding))}</span>
          </p>
        </div>
        <div class="finding-head-side">
          {verification_link_html}
          <time>{escape(finding.get('time', ''))}</time>
        </div>
      </summary>

      <div class="finding-body">
        <dl class="meta-grid">
          <div><dt>目标</dt><dd>{escape(host_for(finding))}</dd></div>
          <div><dt>参数</dt><dd>{escape(parameter)}</dd></div>
          <div><dt>类型</dt><dd>{escape(type_label(vuln_type))}</dd></div>
          <div><dt>完整 URL</dt><dd>{escape(finding.get('url', ''))}</dd></div>
        </dl>

        {payload_html}

        <h3>证据摘要</h3>
        {render_evidence(evidence)}

        {render_proof("验证请求与响应", proof, item_id)}
        {''.join(extra_html)}
      </div>
    </details>
    """


def render_stat(label, value):
    return f"""
    <div class="stat">
      <strong>{escape(value)}</strong>
      <span>{escape(label)}</span>
    </div>
    """


def render_distribution(title, items, filter_type=""):
    total = sum(count for _label, count, _value in items) or 1
    rows = []
    for label, count, value in items:
        width = max(6, int(count / total * 100))
        attrs = ""
        tag = "div"
        if filter_type and value:
            tag = "button"
            attrs = (
                ' type="button"'
                f' data-dist-filter="{escape(filter_type)}"'
                f' data-dist-value="{escape(value)}"'
                ' aria-pressed="false"'
            )
        rows.append(
            f"""
            <{tag} class="dist-row"{attrs}>
              <span>{escape(label)}</span>
              <div class="bar"><i style="width: {width}%"></i></div>
              <strong>{count}</strong>
            </{tag}>
            """
        )

    return f"""
    <section class="panel">
      <h2>{escape(title)}</h2>
      {''.join(rows) or '<p class="muted">暂无数据。</p>'}
    </section>
    """


def render_type_options(type_counts):
    options = ['<option value="">全部类型</option>']
    for vuln_type, _count in type_counts:
        options.append(
            f'<option value="{escape(vuln_type)}">{escape(type_label(vuln_type))}</option>'
        )
    return "\n".join(options)


def render_host_options(host_counts):
    options = ['<option value="">全部目标</option>']
    for host, _count in host_counts:
        options.append(
            f'<option value="{escape(host)}">{escape(host)}</option>'
        )
    return "\n".join(options)


def build_summary(findings):
    type_counts = Counter(
        finding.get("type") or finding.get("method") or "unknown"
        for finding in findings
    )
    host_counts = Counter(host_for(finding) for finding in findings)
    return {
        "types": type_counts.most_common(),
        "hosts": host_counts.most_common(8),
        "host_total": len(host_counts),
        # 供筛选下拉用的全部 host（不像概览只取前 8），按命中数排序。
        "all_hosts": host_counts.most_common(),
        "latest_time": findings[0].get("time", "-") if findings else "-",
    }


# ----------------------------------------------------------------------
# 指纹识别结果渲染（报告里的“指纹”标签页）
# ----------------------------------------------------------------------

def fingerprint_path_for(vuln_jsonl_path):
    """根据漏洞 jsonl 路径推导指纹 jsonl 路径（同目录 fingerprints.jsonl）。"""
    directory = os.path.dirname(vuln_jsonl_path) or "."
    return os.path.join(directory, "fingerprints.jsonl")


def logic_path_for(vuln_jsonl_path):
    """根据漏洞 jsonl 路径推导逻辑漏洞 jsonl 路径（同目录 logic_vulns.jsonl）。"""
    directory = os.path.dirname(vuln_jsonl_path) or "."
    return os.path.join(directory, "logic_vulns.jsonl")


def read_fingerprint_hosts(path):
    """读取 fingerprints.jsonl，按 host 聚合。

    返回 [{host, paths:[...], techs:{name:{...}}}]，按最后命中时间降序排序。
    techs 跨路径合并同名指纹。
    """
    records = read_findings(path)  # 复用 jsonl 读取
    hosts = {}

    for record in records:
        host = record.get("host", "unknown")
        host_entry = hosts.setdefault(
            host,
            {"host": host, "paths": [], "techs": {}, "latest_time": ""},
        )
        record_time = record.get("time", "")
        if record_time and record_time > host_entry["latest_time"]:
            host_entry["latest_time"] = record_time
        path_label = record.get("path", "/")
        if path_label not in host_entry["paths"]:
            host_entry["paths"].append(path_label)

        for fingerprint in record.get("fingerprints", []):
            name = fingerprint.get("name", "")
            if not name:
                continue
            tech = host_entry["techs"].setdefault(
                name,
                {
                    "name": name,
                    "category": fingerprint.get("category", ""),
                    "version": "",
                    "implied_by": fingerprint.get("implied_by", ""),
                    "paths": set(),
                    "latest_time": "",
                },
            )
            if not tech["version"] and fingerprint.get("version"):
                tech["version"] = fingerprint["version"]
            if record_time and record_time > tech["latest_time"]:
                tech["latest_time"] = record_time
            tech["paths"].add(path_label)

    host_entries = sorted(hosts.values(), key=lambda item: item["host"].lower())
    return sorted(
        host_entries,
        key=lambda item: str(item.get("latest_time") or ""),
        reverse=True,
    )


def build_fingerprint_summary(fp_hosts):
    """指纹标签页的概览统计。"""
    fingerprint_counts = Counter()
    host_counts = Counter()
    tech_total = 0
    latest_time = ""
    for host_entry in fp_hosts:
        host_total = len(host_entry["techs"])
        host_counts[host_entry["host"]] = host_total
        if host_entry.get("latest_time", "") > latest_time:
            latest_time = host_entry["latest_time"]
        for tech in host_entry["techs"].values():
            fingerprint_counts[tech["name"]] += 1
            tech_total += 1
    return {
        "host_count": len(fp_hosts),
        "tech_total": tech_total,
        "fingerprints": fingerprint_counts.most_common(),
        "hosts": host_counts.most_common(8),
        "latest_time": latest_time or "-",
    }


def render_fingerprint_host(host_entry, index):
    """渲染指纹标签页里的单个 host 卡片。"""
    techs = sorted(
        host_entry["techs"].values(),
        key=lambda item: item["name"].lower(),
    )
    techs = sorted(
        techs,
        key=lambda item: str(item.get("latest_time") or ""),
        reverse=True,
    )

    chips = []
    for tech in techs:
        version = f" {tech['version']}" if tech["version"] else ""
        implied = ' title="由其它指纹推导"' if tech["implied_by"] else ""
        paths = ", ".join(sorted(tech["paths"]))
        chips.append(
            f'<span class="fp-chip"{implied} data-paths="{escape(paths)}">'
            f'<b>{escape(tech["name"])}{escape(version)}</b>'
            f"</span>"
        )

    path_list = ", ".join(escape(p) for p in host_entry["paths"])
    open_attr = "open" if index <= 8 else ""

    # data-techs：本 host 所有指纹名，用 | 包裹分隔，供 JS 按指纹精确筛选。
    techs_attr = "|" + "|".join(tech["name"] for tech in techs) + "|"

    return f"""
    <details class="fp-host" data-host="{escape(host_entry['host'])}" data-techs="{escape(techs_attr)}" {open_attr}>
      <summary class="fp-host-head">
        <div>
          <h2>{escape(host_entry['host'])}</h2>
          <p class="fp-paths">识别路径: {path_list}</p>
        </div>
        <time>{escape(host_entry.get("latest_time") or "-")}</time>
        <span class="fp-count">{len(techs)} 项</span>
      </summary>
      <div class="fp-chips">{''.join(chips) or '<span class="muted">无</span>'}</div>
    </details>
    """


def render_fp_host_options(fp_hosts):
    """指纹页“目标”下拉：纯 host 列表。"""
    options = ['<option value="">全部目标</option>']
    for host_entry in fp_hosts:
        host = host_entry["host"]
        options.append(f'<option value="{escape(host)}">{escape(host)}</option>')
    return "\n".join(options)


def render_fp_tech_options(fp_hosts):
    """指纹页“指纹”下拉：所有 host 里出现过的指纹名（去重、按名排序）。"""
    names = set()
    for host_entry in fp_hosts:
        names.update(host_entry["techs"].keys())
    options = ['<option value="">全部指纹</option>']
    for name in sorted(names, key=lambda s: s.lower()):
        options.append(f'<option value="{escape(name)}">{escape(name)}</option>')
    return "\n".join(options)


def render_fingerprint_section(fp_hosts):
    """渲染整个指纹标签页内容（概览 + host 列表）。"""
    summary = build_fingerprint_summary(fp_hosts)

    cards = "\n".join(
        render_fingerprint_host(host_entry, index)
        for index, host_entry in enumerate(fp_hosts, start=1)
    )
    return f"""
    <section class="stats" aria-label="指纹概览">
      {render_stat("识别目标", summary["host_count"])}
      {render_stat("指纹总数", summary["tech_total"])}
      {render_stat("指纹种类", len(summary["fingerprints"]))}
      {render_stat("最后命中", summary["latest_time"])}
    </section>
    <section class="toolbar">
      <input id="fpSearch" type="search" placeholder="搜索 host、框架、服务">
      <select id="fpHostFilter">
        {render_fp_host_options(fp_hosts)}
      </select>
      <select id="fpTechFilter">
        {render_fp_tech_options(fp_hosts)}
      </select>
      <span class="visible-count">显示 <strong id="fpVisibleCount">{len(fp_hosts)}</strong> / {len(fp_hosts)}</span>
    </section>
    <div id="fpHosts">
      {cards or '<section class="empty">暂未识别到指纹。</section>'}
    </div>
    <section id="fpEmptyFiltered" hidden>当前筛选条件下没有匹配结果。</section>
    """


# ----------------------------------------------------------------------
# 主动验证结果渲染（报告里的“验证”标签页）
# ----------------------------------------------------------------------

def verification_path_for(vuln_jsonl_path):
    """根据漏洞 jsonl 路径推导验证结果 jsonl 路径（同目录 verifications.jsonl）。"""
    directory = os.path.dirname(vuln_jsonl_path) or "."
    return os.path.join(directory, "verifications.jsonl")


def verification_status_label(status):
    return VERIFICATION_STATUS_LABELS.get(status, status or "未知")


def verification_confidence_label(confidence):
    return VERIFICATION_CONFIDENCE_LABELS.get(confidence, confidence or "-")


def verification_source(result):
    return result.get("source", {}) or {}


def verification_result_key(result):
    source = verification_source(result)
    return result.get("finding_key") or source.get("finding_key") or ""


def verification_lookup_keys(result):
    source = verification_source(result)
    keys = []
    primary_key = verification_result_key(result)
    if primary_key:
        keys.append(primary_key)
    fallback_key = fallback_finding_match_key(source)
    if fallback_key and fallback_key not in keys:
        keys.append(fallback_key)
    return keys


def build_verification_lookup(results):
    lookup = set()
    for result in results:
        lookup.update(verification_lookup_keys(result))
    return lookup


def verification_link_key_for(finding, verification_lookup):
    keys = [report_finding_key(finding), fallback_finding_match_key(finding)]
    for key in keys:
        if key in verification_lookup:
            return key
    return ""


def verification_host_for(result):
    source = verification_source(result)
    return urlsplit(source.get("url", "")).netloc or "unknown"


def verification_path_label(result):
    source = verification_source(result)
    parts = urlsplit(source.get("url", ""))
    path = parts.path or "/"
    if parts.query:
        return f"{path}?{parts.query}"
    return path


def render_list(items, empty_text="暂无。"):
    if not items:
        return f'<p class="muted">{escape(empty_text)}</p>'
    rows = []
    for item in items:
        rows.append(f"<li>{escape(render_value(item))}</li>")
    return f"<ol class=\"chain\">{''.join(rows)}</ol>"


# ----------------------------------------------------------------------
# Agent 逻辑漏洞结果渲染（报告里的“逻辑漏洞”标签页）
# ----------------------------------------------------------------------

def logic_status_label(status):
    return LOGIC_STATUS_LABELS.get(status, status or "未知")


def logic_host_for(result):
    return result.get("host") or urlsplit(result.get("url", "")).netloc or "unknown"


def logic_path_label(result):
    endpoint = result.get("endpoint") or ""
    if endpoint:
        return endpoint
    parts = urlsplit(result.get("url", ""))
    path = parts.path or "/"
    if parts.query:
        return f"{path}?{parts.query}"
    return path


def build_logic_summary(results):
    status_counts = Counter(result.get("status") or "unknown" for result in results)
    type_counts = Counter(result.get("type") or "other_logic" for result in results)
    host_counts = Counter(logic_host_for(result) for result in results)
    return {
        "statuses": status_counts.most_common(),
        "types": type_counts.most_common(),
        "hosts": host_counts.most_common(),
        "host_total": len(host_counts),
        "confirmed": status_counts.get("confirmed", 0) + status_counts.get("likely", 0),
        "latest_time": results[0].get("time", "-") if results else "-",
    }


def render_logic_status_options(status_counts):
    options = ['<option value="">全部状态</option>']
    for status, _count in status_counts:
        options.append(
            f'<option value="{escape(status)}">{escape(logic_status_label(status))}</option>'
        )
    return "\n".join(options)


def render_logic_type_options(type_counts):
    options = ['<option value="">全部类型</option>']
    for vuln_type, _count in type_counts:
        options.append(
            f'<option value="{escape(vuln_type)}">{escape(type_label(vuln_type))}</option>'
        )
    return "\n".join(options)


def render_logic_host_options(host_counts):
    options = ['<option value="">全部目标</option>']
    for host, _count in host_counts:
        options.append(f'<option value="{escape(host)}">{escape(host)}</option>')
    return "\n".join(options)


def render_logic_result(result, index):
    status = result.get("status", "needs_manual_review")
    confidence = result.get("confidence", "")
    vuln_type = result.get("type", "other_logic")
    severity = normalize_severity(result.get("severity")) or "medium"
    item_id = f"logic-{index}"
    observations = result.get("verification_observations") or []
    exploit_chain = logic_exploit_chain_for(result)
    chain_html = render_logic_exploit_chain(exploit_chain, item_id)

    observation_html = []
    for observation_index, observation in enumerate(observations, start=1):
        title = observation.get("purpose") or f"差分验证请求 {observation_index}"
        proof = {
            "request": observation.get("request", ""),
            "response": render_logic_observation_response(observation),
        }
        observation_html.append(
            render_proof(
                title,
                proof,
                f"{item_id}-observation-{observation_index}",
            )
        )

    return f"""
    <details class="logic-finding" data-status="{escape(status)}" data-type="{escape(vuln_type)}" data-host="{escape(logic_host_for(result))}">
      <summary class="finding-head">
        <div>
          <div class="badges">
            <span class="badge status status-{escape(status)}">{escape(logic_status_label(status))}</span>
            <span class="badge risk risk-{escape(severity)}">{escape(SEVERITY_LABELS[severity])}</span>
            <span class="badge method">{escape(type_label(vuln_type))}</span>
            <span class="badge confidence">置信度 {escape(verification_confidence_label(confidence))}</span>
          </div>
          <h2>#{index} {escape(result.get('title') or type_label(vuln_type))}</h2>
          <p class="target">
            <span class="target-method">{escape(result.get('method', ''))}</span>
            <span class="target-host">{escape(logic_host_for(result))}</span><span class="target-path">{escape(logic_path_label(result))}</span>
          </p>
        </div>
        <time>{escape(result.get('time', ''))}</time>
      </summary>

      <div class="finding-body">
        <dl class="meta-grid">
          <div><dt>检测状态</dt><dd>{escape(logic_status_label(status))}</dd></div>
          <div><dt>类型</dt><dd>{escape(type_label(vuln_type))}</dd></div>
          <div><dt>主动验证</dt><dd>{escape('是' if result.get('verified') else '否/需复核')}</dd></div>
          <div><dt>模型</dt><dd>{escape(result.get('model') or '-')}</dd></div>
          <div><dt>目标</dt><dd>{escape(logic_host_for(result))}</dd></div>
          <div><dt>接口</dt><dd>{escape(logic_path_label(result))}</dd></div>
          <div><dt>SQLite</dt><dd>{escape(result.get('sqlite_file') or '-')}</dd></div>
          <div><dt>候选来源</dt><dd>{escape(result.get('detector') or '-')}</dd></div>
        </dl>

        <h3>Agent 结论</h3>
        <p class="verification-summary">{escape(result.get('summary') or '-')}</p>

        <h3>安全影响</h3>
        <p class="verification-summary">{escape(result.get('impact') or '-')}</p>

        <h3>证据</h3>
        {render_list(result.get("evidence") or [], "暂无结构化证据。")}

        <h3>安全边界说明</h3>
        <p class="verification-summary">{escape(result.get('safety_notes') or '-')}</p>

        <h3>完整利用链数据包</h3>
        {chain_html or ''.join(observation_html) or '<p class="muted">暂无主动差分请求，结果来自被动上下文分析。</p>'}
      </div>
    </details>
    """


def render_logic_section(results):
    summary = build_logic_summary(results)
    cards = "\n".join(
        render_logic_result(result, index)
        for index, result in enumerate(results, start=1)
    )

    return f"""
    <section class="stats" aria-label="逻辑漏洞概览">
      {render_stat("逻辑风险", len(results))}
      {render_stat("已确认/基本确认", summary["confirmed"])}
      {render_stat("影响目标", summary["host_total"])}
      {render_stat("最后检测", summary["latest_time"])}
    </section>

    <section class="toolbar" aria-label="逻辑漏洞筛选">
      <input id="logicSearch" type="search" placeholder="搜索 URL、业务对象、证据、利用链">
      <select id="logicStatusFilter">
        {render_logic_status_options(summary["statuses"])}
      </select>
      <select id="logicTypeFilter">
        {render_logic_type_options(summary["types"])}
      </select>
      <select id="logicHostFilter">
        {render_logic_host_options(summary["hosts"])}
      </select>
      <span class="visible-count">显示 <strong id="logicVisibleCount">{len(results)}</strong> / {len(results)}</span>
    </section>

    <div id="logicFindings">
      {cards or '<section class="empty">暂未产生逻辑漏洞结果。使用 --logic 启动后才会调用 Agent 检测。</section>'}
    </div>
    <section id="logicEmptyFiltered" hidden>当前筛选条件下没有匹配结果。</section>
    """


def render_verification_payloads(payloads):
    if not payloads:
        return '<p class="muted">暂无结构化 payload。</p>'

    rows = []
    for payload in payloads:
        if isinstance(payload, dict):
            step = payload.get("step") or payload.get("name") or "-"
            value = payload.get("payload") or payload.get("value") or ""
            purpose = payload.get("purpose") or payload.get("result") or ""
        else:
            step = "-"
            value = payload
            purpose = ""
        purpose_html = f'<p class="muted">{escape(purpose)}</p>' if purpose else ""
        rows.append(
            "<tr>"
            f"<th>{escape(step)}</th>"
            f"<td><code>{escape(value)}</code>{purpose_html}</td>"
            "</tr>"
        )
    return f"""
    <table class="evidence payload-table">
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def render_verification_result(result, index):
    source = verification_source(result)
    vuln_type = source.get("type", "")
    status = result.get("status", "needs_manual_review")
    confidence = result.get("confidence", "")
    item_id = f"verification-{index}"
    finding_key = verification_result_key(result)
    match_key = fallback_finding_match_key(source)
    param = f"{source.get('param_place', '')}.{source.get('param_name', '')}"
    requests = result.get("requests", []) or []
    successful_request_ids = set(result.get("successful_request_ids") or [])
    successful_requests = result.get("successful_requests") or [
        request_result
        for request_result in requests
        if request_result.get("action_id") in successful_request_ids
    ]

    success_html = []
    for request_index, request_result in enumerate(successful_requests, start=1):
        title = (
            request_result.get("chain_step")
            or request_result.get("purpose")
            or f"成功利用数据包 {request_index}"
        )
        proof = {
            "request": request_result.get("request", ""),
            "response": request_result.get("response", ""),
        }
        success_html.append(
            render_proof(
                f"成功利用数据包 {request_index}: {title}",
                proof,
                f"{item_id}-success-{request_index}",
            )
        )

    request_html = []
    for request_index, request_result in enumerate(requests, start=1):
        title = (
            request_result.get("chain_step")
            or request_result.get("purpose")
            or f"主动验证请求 {request_index}"
        )
        proof = {
            "request": request_result.get("request", ""),
            "response": request_result.get("response", ""),
        }
        request_html.append(
            render_proof(
                title,
                proof,
                f"{item_id}-request-{request_index}",
            )
        )

    return f"""
    <details class="verification" id="{escape(item_id)}" data-status="{escape(status)}" data-type="{escape(vuln_type)}" data-host="{escape(verification_host_for(result))}" data-finding-key="{escape(finding_key)}" data-match-key="{escape(match_key)}">
      <summary class="finding-head">
        <div>
          <div class="badges">
            <span class="badge status status-{escape(status)}">{escape(verification_status_label(status))}</span>
            <span class="badge method">{escape(type_label(vuln_type))}</span>
            <span class="badge param">{escape(param)}</span>
            <span class="badge confidence">置信度 {escape(verification_confidence_label(confidence))}</span>
          </div>
          <h2>#{index} {escape(result.get('exploitability') or 'verification')}</h2>
          <p class="target">
            <span class="target-method">{escape(source.get('request_method', ''))}</span>
            <span class="target-host">{escape(verification_host_for(result))}</span><span class="target-path">{escape(verification_path_label(result))}</span>
          </p>
        </div>
        <time>{escape(result.get('time', ''))}</time>
      </summary>

      <div class="finding-body">
        <dl class="meta-grid">
          <div><dt>验证状态</dt><dd>{escape(verification_status_label(status))}</dd></div>
          <div><dt>利用深度</dt><dd>{escape(result.get('depth') or '-')}</dd></div>
          <div><dt>验证终点</dt><dd>{escape(result.get('endpoint') or '-')}</dd></div>
          <div><dt>主动请求数</dt><dd>{escape(result.get('request_count', len(requests)))}</dd></div>
          <div><dt>目标</dt><dd>{escape(verification_host_for(result))}</dd></div>
          <div><dt>参数</dt><dd>{escape(param)}</dd></div>
          <div><dt>类型</dt><dd>{escape(type_label(vuln_type))}</dd></div>
          <div><dt>模型</dt><dd>{escape(result.get('model') or '-')}</dd></div>
        </dl>

        <h3>验证结论</h3>
        <p class="verification-summary">{escape(result.get('summary') or '-')}</p>
        {('<h3>结果校验</h3>' + render_list(result.get("validation_warnings") or [])) if result.get("validation_warnings") else ''}

        <h3>安全影响</h3>
        <p class="verification-summary">{escape(result.get('impact') or '-')}</p>

        <h3>完整利用链</h3>
        {render_list(result.get("exploit_chain") or [])}

        <h3>Payload</h3>
        {render_verification_payloads(result.get("payloads") or [])}

        <h3>成功利用/组合成功数据包</h3>
        {''.join(success_html) or '<p class="muted">Agent 未标记成功数据包。</p>'}

        <h3>复现步骤</h3>
        {render_list(result.get("reproduction") or [])}

        <h3>安全边界说明</h3>
        <p class="verification-summary">{escape(result.get('safety_notes') or '-')}</p>

        <h3>全部主动验证请求</h3>
        {''.join(request_html) or '<p class="muted">暂无主动请求记录。</p>'}
      </div>
    </details>
    """


def build_verification_summary(results):
    status_counts = Counter(result.get("status") or "unknown" for result in results)
    type_counts = Counter(
        verification_source(result).get("type") or "unknown"
        for result in results
    )
    host_counts = Counter(verification_host_for(result) for result in results)
    return {
        "statuses": status_counts.most_common(),
        "types": type_counts.most_common(),
        "hosts": host_counts.most_common(),
        "host_total": len(host_counts),
        "confirmed": status_counts.get("confirmed", 0) + status_counts.get("likely", 0),
        "latest_time": results[0].get("time", "-") if results else "-",
    }


def render_verify_status_options(status_counts):
    options = ['<option value="">全部状态</option>']
    for status, _count in status_counts:
        options.append(
            f'<option value="{escape(status)}">{escape(verification_status_label(status))}</option>'
        )
    return "\n".join(options)


def render_verify_type_options(type_counts):
    options = ['<option value="">全部类型</option>']
    for vuln_type, _count in type_counts:
        options.append(
            f'<option value="{escape(vuln_type)}">{escape(type_label(vuln_type))}</option>'
        )
    return "\n".join(options)


def render_verify_host_options(host_counts):
    options = ['<option value="">全部目标</option>']
    for host, _count in host_counts:
        options.append(f'<option value="{escape(host)}">{escape(host)}</option>')
    return "\n".join(options)


def render_verification_section(results):
    summary = build_verification_summary(results)
    cards = "\n".join(
        render_verification_result(result, index)
        for index, result in enumerate(results, start=1)
    )

    return f"""
    <section class="stats" aria-label="验证概览">
      {render_stat("验证总数", len(results))}
      {render_stat("已确认/基本确认", summary["confirmed"])}
      {render_stat("影响目标", summary["host_total"])}
      {render_stat("最后验证", summary["latest_time"])}
    </section>

    <section class="toolbar" aria-label="验证筛选">
      <input id="verifySearch" type="search" placeholder="搜索 URL、payload、利用链、验证结论">
      <select id="verifyStatusFilter">
        {render_verify_status_options(summary["statuses"])}
      </select>
      <select id="verifyTypeFilter">
        {render_verify_type_options(summary["types"])}
      </select>
      <select id="verifyHostFilter">
        {render_verify_host_options(summary["hosts"])}
      </select>
      <span class="visible-count">显示 <strong id="verifyVisibleCount">{len(results)}</strong> / {len(results)}</span>
    </section>

    <div id="verifications">
      {cards or '<section class="empty">暂未产生验证结果。使用 --verify 启动后才会调用 LLM 主动验证。</section>'}
    </div>
    <section id="verifyEmptyFiltered" hidden>当前筛选条件下没有匹配结果。</section>
    """


def write_html_report(
    jsonl_path,
    html_path,
    fingerprint_jsonl_path=None,
    verification_jsonl_path=None,
    logic_jsonl_path=None,
):
    """根据 JSONL 结果生成带“漏洞 / 指纹 / 逻辑漏洞 / 验证”标签页的 HTML 报告。"""
    findings = sorted(
        read_findings(jsonl_path),
        key=lambda finding: str(finding.get("time") or ""),
        reverse=True,
    )
    summary = build_summary(findings)
    os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)

    if fingerprint_jsonl_path is None:
        fingerprint_jsonl_path = fingerprint_path_for(jsonl_path)
    fp_hosts = read_fingerprint_hosts(fingerprint_jsonl_path)
    fingerprint_section = render_fingerprint_section(fp_hosts)
    fp_host_count = len(fp_hosts)

    if logic_jsonl_path is None:
        logic_jsonl_path = logic_path_for(jsonl_path)
    logic_findings = sorted(
        merge_logic_result_list(read_findings(logic_jsonl_path)),
        key=lambda result: str(result.get("time") or ""),
        reverse=True,
    )
    logic_section = render_logic_section(logic_findings)

    if verification_jsonl_path is None:
        verification_jsonl_path = verification_path_for(jsonl_path)
    verifications = sorted(
        read_findings(verification_jsonl_path),
        key=lambda result: str(result.get("time") or ""),
        reverse=True,
    )
    verification_lookup = build_verification_lookup(verifications)
    verification_section = render_verification_section(verifications)

    body = "\n".join(
        render_finding(finding, index, verification_lookup)
        for index, finding in enumerate(findings, start=1)
    )

    type_dist = [
        (type_label(vuln_type), count, vuln_type)
        for vuln_type, count in summary["types"]
    ]
    host_dist = [
        (host, count, host)
        for host, count in summary["hosts"]
    ]

    content = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>pass_scan 漏洞报告</title>
  <style>
    :root {{
      --bg: #f4f6f8;
      --surface: #ffffff;
      --soft: #f8fafc;
      --line: #d9e0ea;
      --text: #172033;
      --muted: #64748b;
      --strong: #0f172a;
      --red: #b42318;
      --red-soft: #fee4e2;
      --teal: #0f766e;
      --teal-soft: #dff7f3;
      --amber: #92400e;
      --amber-soft: #fef3c7;
      --code: #ffffff;
      --code-text: #111827;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      letter-spacing: 0;
    }}
    header {{
      background: #101828;
      color: #fff;
      border-bottom: 4px solid var(--teal);
    }}
    .header-inner {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 26px 24px;
    }}
    .eyebrow {{
      margin: 0 0 8px;
      color: #8bd7cd;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    h1 {{
      margin: 0;
      font-size: 28px;
      line-height: 1.2;
    }}
    .subtitle {{
      margin: 10px 0 0;
      color: #cbd5e1;
      line-height: 1.5;
    }}
    main {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }}
    .stat,
    .panel,
    .finding,
    .verification,
    .logic-finding,
    .empty {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }}
    .stat {{
      padding: 16px;
      min-height: 96px;
    }}
    .stat strong {{
      display: block;
      margin-bottom: 8px;
      color: var(--strong);
      font-size: 30px;
      line-height: 1;
    }}
    .stat span {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }}
    .overview {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }}
    .panel {{
      padding: 16px;
    }}
    .panel h2,
    .finding h2,
    .verification h2,
    .logic-finding h2 {{
      margin: 0;
      color: var(--strong);
      font-size: 18px;
      line-height: 1.3;
    }}
    .dist-row {{
      display: grid;
      grid-template-columns: minmax(120px, 1fr) minmax(120px, 2fr) 42px;
      gap: 12px;
      align-items: center;
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
    }}
    button.dist-row {{
      width: 100%;
      min-height: auto;
      padding: 0;
      border: 0;
      background: transparent;
      cursor: pointer;
      text-align: left;
      font-family: inherit;
      font-size: 13px;
      font-weight: 400;
      line-height: normal;
    }}
    button.dist-row:hover,
    button.dist-row:focus-visible,
    button.dist-row[aria-pressed="true"] {{
      color: var(--strong);
    }}
    button.dist-row:focus-visible {{
      outline: 2px solid var(--teal);
      outline-offset: 3px;
    }}
    button.dist-row[aria-pressed="true"] .bar {{
      background: var(--teal-soft);
    }}
    button.dist-row[aria-pressed="true"] .bar i {{
      background: #0b5f59;
    }}
    .bar {{
      height: 8px;
      overflow: hidden;
      border-radius: 99px;
      background: #e2e8f0;
    }}
    .bar i {{
      display: block;
      height: 100%;
      border-radius: inherit;
      background: var(--teal);
    }}
    .toolbar {{
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-bottom: 16px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.94);
      backdrop-filter: blur(8px);
    }}
    .toolbar input[type="search"] {{
      flex: 1 1 220px;
    }}
    .toolbar select {{
      flex: 0 1 200px;
    }}
    .toolbar .visible-count {{
      margin-left: auto;
    }}
    input,
    select {{
      width: 100%;
      min-height: 40px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      font-size: 14px;
    }}
    input {{
      padding: 0 12px;
    }}
    select {{
      padding: 0 10px;
    }}
    .visible-count {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      white-space: nowrap;
    }}
    .finding,
    .verification,
    .logic-finding {{
      margin-bottom: 16px;
    }}
    .finding[hidden],
    .verification[hidden],
    .logic-finding[hidden],
    .fp-host[hidden],
    #emptyFiltered[hidden],
    #fpEmptyFiltered[hidden],
    #logicEmptyFiltered[hidden],
    #verifyEmptyFiltered[hidden] {{
      display: none;
    }}
    .finding-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      min-height: 96px;
      padding: 18px;
      cursor: pointer;
      list-style: none;
    }}
    .finding-head::-webkit-details-marker {{
      display: none;
    }}
    .finding-head > div:first-child {{
      min-width: 0;
      flex: 1 1 auto;
    }}
    .finding-head::after {{
      content: "+";
      display: inline-grid;
      place-items: center;
      flex: 0 0 28px;
      width: 28px;
      height: 28px;
      margin-top: 2px;
      border-radius: 50%;
      background: #e2e8f0;
      color: #334155;
      font-size: 18px;
      font-weight: 900;
    }}
    .finding[open] .finding-head,
    .verification[open] .finding-head,
    .logic-finding[open] .finding-head {{
      border-bottom: 1px solid var(--line);
    }}
    .finding[open] .finding-head::after,
    .verification[open] .finding-head::after,
    .logic-finding[open] .finding-head::after {{
      content: "-";
    }}
    .finding-body {{
      padding: 18px;
    }}
    .badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 10px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid transparent;
      font-size: 12px;
      font-weight: 800;
      line-height: 1.2;
    }}
    .badge.risk {{
      border-color: #fda29b;
      background: var(--red-soft);
      color: var(--red);
    }}
    .badge.risk-critical {{
      border-color: #c4b5fd;
      background: #ede9fe;
      color: #5b21b6;
    }}
    .badge.risk-high {{
      border-color: #fda29b;
      background: var(--red-soft);
      color: var(--red);
    }}
    .badge.risk-medium {{
      border-color: #f59e0b;
      background: #fef3c7;
      color: #9a3412;
    }}
    .badge.risk-low {{
      border-color: #86efac;
      background: #dcfce7;
      color: #166534;
    }}
    .badge.risk-info {{
      border-color: #93c5fd;
      background: #dbeafe;
      color: #1d4ed8;
    }}
    .badge.method {{
      border-color: #99f6e4;
      background: var(--teal-soft);
      color: #115e59;
    }}
    .badge.param {{
      border-color: #fde68a;
      background: var(--amber-soft);
      color: var(--amber);
    }}
    .badge.status {{
      border-color: #bfdbfe;
      background: #dbeafe;
      color: #1d4ed8;
    }}
    .badge.status-confirmed {{
      border-color: #86efac;
      background: #dcfce7;
      color: #166534;
    }}
    .badge.status-likely {{
      border-color: #99f6e4;
      background: var(--teal-soft);
      color: #115e59;
    }}
    .badge.status-false_positive,
    .badge.status-error {{
      border-color: #fda29b;
      background: var(--red-soft);
      color: var(--red);
    }}
    .badge.status-needs_manual_review,
    .badge.confidence {{
      border-color: #fde68a;
      background: var(--amber-soft);
      color: var(--amber);
    }}
    .target {{
      margin: 6px 0 0;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-size: 14px;
    }}
    .target-method {{
      margin-right: 6px;
      padding: 1px 6px;
      border-radius: 4px;
      background: #e2e8f0;
      color: #334155;
      font-size: 12px;
      font-weight: 800;
    }}
    .target-host {{
      color: var(--strong);
      font-weight: 800;
    }}
    .target-path {{
      color: var(--muted);
    }}
    time {{
      flex: 0 0 auto;
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }}
    .finding-head-side {{
      display: flex;
      flex: 0 0 auto;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }}
    .verify-link {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 30px;
      padding: 0 10px;
      border: 1px solid #99f6e4;
      border-radius: 6px;
      background: var(--teal-soft);
      color: #115e59;
      font-size: 12px;
      font-weight: 900;
      text-decoration: none;
      white-space: nowrap;
    }}
    .verify-link:hover,
    .verify-link:focus-visible {{
      border-color: var(--teal);
      color: #0f766e;
      outline: none;
    }}
    .verify-link-muted {{
      border-color: #e2e8f0;
      background: #f8fafc;
      color: var(--muted);
      cursor: default;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin: 0 0 14px;
    }}
    .meta-grid div {{
      min-width: 0;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--soft);
    }}
    dt {{
      margin: 0 0 4px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
    }}
    dd {{
      margin: 0;
      color: var(--strong);
      overflow-wrap: anywhere;
      font-size: 13px;
    }}
    .payload {{
      display: grid;
      grid-template-columns: 82px minmax(0, 1fr);
      gap: 10px;
      align-items: start;
      margin-bottom: 16px;
      padding: 10px;
      border: 1px solid #bae6fd;
      border-radius: 6px;
      background: #f0f9ff;
    }}
    .payload span {{
      color: #0369a1;
      font-size: 12px;
      font-weight: 900;
    }}
    code {{
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 13px;
    }}
    h3 {{
      margin: 18px 0 10px;
      color: var(--strong);
      font-size: 15px;
    }}
    h4 {{
      margin: 0 0 8px;
      color: var(--strong);
      font-size: 13px;
    }}
    .evidence {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 6px;
      font-size: 13px;
    }}
    .evidence tr + tr {{
      border-top: 1px solid var(--line);
    }}
    .evidence th,
    .evidence td {{
      padding: 9px 10px;
      vertical-align: top;
      text-align: left;
      overflow-wrap: anywhere;
    }}
    .evidence th {{
      width: 190px;
      background: var(--soft);
      color: var(--muted);
      font-weight: 800;
    }}
    .proof {{
      margin-top: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
    }}
    .proof summary {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-height: 48px;
      padding: 10px 12px;
      cursor: pointer;
      color: var(--strong);
      font-weight: 900;
      list-style: none;
    }}
    .proof summary::-webkit-details-marker {{
      display: none;
    }}
    .proof summary::before {{
      content: "+";
      display: inline-grid;
      place-items: center;
      flex: 0 0 20px;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #e2e8f0;
      color: #334155;
      font-weight: 900;
    }}
    .proof[open] summary::before {{
      content: "-";
    }}
    .proof-actions {{
      display: inline-flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-left: auto;
    }}
    button {{
      min-height: 30px;
      padding: 0 10px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      background: #fff;
      color: #334155;
      cursor: pointer;
      font: inherit;
      font-size: 12px;
      font-weight: 800;
    }}
    button:hover {{
      border-color: #94a3b8;
      background: #f8fafc;
    }}
    .proof-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      padding: 0 12px 12px;
    }}
    pre {{
      max-height: 520px;
      min-height: 120px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0;
      padding: 12px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      background: var(--code);
      color: var(--code-text);
      line-height: 1.45;
      font-size: 12px;
    }}
    .empty,
    #emptyFiltered,
    #fpEmptyFiltered,
    #logicEmptyFiltered,
    #verifyEmptyFiltered {{
      padding: 24px;
      text-align: center;
      color: var(--muted);
    }}
    .chain {{
      margin: 0;
      padding-left: 22px;
      color: var(--text);
      line-height: 1.7;
    }}
    .verification-summary {{
      margin: 0;
      color: var(--text);
      line-height: 1.7;
      overflow-wrap: anywhere;
    }}
    .payload-table code {{
      display: block;
      white-space: pre-wrap;
    }}
    .muted {{
      color: var(--muted);
    }}
    @media (max-width: 920px) {{
      .stats,
      .overview,
      .meta-grid,
      .proof-grid {{
        grid-template-columns: 1fr;
      }}
      .toolbar {{
        position: static;
        grid-template-columns: 1fr;
      }}
      .tabs {{
        flex-wrap: wrap;
      }}
      .tab-btn {{
        flex: 1 1 calc(50% - 8px);
        min-width: 0;
        padding: 0 12px;
      }}
      .finding-head {{
        display: flex;
      }}
      time {{
        display: block;
        margin-top: 10px;
      }}
      .finding-head-side {{
        align-items: flex-start;
      }}
      .dist-row {{
        grid-template-columns: 1fr 2fr 34px;
      }}
    }}
    /* 标签页切换（指纹 / 逻辑漏洞 / 漏洞 / 验证） */
    .tabs {{
      display: flex;
      gap: 8px;
      max-width: 1280px;
      margin: 0 auto;
      padding: 16px 24px 0;
    }}
    .tab-btn {{
      min-height: 40px;
      padding: 0 22px;
      border: 1px solid var(--line);
      border-bottom: none;
      border-radius: 8px 8px 0 0;
      background: #e8edf3;
      color: var(--muted);
      cursor: pointer;
      font: inherit;
      font-size: 14px;
      font-weight: 800;
    }}
    .tab-btn .tab-num {{
      margin-left: 8px;
      padding: 1px 8px;
      border-radius: 999px;
      background: #cbd5e1;
      color: #334155;
      font-size: 12px;
    }}
    .tab-btn[aria-selected="true"] {{
      background: var(--surface);
      color: var(--strong);
    }}
    .tab-btn[aria-selected="true"] .tab-num {{
      background: var(--teal);
      color: #fff;
    }}
    .tab-panel[hidden] {{
      display: none;
    }}
    @media (max-width: 920px) {{
      .tabs {{
        flex-wrap: wrap;
      }}
      .tab-btn {{
        flex: 1 1 calc(50% - 8px);
        min-width: 0;
        padding: 0 12px;
      }}
    }}
    .fp-host {{
      margin-bottom: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }}
    .fp-host-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 18px;
      cursor: pointer;
      list-style: none;
    }}
    .fp-host-head::-webkit-details-marker {{
      display: none;
    }}
    .fp-host-head h2 {{
      margin: 0;
      font-size: 16px;
      color: var(--strong);
    }}
    .fp-host-head > div:first-child {{
      min-width: 0;
      flex: 1 1 auto;
    }}
    .fp-paths {{
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
    }}
    .fp-count {{
      flex: 0 0 auto;
      padding: 3px 10px;
      border-radius: 999px;
      background: var(--teal-soft);
      color: #115e59;
      font-size: 12px;
      font-weight: 800;
    }}
    .fp-chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 0 18px 16px;
    }}
    .fp-chip {{
      display: inline-flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--soft);
      font-size: 13px;
    }}
    .fp-chip b {{
      color: var(--strong);
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <p class="eyebrow">pass_scan report</p>
      <h1>扫描报告</h1>
      <p class="subtitle">识别 {fp_host_count} 个目标的指纹，发现 {len(logic_findings)} 个逻辑风险，以及{len(findings)} 个漏洞，完成 {len(verifications)} 条主动验证。</p>
    </div>
  </header>
  <div class="tabs" role="tablist">
    <button class="tab-btn" id="tabBtnFp" role="tab" aria-selected="true" aria-controls="panelFp">
      指纹<span class="tab-num">{fp_host_count}</span>
    </button>
    <button class="tab-btn" id="tabBtnLogic" role="tab" aria-selected="false" aria-controls="panelLogic">
      逻辑漏洞<span class="tab-num">{len(logic_findings)}</span>
    </button>
    <button class="tab-btn" id="tabBtnVuln" role="tab" aria-selected="false" aria-controls="panelVuln">
      漏洞<span class="tab-num">{len(findings)}</span>
    </button>
    <button class="tab-btn" id="tabBtnVerify" role="tab" aria-selected="false" aria-controls="panelVerify">
      验证<span class="tab-num">{len(verifications)}</span>
    </button>
  </div>
  <main>
    <div class="tab-panel" id="panelVuln" role="tabpanel" hidden>
    <section class="stats" aria-label="报告概览">
      {render_stat("漏洞总数", len(findings))}
      {render_stat("影响目标", summary["host_total"])}
      {render_stat("漏洞类型", len(summary["types"]))}
      {render_stat("最后命中", summary["latest_time"])}
    </section>

    <section class="overview">
      {render_distribution("漏洞类型分布", type_dist, "type")}
      {render_distribution("目标分布", host_dist, "host")}
    </section>

    <section class="toolbar" aria-label="报告筛选">
      <input id="search" type="search" placeholder="搜索 URL、参数、payload、响应证据">
      <select id="typeFilter">
        {render_type_options(summary["types"])}
      </select>
      <select id="hostFilter">
        {render_host_options(summary["all_hosts"])}
      </select>
      <span class="visible-count">显示 <strong id="visibleCount">{len(findings)}</strong> / {len(findings)}</span>
    </section>

    <div id="findings">
      {body or '<section class="empty">暂未发现漏洞。</section>'}
    </div>
    <section id="emptyFiltered" hidden>当前筛选条件下没有匹配结果。</section>
    </div>

    <div class="tab-panel" id="panelFp" role="tabpanel">
      {fingerprint_section}
    </div>

    <div class="tab-panel" id="panelLogic" role="tabpanel" hidden>
      {logic_section}
    </div>

    <div class="tab-panel" id="panelVerify" role="tabpanel" hidden>
      {verification_section}
    </div>
  </main>
  <script>
    (function () {{
      var search = document.getElementById("search");
      var typeFilter = document.getElementById("typeFilter");
      var hostFilter = document.getElementById("hostFilter");
      var visibleCount = document.getElementById("visibleCount");
      var emptyFiltered = document.getElementById("emptyFiltered");
      var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
      var distRows = Array.prototype.slice.call(document.querySelectorAll("#panelVuln [data-dist-filter]"));

      function applyFilters() {{
        var query = (search.value || "").trim().toLowerCase();
        var vulnType = typeFilter.value;
        var host = hostFilter.value;
        var count = 0;

        findings.forEach(function (finding) {{
          var textMatch = !query || finding.textContent.toLowerCase().indexOf(query) !== -1;
          var typeMatch = !vulnType || finding.dataset.type === vulnType;
          var hostMatch = !host || finding.dataset.host === host;
          var visible = textMatch && typeMatch && hostMatch;
          finding.hidden = !visible;
          if (visible) {{
            count += 1;
          }}
        }});

        visibleCount.textContent = String(count);
        emptyFiltered.hidden = count !== 0 || findings.length === 0;
        distRows.forEach(function (row) {{
          var active = (
            (row.dataset.distFilter === "type" && row.dataset.distValue === vulnType) ||
            (row.dataset.distFilter === "host" && row.dataset.distValue === host)
          );
          row.setAttribute("aria-pressed", String(active));
        }});
      }}

      function copyText(text) {{
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          return navigator.clipboard.writeText(text);
        }}

        var textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        return Promise.resolve();
      }}

      document.addEventListener("click", function (event) {{
        var button = event.target.closest("[data-copy]");
        if (!button) {{
          return;
        }}

        event.preventDefault();
        var target = document.getElementById(button.dataset.copy);
        if (!target) {{
          return;
        }}

        var originalText = button.textContent;
        copyText(target.textContent).then(function () {{
          button.textContent = "已复制";
          window.setTimeout(function () {{
            button.textContent = originalText;
          }}, 1200);
        }});
      }});

      document.addEventListener("click", function (event) {{
        var row = event.target.closest("#panelVuln [data-dist-filter]");
        if (!row) {{
          return;
        }}

        event.preventDefault();
        if (row.dataset.distFilter === "type") {{
          typeFilter.value = typeFilter.value === row.dataset.distValue ? "" : row.dataset.distValue;
        }}
        if (row.dataset.distFilter === "host") {{
          hostFilter.value = hostFilter.value === row.dataset.distValue ? "" : row.dataset.distValue;
        }}
        applyFilters();
      }});

      search.addEventListener("input", applyFilters);
      typeFilter.addEventListener("change", applyFilters);
      hostFilter.addEventListener("change", applyFilters);
      applyFilters();

      // 标签页切换（指纹 / 逻辑漏洞 / 漏洞 / 验证）。
      var tabBtnVuln = document.getElementById("tabBtnVuln");
      var tabBtnFp = document.getElementById("tabBtnFp");
      var tabBtnLogic = document.getElementById("tabBtnLogic");
      var tabBtnVerify = document.getElementById("tabBtnVerify");
      var panelVuln = document.getElementById("panelVuln");
      var panelFp = document.getElementById("panelFp");
      var panelLogic = document.getElementById("panelLogic");
      var panelVerify = document.getElementById("panelVerify");
      var tabAliases = {{
        fingerprint: "fp",
        fingerprints: "fp",
        fp: "fp",
        logic: "logic",
        logic_vuln: "logic",
        logic_vulns: "logic",
        vuln: "vuln",
        vulns: "vuln",
        vulnerability: "vuln",
        vulnerabilities: "vuln",
        verify: "verify",
        verification: "verify",
        verifications: "verify"
      }};

      function normalizeTab(which) {{
        return tabAliases[String(which || "").trim()] || "";
      }}

      function hashFor(tab, verificationKey) {{
        if (tab === "verify" && verificationKey) {{
          return "verify:" + encodeURIComponent(verificationKey);
        }}
        return tab;
      }}

      function setReportHash(tab, verificationKey) {{
        var nextHash = "#" + hashFor(tab, verificationKey || "");
        if (window.location.hash === nextHash) {{
          return;
        }}
        if (window.history && window.history.replaceState) {{
          window.history.replaceState(
            null,
            "",
            window.location.pathname + window.location.search + nextHash
          );
          return;
        }}
        window.location.hash = nextHash;
      }}

      function parseReportHash() {{
        var raw = window.location.hash ? window.location.hash.slice(1) : "";
        if (!raw) {{
          return {{ tab: "fp", verificationKey: "" }};
        }}
        try {{
          raw = decodeURIComponent(raw);
        }} catch (_error) {{
          raw = "";
        }}
        var match = raw.match(/^([^:=\\/]+)(?:[:=\\/](.+))?$/);
        var tab = normalizeTab(match ? match[1] : raw);
        var verificationKey = match && match[2] ? match[2] : "";
        return {{ tab: tab || "fp", verificationKey: verificationKey }};
      }}

      function selectTab(which, options) {{
        options = options || {{}};
        which = normalizeTab(which) || "fp";
        var fp = which === "fp";
        var logic = which === "logic";
        var vuln = which === "vuln";
        var verify = which === "verify";
        tabBtnVuln.setAttribute("aria-selected", String(vuln));
        tabBtnFp.setAttribute("aria-selected", String(fp));
        tabBtnLogic.setAttribute("aria-selected", String(logic));
        tabBtnVerify.setAttribute("aria-selected", String(verify));
        panelVuln.hidden = !vuln;
        panelFp.hidden = !fp;
        panelLogic.hidden = !logic;
        panelVerify.hidden = !verify;
        if (options.updateHash !== false) {{
          setReportHash(which, options.verificationKey || "");
        }}
      }}
      tabBtnFp.addEventListener("click", function () {{ selectTab("fp"); }});
      tabBtnLogic.addEventListener("click", function () {{ selectTab("logic"); }});
      tabBtnVuln.addEventListener("click", function () {{ selectTab("vuln"); }});
      tabBtnVerify.addEventListener("click", function () {{ selectTab("verify"); }});

      function resetVerifyFilters() {{
        if (verifySearch) {{ verifySearch.value = ""; }}
        if (verifyStatusFilter) {{ verifyStatusFilter.value = ""; }}
        if (verifyTypeFilter) {{ verifyTypeFilter.value = ""; }}
        if (verifyHostFilter) {{ verifyHostFilter.value = ""; }}
        applyVerifyFilter();
      }}

      function verificationCardFor(key) {{
        for (var index = 0; index < verifications.length; index += 1) {{
          var card = verifications[index];
          if (card.dataset.findingKey === key || card.dataset.matchKey === key) {{
            return card;
          }}
        }}
        return null;
      }}

      function openVerificationByKey(key) {{
        if (!key) {{
          return;
        }}
        resetVerifyFilters();
        var card = verificationCardFor(key);
        if (!card) {{
          return;
        }}
        card.hidden = false;
        card.open = true;
        card.scrollIntoView({{ block: "start", behavior: "smooth" }});
      }}

      function applyReportHash() {{
        var state = parseReportHash();
        selectTab(state.tab, {{ updateHash: false, verificationKey: state.verificationKey }});
        if (state.tab === "verify" && state.verificationKey) {{
          openVerificationByKey(state.verificationKey);
        }}
      }}

      document.addEventListener("click", function (event) {{
        var link = event.target.closest("[data-open-verification]");
        if (!link) {{
          return;
        }}
        event.preventDefault();
        event.stopPropagation();
        var key = link.dataset.openVerification || "";
        selectTab("verify", {{ verificationKey: key }});
        openVerificationByKey(key);
      }});

      // 指纹标签页搜索（按 host / 框架名过滤 host 卡片）。
      var fpSearch = document.getElementById("fpSearch");
      var fpVisibleCount = document.getElementById("fpVisibleCount");
      var fpEmptyFiltered = document.getElementById("fpEmptyFiltered");
      var fpHosts = Array.prototype.slice.call(document.querySelectorAll(".fp-host"));

      // 指纹标签页筛选（按 host / 指纹名 / 关键词过滤 host 卡片）。
      var fpSearch = document.getElementById("fpSearch");
      var fpHostFilter = document.getElementById("fpHostFilter");
      var fpTechFilter = document.getElementById("fpTechFilter");
      var fpVisibleCount = document.getElementById("fpVisibleCount");
      var fpEmptyFiltered = document.getElementById("fpEmptyFiltered");
      var fpHosts = Array.prototype.slice.call(document.querySelectorAll(".fp-host"));
      var fpDistRows = Array.prototype.slice.call(document.querySelectorAll("#panelFp [data-dist-filter]"));

      function applyFpFilter() {{
        if (!fpSearch) {{ return; }}
        var query = (fpSearch.value || "").trim().toLowerCase();
        var host = fpHostFilter ? fpHostFilter.value : "";
        var tech = fpTechFilter ? fpTechFilter.value.toLowerCase() : "";
        var count = 0;
        fpHosts.forEach(function (card) {{
          var textMatch = !query || card.textContent.toLowerCase().indexOf(query) !== -1;
          var hostMatch = !host || card.dataset.host === host;
          var techMatch = !tech ||
            (card.dataset.techs || "").toLowerCase().indexOf("|" + tech + "|") !== -1;
          var visible = textMatch && hostMatch && techMatch;
          card.hidden = !visible;
          if (visible) {{ count += 1; }}
        }});
        if (fpVisibleCount) {{ fpVisibleCount.textContent = String(count); }}
        if (fpEmptyFiltered) {{ fpEmptyFiltered.hidden = count !== 0 || fpHosts.length === 0; }}
        fpDistRows.forEach(function (row) {{
          var active = (
            (row.dataset.distFilter === "fp-tech" && row.dataset.distValue.toLowerCase() === tech) ||
            (row.dataset.distFilter === "fp-host" && row.dataset.distValue === host)
          );
          row.setAttribute("aria-pressed", String(active));
        }});
      }}
      document.addEventListener("click", function (event) {{
        var row = event.target.closest("#panelFp [data-dist-filter]");
        if (!row) {{
          return;
        }}

        event.preventDefault();
        if (row.dataset.distFilter === "fp-tech" && fpTechFilter) {{
          fpTechFilter.value = fpTechFilter.value === row.dataset.distValue ? "" : row.dataset.distValue;
        }}
        if (row.dataset.distFilter === "fp-host" && fpHostFilter) {{
          fpHostFilter.value = fpHostFilter.value === row.dataset.distValue ? "" : row.dataset.distValue;
        }}
        applyFpFilter();
      }});
      if (fpSearch) {{ fpSearch.addEventListener("input", applyFpFilter); }}
      if (fpHostFilter) {{ fpHostFilter.addEventListener("change", applyFpFilter); }}
      if (fpTechFilter) {{ fpTechFilter.addEventListener("change", applyFpFilter); }}
      applyFpFilter();

      // 逻辑漏洞标签页筛选（按状态 / 类型 / host / 关键词过滤卡片）。
      var logicSearch = document.getElementById("logicSearch");
      var logicStatusFilter = document.getElementById("logicStatusFilter");
      var logicTypeFilter = document.getElementById("logicTypeFilter");
      var logicHostFilter = document.getElementById("logicHostFilter");
      var logicVisibleCount = document.getElementById("logicVisibleCount");
      var logicEmptyFiltered = document.getElementById("logicEmptyFiltered");
      var logicFindings = Array.prototype.slice.call(document.querySelectorAll(".logic-finding"));

      function applyLogicFilter() {{
        if (!logicSearch) {{ return; }}
        var query = (logicSearch.value || "").trim().toLowerCase();
        var status = logicStatusFilter ? logicStatusFilter.value : "";
        var vulnType = logicTypeFilter ? logicTypeFilter.value : "";
        var host = logicHostFilter ? logicHostFilter.value : "";
        var count = 0;
        logicFindings.forEach(function (card) {{
          var textMatch = !query || card.textContent.toLowerCase().indexOf(query) !== -1;
          var statusMatch = !status || card.dataset.status === status;
          var typeMatch = !vulnType || card.dataset.type === vulnType;
          var hostMatch = !host || card.dataset.host === host;
          var visible = textMatch && statusMatch && typeMatch && hostMatch;
          card.hidden = !visible;
          if (visible) {{ count += 1; }}
        }});
        if (logicVisibleCount) {{ logicVisibleCount.textContent = String(count); }}
        if (logicEmptyFiltered) {{ logicEmptyFiltered.hidden = count !== 0 || logicFindings.length === 0; }}
      }}
      if (logicSearch) {{ logicSearch.addEventListener("input", applyLogicFilter); }}
      if (logicStatusFilter) {{ logicStatusFilter.addEventListener("change", applyLogicFilter); }}
      if (logicTypeFilter) {{ logicTypeFilter.addEventListener("change", applyLogicFilter); }}
      if (logicHostFilter) {{ logicHostFilter.addEventListener("change", applyLogicFilter); }}
      applyLogicFilter();

      // 验证标签页筛选（按状态 / 类型 / host / 关键词过滤验证卡片）。
      var verifySearch = document.getElementById("verifySearch");
      var verifyStatusFilter = document.getElementById("verifyStatusFilter");
      var verifyTypeFilter = document.getElementById("verifyTypeFilter");
      var verifyHostFilter = document.getElementById("verifyHostFilter");
      var verifyVisibleCount = document.getElementById("verifyVisibleCount");
      var verifyEmptyFiltered = document.getElementById("verifyEmptyFiltered");
      var verifications = Array.prototype.slice.call(document.querySelectorAll(".verification"));

      function applyVerifyFilter() {{
        if (!verifySearch) {{ return; }}
        var query = (verifySearch.value || "").trim().toLowerCase();
        var status = verifyStatusFilter ? verifyStatusFilter.value : "";
        var vulnType = verifyTypeFilter ? verifyTypeFilter.value : "";
        var host = verifyHostFilter ? verifyHostFilter.value : "";
        var count = 0;
        verifications.forEach(function (card) {{
          var textMatch = !query || card.textContent.toLowerCase().indexOf(query) !== -1;
          var statusMatch = !status || card.dataset.status === status;
          var typeMatch = !vulnType || card.dataset.type === vulnType;
          var hostMatch = !host || card.dataset.host === host;
          var visible = textMatch && statusMatch && typeMatch && hostMatch;
          card.hidden = !visible;
          if (visible) {{ count += 1; }}
        }});
        if (verifyVisibleCount) {{ verifyVisibleCount.textContent = String(count); }}
        if (verifyEmptyFiltered) {{ verifyEmptyFiltered.hidden = count !== 0 || verifications.length === 0; }}
      }}
      if (verifySearch) {{ verifySearch.addEventListener("input", applyVerifyFilter); }}
      if (verifyStatusFilter) {{ verifyStatusFilter.addEventListener("change", applyVerifyFilter); }}
      if (verifyTypeFilter) {{ verifyTypeFilter.addEventListener("change", applyVerifyFilter); }}
      if (verifyHostFilter) {{ verifyHostFilter.addEventListener("change", applyVerifyFilter); }}
      applyVerifyFilter();
      window.addEventListener("hashchange", applyReportHash);
      applyReportHash();
    }})();
  </script>
</body>
</html>
"""

    with REPORT_WRITE_LOCK:
        with open(html_path, "w", encoding="utf-8") as file:
            file.write(content)
