# SQL 注入检测流程文件。
#
# 这个文件只负责“怎么检测”：
# - 从请求里提取参数
# - 主动重放请求
# - 发送 payload
# - 比较响应内容、marker 和耗时
# - 记录漏洞结果
#
# 当前支持的 SQL 注入检测类型：
# - error_based：payload 后出现数据库错误指纹
# - boolean_based：true/false payload 导致响应差异
# - inline_query：子查询 marker 进入响应
# - union_based：UNION 查询 marker 进入响应
# - stacked_query：分号追加第二条 SQL 后产生稳定延时
# - time_based：普通延时盲注
#
# Header 参数会优先使用 rules.yaml 里的 header_* 规则：
# - 更偏向日志入库、INSERT/UPDATE 字符串上下文
# - 默认跳过 inline/UNION marker，减少无效请求
#
# WAF 场景的处理方式：
# - 先发送正常 payload，不主动增加请求量
# - 如果响应状态码、响应头或响应正文像 WAF 拦截页，再尝试 tamper 变形
# - 如果某个变形绕过了 WAF 但没有命中漏洞证据，会继续尝试后面的变形
# - true/false、control/delay 这类成对 payload 会使用同一种 tamper，避免误判
#
# 深度检测场景：
# - 如果 config.yaml 里开启 deep_tamper，普通 payload 没命中时也会尝试少量 tamper
# - 这类 tamper 用来处理普通后端过滤，不会触发 WAF 冷却等待
#
# 具体 payload、marker、数据库错误指纹都放在 rules.yaml。
# rules.py 只是一个很薄的 YAML 加载器。

import base64
import os
import re
import socket
import ssl
import threading
import time
from difflib import SequenceMatcher
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from pass_scan.body_paser import decode_body_text, get_header, get_media_type
from pass_scan.reporter import print_finding_once, write_html_report, write_jsonl
from pass_scan.scan_context import build_scan_context, replace_json_body_parameter
from pass_scan.terminal import red
from pass_scan.sql_injection.rules import (
    build_boolean_payload_groups,
    build_error_payloads,
    build_header_boolean_payload_groups,
    build_header_error_payloads,
    build_header_stacked_payload_groups,
    build_header_time_payload_groups,
    build_inline_payload_groups,
    build_stacked_payload_groups,
    build_time_payload_groups,
    build_union_payload_groups,
    find_sql_error,
    max_tampered_payloads_per_probe,
    tamper_profiles,
    waf_detection_rules,
)
from pass_scan.sql_injection.tamper import apply_tampers


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

# 单个主动探测请求的超时时间。
TIMEOUT = 10

# 做响应相似度比较时，只取响应前面一部分，避免大页面比较太慢。
MAX_COMPARE_CHARS = 30000

# 延时响应比普通响应慢多少秒，才认为可能命中。
TIME_THRESHOLD = 3.0

# baseline 两次重放的相似度低于这个值，就认为页面不稳定。
BASELINE_STABLE_MIN = 0.90

# 布尔盲注判断阈值。
TRUE_SIMILARITY_MIN = 0.88
FALSE_SIMILARITY_MAX = 0.78
TRUE_FALSE_SIMILARITY_MAX = 0.85

# 当前 IP/会话被封禁的强信号。普通 WAF payload 拦截不走这里。
IP_BLOCK_STATUS_CODES = {429, 503}
IP_BLOCK_HINT_STATUS_CODES = {403, 429, 503}
IP_BLOCK_HEADER_KEYWORDS = (
    "retry-after",
    "rate-limit",
    "x-ratelimit",
)
IP_BLOCK_BODY_KEYWORDS = (
    "too many requests",
    "rate limit",
    "rate-limit",
    "temporarily blocked",
    "temporarily banned",
    "your ip has been blocked",
    "ip address has been blocked",
    "ip blocked",
    "blocked your ip",
    "访问过快",
    "请求过于频繁",
    "频率过高",
    "ip已被封",
    "ip 被封",
    "稍后再试",
)

# 这些 dbms 是“具体数据库”。识别出其中之一后，带 dbms 标签的 payload
# 就只发当前数据库的版本。generic 不算具体数据库，不会触发裁剪。
CONCRETE_DBMS = {"mysql", "postgresql", "mssql", "oracle", "sqlite"}

# 这些 header 是连接级别的，不适合照抄到主动重放请求里。
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


class SQLInjectionScanner:
    """SQL 注入扫描器。

    外层 pass_scan/scanner.py 会调用 check()。
    check() 收到一条 mitmproxy flow 后，会完成参数提取、主动发包和结果判断。
    """

    name = "sql_injection"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        self.deep_tamper = bool(self.config.get("deep_tamper", False))
        self.deep_tamper_max_profiles = int(
            self.config.get("deep_tamper_max_profiles", 4)
        )
        self.deep_tamper_methods = set(
            self.config.get(
                "deep_tamper_methods",
                [
                    "error_based",
                    "boolean_based",
                    "inline_query",
                    "union_based",
                    "stacked_query",
                    "time_based",
                ],
            )
        )

        # 去重集合：同一个路径下同一个参数只扫描一次，避免重复发包。
        self.scanned = set()

        # 每个 host 已识别出的数据库类型。
        # 一旦某个 host 被确认是 mysql/postgresql/mssql/oracle/sqlite，
        # 后续带 dbms 标签的 payload（时间盲注、stacked、inline）就只发当前数据库的版本，
        # 不再把其他数据库的 payload 也发一遍。
        self.host_dbms = {}

        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

        # 不走系统代理，避免主动探测请求又绕回 Burp/mitmproxy 导致循环。
        # 不校验 HTTPS 证书，方便测试自签名站点。
        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
        )

        os.makedirs(os.path.dirname(self.vuln_file) or ".", exist_ok=True)

    def interested(self, context):
        """轻量判断：SQL 注入插件是否关心这条流量。

        这个函数不能发请求，只做快速判断。
        调度器会先调用 interested()，只有返回 True 才会入队主动扫描。
        """
        if context.is_skipped:
            return False

        if context.method not in ("GET", "POST"):
            return False

        return bool(self.extract_candidates(context))

    def dedup_key(self, context):
        """生成调度层去重 key。

        同一个 URL 路径 + 同一批参数名，在 TTL 内只入队一次。
        SQL 插件内部还会按单个参数继续去重。
        """
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
        """SQL 注入检测入口。"""
        # 兼容旧调用方式：check(record, flow)。
        # 新调度器会调用 check(context)。
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

        baseline_info = self.build_baseline(flow)
        if not baseline_info:
            return []

        findings = []
        for candidate in candidates:
            scan_key = self.make_scan_key(flow, candidate)
            with self.lock:
                if scan_key in self.scanned:
                    continue
                self.scanned.add(scan_key)

            finding = self.check_one_param(flow, baseline_info, candidate)
            if finding:
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    def extract_candidates(self, context):
        """从请求中提取可控参数。

        Cookie/Header 注入只在 full_payload_scan 模式下执行：
        - 普通模式只扫描 query/form/json。
        - 全量模式会额外扫描 Cookie、User-Agent、Referer 等白名单 Header。
        - 全量模式下，即使请求只有 Cookie 或 Header，也会进入扫描。
        """
        normal_places = {"query", "form", "json"}
        normal_params = [
            param for param in context.parameters
            if param["place"] in normal_places
        ]
        cookie_params = [
            param for param in context.parameters
            if param["place"] == "cookie"
        ]
        header_params = [
            param for param in context.parameters
            if param["place"] == "header"
        ]

        if self.full_payload_scan:
            return normal_params + cookie_params + header_params

        return normal_params

    def normalize_path_for_dedup(self, path):
        """去重用路径归一化。

        `/admin` 和 `/admin/` 经常只是目录跳转前后的同一个页面。
        这里仅用于入队去重和内部扫描去重，不影响真正发送的 URL。
        """
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    def build_baseline(self, flow):
        """构造 baseline，并判断页面是否稳定。"""
        original = self.response_from_flow(flow)

        active_one = self.send_probe(flow, None, "")
        active_two = self.send_probe(flow, None, "")

        # 超时探测正文为空，不能用来当 baseline，否则后续相似度比较全部失真。
        if active_one and active_one.get("timed_out"):
            active_one = None
        if active_two and active_two.get("timed_out"):
            active_two = None

        if active_one and active_two:
            stability = self.similarity(active_one["text"], active_two["text"])
            return {
                "response": active_one,
                "stable": stability >= BASELINE_STABLE_MIN,
                "stability": round(stability, 4),
            }

        if active_one:
            return {"response": active_one, "stable": True, "stability": 1.0}

        if original:
            return {"response": original, "stable": True, "stability": 1.0}

        return None

    def response_from_flow(self, flow):
        """把 mitmproxy 已经拿到的原始响应转换成可比较结构。"""
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

    def check_one_param(self, flow, baseline_info, candidate):
        """按顺序对单个参数做多种 SQL 注入检测。

        注意：即使开启 full_payload_scan，只要当前参数已经确认 SQL 注入，
        SQL 注入插件就停止后续 SQLi payload。其他漏洞插件仍然可以继续检测。
        """
        baseline = baseline_info["response"]

        if self.is_header_candidate(candidate):
            return self.check_header_param(flow, baseline_info, candidate)

        finding = self.check_error_based(flow, baseline, candidate)
        if finding:
            return finding

        if baseline_info["stable"]:
            finding = self.check_boolean_based(flow, baseline_info, candidate)
            if finding:
                return finding

            finding = self.check_inline_query(flow, baseline, candidate)
            if finding:
                return finding

            finding = self.check_union_based(flow, baseline, candidate)
            if finding:
                return finding

        finding = self.check_stacked_query(flow, baseline, candidate)
        if finding:
            return finding

        finding = self.check_time_based(flow, baseline, candidate)
        if finding:
            return finding

        return None

    def check_header_param(self, flow, baseline_info, candidate):
        """Header 参数专用检测顺序。

        Header 注入常见于 User-Agent、Referer 这类值被写入访问日志、
        登录记录或审计表。它们通常不会把 UNION/inline marker 回显到页面，
        所以这里跳过 marker 型检测，优先使用报错、布尔和延时类 payload。
        """
        baseline = baseline_info["response"]

        finding = self.check_error_based(flow, baseline, candidate)
        if finding:
            return finding

        if baseline_info["stable"]:
            finding = self.check_boolean_based(flow, baseline_info, candidate)
            if finding:
                return finding

        finding = self.check_time_based(flow, baseline, candidate)
        if finding:
            return finding

        finding = self.check_stacked_query(flow, baseline, candidate)
        if finding:
            return finding

        return None

    def check_error_based(self, flow, baseline, candidate):
        """报错型 SQL 注入检测。"""
        baseline_error = find_sql_error(baseline["text"])
        if baseline_error:
            return None

        for payload in self.error_payloads_for(candidate):
            for probe in self.send_probe_variants(
                flow,
                candidate,
                payload,
                baseline,
                deep_tamper=self.use_deep_tamper("error_based"),
            ):
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue

                sql_error = find_sql_error(probe["text"])
                if sql_error:
                    self.record_dbms(flow, sql_error["dbms"])
                    return self.build_finding(
                        flow,
                        candidate,
                        "error_based",
                        {
                            "message": "database error appeared after injecting payload",
                            "payload": probe["sent_payload"],
                            "dbms": sql_error["dbms"],
                            "matched": sql_error["matched"],
                            "baseline_status": baseline["status_code"],
                            "probe_status": probe["status_code"],
                            "probe_length": probe["length"],
                            **self.tamper_evidence(probe),
                        },
                        proof_probe=probe,
                    )

        return None

    def check_boolean_based(self, flow, baseline_info, candidate):
        """布尔盲注检测。"""
        baseline = baseline_info["response"]

        for payload_group in self.boolean_payload_groups_for(candidate):
            response_pairs = self.send_probe_pair_variants(
                flow,
                candidate,
                payload_group["true"],
                payload_group["false"],
                baseline,
                deep_tamper=self.use_deep_tamper("boolean_based"),
            )

            for true_response, false_response in response_pairs:
                if not true_response or not false_response:
                    continue
                if true_response.get("waf_blocked") or false_response.get("waf_blocked"):
                    continue
                # 超时探测的正文是空的，拿来做相似度比较会被误判成“页面剧变”，
                # 布尔盲注必须有真实正文才能比较，所以跳过。
                if true_response.get("timed_out") or false_response.get("timed_out"):
                    continue

                true_similarity = self.similarity(baseline["text"], true_response["text"])
                false_similarity = self.similarity(baseline["text"], false_response["text"])
                true_false_similarity = self.similarity(
                    true_response["text"],
                    false_response["text"],
                )

                true_status_ok = true_response["status_code"] == baseline["status_code"]
                false_status_ok = false_response["status_code"] == baseline["status_code"]
                true_like_baseline = true_similarity >= TRUE_SIMILARITY_MIN
                false_like_baseline = false_similarity >= TRUE_SIMILARITY_MIN
                true_changed = true_similarity <= FALSE_SIMILARITY_MAX
                false_changed = false_similarity <= FALSE_SIMILARITY_MAX
                true_false_changed = true_false_similarity <= TRUE_FALSE_SIMILARITY_MAX

                and_style_hit = true_status_ok and true_like_baseline and false_changed
                or_style_hit = false_status_ok and false_like_baseline and true_changed

                if (and_style_hit or or_style_hit) and true_false_changed:
                    if and_style_hit:
                        message = "true payload is similar to baseline, false payload is different"
                    else:
                        message = "false payload is similar to baseline, true payload is different"

                    return self.build_finding(
                        flow,
                        candidate,
                        "boolean_based",
                        {
                            "message": message,
                            "payload_group": payload_group["name"],
                            "true_payload": true_response["sent_payload"],
                            "false_payload": false_response["sent_payload"],
                            "baseline_stability": baseline_info["stability"],
                            "baseline_status": baseline["status_code"],
                            "true_status": true_response["status_code"],
                            "false_status": false_response["status_code"],
                            "baseline_length": baseline["length"],
                            "true_length": true_response["length"],
                            "false_length": false_response["length"],
                            "true_similarity": round(true_similarity, 4),
                            "false_similarity": round(false_similarity, 4),
                            "true_false_similarity": round(true_false_similarity, 4),
                            **self.tamper_evidence(true_response),
                        },
                        proof_probe=true_response,
                        extra_probes=[
                            {
                                "name": "false payload",
                                "probe": false_response,
                            }
                        ],
                    )

        return None

    def check_inline_query(self, flow, baseline, candidate):
        """inline query 注入检测。

        参考 sqlmap 的 inline query 思路：
        把参数替换成一个子查询，如果查询结果里的 marker 出现在页面里，
        说明参数可能被当作 SQL 表达式执行。

        为了避免普通反射型页面误报，先发送 marker 本身做反射控制。
        如果页面会原样回显 marker，就不做 inline/UNION 的 marker 判断。
        """
        if self.is_header_candidate(candidate):
            return None

        payload_groups = build_inline_payload_groups(candidate["value"])
        if not payload_groups:
            return None
        payload_groups = self.filter_groups_by_dbms(flow, payload_groups)

        marker = payload_groups[0]["marker"]
        if marker in baseline["text"] or self.marker_reflected(flow, candidate, marker, baseline):
            return None

        for payload_group in payload_groups:
            probes = self.send_probe_variants(
                flow,
                candidate,
                payload_group["payload"],
                baseline,
                deep_tamper=self.use_deep_tamper("inline_query"),
            )
            for probe in probes:
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue

                if marker in probe["text"]:
                    self.record_dbms(flow, payload_group["dbms"])
                    return self.build_finding(
                        flow,
                        candidate,
                        "inline_query",
                        {
                            "message": "inline query marker appeared in response",
                            "dbms": payload_group["dbms"],
                            "payload_group": payload_group["name"],
                            "payload": probe["sent_payload"],
                            "marker": marker,
                            "baseline_status": baseline["status_code"],
                            "probe_status": probe["status_code"],
                            "probe_length": probe["length"],
                            **self.tamper_evidence(probe),
                        },
                        proof_probe=probe,
                    )

        return None

    def check_union_based(self, flow, baseline, candidate):
        """UNION query 注入检测。

        参考 sqlmap 的 UNION query 思路：
        猜测列数，并把唯一 marker 放到某一列里。
        如果响应里出现 marker，说明 UNION 查询结果进入了页面。
        """
        if self.is_header_candidate(candidate):
            return None

        payload_groups = build_union_payload_groups(candidate["value"])
        if not payload_groups:
            return None

        marker = payload_groups[0]["marker"]
        if marker in baseline["text"] or self.marker_reflected(flow, candidate, marker, baseline):
            return None

        for payload_group in payload_groups:
            probes = self.send_probe_variants(
                flow,
                candidate,
                payload_group["payload"],
                baseline,
                deep_tamper=self.use_deep_tamper("union_based"),
            )
            for probe in probes:
                if probe.get("waf_blocked") or probe.get("timed_out"):
                    continue

                if marker in probe["text"]:
                    return self.build_finding(
                        flow,
                        candidate,
                        "union_based",
                        {
                            "message": "UNION marker appeared in response",
                            "payload_group": payload_group["name"],
                            "payload": probe["sent_payload"],
                            "marker": marker,
                            "columns": payload_group["columns"],
                            "marker_index": payload_group["marker_index"],
                            "baseline_status": baseline["status_code"],
                            "probe_status": probe["status_code"],
                            "probe_length": probe["length"],
                            **self.tamper_evidence(probe),
                        },
                        proof_probe=probe,
                    )

        return None

    def check_stacked_query(self, flow, baseline, candidate):
        """stacked query 注入检测。

        stacked query 的特点是用分号追加第二条 SQL。
        当前只用延时函数验证，不执行写库操作。
        """
        for payload_group in self.stacked_payload_groups_for(flow, candidate):
            finding = self.check_delay_pair(flow, baseline, candidate, payload_group, "stacked_query")
            if finding:
                return finding

        return None

    def check_time_based(self, flow, baseline, candidate):
        """时间盲注检测。"""
        for payload_group in self.time_payload_groups_for(flow, candidate):
            finding = self.check_delay_pair(flow, baseline, candidate, payload_group, "time_based")
            if finding:
                return finding

        return None

    def is_header_candidate(self, candidate):
        """判断当前候选参数是否来自请求头。"""
        return candidate.get("place") == "header"

    def host_from_flow(self, flow):
        """从 flow 取出 host，作为 DBMS 记忆的 key。"""
        return urlsplit(flow.request.pretty_url).netloc

    def record_dbms(self, flow, dbms):
        """记住某个 host 已经识别出的具体数据库类型。

        只记录 mysql/postgresql/mssql/oracle/sqlite 这类具体数据库。
        generic 说明无法判断是哪种库，不做记录，后续仍按全部数据库尝试。
        """
        if not dbms or dbms not in CONCRETE_DBMS:
            return
        host = self.host_from_flow(flow)
        with self.lock:
            if self.host_dbms.get(host) != dbms:
                self.host_dbms[host] = dbms

    def known_dbms(self, flow):
        """读取某个 host 已识别出的具体数据库类型，没有则返回 None。"""
        with self.lock:
            return self.host_dbms.get(self.host_from_flow(flow))

    def filter_groups_by_dbms(self, flow, groups):
        """按已识别的 host 数据库类型裁剪带 dbms 标签的 payload 组。

        如果当前 host 还没识别出具体数据库，返回全部 payload 组，按原顺序广泛尝试。
        如果已经识别出具体数据库（例如 mysql），只保留该数据库以及 generic 的 payload 组，
        其他数据库的 payload 不再发送，减少无效请求。
        """
        dbms = self.known_dbms(flow)
        if not dbms:
            return groups

        filtered = [
            group for group in groups
            if group.get("dbms", "generic") in (dbms, "generic")
        ]
        # 极端情况下（规则里某数据库没有对应 payload）裁剪后为空，
        # 退回全部 payload，避免直接漏检。
        return filtered or groups

    def error_payloads_for(self, candidate):
        """按参数位置选择报错型 payload。"""
        if self.is_header_candidate(candidate):
            return build_header_error_payloads(candidate["value"])
        return build_error_payloads(candidate["value"])

    def boolean_payload_groups_for(self, candidate):
        """按参数位置选择布尔盲注 payload。"""
        if self.is_header_candidate(candidate):
            return build_header_boolean_payload_groups(candidate["value"])
        return build_boolean_payload_groups(candidate["value"])

    def time_payload_groups_for(self, flow, candidate):
        """按参数位置选择时间盲注 payload，并按已识别数据库裁剪。"""
        if self.is_header_candidate(candidate):
            groups = build_header_time_payload_groups(candidate["value"])
        else:
            groups = build_time_payload_groups(candidate["value"])
        return self.filter_groups_by_dbms(flow, groups)

    def stacked_payload_groups_for(self, flow, candidate):
        """按参数位置选择 stacked query payload，并按已识别数据库裁剪。"""
        if self.is_header_candidate(candidate):
            groups = build_header_stacked_payload_groups(candidate["value"])
        else:
            groups = build_stacked_payload_groups(candidate["value"])
        return self.filter_groups_by_dbms(flow, groups)

    def check_delay_pair(self, flow, baseline, candidate, payload_group, method):
        """通用延时验证逻辑。

        time_based 和 stacked_query 都可以用 control/delay 两个 payload 判断。
        """
        response_pairs = self.send_probe_pair_variants(
            flow,
            candidate,
            payload_group["control"],
            payload_group["delay"],
            baseline,
            deep_tamper=self.use_deep_tamper(method),
        )

        for control, delayed in response_pairs:
            if not control or not delayed:
                continue
            if control.get("waf_blocked") or delayed.get("waf_blocked"):
                continue

            # control 是 0 延时 payload，它本身不该慢。
            # 如果连 control 都超时，说明页面整体在挂（网络差/服务端慢），
            # 不是注入引起的延时，跳过以避免误报。
            if control.get("timed_out"):
                continue

            first_gap = delayed["elapsed"] - control["elapsed"]
            if first_gap < TIME_THRESHOLD:
                continue

            # 二次确认：使用同一组已经选中的 payload，避免第一次用 tamper，
            # 第二次又回到原始 payload。
            control_again, delayed_again = self.send_same_payload_pair(
                flow,
                candidate,
                control,
                delayed,
                baseline,
            )
            if not control_again or not delayed_again:
                continue
            if control_again.get("waf_blocked") or delayed_again.get("waf_blocked"):
                continue
            if control_again.get("timed_out"):
                continue

            second_gap = delayed_again["elapsed"] - control_again["elapsed"]
            if second_gap < TIME_THRESHOLD:
                continue

            # 两次 delay 都因为超时才变慢时，说明真实延时可能远大于 TIMEOUT
            # （例如 ORDER BY 上下文里 SLEEP 被逐行放大），在证据里标注出来。
            delay_timed_out = bool(delayed.get("timed_out") and delayed_again.get("timed_out"))

            self.record_dbms(flow, payload_group["dbms"])
            return self.build_finding(
                flow,
                candidate,
                method,
                {
                    "message": "delay payload is consistently slower than control payload",
                    "dbms": payload_group["dbms"],
                    "payload_group": payload_group["name"],
                    "control_payload": control["sent_payload"],
                    "delay_payload": delayed["sent_payload"],
                    "first_control_elapsed": round(control["elapsed"], 3),
                    "first_delay_elapsed": round(delayed["elapsed"], 3),
                    "second_control_elapsed": round(control_again["elapsed"], 3),
                    "second_delay_elapsed": round(delayed_again["elapsed"], 3),
                    "first_gap": round(first_gap, 3),
                    "second_gap": round(second_gap, 3),
                    "delay_timed_out": delay_timed_out,
                    **self.tamper_evidence(control),
                },
                proof_probe=delayed,
                extra_probes=[
                    {
                        "name": "control payload",
                        "probe": control,
                    }
                ],
            )

        return None

    def send_probe(self, flow, candidate, payload):
        """主动发送探测请求。

        candidate 为 None 表示重放原始请求。
        candidate 不为空时，只替换当前参数的值。
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
            # 4xx/5xx 里也可能有数据库报错，所以不能直接丢弃。
            response_body = error.read()
            status_code = error.code
            reason = getattr(error, "reason", "")
            response_headers = error.headers
        except (socket.timeout, TimeoutError):
            # 请求已经发出去，但服务端迟迟不返回，直到客户端超时。
            # 这本身就是时间盲注的强信号：例如 SLEEP 在 ORDER BY 上下文里
            # 被逐行放大，整体耗时远超 TIMEOUT。
            # 不能当成连接失败丢弃，否则时间盲注永远命中不了，还白等一次超时。
            return self.timed_out_probe(request_packet)
        except (URLError, OSError) as error:
            # 真正连不上目标（DNS、连接被拒、网络不可达）才算失败。
            # 但 URLError 也可能是 socket.timeout 包装而来，需要单独识别。
            if isinstance(getattr(error, "reason", None), (socket.timeout, TimeoutError)):
                return self.timed_out_probe(request_packet)
            return None

        elapsed = time.monotonic() - start_time
        charset = response_headers.get_content_charset() or "utf-8"
        text = response_body.decode(charset, errors="replace")
        response_packet = self.build_response_packet(
            status_code,
            reason,
            response_headers,
            response_body,
            charset,
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
        """构造一个“请求超时”的探测结果。

        和返回 None（连接失败）不同：超时说明请求已经发出且服务端在执行，
        只是耗时超过了 TIMEOUT。这是时间盲注的有效信号，所以要保留一个
        elapsed 标在 TIMEOUT 上、带 timed_out=True 的结构，让上层据此判断。

        status_code 用 0、text 用空串，避免被报错/布尔/marker 检测误判。
        """
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

    def send_probe_variants(
        self,
        flow,
        candidate,
        payload,
        baseline=None,
        deep_tamper=False,
    ):
        """发送单个 payload，并按需产出 tamper 版本。

        如果原始 payload 没被拦，只产出原始响应。
        如果原始 payload 被拦，会继续尝试多个 tamper profile。
        如果开启 deep_tamper，原始 payload 没命中时也会尝试少量 tamper。
        检测函数会逐个判断这些响应，直到找到真正的漏洞证据。
        """
        probe = self.send_probe(flow, candidate, payload)
        if not probe:
            return

        waf_info = self.detect_waf_block(probe, baseline)
        self.annotate_probe(probe, payload, "none", [], waf_info, [])
        self.notify_waf(flow, waf_info, baseline)
        yield probe

        if not waf_info["blocked"] and not deep_tamper:
            return

        original_reasons = waf_info["reasons"]
        profile_limit = None
        is_deep_retry = False
        if not original_reasons:
            profile_limit = self.deep_tamper_profile_limit()
            is_deep_retry = True

        seen_payloads = {payload}

        for profile in self.iter_tamper_profiles(candidate, profile_limit):
            tampered_payload = apply_tampers(payload, profile["tampers"])
            if tampered_payload in seen_payloads:
                continue
            seen_payloads.add(tampered_payload)

            retry = self.send_probe(flow, candidate, tampered_payload)
            if not retry:
                continue

            retry_waf_info = self.detect_waf_block(retry, baseline)
            self.annotate_probe(
                retry,
                tampered_payload,
                profile["name"],
                profile["tampers"],
                retry_waf_info,
                original_reasons,
                deep_tamper=is_deep_retry,
            )
            self.notify_waf(flow, retry_waf_info, baseline)
            yield retry

    def send_probe_with_waf_retry(self, flow, candidate, payload, baseline=None):
        """兼容旧调用：返回第一个没有被 WAF 拦截的响应。"""
        last_probe = None
        for probe in self.send_probe_variants(flow, candidate, payload, baseline):
            last_probe = probe
            if not probe.get("waf_blocked"):
                return probe
        return last_probe

    def send_probe_pair_variants(
        self,
        flow,
        candidate,
        left_payload,
        right_payload,
        baseline=None,
        deep_tamper=False,
    ):
        """发送成对 payload，并按需产出 tamper 版本。

        布尔盲注的 true/false、时间盲注的 control/delay 都必须成对比较。
        如果只变形其中一个，响应差异可能来自 payload 形态，而不是漏洞。
        """
        left = self.send_probe(flow, candidate, left_payload)
        right = self.send_probe(flow, candidate, right_payload)
        if not left or not right:
            return

        left_waf_info = self.detect_waf_block(left, baseline)
        right_waf_info = self.detect_waf_block(right, baseline)
        self.annotate_probe(left, left_payload, "none", [], left_waf_info, [])
        self.annotate_probe(right, right_payload, "none", [], right_waf_info, [])
        self.notify_waf(flow, left_waf_info, baseline)
        self.notify_waf(flow, right_waf_info, baseline)
        yield left, right

        if not left_waf_info["blocked"] and not right_waf_info["blocked"] and not deep_tamper:
            return

        original_reasons = self.merge_reasons(
            left_waf_info["reasons"],
            right_waf_info["reasons"],
        )
        profile_limit = None
        is_deep_retry = False
        if not original_reasons:
            profile_limit = self.deep_tamper_profile_limit()
            is_deep_retry = True

        seen_pairs = {(left_payload, right_payload)}

        for profile in self.iter_tamper_profiles(candidate, profile_limit):
            tampered_left_payload = apply_tampers(left_payload, profile["tampers"])
            tampered_right_payload = apply_tampers(right_payload, profile["tampers"])
            pair_key = (tampered_left_payload, tampered_right_payload)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            left_retry = self.send_probe(flow, candidate, tampered_left_payload)
            right_retry = self.send_probe(flow, candidate, tampered_right_payload)
            if not left_retry or not right_retry:
                continue

            left_retry_waf = self.detect_waf_block(left_retry, baseline)
            right_retry_waf = self.detect_waf_block(right_retry, baseline)
            self.annotate_probe(
                left_retry,
                tampered_left_payload,
                profile["name"],
                profile["tampers"],
                left_retry_waf,
                original_reasons,
                deep_tamper=is_deep_retry,
            )
            self.annotate_probe(
                right_retry,
                tampered_right_payload,
                profile["name"],
                profile["tampers"],
                right_retry_waf,
                original_reasons,
                deep_tamper=is_deep_retry,
            )
            self.notify_waf(flow, left_retry_waf, baseline)
            self.notify_waf(flow, right_retry_waf, baseline)
            yield left_retry, right_retry

    def send_probe_pair_with_waf_retry(
        self,
        flow,
        candidate,
        left_payload,
        right_payload,
        baseline=None,
    ):
        """兼容旧调用：返回第一组没有被 WAF 拦截的成对响应。"""
        last_pair = (None, None)
        for left, right in self.send_probe_pair_variants(
            flow,
            candidate,
            left_payload,
            right_payload,
            baseline,
        ):
            last_pair = (left, right)
            if not left.get("waf_blocked") and not right.get("waf_blocked"):
                return left, right
        return last_pair

    def send_same_payload_pair(self, flow, candidate, left_probe, right_probe, baseline):
        """用同一组已经选中的 payload 再发一次，给延时注入做确认。"""
        left = self.send_probe(flow, candidate, left_probe["sent_payload"])
        right = self.send_probe(flow, candidate, right_probe["sent_payload"])
        if not left or not right:
            return left, right

        left_waf_info = self.detect_waf_block(left, baseline)
        right_waf_info = self.detect_waf_block(right, baseline)
        retry_reasons = left_probe.get("waf_retry_reasons", [])

        self.annotate_probe(
            left,
            left_probe["sent_payload"],
            left_probe.get("tamper_profile", "none"),
            left_probe.get("tampers", []),
            left_waf_info,
            retry_reasons,
        )
        self.annotate_probe(
            right,
            right_probe["sent_payload"],
            right_probe.get("tamper_profile", "none"),
            right_probe.get("tampers", []),
            right_waf_info,
            retry_reasons,
        )
        self.notify_waf(flow, left_waf_info, baseline)
        self.notify_waf(flow, right_waf_info, baseline)
        return left, right

    def notify_waf(self, flow, waf_info, baseline=None):
        """只有原始请求也被 WAF 拦截时，才认为当前 IP/会话可能被封。"""
        if not self.waf_state or not waf_info.get("blocked"):
            return

        host = urlsplit(flow.request.pretty_url).netloc
        if not self.waf_state.should_check_ip_blocked(host):
            return

        clean_probe = self.send_probe(flow, None, "")
        if not clean_probe:
            return

        ip_block_info = self.detect_ip_block(clean_probe, baseline)
        if ip_block_info.get("blocked"):
            self.waf_state.block_host(host, ip_block_info.get("reasons", []))

    def iter_tamper_profiles(self, candidate=None, limit=None):
        """按 rules.yaml 的顺序返回有限数量的 tamper 策略。

        有些 tamper 不适合所有参数位置。
        例如换行和 Tab 不应该放进 Cookie header，所以 YAML 里可以写 places。
        """
        count = 0
        if limit is None:
            limit = max_tampered_payloads_per_probe()
        if limit <= 0:
            return

        place = candidate.get("place") if candidate else ""

        for profile in tamper_profiles():
            allowed_places = profile.get("places", [])
            if allowed_places and place and place not in allowed_places:
                continue

            tampers = profile.get("tampers", [])
            if not tampers:
                continue

            yield {
                "name": profile.get("name") or "+".join(tampers),
                "tampers": tampers,
                "places": allowed_places,
            }

            count += 1
            if count >= limit:
                break

    def detect_waf_block(self, response, baseline=None):
        """判断一次探测响应是否像 WAF 拦截页。"""
        rules = waf_detection_rules()
        reasons = []

        status_codes = {int(code) for code in rules.get("status_codes", [])}
        status_code = int(response.get("status_code", 0))
        baseline_status = baseline.get("status_code") if baseline else None

        # 如果 baseline 本来就是同样的 403/406，不只靠状态码判断 WAF。
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

        return {
            "blocked": bool(reasons),
            "reasons": self.merge_reasons(reasons),
        }

    def detect_ip_block(self, response, baseline=None):
        """判断原始干净请求是否显示当前 IP/会话被封禁。"""
        reasons = []
        status_code = int(response.get("status_code", 0))
        baseline_status = baseline.get("status_code") if baseline else None

        if status_code in IP_BLOCK_STATUS_CODES and status_code != baseline_status:
            reasons.append(f"status_code:{status_code}")

        if status_code in IP_BLOCK_HINT_STATUS_CODES:
            headers_text = "\n".join(
                f"{name}: {value}" for name, value in response.get("headers", {}).items()
            ).lower()
            for keyword in IP_BLOCK_HEADER_KEYWORDS:
                if keyword in headers_text:
                    reasons.append(f"header:{keyword}")

            body_text = response.get("text", "")[:8000].lower()
            for keyword in IP_BLOCK_BODY_KEYWORDS:
                if keyword.lower() in body_text:
                    reasons.append(f"body:{keyword}")

        return {
            "blocked": bool(reasons),
            "reasons": self.merge_reasons(reasons),
        }

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
        """给探测响应补充 payload 和 WAF 元信息。"""
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
        """生成漏洞结果里的 tamper 相关证据字段。"""
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

    def waf_evidence(self, probe):
        """兼容旧名字：现在返回所有 tamper 相关证据。"""
        return self.tamper_evidence(probe)

    def use_deep_tamper(self, method):
        """判断某种检测方法是否启用 deep tamper。"""
        if self.full_payload_scan:
            return True
        return self.deep_tamper and method in self.deep_tamper_methods

    def deep_tamper_profile_limit(self):
        """非 WAF 场景下 deep tamper 的 profile 数量上限。

        full_payload_scan 打开时返回 None，表示使用 rules.yaml 里的完整 tamper 上限。
        """
        if self.full_payload_scan:
            return None
        return self.deep_tamper_max_profiles

    def merge_reasons(self, *reason_lists):
        """合并原因列表并去重，保持原来的顺序。"""
        merged = []
        for reasons in reason_lists:
            for reason in reasons:
                if reason not in merged:
                    merged.append(reason)
        return merged[:8]

    def marker_reflected(self, flow, candidate, marker, baseline=None):
        """判断页面是否会原样反射 marker。

        如果普通参数值都会被页面回显，那么 UNION/inline 的 marker 出现
        就不一定代表 SQL 执行成功，所以这类情况直接跳过 marker 检测。
        """
        reflected = self.send_probe(flow, candidate, marker)
        if not reflected:
            return False
        if self.detect_waf_block(reflected, baseline)["blocked"]:
            return False
        return marker in reflected["text"]

    def build_probe_request(self, flow, candidate, payload):
        """根据参数位置构造新的 URL、body 和 header 覆盖项。"""
        request = flow.request
        url = request.pretty_url
        body = request.content or b""
        header_overrides = {}

        if not candidate:
            return url, body, header_overrides

        if candidate["place"] == "query":
            url = self.replace_query_value(url, candidate["index"], payload)
            return url, body, header_overrides

        if candidate["place"] == "cookie":
            cookie_header = get_header(request.headers, "cookie")
            pairs = self.parse_cookie_pairs(cookie_header)
            pairs[candidate["index"]] = (
                candidate["name"],
                self.cookie_safe_payload(payload, candidate.get("value", "")),
            )
            header_overrides["Cookie"] = self.build_cookie_header(pairs)
            return url, body, header_overrides

        if candidate["place"] == "header":
            header_overrides[candidate["name"]] = payload
            return url, body, header_overrides

        if candidate["place"] == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            pairs[candidate["index"]] = (candidate["name"], payload)
            charset = candidate.get("charset") or "utf-8"
            body = self.urlencode_pairs(pairs, charset).encode(charset, errors="replace")
            return url, body, header_overrides

        if candidate["place"] == "json":
            body = replace_json_body_parameter(
                body,
                request.headers,
                candidate,
                payload,
            )
            return url, body, header_overrides

        return url, body, header_overrides

    def replace_query_value(self, url, index, new_value):
        """只替换 URL 里第 index 个 query 参数。"""
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs[index] = (pairs[index][0], new_value)
        new_query = self.urlencode_pairs(pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def urlencode_pairs(self, pairs, charset="utf-8"):
        """编码 query/form 参数，并保留 payload 里手写的 %xx。

        宽字节/多次解码场景需要发送类似 %df%27 的原始编码。
        如果这里再把百分号编码成 %25df%2527，服务端就收不到预期 payload。
        """
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

    def build_cookie_header(self, pairs):
        """把 Cookie 参数列表重新拼成请求头。"""
        return "; ".join(f"{name}={value}" for name, value in pairs)

    def cookie_safe_payload(self, payload, original_value=""):
        """让 SQL payload 更适合放进 Cookie 值。

        普通 Cookie 不适合直接放空格，所以用 /**/ 替代。
        如果原始 Cookie 本身是短文本 base64，说明应用可能会先解码再使用。
        这时把 SQL payload 也 base64 后再塞回 Cookie，尽量保持原业务编码形态。
        """
        if self.looks_like_base64_text(original_value):
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")

        return payload.replace(" ", "/**/")

    def looks_like_base64_text(self, value):
        """判断 Cookie 值是否像 base64 编码的短文本。"""
        value = (value or "").strip()
        if len(value) < 4 or len(value) > 160:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
            return False

        normalized = value.replace("-", "+").replace("_", "/")
        normalized += "=" * (-len(normalized) % 4)

        try:
            decoded = base64.b64decode(normalized, validate=False)
            text = decoded.decode("utf-8")
        except Exception:
            return False

        if not text or len(text) > 120:
            return False
        return all(char.isprintable() for char in text)

    def copy_headers(self, headers):
        """复制请求头，并移除不适合主动重放的 header。"""
        copied = {}
        for name, value in headers.items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            copied[name] = value

        # 禁用压缩，方便直接比较响应文本。
        copied["Accept-Encoding"] = "identity"
        return copied

    def set_header(self, headers, name, value):
        """大小写不敏感地覆盖 header，避免 User-Agent/user-agent 重复。"""
        for old_name in list(headers.keys()):
            if old_name.lower() == name.lower():
                del headers[old_name]
        headers[name] = value

    def normalize_text(self, text):
        """响应归一化，减少动态内容对相似度的影响。"""
        text = text[:MAX_COMPARE_CHARS]
        text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<UUID>", text, flags=re.I)
        text = re.sub(r"\b[0-9a-f]{16,}\b", "<HEX>", text, flags=re.I)
        text = re.sub(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b", "<DATETIME>", text)
        text = re.sub(r"\b\d{10,13}\b", "<TS>", text)
        text = re.sub(r"csrf[_-]?token['\"]?\s*[:=]\s*['\"][^'\"]+", "csrf_token=<TOKEN>", text, flags=re.I)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def similarity(self, left, right):
        """计算两个响应正文的相似度，返回 0 到 1。"""
        left = self.normalize_text(left)
        right = self.normalize_text(right)
        return SequenceMatcher(None, left, right).ratio()

    def make_scan_key(self, flow, candidate):
        """生成去重 key，避免同一个参数反复扫描。"""
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

    def build_finding(
        self,
        flow,
        candidate,
        method,
        evidence,
        proof_probe=None,
        extra_probes=None,
    ):
        """生成统一漏洞结果结构。"""
        request = flow.request
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "sql_injection",
            "method": method,
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
        """从一次主动探测结果里提取报告需要的请求包和响应包。"""
        if not probe:
            return {"request": "", "response": ""}

        return {
            "request": probe.get("request_packet", ""),
            "response": probe.get("response_packet", ""),
        }

    def write_finding(self, finding):
        """把漏洞结果写入 JSON Lines，并更新 HTML 报告。"""
        write_jsonl(self.vuln_file, finding)
        print_finding_once(self, finding)
        if self.on_finding:
            self.on_finding(finding)
        write_html_report(self.vuln_file, self.report_file)

    def print_finding(self, finding):
        """终端打印简短提示。"""
        print(
            red(
                "[漏洞] "
                f"检测到 SQL 注入: {finding['method']} | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
