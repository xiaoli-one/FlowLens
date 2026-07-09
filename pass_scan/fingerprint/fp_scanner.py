# 指纹识别检测流程。
#
# 和 SQL 注入插件不同，指纹识别的目标只有一个：判断目标站点用了什么
# 框架 / 语言 / 中间件 / 开源应用，不去证明任何漏洞。
#
# 工作方式（半被动，参考 ehole / xray 的实时被动识别）：
# 1. 调度器把一条新流量交给本插件（按 host + 归一真实路径触发）。
# 2. 先用流量里已经有的请求/响应做被动识别（响应头、Set-Cookie、正文、URL）。
# 3. 再主动补轻量请求：当前路径段落地页 + 站点级 /favicon.ico。
#    落地页拿更完整的 HTML 特征；favicon 的 mmh3 hash 能精确命中开源项目。
# 4. 把所有信号丢进规则引擎（rules.yaml + rules.generated.yaml）做匹配，处理 implies 推导。
# 5. 输出识别结果；同一 host 后续真实路径仍会继续被动识别，发现新指纹会追加到报告聚合里。
#
# 去重（让后续路径继续识别，又不爆炸）靠三层：
# - interested()：同一个 host 的真实路径样本已识别、或样本数到上限，直接返回 False。
# - dedup_key()：返回 (host, 归一真实路径)，调度层 Deduper 挡住同路径并发流量。
# - check()：加锁做 check-and-add，是最终、权威的一次性保证。
# 主动补包另按 (host, 路径段) 限制；同一个路径段只补一次入口页/favicon。
# 同一个 host 已经报过的指纹名跨路径去重，但后续新路径识别到其它指纹会继续追加。
#
# favicon 抓到了但规则没命中时，会把 host + hash 记到 fingerprints_unknown.jsonl，
# 方便后续把这些 hash 补进规则库，慢慢积累开源项目识别能力。

import re
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from pass_scan.body_paser import decode_body_text, get_header
from pass_scan.fingerprint.reporter import write_jsonl
from pass_scan.fingerprint.rules import compiled_fingerprints, favicon_mmh3
from pass_scan.reporter import write_html_report
from pass_scan.terminal import green, yellow


# 主动补包的超时时间。指纹识别要轻，不值得为一个慢站等太久。
TIMEOUT = 8

# 参与匹配的正文最大长度。指纹特征基本都在页面头部（meta/script/title/版本号），
# 截断到 64KB 既覆盖特征，又限制正则在超大页面上的最坏开销。
MAX_BODY_CHARS = 65536
BODY_TRUNCATION_MARKER = "\n\n[pass_scan:fingerprint:body-truncated]\n\n"

# 从 HTML 里抽取 <title>。
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# 默认过滤掉的低价值指纹。它们通常只说明基础运行环境、前端库、CDN 或统计组件，
# 对后续渗透决策帮助很小，反而会淹没 CMS / 管理后台 / 应用框架。
LOW_VALUE_FINGERPRINT_NAMES = {
    "akamai",
    "amazon cloudfront",
    "apache",
    "apache http server",
    "angular",
    "angularjs",
    "asp.net",
    "baidu analytics",
    "bootstrap",
    "bootstrap icons",
    "bun",
    "caddy",
    "centos",
    "cdnjs",
    "cloudflare",
    "cloudfront",
    "core-js",
    "debian",
    "doubleclick floodlight",
    "envoy",
    "fastly",
    "font awesome",
    "go",
    "google analytics",
    "google font api",
    "google hosted libraries",
    "google tag manager",
    "gunicorn",
    "haproxy",
    "http/3",
    "hsts",
    "iis",
    "java",
    "jquery",
    "jquery blockui",
    "jquery migrate",
    "jquery mobile",
    "jquery sparklines",
    "jquery ui",
    "jsdelivr",
    "lighttpd",
    "lodash",
    "linux",
    "microsoft-iis",
    "modernizr",
    "moment.js",
    "nginx",
    "node.js",
    "openresty",
    "openssl",
    "perl",
    "php",
    "python",
    "react",
    "requirejs",
    "ruby",
    "tengine",
    "ubuntu",
    "underscore.js",
    "unix",
    "unpkg",
    "varnish",
    "vue.js",
    "webpack",
    "windows server",
}

LOW_VALUE_NAME_KEYWORDS = (
    "analytics",
    "doubleclick",
    "font awesome",
    "google tag manager",
    "tag manager",
)

LOW_VALUE_CATEGORIES = {
    "advertising",
    "analytics",
    "cdn",
    "cookie compliance",
    "font scripts",
    "javascript libraries",
    "maps",
    "marketing automation",
    "operating systems",
    "programming languages",
    "reverse proxies",
    "tag managers",
    "ui frameworks",
    "web servers",
    "widgets",
}

HIGH_VALUE_CATEGORIES = {
    "api文档",
    "cms",
    "database managers",
    "documentation",
    "ecommerce",
    "e-commerce",
    "ehole",
    "issue trackers",
    "message boards",
    "project management",
    "web frameworks",
    "wikis",
    "中间件",
    "开源应用",
    "应用",
    "框架",
    "管理后台",
}

HIGH_VALUE_NAME_KEYWORDS = (
    "admin",
    "adminer",
    "airflow",
    "api gateway",
    "apollo",
    "cas",
    "cms",
    "codeigniter",
    "confluence",
    "console",
    "consul",
    "dashboard",
    "dedecms",
    "django",
    "docker registry",
    "drupal",
    "dubbo",
    "druid",
    "elasticsearch",
    "etcd",
    "express",
    "fastapi",
    "flask",
    "flink",
    "grafana",
    "harbor",
    "jboss",
    "jenkins",
    "jetty",
    "jira",
    "joomla",
    "kibana",
    "kubernetes",
    "laravel",
    "magento",
    "nacos",
    "nestjs",
    "next.js",
    "nexus",
    "nuxt.js",
    "oa",
    "openapi",
    "panel",
    "phpmyadmin",
    "portal",
    "prometheus",
    "rabbitmq",
    "rails",
    "ruby on rails",
    "ruoyi",
    "seata",
    "shiro",
    "solr",
    "sonarqube",
    "spring",
    "spring boot",
    "springboot",
    "struts",
    "swagger",
    "swagger ui",
    "swaggerui",
    "symfony",
    "thinkphp",
    "tomcat",
    "weblogic",
    "wildfly",
    "wordpress",
    "xxl-job",
    "yii",
    "zabbix",
    "zend",
    "zookeeper",
    "宝塔",
    "泛微",
    "管理",
    "若依",
    "蓝凌",
    "用友",
    "金蝶",
)


class FingerprintScanner:
    """指纹识别插件。

    接口和 SQLInjectionScanner 对齐：
    - name
    - interested(context)
    - dedup_key(context)
    - check(context)
    """

    name = "fingerprint"

    def __init__(self, config=None, output_file=None, unknown_file=None,
                 report_file=None, vuln_file=None):
        self.config = config or {}
        # 是否允许主动补包（落地页 + favicon）。关掉就退化成纯被动。
        self.active_probe = bool(self.config.get("active_probe", True))
        self.fetch_favicon = bool(self.config.get("fetch_favicon", True))
        # 默认只上报有价值的指纹。基础语言、Web Server、前端库、统计/CDN 等低价值
        # 命中仍可参与内部判断，但不会污染输出，也不会阻止主动补包继续找应用指纹。
        self.report_low_value = bool(self.config.get("report_low_value", False))

        # 同一个 host 下，按“路径段”分别识别，让不同路径上的不同框架/服务都能被发现。
        # 例如 /grafana/* 识别出 Grafana、/jenkins/* 识别出 Jenkins、/ 识别出主站框架。
        # path_segment_depth 控制按前几段路径归一：
        #   depth=1：/grafana/login 和 /grafana/dash 都归到 /grafana（推荐）。
        #   /article/1 /article/2 也会归到 /article，避免按每个 URL 爆炸。
        self.segment_depth = max(1, int(self.config.get("path_segment_depth", 1)))
        # 每个 host 最多识别多少个不同路径段，防止一个站点路径太多导致请求爆炸。
        self.max_path_samples_per_host = int(self.config.get("max_paths_per_host", 25))

        self.output_file = output_file or "logs/fingerprints.jsonl"
        self.unknown_file = unknown_file or "logs/fingerprints_unknown.jsonl"
        # 报告文件：识别到指纹后刷新同一个 HTML 报告（漏洞/指纹共用）。
        # vuln_file 给报告生成器读漏洞数据，指纹只负责触发重绘指纹标签页。
        self.report_file = report_file
        self.vuln_file = vuln_file or "logs/vulns.jsonl"

        # 本次运行已经识别过的 (host, 归一真实路径)，进程生命周期内只增不减。
        # 这里故意不用路径段：同一段后续可能出现 /admin、/swagger 等新指纹。
        self.scanned_path_samples = set()
        # 每个 host 已识别的真实路径样本数量，用于限流。
        self.host_path_sample_count = {}
        # 主动补包按路径段限流，同一段只补一次，避免持续识别时主动请求爆炸。
        self.active_probed_segments = set()
        # 每个 host 已经报告过的指纹名，跨路径去重：Nginx 这种每条路径都在的，只报一次。
        self.host_reported = {}
        # 每个 host 的 favicon hash 缓存：favicon 是站点级的，整站只抓一次。
        self.favicon_cache = {}
        self.lock = threading.Lock()

        # 这两个属性由 scanner.py 在注册插件后注入，保持和其它插件一致。
        self.waf_state = None
        self.on_finding = None

        # 不走系统代理，避免主动请求又绕回 mitmproxy 形成回环。
        # 不校验证书，方便识别自签名站点。
        ssl_context = ssl._create_unverified_context()
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl_context),
        )

    def path_segment(self, path):
        """把路径归一成“路径段”，作为主动补包限流单元。

        depth=1 时：
          /                 -> /
          /grafana/login    -> /grafana
          /article/123      -> /article
          /api/v1/users     -> /api
        """
        parts = [p for p in (path or "/").split("/") if p]
        if not parts:
            return "/"
        return "/" + "/".join(parts[: self.segment_depth])

    def path_sample(self, path):
        """把真实路径归一成持续采样 key。

        它比 path_segment 更细：/app/login 和 /app/swagger 会分别识别；
        同时折叠纯数字、UUID、长 hash 这类动态 ID，避免 /article/1、/article/2
        把每个 host 的样本预算吃光。
        """
        parts = [p for p in (path or "/").split("/") if p]
        if not parts:
            return "/"

        normalized = [self.normalize_path_part(part) for part in parts]
        return "/" + "/".join(normalized)

    def normalize_path_part(self, part):
        """归一单个路径片段，用于降低动态路径爆炸。"""
        lower = str(part or "").lower()
        if re.fullmatch(r"\d+", lower):
            return "{id}"
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            lower,
        ):
            return "{uuid}"
        if re.fullmatch(r"[0-9a-f]{16,}", lower):
            return "{hash}"
        if len(lower) > 80:
            return "{long}"
        return lower

    def interested(self, context):
        """快速判断：是否需要识别这条流量的 (host, 归一真实路径)。

        这一层只做最便宜的判断，不发请求。
        """
        if context.is_skipped:
            return False
        if not context.host:
            return False

        key = (context.host, self.path_sample(context.path))
        with self.lock:
            if key in self.scanned_path_samples:
                return False
            # 该 host 真实路径样本已达上限，且这是个新样本，不再扫。
            if (
                self.host_path_sample_count.get(context.host, 0)
                >= self.max_path_samples_per_host
            ):
                return False
            return True

    def dedup_key(self, context):
        """调度层去重 key。

        用 (host, 归一真实路径)，保证同一路径在 TTL 内只入队一次，
        但同 host 下后续不同路径仍会各自入队、分别识别。
        """
        return (self.name, context.host, self.path_sample(context.path))

    def check(self, context):
        """指纹识别入口。由后台 worker 调用。"""
        host = context.host
        if not host:
            return []

        segment = self.path_segment(context.path)
        sample = self.path_sample(context.path)
        key = (host, sample)

        # 最终、权威的一次性保证：加锁 check-and-add，并做 host 级路径样本限流。
        with self.lock:
            if key in self.scanned_path_samples:
                return []
            if self.host_path_sample_count.get(host, 0) >= self.max_path_samples_per_host:
                return []
            self.scanned_path_samples.add(key)
            self.host_path_sample_count[host] = (
                self.host_path_sample_count.get(host, 0) + 1
            )

        # 被动优先（参考 ehole/xray）：先只用流量本身已有的请求/响应做识别。
        # match() 默认过滤低价值结果；只有识别到值得上报的 CMS / 应用框架 /
        # 管理后台等指纹时，才认为本段已足够，不再主动补包。
        signals = self.collect_passive_signals(context)
        detected = self.match(signals)

        # 被动只命中 Nginx/PHP/jQuery 这类低价值指纹时，detected 仍为空；
        # 此时继续补抓落地页 + favicon，避免通用环境指纹截停真正有价值的识别。
        if not detected and self.active_probe and self.reserve_active_probe(host, segment):
            self.add_active_signals(context, segment, signals)
            detected = self.match(signals)

        # 跨路径去重：同一个 host 已经报过的指纹名不再重复报。
        with self.lock:
            reported = self.host_reported.setdefault(host, set())
            new_detected = [item for item in detected if item["name"] not in reported]
            for item in new_detected:
                reported.add(item["name"])

        self.write_result(context, host, segment, signals, detected, new_detected)

        if new_detected:
            self.print_result(host, segment, new_detected)
            if self.on_finding:
                for _ in new_detected:
                    self.on_finding()
            self.refresh_report()
        elif not detected and signals.get("favicon_hash") is not None:
            # 没识别出来但拿到了 favicon，记下来方便后续补规则。
            self.write_unknown(host, segment, signals)

        return detected

    def reserve_active_probe(self, host, segment):
        """为 (host, 路径段) 预留一次主动补包机会。"""
        key = (host, segment)
        with self.lock:
            if key in self.active_probed_segments:
                return False
            self.active_probed_segments.add(key)
            return True

    def refresh_report(self):
        """识别到新指纹后刷新 HTML 报告（指纹标签页）。

        报告是漏洞和指纹共用的同一个文件，这里把当前漏洞数据一起带上，
        让两个标签页都是最新的。报告生成失败不影响扫描主流程。
        """
        if not self.report_file:
            return
        try:
            write_html_report(self.vuln_file, self.report_file, self.output_file)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 信号采集
    # ------------------------------------------------------------------

    def collect_passive_signals(self, context):
        """只汇总流量本身已有的被动信号，不发任何包。

        来源：触发本次识别的请求 Cookie + 响应头/Set-Cookie/正文。
        这是 ehole/xray 式实时识别的第一步：能被动判断就绝不主动发包。
        """
        signals = {
            "headers": {},          # 小写头名 -> [值, ...]，匹配 header 源
            "cookie_names": set(),  # 出现过的 cookie 名（小写），匹配 cookie 源
            "cookie_raw": "",       # 原始 cookie 文本，给 cookie 版本正则兜底
            "body": "",
            "title": "",
            "url": context.url,
            "favicon_hash": None,
        }

        flow = getattr(context, "flow", None)
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)

        if request is not None:
            self.absorb_request_cookies(request, signals)
        if response is not None:
            self.absorb_mitm_response(response, signals)

        self.finalize_signals(signals)
        return signals

    def add_active_signals(self, context, segment, signals):
        """被动没识别出来时，主动补抓落地页 + favicon，并入已有 signals。

        抓两个页面（best-effort，去重后最多两次请求）：
        - 原始触发路径：用户实际访问的完整路径最可能承载目标框架。
          例如 /业务路径/grafana，Grafana 特征在这个完整路径下，不在归一段 /业务路径。
        - 归一路径段：子应用入口页（如 /grafana/login 触发时补抓 /grafana）。
        favicon 是站点级资源，每个 host 只抓一次，算 mmh3 hash。
        发包节奏由 ScanQueue 的 per_host_interval / waf_state 控制，不在这里加速。
        """
        base = f"{context.scheme}://{context.host}"
        request = getattr(getattr(context, "flow", None), "request", None)

        current_path = context.path or "/"
        # 待补抓路径：优先原始触发路径，再补归一段，去重避免重复请求。
        probe_paths = []
        for candidate in (current_path, segment):
            normalized = candidate.rstrip("/") or "/"
            if normalized not in [p.rstrip("/") or "/" for p in probe_paths]:
                probe_paths.append(candidate)

        for probe_path in probe_paths:
            self.absorb_active_response(base + probe_path, request, signals)

        if self.fetch_favicon:
            signals["favicon_hash"] = self.get_favicon_hash(
                context.host, base, request
            )

        self.finalize_signals(signals)

    def finalize_signals(self, signals):
        """正文压缩 + 抽取标题。被动/主动阶段结束后都调用一次。"""
        signals["body"] = self.compact_body_text(signals["body"])
        if not signals["title"]:
            title_match = TITLE_RE.search(signals["body"])
            if title_match:
                signals["title"] = title_match.group(1).strip()

        return signals

    def append_body_signal(self, signals, text):
        """追加正文信号，同时保留开头和最新尾部。

        旧逻辑总是保留最前 64KB：被动响应很大时，主动补抓的入口页会被裁掉。
        这里保留整体开头 + 最新尾部，兼顾 title/meta 和后续补包里的应用特征。
        """
        if not text:
            return
        if signals["body"]:
            combined = signals["body"] + "\n" + text
        else:
            combined = text
        signals["body"] = self.compact_body_text(combined)

    def compact_body_text(self, text):
        """把参与匹配的正文压到 MAX_BODY_CHARS 内，并尽量保留两端特征。"""
        if len(text) <= MAX_BODY_CHARS:
            return text

        marker = BODY_TRUNCATION_MARKER
        head_budget = MAX_BODY_CHARS // 2
        tail_budget = MAX_BODY_CHARS - head_budget - len(marker)
        if tail_budget <= 0:
            return text[:MAX_BODY_CHARS]
        return text[:head_budget] + marker + text[-tail_budget:]

    def get_favicon_hash(self, host, base, origin_request):
        """获取 host 的 favicon hash。

        favicon 是站点级资源，同一个 host 的不同路径段共用，所以整站只抓一次，
        结果缓存。缓存值用哨兵区分“没抓到”和“还没抓过”。
        """
        with self.lock:
            if host in self.favicon_cache:
                return self.favicon_cache[host]

        result = self.fetch(base + "/favicon.ico", origin_request, want_bytes=True)
        favicon_hash = None
        if result:
            content = result.get("raw") or b""
            # 太大的多半不是图标，跳过避免误算。
            if content and len(content) <= 1024 * 200:
                favicon_hash = favicon_mmh3(content)

        with self.lock:
            self.favicon_cache[host] = favicon_hash
        return favicon_hash

    def absorb_request_cookies(self, request, signals):
        """从请求的 Cookie 头里收集 cookie 名。

        PHPSESSID、JSESSIONID 这类常出现在请求 Cookie 里（前面页面 set 的），
        所以请求侧也要看，不能只看响应的 Set-Cookie。
        """
        cookie_header = get_header(request.headers, "cookie")
        if not cookie_header:
            return
        signals["cookie_raw"] += cookie_header + "\n"
        for item in cookie_header.split(";"):
            name = item.split("=", 1)[0].strip()
            if name:
                signals["cookie_names"].add(name.lower())

    def absorb_mitm_response(self, response, signals):
        """吸收 mitmproxy 已经拿到的响应。"""
        pairs = self.mitm_header_pairs(response.headers)
        self.absorb_header_pairs(pairs, signals)

        body = response.content or b""
        text, _charset = decode_body_text(body, response.headers)
        self.append_body_signal(signals, text)

    def absorb_active_response(self, url, origin_request, signals):
        """主动 GET 一个页面并吸收其响应（落地页等）。"""
        result = self.fetch(url, origin_request)
        if not result:
            return
        self.absorb_header_pairs(result["headers"], signals)
        self.append_body_signal(signals, result["body"])

    def absorb_header_pairs(self, pairs, signals):
        """把 (name, value) 头列表并入信号。"""
        for name, value in pairs:
            lower = name.lower()
            signals["headers"].setdefault(lower, []).append(value)
            if lower == "set-cookie":
                signals["cookie_raw"] += value + "\n"
                cookie_name = value.split("=", 1)[0].strip()
                if cookie_name:
                    signals["cookie_names"].add(cookie_name.lower())

    def mitm_header_pairs(self, headers):
        """把 mitmproxy 的 headers 转成 (name, value) 列表，保留重复头。"""
        fields = getattr(headers, "fields", None)
        if fields:
            pairs = []
            for raw_name, raw_value in fields:
                name = raw_name.decode("latin-1") if isinstance(raw_name, bytes) else raw_name
                value = raw_value.decode("latin-1") if isinstance(raw_value, bytes) else raw_value
                pairs.append((name, value))
            return pairs
        return list(headers.items())

    def fetch(self, url, origin_request, want_bytes=False):
        """主动发起一个 GET 请求，best-effort，失败返回 None。"""
        headers = self.probe_headers(origin_request)
        try:
            request = Request(url, headers=headers, method="GET")
            response = self.opener.open(request, timeout=TIMEOUT)
            raw = response.read(1024 * 1024)  # 最多读 1MB，指纹用不到更多
            status = response.status
            response_headers = response.headers
        except HTTPError as error:
            # 4xx/5xx 里也常有 Server/X-Powered-By 头和报错页特征，照样吸收。
            raw = error.read(1024 * 1024) if hasattr(error, "read") else b""
            status = error.code
            response_headers = error.headers
        except (URLError, OSError, ValueError):
            return None

        pairs = [(name, value) for name, value in response_headers.items()]
        # email.message 的 items() 会保留重复 Set-Cookie，这里无需特殊处理。

        result = {"status": status, "headers": pairs}
        if want_bytes:
            result["raw"] = raw
            result["body"] = ""
        else:
            charset = response_headers.get_content_charset() or "utf-8"
            result["body"] = raw.decode(charset, errors="replace")
            result["raw"] = b""
        return result

    def probe_headers(self, origin_request):
        """构造主动请求头。

        尽量沿用原始请求的 UA / Accept-Language / Cookie，
        让目标把我们当成同一个客户端，提高识别成功率。
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; pass_scan-fingerprint)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
        }
        if origin_request is not None:
            for name in ("User-Agent", "Accept-Language", "Cookie"):
                value = get_header(origin_request.headers, name)
                if value:
                    headers[name] = value
        return headers

    # ------------------------------------------------------------------
    # 规则匹配
    # ------------------------------------------------------------------

    def match(self, signals, include_low_value=None):
        """跑规则引擎，返回识别结果列表。

        每个结果：
        {"name", "category", "version", "evidence", "implied_by"}
        """
        if include_low_value is None:
            include_low_value = self.report_low_value

        results = {}

        for fingerprint in compiled_fingerprints():
            hit_evidence, version = self.match_fingerprint(fingerprint, signals)
            if hit_evidence is None:
                continue
            results[fingerprint["name"]] = {
                "name": fingerprint["name"],
                "category": fingerprint["category"],
                "version": version or "",
                "evidence": hit_evidence,
                "implied_by": "",
            }

        # 处理 implies 推导（可传递）。
        self.apply_implies(results)

        items = list(results.values())
        if not include_low_value:
            items = [item for item in items if self.is_reportable_fingerprint(item)]

        # 按分类稳定排序，方便阅读。
        return sorted(items, key=lambda item: (item["category"], item["name"]))

    def is_reportable_fingerprint(self, item):
        """判断一个命中是否值得输出给使用者。

        目标是把结果面收敛到 CMS、业务应用、服务端框架、管理后台、控制台、
        API 文档和中间件管理面。低价值基础设施信号仍会参与内部匹配，但默认不上报。
        """
        name = self.normalize_fingerprint_text(item.get("name", ""))
        category = self.normalize_fingerprint_text(item.get("category", ""))

        if name in LOW_VALUE_FINGERPRINT_NAMES:
            return False
        if any(keyword in name for keyword in LOW_VALUE_NAME_KEYWORDS):
            return False

        if category in HIGH_VALUE_CATEGORIES:
            return True
        if self.has_high_value_name_keyword(name):
            return True
        if item.get("evidence") == "favicon:hash":
            return True

        if category in LOW_VALUE_CATEGORIES:
            return False

        return False

    def normalize_fingerprint_text(self, value):
        """统一指纹名称/分类的比较形式。"""
        return re.sub(r"\s+", " ", str(value or "").strip().lower())

    def has_high_value_name_keyword(self, name):
        """判断名称里是否包含高价值产品/后台关键词。

        英文关键词按非字母数字边界匹配，避免 cas -> EdgeCast、
        oa -> GoatCounter、panel -> Mixpanel 这类子串误报。中文产品名仍按子串匹配。
        """
        for keyword in HIGH_VALUE_NAME_KEYWORDS:
            if not keyword:
                continue
            if re.search(r"[^\x00-\x7f]", keyword):
                if keyword in name:
                    return True
                continue
            pattern = rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])"
            if re.search(pattern, name):
                return True
        return False

    def match_fingerprint(self, fingerprint, signals):
        """判断单个指纹是否命中。命中返回 (证据, 版本)，否则 (None, None)。"""
        for matcher in fingerprint["matchers"]:
            matched_text = self.match_one(matcher, signals)
            if matched_text is None:
                continue

            version = self.extract_version(matcher, matched_text)
            evidence = self.evidence_label(matcher)
            return evidence, version

        return None, None

    def match_one(self, matcher, signals):
        """判断单个 matcher 是否命中。

        命中时返回用于版本提取的文本；不命中返回 None。
        """
        source = matcher["source"]

        if source == "favicon":
            target = matcher["hash"]
            if target is not None and signals["favicon_hash"] == target:
                return ""  # favicon 没有可供版本提取的文本
            return None

        if source == "cookie":
            # cookie 源主要看 cookie 名是否出现。
            if matcher["name"] and matcher["name"] in signals["cookie_names"]:
                return signals["cookie_raw"]
            name_pattern = matcher.get("name_pattern")
            if name_pattern:
                for cookie_name in signals["cookie_names"]:
                    if name_pattern.match(cookie_name):
                        return signals["cookie_raw"]
            return None

        if source == "header":
            if matcher["name"]:
                values = signals["headers"].get(matcher["name"], [])
            else:
                values = [
                    f"{name}: {value}"
                    for name, header_values in signals["headers"].items()
                    for value in header_values
                ]
            if not values:
                return None
            joined = "\n".join(values)
            if matcher["pattern"] is None:
                return joined  # 只要该头存在就算命中
            if matcher["pattern"].search(joined):
                return joined
            return None

        # body / url / title 都是纯文本搜索。
        text = signals.get(source, "")
        if not text:
            return None

        # all_of：一组字面子串必须全部出现（纯子串匹配，无正则回溯风险）。
        if matcher.get("all_of"):
            low = text.lower()
            if all(token in low for token in matcher["all_of"]):
                return text
            return None

        if matcher["pattern"] is None:
            return None
        # 预过滤：正则有固定字面段时，先做一次极快子串判断。
        # 字面段都不在正文里，正则不可能命中，直接跳过——既加速又避免
        # 在不匹配的长正文上触发灾难性回溯。
        literal = matcher.get("literal")
        if literal and literal not in text.lower():
            return None
        if matcher["pattern"].search(text):
            return text
        return None

    def extract_version(self, matcher, text):
        """用 matcher 的 version 正则从命中文本里提取版本号。"""
        version_re = matcher.get("version")
        if not version_re or not text:
            return ""
        match = version_re.search(text)
        if not match:
            return ""
        # 取第一个非空捕获组。
        for group in match.groups():
            if group:
                version = group.strip()
                # 版本号不该很长。过长说明捕获正则太宽，宁可不报版本也不污染结果。
                if len(version) > 40:
                    return ""
                return version
        return ""

    def evidence_label(self, matcher):
        """生成简短证据标签，例如 header:server、body、favicon:hash。"""
        source = matcher["source"]
        if source in ("header", "cookie") and matcher["name"]:
            return f"{source}:{matcher['name']}"
        if source == "favicon":
            return "favicon:hash"
        return source

    def apply_implies(self, results):
        """把 implies 推导出的指纹补进结果集（可传递）。

        例如识别出 WordPress -> 自动带出 PHP；
        Next.js -> React、Node.js。
        被推导出来、又没有独立证据的指纹，标记 implied_by。
        """
        compiled = {fp["name"]: fp for fp in compiled_fingerprints()}
        pending = list(results.keys())

        while pending:
            current = pending.pop()
            fingerprint = compiled.get(current)
            if not fingerprint:
                continue
            for implied_name in fingerprint["implies"]:
                if implied_name in results:
                    continue
                implied_fp = compiled.get(implied_name, {})
                results[implied_name] = {
                    "name": implied_name,
                    "category": implied_fp.get("category", "推导"),
                    "version": "",
                    "evidence": "implied",
                    "implied_by": current,
                }
                pending.append(implied_name)

    # ------------------------------------------------------------------
    # 输出
    # ------------------------------------------------------------------

    def write_result(self, context, host, segment, signals, detected, new_detected):
        """把识别结果写入 fingerprints.jsonl，每个 (host, 路径段) 一条。

        detected 是本路径段识别出的全部指纹；
        new_detected 是其中该 host 首次出现、本次新报告的指纹。
        两者都记录，方便区分“这个路径段有什么”和“整站新增了什么”。
        """
        new_names = {item["name"] for item in new_detected}
        record = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "host": host,
            "path": segment,
            "url": context.url,
            "favicon_hash": signals.get("favicon_hash"),
            "fingerprints": [
                {
                    "name": item["name"],
                    "category": item["category"],
                    "version": item["version"],
                    "evidence": item["evidence"],
                    "implied_by": item["implied_by"],
                    "first_seen_on_host": item["name"] in new_names,
                }
                for item in detected
            ],
        }
        write_jsonl(self.output_file, record)

    def write_unknown(self, host, segment, signals):
        """记录抓到 favicon 但没命中规则的路径，方便后续补库。"""
        record = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "host": host,
            "path": segment,
            "favicon_hash": signals.get("favicon_hash"),
            "title": signals.get("title", ""),
        }
        write_jsonl(self.unknown_file, record)

    def print_result(self, host, segment, new_detected):
        """终端彩色打印一行识别摘要（只打印该 host 新出现的指纹）。"""
        labels = []
        for item in new_detected:
            label = item["name"]
            if item["version"]:
                label += f" {item['version']}"
            label += f"({item['category']})"
            labels.append(label)

        location = host if segment == "/" else f"{host}{segment}"
        print(
            green(f"[指纹] {location} -> " + ", ".join(labels)),
            flush=True,
        )
