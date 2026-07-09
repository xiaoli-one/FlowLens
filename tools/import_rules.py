#!/usr/bin/env python3
# 公开指纹库导入工具。
#
# 手写的 rules.yaml 只覆盖几十个高置信度指纹。想识别几千个框架 / 开源应用，
# 用这个脚本把公开指纹库转换成我们的规则格式，输出到：
#   pass_scan/fingerprint/rules.generated.yaml
# rules.py 会自动把它和手写规则一起加载。
#
# 目前支持三种公开库格式：
#
# 1. Wappalyzer（technologies/*.json 或合并后的 technologies.json）
#    项目地址（已转社区维护）：
#      https://github.com/enthec/webappanalyzer  （技术库 JSON）
#    或历史版本：
#      https://github.com/wappalyzer/wappalyzer  src/technologies/*.json
#
# 2. EHole（finger.json）
#    https://github.com/EdgeSecurityTeam/EHole
#    国内红队常用，专攻 OA / CMS / 框架 / 中间件。
#
# 3. FingerprintHub / ObserverWard（web_fingerprint_v4.json / v3）
#    https://github.com/0x727/FingerprintHub
#    偏应用、CMS、后台、国产系统、设备面板和 favicon hash。
#
# 用法：
#   # Wappalyzer：传入一个或多个 a.json b.json ...（或一个合并的大 json）
#   python3 tools/import_rules.py wappalyzer technologies.json
#   python3 tools/import_rules.py wappalyzer src/technologies/*.json
#
#   # EHole：
#   python3 tools/import_rules.py ehole finger.json
#
#   # FingerprintHub：
#   python3 tools/import_rules.py fingerprinthub web_fingerprint_v4.json
#
# ⚠️ 许可证提醒：
#   这些公开库各有许可证（Wappalyzer 新版本为商业许可，旧版本 GPL；
#   EHole / FingerprintHub 见其仓库）。
#   仅自用 / 内部使用通常没问题；如需分发请先确认对应库的授权条款。
#
# 这个脚本是离线一次性工具，不在扫描运行时调用。

import glob
import json
import os
import re
import sys


OUTPUT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "pass_scan",
    "fingerprint",
    "rules.generated.yaml",
)

LIBS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "fingerprint_libs"
)


def download_libs():
    """下载公开指纹库到 fingerprint_libs/。

    用标准库 urllib，不依赖 curl。下载完用 `import_rules.py all` 导入。
    导入生成的 rules.generated.yaml 是自包含的，导入后 fingerprint_libs/ 可删。
    """
    import ssl
    import urllib.request

    wapp_dir = os.path.join(LIBS_DIR, "wappalyzer")
    os.makedirs(wapp_dir, exist_ok=True)
    ctx = ssl._create_unverified_context()

    def fetch(url, dest):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "pass_scan-fp"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = resp.read()
            if data[:1] not in (b"{", b"["):
                return False
            with open(dest, "wb") as file:
                file.write(data)
            return True
        except Exception:
            return False

    base = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
    ok = 0
    for letter in "abcdefghijklmnopqrstuvwxyz_":
        url = f"{base}/technologies/{letter}.json"
        if fetch(url, os.path.join(wapp_dir, f"{letter}.json")):
            ok += 1
    fetch(f"{base}/categories.json", os.path.join(wapp_dir, "categories.json"))
    print(f"  Wappalyzer: 下载 {ok} 个分片")

    ehole_ok = False
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/{branch}/finger.json"
        if fetch(url, os.path.join(LIBS_DIR, "ehole_finger.json")):
            ehole_ok = True
            break
    print(f"  EHole: {'下载成功' if ehole_ok else '下载失败'}")

    fh_dir = os.path.join(LIBS_DIR, "fingerprinthub")
    os.makedirs(fh_dir, exist_ok=True)
    fh_ok = 0
    fh_base = "https://raw.githubusercontent.com/0x727/FingerprintHub/main"
    for name in ("web_fingerprint_v4.json", "web_fingerprint_v3.json"):
        if fetch(f"{fh_base}/{name}", os.path.join(fh_dir, name)):
            fh_ok += 1
    print(f"  FingerprintHub: 下载 {fh_ok} 个文件")

    print(f"下载完成，存到 {LIBS_DIR}")
    print("下一步: python3 tools/import_rules.py all")


def _load_categories(paths):
    """从同目录的 categories.json 加载分类 ID -> 名称映射。

    Wappalyzer 的 cats 是数字 ID，例如 [1] 表示 CMS。
    映射到名称后输出更可读。找不到映射文件就返回空字典。
    """
    import os

    for path in paths:
        candidate = os.path.join(os.path.dirname(path), "categories.json")
        if os.path.exists(candidate):
            try:
                data = json.load(open(candidate, encoding="utf-8"))
                return {str(k): v.get("name", "") for k, v in data.items()}
            except (json.JSONDecodeError, AttributeError):
                continue
    return {}


def import_wappalyzer(paths):
    """把 Wappalyzer 技术库转换成我们的指纹规则。

    Wappalyzer 每个技术大致长这样：
      "WordPress": {
        "cats": [1],
        "html": ["wp-content", ...],
        "headers": {"X-Powered-By": "WordPress"},
        "cookies": {"wordpress_\\d+": ""},
        "url": ["/wp-admin"],
        "scriptSrc": ["wp-content/.*\\.js"],
        "meta": {"generator": "WordPress ([\\d.]+)\\;version:\\1"},
        "implies": ["PHP"],
        ...
      }

    被动扫描能用到的字段都转过来：
    - html / meta / scriptSrc -> body（meta、script 标签都在 HTML 正文里）
    - headers                 -> header
    - cookies                 -> cookie
    - url                     -> url（路径结构特征，识别开源框架很有用）

    带 \\;version:\\1 的，转成我们的 version 捕获正则。
    js / dom 这类需要执行 JS 才能拿到的，被动扫描拿不到，跳过。
    """
    categories = _load_categories(paths)
    fingerprints = []

    for path in paths:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        # 可能是 {"technologies": {...}} 或直接 {...}。
        technologies = data.get("technologies", data)

        for name, tech in technologies.items():
            matchers = []

            # html / scriptSrc -> body（script src 也出现在 HTML 文本里）
            for field in ("html", "scriptSrc"):
                for pattern in _as_list(tech.get(field)):
                    matchers.append(_text_matcher("body", pattern))

            # meta -> body，但要锚定到具体的 <meta name=...> 标签。
            # Wappalyzer 的 meta 是 {名称: 值正则}，值正则只作用于该 meta 标签的 content，
            # 不能当成全文搜索（否则 "^(.+)$" 会匹配任意页面）。
            for meta_name, pattern in (tech.get("meta") or {}).items():
                matchers.append(_meta_matcher(meta_name, pattern))

            # url -> url（路径结构特征）
            for pattern in _as_list(tech.get("url")):
                matchers.append(_text_matcher("url", pattern))

            # headers -> header
            for header_name, pattern in (tech.get("headers") or {}).items():
                matcher = {"source": "header", "name": header_name}
                _fill_pattern_and_version(matcher, pattern, allow_empty=True)
                matchers.append(matcher)

            # cookies -> cookie（取 cookie 名）
            for cookie_name in (tech.get("cookies") or {}).keys():
                matchers.append({"source": "cookie", "name": cookie_name})

            # 去掉转换后 pattern 为空的无效 matcher。
            matchers = [m for m in matchers if m]
            if not matchers:
                continue

            entry = {
                "name": name,
                "category": _category_name(tech.get("cats"), categories),
                "matchers": matchers,
            }
            implies = [_strip_confidence(item) for item in _as_list(tech.get("implies"))]
            implies = [item for item in implies if item]
            if implies:
                entry["implies"] = implies

            fingerprints.append(entry)

    return fingerprints


def _category_name(cats, categories):
    """把 Wappalyzer 的 cats 数字列表映射成第一个分类名称。"""
    for cat_id in _as_list(cats):
        name = categories.get(str(cat_id))
        if name:
            return name
    return "Wappalyzer"


def _text_matcher(source, pattern):
    """构造 body/url 类 matcher，处理 \\;version 元信息。

    过滤掉过于宽松、没有字面锚点的正则（例如 \\d+、^(.+)$、[\\d.]+），
    这类来自 Wappalyzer 的 meta/js 字段，单独当全文搜索会匹配任意页面，是误报源头。
    返回 None 表示这条 matcher 不可用，调用方会丢弃。
    """
    matcher = {"source": source}
    _fill_pattern_and_version(matcher, pattern, allow_empty=False)
    cleaned = matcher.get("pattern")
    if cleaned is None or _is_too_loose(cleaned):
        return None
    return matcher


def _meta_matcher(meta_name, raw_value):
    """把 Wappalyzer 的 meta 规则转成锚定到具体 <meta> 标签的 body 正则。

    {meta_name: value_pattern} 的语义是：名为 meta_name 的 meta 标签，
    其 content 匹配 value_pattern。这里构造：
      <meta ... name="meta_name" ... content="value...">
    meta_name 本身（如 tiddlywiki-version、generator）就是很强的指纹信号。

    value_pattern 是 "^(.+)$" 这类“任意值”时，只锚定 meta 名 + 捕获 content 当版本；
    是具体值（如 ^WordPress ([\\d.]+)）时，去掉首尾锚点后嵌进去。
    """
    import re

    if not meta_name:
        return None

    value = _clean_wappalyzer_pattern(raw_value)
    version_meta = _version_from_wappalyzer(raw_value)
    name_esc = re.escape(meta_name)

    # meta 标签里 name/property 和 content 顺序不固定，这里要求 name 在前、content 在后，
    # 覆盖绝大多数真实写法，避免过度复杂。
    head = f'<meta[^>]+(?:name|property)=["\\\']?{name_esc}["\\\' ][^>]*?content=["\\\']?'

    catch_all = value in ("", "^(.+)$", "^(.*)$", "(.+)", "(.*)", ".+", ".*", "^.+$", "^.*$")
    if catch_all:
        # 值是任意内容：锚定 meta 名即可，content 捕获组留给版本提取。
        pattern = head + '([^"\\\'>]+)'
        matcher = {"source": "body", "pattern": pattern}
        if version_meta:  # 通常是 \1，指 content
            matcher["version"] = pattern
        return matcher

    # 具体值：去掉首尾锚点后嵌入。
    inner = value.lstrip("^").rstrip("$")
    pattern = head + inner
    matcher = {"source": "body", "pattern": pattern}
    if version_meta and "\\1" in version_meta:
        matcher["version"] = pattern
    return matcher


# 这些“裸”正则没有任何字面标识，不能单独作为 body/url 指纹。
_LOOSE_PATTERNS = {
    r"\d+", r"[\d.]+", r"[\d.]*", r"\d", r".+", r".*",
    r"^(.+)$", r"^(.*)$", r"(.+)", r"(.*)", r"^.+$", r"^.*$",
    r"[a-f\d]+", r"[a-f0-9]+", r"[0-9.]+", r"[0-9]+", r"\w+", r".",
}


def _is_too_loose(pattern):
    """判断一个正则是否过于宽松、没有可识别的字面内容。

    规则：去掉正则元字符后，剩下的字面字符少于 3 个，就认为太松。
    例如 \\d+、[\\d.]+、^(.+)$ 都会被判为太松。
    """
    import re

    if pattern in _LOOSE_PATTERNS:
        return True
    # 去掉常见正则元字符和量词，看还剩多少“字面”字符。
    literal = re.sub(r"[\\^$.|?*+()\[\]{}\d\s/_:-]", "", pattern)
    return len(literal) < 3


def _fill_pattern_and_version(matcher, raw, allow_empty):
    """把 Wappalyzer 的 'regex\\;version:\\1' 拆成 pattern + version。

    - 正则主体写入 pattern。
    - 如果带 \\;version:\\1，说明 group(1) 是版本号，写入 version 捕获正则。
    - allow_empty=True（header 用）：空正则表示“只要该头存在就命中”，pattern 设为 .*。
    """
    cleaned = _clean_wappalyzer_pattern(raw)
    version = _version_from_wappalyzer(raw)

    if cleaned:
        matcher["pattern"] = cleaned
        # 带 \1 反向引用的 version 字段，直接复用主正则做捕获。
        if version and "\\1" in version:
            matcher["version"] = cleaned
    elif allow_empty:
        matcher["pattern"] = ".*"
    else:
        matcher["pattern"] = None


def _version_from_wappalyzer(raw):
    """从 'regex\\;version:\\1' 里取出 version: 后面的部分。"""
    if not raw or "\\;" not in str(raw):
        return ""
    for part in str(raw).split("\\;")[1:]:
        if part.startswith("version:"):
            return part[len("version:"):]
    return ""


def import_ehole(paths):
    """把 EHole finger.json 转换成我们的指纹规则。

    EHole 的 fingerprint 数组每项：
      {
        "cms": "Nacos",
        "method": "keyword",       # keyword 或 faviconhash
        "location": "body",        # body / header / title
        "keyword": ["console", "nacos"]
      }
    """
    fingerprints = []

    for path in paths:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        for item in data.get("fingerprint", []):
            name = item.get("cms") or item.get("name")
            if not name:
                continue

            method = (item.get("method") or "keyword").lower()
            location = (item.get("location") or "body").lower()
            keywords = _as_list(item.get("keyword"))

            matcher = None
            if method == "faviconhash":
                # EHole 的 favicon hash 也是 mmh3，可直接用。
                for keyword in keywords:
                    try:
                        matcher = {"source": "favicon", "hash": int(keyword)}
                    except (TypeError, ValueError):
                        matcher = None
                    if matcher:
                        fingerprints.append(
                            {
                                "name": name,
                                "category": "EHole",
                                "matchers": [matcher],
                            }
                        )
                continue

            # keyword 方法：EHole 要求所有关键字同时出现（AND）。
            # 关键字是字面串（路径、产品名、文件名），不是正则。
            # 用 all_of 做纯子串 AND 匹配，避免多关键字正则前瞻导致灾难性回溯。
            source = {"body": "body", "header": "header", "title": "title"}.get(
                location, "body"
            )
            # EHole 的 header 关键字其实也常出现在错误页正文里，且我们没有“全部响应头
            # 拼成一段文本”的 header 源，统一退化到 body 搜索。
            if source == "header":
                source = "body"

            keywords = [str(k) for k in keywords if str(k)]
            if not keywords:
                continue

            fingerprints.append(
                {
                    "name": name,
                    "category": "EHole",
                    "matchers": [{"source": source, "all_of": keywords}],
                }
            )

    return fingerprints


FINGERPRINTHUB_KEEP_KEYWORDS = (
    "admin",
    "adminer",
    "api-doc",
    "apigateway",
    "apollo",
    "cas",
    "cms",
    "codeigniter",
    "confluence",
    "console",
    "dashboard",
    "dedecms",
    "django",
    "drupal",
    "dubbo",
    "druid",
    "ecshop",
    "elasticsearch",
    "eoffice",
    "eolinker",
    "etcd",
    "express",
    "fastapi",
    "flask",
    "flink",
    "framework",
    "grafana",
    "harbor",
    "jira",
    "joomla",
    "kibana",
    "kubernetes",
    "laravel",
    "magento",
    "mall",
    "manage",
    "management",
    "manager",
    "nacos",
    "nestjs",
    "next.js",
    "nexus",
    "oa",
    "openapi",
    "panel",
    "phpmyadmin",
    "portal",
    "rabbitmq",
    "rails",
    "ruoyi",
    "seata",
    "shiro",
    "solr",
    "sonarqube",
    "spring",
    "struts",
    "swagger",
    "symfony",
    "thinkphp",
    "tomcat",
    "weblogic",
    "wiki",
    "wordpress",
    "xxl-job",
    "yii",
    "zabbix",
    "zblog",
    "zentao",
    "zend",
    "zookeeper",
    "云",
    "后台",
    "宝塔",
    "泛微",
    "框架",
    "管理",
    "系统",
    "若依",
    "蓝凌",
    "致远",
    "用友",
    "禅道",
    "金蝶",
)

FINGERPRINTHUB_DROP_KEYWORDS = (
    "camera",
    "dvr",
    "nvr",
    "router",
    "printer",
    "modem",
    "gateway",
    "ip camera",
    "network device",
)


def import_fingerprinthub(paths):
    """把 FingerprintHub / ObserverWard Web 指纹转换成我们的规则格式。

    支持 v4（nuclei-like）和 v3（keyword/favicon_hash）两种 JSON。
    为了保持当前工具聚焦 CMS / 应用框架 / 管理后台，导入时只保留名称、
    tags、product、vendor 命中高价值关键词的条目；设备类关键词会被丢弃。
    """
    fingerprints = []

    for path in paths:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, list):
            continue
        if data and isinstance(data[0], dict) and "http" in data[0]:
            fingerprints.extend(_import_fingerprinthub_v4_items(data))
        else:
            fingerprints.extend(_import_fingerprinthub_v3_items(data))

    return fingerprints


def _import_fingerprinthub_v4_items(items):
    fingerprints = []
    for item in items:
        info = item.get("info") or {}
        metadata = info.get("metadata") or {}
        name = (
            info.get("name")
            or metadata.get("product")
            or item.get("id")
            or ""
        )
        name = str(name).strip()
        if not name or not _keep_fingerprinthub_item(item):
            continue

        matchers = []
        for http_item in item.get("http") or []:
            for matcher in http_item.get("matchers") or []:
                matchers.extend(_fingerprinthub_v4_matchers(matcher))

        matchers = [matcher for matcher in matchers if matcher]
        if not matchers:
            continue

        fingerprints.append(
            {
                "name": _display_name(name),
                "category": _fingerprinthub_category(item),
                "matchers": matchers,
            }
        )
    return fingerprints


def _fingerprinthub_v4_matchers(matcher):
    matcher_type = str(matcher.get("type") or "").lower()
    if matcher_type == "favicon":
        result = []
        for value in _as_list(matcher.get("hash")):
            try:
                result.append({"source": "favicon", "hash": int(value)})
            except (TypeError, ValueError):
                continue
        return result

    source = "body"
    if str(matcher.get("part") or "").lower() in ("header", "headers"):
        source = "header"

    if matcher_type == "word":
        words = [str(word) for word in _as_list(matcher.get("words")) if str(word)]
        if not words:
            return []
        condition = str(matcher.get("condition") or "or").lower()
        if condition == "and" and len(words) > 1:
            return [{"source": source, "all_of": words}]
        return [_literal_matcher(source, word) for word in words]

    if matcher_type == "regex":
        result = []
        for pattern in _as_list(matcher.get("regex")):
            text = str(pattern or "").strip()
            if text and not _is_too_loose(text):
                result.append({"source": source, "pattern": text})
        return result

    return []


def _import_fingerprinthub_v3_items(items):
    fingerprints = []
    for item in items:
        name = str(item.get("name") or "").strip()
        if not name or not _keep_fingerprinthub_item(item):
            continue

        matchers = []
        keywords = [str(keyword) for keyword in _as_list(item.get("keyword")) if str(keyword)]
        if len(keywords) == 1:
            matchers.append(_literal_matcher("body", keywords[0]))
        elif len(keywords) > 1:
            matchers.append({"source": "body", "all_of": keywords})

        headers = item.get("headers") or {}
        if isinstance(headers, dict):
            for header_name, header_value in headers.items():
                matcher = {"source": "header", "name": str(header_name)}
                value = str(header_value or "").strip()
                if value:
                    matcher["pattern"] = re.escape(value)
                matchers.append(matcher)

        for value in _as_list(item.get("favicon_hash")):
            try:
                matchers.append({"source": "favicon", "hash": int(value)})
            except (TypeError, ValueError):
                continue

        matchers = [matcher for matcher in matchers if matcher]
        if not matchers:
            continue

        fingerprints.append(
            {
                "name": _display_name(name),
                "category": _fingerprinthub_category(item),
                "matchers": matchers,
            }
        )
    return fingerprints


def _literal_matcher(source, text):
    text = str(text or "")
    if not text:
        return None
    if source == "body":
        return {"source": "body", "all_of": [text]}
    return {"source": source, "pattern": re.escape(text)}


def _keep_fingerprinthub_item(item):
    haystack = _fingerprinthub_haystack(item)
    if any(keyword in haystack for keyword in FINGERPRINTHUB_DROP_KEYWORDS):
        return any(keyword in haystack for keyword in ("cms", "panel", "admin", "manage"))
    return any(keyword in haystack for keyword in FINGERPRINTHUB_KEEP_KEYWORDS)


def _fingerprinthub_haystack(item):
    parts = []
    if isinstance(item, dict):
        parts.extend(
            [
                item.get("id", ""),
                item.get("name", ""),
                item.get("path", ""),
            ]
        )
        info = item.get("info") or {}
        metadata = info.get("metadata") or {}
        parts.extend(
            [
                info.get("name", ""),
                info.get("tags", ""),
                metadata.get("product", ""),
                metadata.get("vendor", ""),
            ]
        )
    return " ".join(str(part).lower() for part in parts if part)


def _fingerprinthub_category(item):
    haystack = _fingerprinthub_haystack(item)
    if "cms" in haystack:
        return "CMS"
    if any(keyword in haystack for keyword in ("framework", "spring", "thinkphp", "laravel", "django", "flask", "fastapi", "yii", "rails")):
        return "框架"
    if any(keyword in haystack for keyword in ("swagger", "openapi", "api-doc")):
        return "API文档"
    if any(keyword in haystack for keyword in ("admin", "panel", "console", "dashboard", "manage", "manager", "后台", "管理")):
        return "管理后台"
    return "开源应用"


def _display_name(name):
    """把 FingerprintHub 常见 snake/kebab 名称稍微整理成可读形式。"""
    text = str(name or "").strip()
    if not text:
        return text
    return re.sub(r"[_-]+", " ", text).strip()


def _as_list(value):
    """Wappalyzer 字段可能是字符串或列表，统一成列表。"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean_wappalyzer_pattern(pattern):
    """去掉 Wappalyzer 正则里的 \\;version:、\\;confidence: 等元信息。

    同时去掉开头多余的 .* / .+ —— 我们用 re.search（任意位置匹配），
    开头的 .*/.+ 不改变是否命中，却会在不匹配的长正文上引发灾难性回溯
    （例如 ".+\\.twic\\.pics" 会从每个位置回溯）。去掉后语义不变、还更快。
    """
    if not pattern:
        return ""
    # Wappalyzer 用 \; 分隔正则和元信息。
    cleaned = str(pattern).split("\\;")[0].strip()
    # 反复剥掉开头的 .* / .+（可能带量词修饰，如 .*? ）。
    while True:
        stripped = re.sub(r"^\.[*+]\??", "", cleaned)
        if stripped == cleaned:
            break
        cleaned = stripped
    return cleaned


def _strip_confidence(value):
    """implies 里也可能带 \\;confidence:50，去掉它。"""
    return str(value).split("\\;")[0].strip()


def _escape_regex(text):
    """转义关键字里的正则特殊字符，按字面量匹配。"""
    import re

    return re.escape(str(text))


def _dedupe_fingerprints(fingerprints):
    """同名指纹合并 matcher，避免多来源重复。

    - 指纹名按大小写、空白、下划线、短横线归一后合并。
    - matcher 按结构去重，避免 Wappalyzer / EHole / FingerprintHub
      导入相同关键词或 favicon hash 时重复扫描和重复输出。
    """
    merged = {}
    order = []
    for entry in fingerprints:
        name = entry["name"]
        key = _fingerprint_key(name)
        if key not in merged:
            entry["matchers"] = _dedupe_matchers(entry.get("matchers", []))
            merged[key] = entry
            order.append(key)
            continue

        # 合并 matcher 和 implies。
        existing = merged[key]
        existing["matchers"].extend(entry.get("matchers", []))
        existing["matchers"] = _dedupe_matchers(existing["matchers"])
        existing_implies = set(existing.get("implies", []))
        for item in entry.get("implies", []):
            if item not in existing_implies:
                existing.setdefault("implies", []).append(item)
                existing_implies.add(item)
    return [merged[key] for key in order]


def _fingerprint_key(name):
    text = str(name or "").strip().lower()
    text = re.sub(r"[\s_-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _dedupe_matchers(matchers):
    seen = set()
    result = []
    for matcher in matchers:
        key = _matcher_key(matcher)
        if key in seen:
            continue
        seen.add(key)
        result.append(matcher)
    return result


def _matcher_key(matcher):
    normalized = {}
    for key, value in sorted((matcher or {}).items()):
        if key == "all_of" and isinstance(value, list):
            normalized[key] = sorted(str(item).lower() for item in value)
        elif key in ("name", "pattern", "source"):
            normalized[key] = str(value).lower()
        else:
            normalized[key] = value
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True)


def main():
    libs_dir = LIBS_DIR

    if len(sys.argv) < 2:
        print(__doc__)
        print("用法:")
        print("  python3 tools/import_rules.py download")
        print("      下载公开指纹库到 fingerprint_libs/（用标准库，不依赖 curl）")
        print("  python3 tools/import_rules.py all")
        print("      自动发现 fingerprint_libs/ 下的所有库并合并导入")
        print("  python3 tools/import_rules.py wappalyzer <文件...>")
        print("  python3 tools/import_rules.py ehole <文件...>")
        print("  python3 tools/import_rules.py fingerprinthub <文件...>")
        sys.exit(1)

    source = sys.argv[1].lower()
    fingerprints = []

    if source == "download":
        download_libs()
        return

    if source == "all":
        # 自动发现下载好的库文件。
        wapp_paths = sorted(glob.glob(os.path.join(libs_dir, "wappalyzer", "*.json")))
        # 排除 categories.json（它是映射表，不是技术库）。
        wapp_paths = [p for p in wapp_paths if not p.endswith("categories.json")]
        ehole_paths = glob.glob(os.path.join(libs_dir, "*finger*.json"))
        fh_paths = sorted(glob.glob(os.path.join(libs_dir, "fingerprinthub", "*.json")))

        if wapp_paths:
            wapp = import_wappalyzer(wapp_paths)
            print(f"  Wappalyzer: {len(wapp)} 条（来自 {len(wapp_paths)} 个分片）")
            fingerprints.extend(wapp)
        if ehole_paths:
            ehole = import_ehole(ehole_paths)
            print(f"  EHole: {len(ehole)} 条")
            fingerprints.extend(ehole)
        if fh_paths:
            fh = import_fingerprinthub(fh_paths)
            print(f"  FingerprintHub: {len(fh)} 条（来自 {len(fh_paths)} 个文件，已按应用/CMS/框架倾向过滤）")
            fingerprints.extend(fh)

        if not fingerprints:
            print(f"未在 {libs_dir} 找到任何库文件。")
            sys.exit(1)
    else:
        # 支持 shell 没展开的通配符。
        paths = []
        for arg in sys.argv[2:]:
            expanded = glob.glob(arg)
            paths.extend(expanded or [arg])

        if source == "wappalyzer":
            fingerprints = import_wappalyzer(paths)
        elif source == "ehole":
            fingerprints = import_ehole(paths)
        elif source in ("fingerprinthub", "fh", "observerward"):
            fingerprints = import_fingerprinthub(paths)
        else:
            print(f"未知来源: {source}（支持 all / wappalyzer / ehole / fingerprinthub）")
            sys.exit(1)

    before = len(fingerprints)
    fingerprints = _dedupe_fingerprints(fingerprints)
    print(f"合并重名后: {len(fingerprints)} 条（合并前 {before}）")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write("# 由 tools/import_rules.py 自动生成，请勿手动编辑。\n")
        file.write(f"# 来源: {source}，共 {len(fingerprints)} 条。\n\n")
        # JSON 是 YAML 1.2 的子集；写到 .yaml 里仍可被 rules.py 的
        # yaml.safe_load() 读取，同时让这个离线导入器不依赖 PyYAML。
        json.dump(
            {"fingerprints": fingerprints},
            file,
            ensure_ascii=False,
            indent=2,
        )
        file.write("\n")

    print(f"已写入 {len(fingerprints)} 条指纹到 {OUTPUT_FILE}")
    print("重启 run.py 后生效。")


if __name__ == "__main__":
    main()
