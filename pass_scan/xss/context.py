# XSS 上下文识别与闭合验证。
#
# 反射型 XSS 的关键不是“参数有没有回显”，而是“回显在什么位置、能不能打破
# 当前语法上下文”。同样一个值：
#   - 出现在 <div>这里</div> 里，能注入 < > 就能起标签；
#   - 出现在 <input value="这里"> 里，要先能注入 " 闭合属性；
#   - 出现在 <script>var a="这里"</script> 里，要能注入 " 或 ' 闭合 JS 字符串。
#
# 所以这个模块负责两件事：
# 1. locate_reflections：在响应正文里找到 marker 出现的所有位置。
# 2. classify_context：根据 marker 前后的文本，判断它落在哪种上下文。
#
# 真正“能不能打破上下文”由 xss_scanner.py 用 rules.yaml 里每个上下文的
# required_chars 判断：把对应 payload 打进去后，这些关键字符是否原样、
# 未被 HTML 实体编码地出现在响应里。本模块只提供定位 + 上下文分类 + 编码判断。

import re


# marker 前后取多长的上下文来做判断。
CONTEXT_WINDOW = 200


def locate_reflections(text, marker):
    """在响应正文里找到 marker 的所有出现位置。

    返回位置索引列表。没有反射返回空列表。
    """
    positions = []
    if not marker or not text:
        return positions

    start = 0
    while True:
        index = text.find(marker, start)
        if index == -1:
            break
        positions.append(index)
        start = index + len(marker)
        # 防御：marker 出现次数异常多时（例如页面把它塞进列表），
        # 只取前若干个，避免在超大页面上做过多上下文分析。
        if len(positions) >= 20:
            break
    return positions


def classify_context(text, index, marker):
    """判断 marker 在 text[index] 处落在哪种上下文。

    返回 (context, tag) 二元组：
    - context 与 rules.yaml 的 context 字段对应：
        html_text / rawtext / attr_double / attr_single / attr_unquoted /
        js_string_double / js_string_single / js_code / html_comment / url_attr
    - tag 是外层标签名（仅 rawtext 上下文有意义，用于生成 </tag> 闭合序列），
      其它上下文为 ""。
    """
    before = text[max(0, index - CONTEXT_WINDOW):index]

    # 1. HTML 注释：marker 前有 <!-- 且这之后还没有 -->。
    comment_open = before.rfind("<!--")
    comment_close = before.rfind("-->")
    if comment_open != -1 and comment_open > comment_close:
        return "html_comment", ""

    # 2. <script> 块内：marker 前最近的是 <script ...> 而不是 </script>。
    if _inside_tag(before, "script"):
        return _classify_js_context(before), ""

    # 3. 其它 RAWTEXT / RCDATA 标签内（textarea/title/style/xmp/noscript/iframe）。
    #    这类标签里 < 不会被当新标签，必须先 </标签> 闭合当前标签才能逃逸。
    rawtext_tag = _inside_rawtext_tag(before)
    if rawtext_tag:
        return "rawtext", rawtext_tag

    # 4. 标签属性内：marker 前最近的是 < 开标签且还没闭合 >。
    tag_open = before.rfind("<")
    tag_close = before.rfind(">")
    in_tag = tag_open != -1 and tag_open > tag_close
    if in_tag:
        return _classify_attr_context(before, tag_open), ""

    # 5. 其它情况按 HTML 文本区处理。
    return "html_text", ""


# 除 <script> 外的 RAWTEXT / RCDATA 标签：内容不被当作普通 HTML 解析，
# 想逃逸必须先闭合对应标签。<script> 单独处理（走 JS 上下文分类）。
RAWTEXT_TAGS = ("textarea", "title", "style", "xmp", "noscript", "noframes", "iframe")


def _inside_rawtext_tag(before):
    """判断 marker 是否落在某个 RAWTEXT/RCDATA 标签内，返回标签名或 ""。"""
    for tag in RAWTEXT_TAGS:
        if _inside_tag(before, tag):
            return tag
    return ""


def _inside_tag(before, tag):
    """判断 marker 是否落在 <tag ...> 与 </tag> 之间（尚未闭合）。"""
    lowered = before.lower()
    open_pos = _last_tag_open(lowered, tag)
    close_pos = lowered.rfind("</" + tag)
    return open_pos != -1 and open_pos > close_pos


def _last_tag_open(lowered, tag):
    """找到 lowered 里最后一个 <tag 开标签的位置（要求 tag 后是分隔符）。"""
    needle = "<" + tag
    search_start = 0
    last = -1
    while True:
        index = lowered.find(needle, search_start)
        if index == -1:
            break
        # 确认是完整标签名，避免 <scriptx / <titlebar 之类误匹配。
        tail = lowered[index + len(needle): index + len(needle) + 1]
        if tail in ("", " ", ">", "\t", "\n", "\r", "/"):
            last = index
        search_start = index + len(needle)
    return last


def _last_script_open(before):
    """找到 before 里最后一个 <script ...> 开标签的位置。"""
    return _last_tag_open(before.lower(), "script")


def _classify_js_context(before):
    """在 <script> 块内进一步判断 marker 落在字符串还是裸代码里。

    做法很朴素：统计 marker 之前、当前 <script> 块内未配对的引号。
    奇数个双引号 -> 在双引号字符串里；奇数个单引号 -> 单引号字符串里。
    """
    script_start = _last_script_open(before)
    # 从 <script> 标签的 > 之后开始算脚本正文。
    body_start = before.find(">", script_start)
    body = before[body_start + 1:] if body_start != -1 else before[script_start:]

    double = _count_unescaped(body, '"')
    single = _count_unescaped(body, "'")
    backtick = _count_unescaped(body, "`")

    if double % 2 == 1:
        return "js_string_double"
    if single % 2 == 1:
        return "js_string_single"
    if backtick % 2 == 1:
        # 模板字符串，判定逻辑上更接近双引号字符串，归为裸代码更保守。
        return "js_code"
    return "js_code"


def _classify_attr_context(before, tag_open):
    """在标签内部判断 marker 落在哪种属性值上下文。

    - 双/单引号属性：属性名后跟 =" 或 =' 且还没闭合。
    - 无引号属性：= 后直接是值，没有引号。
    - href/src 等 URL 属性单独识别为 url_attr。
    """
    tag_fragment = before[tag_open:]

    # 判断是否 URL 属性上下文（href/src/action/formaction 等）。
    url_attr = _in_url_attribute(tag_fragment)

    # 统计属性区里的引号，判断当前是否处于引号内。
    double = _count_unescaped(tag_fragment, '"')
    single = _count_unescaped(tag_fragment, "'")

    if double % 2 == 1:
        return "url_attr" if url_attr else "attr_double"
    if single % 2 == 1:
        return "url_attr" if url_attr else "attr_single"

    # 不在引号里：可能是无引号属性值。确认最近一个非空白字符是 = 。
    stripped = tag_fragment.rstrip()
    if stripped.endswith("="):
        return "url_attr" if url_attr else "attr_unquoted"

    # 其它：标签内但难以判断，按无引号属性保守处理（要求空格+>）。
    return "attr_unquoted"


URL_ATTR_RE = re.compile(
    r"""(?:href|src|action|formaction|data|poster|xlink:href)\s*=\s*['"]?[^'"]*$""",
    re.IGNORECASE,
)


def _in_url_attribute(tag_fragment):
    """判断 marker 是否落在 href/src 这类 URL 属性值里。"""
    return bool(URL_ATTR_RE.search(tag_fragment))


def _count_unescaped(text, char):
    """统计 text 里未被反斜杠转义的某个字符数量。

    用于粗略判断引号是否配对。JS 里 \\" 不算真正的引号边界。
    """
    count = 0
    escaped = False
    for current in text:
        if escaped:
            escaped = False
            continue
        if current == "\\":
            escaped = True
            continue
        if current == char:
            count += 1
    return count


def chars_reflected_raw(text, marker, required_chars):
    """判断 required_chars 是否原样、未被实体编码地出现在 marker 附近。

    这是反射型 XSS 的最终判定依据：
    我们打进去的 payload 里带了这些关键闭合字符，如果它们在响应里被
    HTML 实体化成 &lt; &quot; 等，就说明被转义了、打不破上下文；
    如果原样出现在 marker 周围，就认为可以打破上下文。

    做法：在响应里找 payload 的两个 marker 之间的片段，
    检查每个 required_char 是否原样存在于这个片段中。
    """
    if not required_chars:
        return False, []

    segment = _payload_segment(text, marker)
    if segment is None:
        return False, []

    matched = []
    for char in required_chars:
        if _char_present_raw(segment, char):
            matched.append(char)

    # 所有关键字符都原样反射，才认为该上下文可被打破。
    all_present = len(matched) == len(required_chars)
    return all_present, matched


def _payload_segment(text, marker):
    """取出响应里两个 marker 之间的片段（payload 主体）。

    reflect payload 形如 {marker}...{marker}，中间就是关键闭合字符。
    如果只找到一个 marker，退化为取 marker 之后一小段。
    """
    first = text.find(marker)
    if first == -1:
        return None
    second = text.find(marker, first + len(marker))
    if second == -1:
        # 只反射了一个 marker，取其后一小段兜底。
        return text[first + len(marker): first + len(marker) + 100]
    return text[first + len(marker): second]


def _char_present_raw(segment, char):
    """判断某个关键字符是否原样存在于片段里（未被实体编码）。

    对多字符 token（例如 "javascript:"、"-->"）直接做子串匹配。
    对单字符（< > " ' 空格等）也做包含判断——因为片段本身就是
    payload 主体，被编码后原字符不会再出现。
    """
    if not char:
        return False
    return char in segment
