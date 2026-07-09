# 目录遍历 / 任意文件读取 payload 变形函数。
#
# 主流绕过编码（%2f 单编码、%252f 双编码、....// 嵌套、反斜杠、file:// 等）已经
# 直接写进 rules.yaml 的基础 payload，一轮就覆盖到。这个文件只是很薄的兜底：
# 当某个“未编码” payload 被 WAF 拦、或开启 deep_tamper 又没命中时，再对它补少量
# 编码变形。只做确定性变形，方便复现。这个文件只负责“怎么变形字符串”，不发包。


def url_encode(payload):
    """把路径分隔符和点做一次 URL 编码：/ -> %2f，\\ -> %5c。

    绕过“对字面 / 或 ../ 做过滤”的场景。已手写的 %xx 不再重复编码。
    """
    return _encode_chars(payload, {"/": "%2f", "\\": "%5c"})


def dot_url_encode(payload):
    """把点和斜杠都 URL 编码：. -> %2e，/ -> %2f，\\ -> %5c。

    绕过对字面 .. 的过滤。
    """
    return _encode_chars(payload, {".": "%2e", "/": "%2f", "\\": "%5c"})


def double_url_encode(payload):
    """二次 URL 编码：/ -> %252f，\\ -> %255c。

    绕过“先解码一次再过滤、随后又被业务代码解码一次”的中间件。
    """
    return _encode_chars(payload, {"/": "%252f", "\\": "%255c"})


def _encode_chars(payload, mapping):
    """按 mapping 替换字符，但跳过已存在的 %xx 转义，避免二次污染。"""
    result = []
    i = 0
    length = len(payload)
    while i < length:
        char = payload[i]
        # 已经是 %xx 转义的，整段原样跳过。
        if char == "%" and i + 2 < length and _is_hex(payload[i + 1]) and _is_hex(payload[i + 2]):
            result.append(payload[i : i + 3])
            i += 3
            continue
        result.append(mapping.get(char, char))
        i += 1
    return "".join(result)


def _is_hex(char):
    return char in "0123456789abcdefABCDEF"


TAMPER_FUNCTIONS = {
    "url_encode": url_encode,
    "dot_url_encode": dot_url_encode,
    "double_url_encode": double_url_encode,
}


def apply_tampers(payload, tamper_names):
    """按顺序执行多个 tamper 函数。"""
    result = payload
    for name in tamper_names:
        function = TAMPER_FUNCTIONS.get(name)
        if not function:
            continue
        result = function(result)
    return result
