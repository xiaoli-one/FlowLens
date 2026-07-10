# SSTI payload 变形函数。
#
# SSTI 基础 payload 已经覆盖主流模板语法与少量空格差异。
# 这里仅做很薄的 URL 编码类兜底：当原始 payload 被 WAF 拦截，或显式开启深度
# tamper 时，尝试把模板分隔符编码，绕过只按字面字符匹配的过滤。


def url_encode_delimiters(payload):
    """对模板分隔符做一次 URL 编码。"""
    return _encode_chars(
        payload,
        {
            "{": "%7b",
            "}": "%7d",
            "<": "%3c",
            ">": "%3e",
            "#": "%23",
            "$": "%24",
            "%": "%25",
        },
    )


def double_url_encode_delimiters(payload):
    """对模板分隔符做二次 URL 编码。"""
    return _encode_chars(
        payload,
        {
            "{": "%257b",
            "}": "%257d",
            "<": "%253c",
            ">": "%253e",
            "#": "%2523",
            "$": "%2524",
            "%": "%2525",
        },
    )


def quote_url_encode(payload):
    """额外编码引号，处理简单的 quote 过滤。"""
    return _encode_chars(
        payload,
        {
            '"': "%22",
            "'": "%27",
        },
    )


def compact_spaces(payload):
    """去掉模板表达式里不必要的空格，绕过按固定字符串匹配的规则。"""
    result = payload
    replacements = {
        " * ": "*",
        " + ": "+",
        " | ": "|",
        ": ": ":",
        " = ": "=",
        " }}": "}}",
        "{{ ": "{{",
        " %}": "%}",
        "{% ": "{%",
        " %>": "%>",
        "<%= ": "<%=",
    }
    for source, target in replacements.items():
        result = result.replace(source, target)
    return result


def _encode_chars(payload, mapping):
    """按 mapping 替换字符，但跳过已存在的 %xx 转义。"""
    result = []
    i = 0
    length = len(payload)
    while i < length:
        char = payload[i]
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
    "compact_spaces": compact_spaces,
    "url_encode_delimiters": url_encode_delimiters,
    "double_url_encode_delimiters": double_url_encode_delimiters,
    "quote_url_encode": quote_url_encode,
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
