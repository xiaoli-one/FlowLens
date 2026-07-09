# SQL 注入 payload 变形函数。
#
# 遇到 WAF 时，不建议一开始就把所有 payload 都变形一遍。
# 更稳的做法是：
# 1. 先发送正常 payload。
# 2. 如果响应像是被 WAF 拦截，再按 rules.yaml 里的 tamper_profiles 尝试变形。
# 3. 同一组 true/false 或 control/delay payload 必须使用同一种变形，避免判断失真。
#
# 这个文件只负责“怎么变形字符串”，不负责发包和判断漏洞。
# 设计上尽量使用确定性的变形，不使用随机大小写，方便复现结果。

import re


# 只处理常见 SQL 关键字，避免把 marker 或普通参数值改坏。
SQL_KEYWORDS = (
    "UNION ALL",
    "ORDER BY",
    "WAITFOR DELAY",
    "PG_SLEEP",
    "DBMS_PIPE",
    "RECEIVE_MESSAGE",
    "EXTRACTVALUE",
    "UPDATEXML",
    "CONVERT",
    "CONCAT",
    "SELECT",
    "UNION",
    "WHERE",
    "SLEEP",
    "CAST",
    "NULL",
    "FROM",
    "AND",
    "OR",
    "AS",
)


KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(word) for word in SQL_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def space_to_comment(payload):
    """把 SQL 里的空白换成 /**/。

    例如：
    1 UNION SELECT NULL
    变成：
    1/**/UNION/**/SELECT/**/NULL

    末尾的空白会保留，因为 MySQL 的 -- 注释通常需要后面有空白。
    """
    return re.sub(r"[ \t\r\n]+(?=\S)", "/**/", payload)


def space_to_tab(payload):
    """把空白换成 Tab。

    query/form 经过 urlencode 后会变成 %09。
    这类变形不适合 Cookie，所以在 rules.yaml 里用 places 做限制。
    """
    return re.sub(r"[ \t\r\n]+(?=\S)", "\t", payload)


def space_to_newline(payload):
    """把空白换成换行。

    query/form 经过 urlencode 后会变成 %0A。
    不适合放进 Cookie header。
    """
    return re.sub(r"[ \t\r\n]+(?=\S)", "\n", payload)


def space_to_plus(payload):
    """把空白换成加号。

    主要用于少数会把 + 当空格处理的场景。
    """
    return re.sub(r"[ \t\r\n]+(?=\S)", "+", payload)


def keyword_mixed_case(payload):
    """把 SQL 关键字改成大小写混合。

    例如 SELECT 变成 SeLeCt。
    这里只改 SQL 关键字，不改 marker，避免影响 marker 检测。
    """

    def mixed(match):
        value = match.group(0)
        result = []
        for index, char in enumerate(value):
            if char.isalpha():
                result.append(char.upper() if index % 2 == 0 else char.lower())
            else:
                result.append(char)
        return "".join(result)

    return KEYWORD_PATTERN.sub(mixed, payload)


def keyword_comment(payload):
    """在部分 SQL 关键字中间插入注释。

    例如 UNION 变成 UN/**/ION，SELECT 变成 SEL/**/ECT。
    这种方式不是所有数据库都支持，所以只在 WAF 拦截后作为重试手段。
    """
    splits = {
        "UNION": "UN/**/ION",
        "SELECT": "SEL/**/ECT",
        "ORDER": "OR/**/DER",
        "WHERE": "WH/**/ERE",
        "SLEEP": "SL/**/EEP",
        "WAITFOR": "WAIT/**/FOR",
        "DELAY": "DE/**/LAY",
        "AND": "A/**/ND",
        "OR": "O/**/R",
    }

    pattern = re.compile(
        r"\b(" + "|".join(re.escape(word) for word in splits) + r")\b",
        re.IGNORECASE,
    )

    def replace(match):
        return splits[match.group(0).upper()]

    return pattern.sub(replace, payload)


def keyword_versioned_comment(payload):
    """把关键字改成 MySQL 版本注释形式。

    例如：
    UNION SELECT
    变成：
    /*!50000UNION*/ /*!50000SELECT*/

    这是 MySQL 场景里常见的 WAF 绕过写法，不保证其他数据库支持。
    """
    mapping = {
        "UNION": "/*!50000UNION*/",
        "SELECT": "/*!50000SELECT*/",
        "AND": "/*!50000AND*/",
        "OR": "/*!50000OR*/",
        "SLEEP": "/*!50000SLEEP*/",
        "ORDER": "/*!50000ORDER*/",
        "BY": "/*!50000BY*/",
    }
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(word) for word in mapping) + r")\b",
        re.IGNORECASE,
    )
    return pattern.sub(lambda match: mapping[match.group(0).upper()], payload)


def logic_operator_symbol(payload):
    """把 AND/OR 换成 MySQL 常见逻辑运算符 &&/||。"""
    payload = re.sub(r"\bAND\b", "&&", payload, flags=re.IGNORECASE)
    payload = re.sub(r"\bOR\b", "||", payload, flags=re.IGNORECASE)
    return payload


def equality_to_greater(payload):
    """把固定的真假比较改成大于号比较。

    当前 SQLi 规则里大量使用 7311=7311 / 7311=7312。
    某些 WAF 会盯着等号，这里把它们改成等价的大小比较：
    - 7311=7311 -> 7312>7311
    - 7311=7312 -> 7311>7312
    """
    rewrites = {
        "7311=7311": "7312>7311",
        "7311 = 7311": "7312>7311",
        "7311=7312": "7311>7312",
        "7311 = 7312": "7311>7312",
        "1=1": "2>1",
        "1 = 1": "2>1",
        "1=2": "1>2",
        "1 = 2": "1>2",
    }

    for old, new in rewrites.items():
        payload = payload.replace(old, new)
    return payload


def equality_to_between(payload):
    """把数字等号比较改成 BETWEEN 比较。

    例如：
    7311=7311 -> 7311 BETWEEN 7311 AND 7311
    7311=7312 -> 7311 BETWEEN 7312 AND 7312
    """
    return re.sub(
        r"\b(\d+)\s*=\s*(\d+)\b",
        r"\1 BETWEEN \2 AND \2",
        payload,
    )


def quote_to_urlencode(payload):
    """把引号换成 URL 编码形式。

    注意：query/form 参数本身还会经过 urlencode，所以这里更适合 Cookie
    或某些会二次解码的场景。默认只在 WAF 重试时使用。
    """
    return payload.replace("'", "%27").replace('"', "%22")


def keyword_to_urlencode(payload):
    """把 SQL 关键字做百分号编码。

    对 query/form 来说，外层 urlencode 可能会形成双重编码。
    有些后端或网关会二次解码，所以仍然作为 WAF 场景的候选策略保留。
    """

    def encode_keyword(match):
        return "".join(f"%{ord(char):02X}" for char in match.group(0))

    return KEYWORD_PATTERN.sub(encode_keyword, payload)


def _string_to_hex(match):
    value = match.group(1)
    if not value or len(value) > 80:
        return match.group(0)
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return match.group(0)
    return "0x" + value.encode("utf-8").hex()


def string_to_mysql_hex(payload):
    """把简单单引号字符串改成 MySQL 十六进制字符串。

    例如：
    'PASS_SCAN_ERR' -> 0x504153535f5343414e5f455252
    """
    return re.sub(r"'([A-Za-z0-9_:-]{1,80})'", _string_to_hex, payload)


def _string_to_char(match):
    value = match.group(1)
    if not value or len(value) > 60:
        return match.group(0)
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return match.group(0)
    numbers = ",".join(str(ord(char)) for char in value)
    return f"CHAR({numbers})"


def string_to_mysql_char(payload):
    """把简单单引号字符串改成 MySQL CHAR() 形式。"""
    return re.sub(r"'([A-Za-z0-9_:-]{1,60})'", _string_to_char, payload)


TAMPER_FUNCTIONS = {
    "space_to_comment": space_to_comment,
    "space_to_tab": space_to_tab,
    "space_to_newline": space_to_newline,
    "space_to_plus": space_to_plus,
    "keyword_mixed_case": keyword_mixed_case,
    "keyword_comment": keyword_comment,
    "keyword_versioned_comment": keyword_versioned_comment,
    "logic_operator_symbol": logic_operator_symbol,
    "equality_to_greater": equality_to_greater,
    "equality_to_between": equality_to_between,
    "quote_to_urlencode": quote_to_urlencode,
    "keyword_to_urlencode": keyword_to_urlencode,
    "string_to_mysql_hex": string_to_mysql_hex,
    "string_to_mysql_char": string_to_mysql_char,
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
