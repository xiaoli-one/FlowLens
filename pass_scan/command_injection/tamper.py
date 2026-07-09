# 命令注入 payload 变形函数。
#
# 遇到 WAF 时不建议一开始就把所有 payload 都变形一遍。更稳的做法：
# 1. 先发送正常 payload。
# 2. 如果响应像被 WAF 拦截，再按 rules.yaml 的 tamper_profiles 尝试变形。
# 3. 同一组 control/delay payload 必须使用同一种变形，避免判断失真。
#
# 命令注入的绕过重点是“空格过滤”：最通用、最高收益的就是把空格换成 shell 里的
# 等价写法。只做确定性变形，方便复现。这个文件只负责“怎么变形字符串”，不发包。

import re


# 只替换真正的空格分隔（sleep 5 / expr 1 \* 2 / ping -n 3 这类），
# 不动换行等已经用 %0a 表达的部分。
_SPACE_PATTERN = re.compile(r" +")


def space2ifs(payload):
    """把空格换成 ${IFS}。绕过“过滤空格”最通用的写法：sleep 5 -> sleep${IFS}5。"""
    return _SPACE_PATTERN.sub("${IFS}", payload)


def space2ifs9(payload):
    """把空格换成 $IFS$9。$9 是空的位置参数，$IFS$9 展开等价于分隔符，
    比 ${IFS} 更能绕过只匹配 "${IFS}" 字面串的过滤。"""
    return _SPACE_PATTERN.sub("$IFS$9", payload)


def space2tab(payload):
    """把空格换成 Tab。query/form urlencode 后是 %09，同样是 shell 字段分隔符。
    不适合放进 Cookie，rules.yaml 用 places 限制。"""
    return _SPACE_PATTERN.sub("\t", payload)


def space2brace(payload):
    """把空格换成 ${IFS%??}。某些环境 ${IFS} 被过滤时的等价替代写法。"""
    return _SPACE_PATTERN.sub("${IFS%??}", payload)


TAMPER_FUNCTIONS = {
    "space2ifs": space2ifs,
    "space2ifs9": space2ifs9,
    "space2tab": space2tab,
    "space2brace": space2brace,
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
