# XXE payload 变形函数（tamper）。
#
# XXE 的主流“外部实体落点写法”（外部通用实体 / 参数实体 / 外部 DTD / XInclude）已经直接写进
# rules.yaml 的基础模板，一轮就覆盖到。这个文件只是很薄的兜底：当某个基础 payload 被 WAF 拦、
# 或开启 deep_tamper 又没命中时，再对整段 XML 追发少量“绕过 WAF 关键字匹配”的变形。
#
# 和其它插件不同，XXE 的变形是针对“整段 XML 文档”的字节级重编码 / 空白混淆，因此每个 tamper
# 函数签名是 str -> bytes（直接产出请求 body 字节）：
#   - utf16_reencode / utf7_reencode：把整段 XML 换成 UTF-16 / UTF-7 编码。WAF 常按 UTF-8 字节
#     匹配 "<!DOCTYPE"/"<!ENTITY" 等关键字，换编码后字节形态完全不同、匹配不到，而 XML 解析器
#     会按声明/BOM 正确解码后照常解析外部实体。这是 XXE 经典 WAF 绕过。
#   - doctype_newline：在 DOCTYPE / ENTITY / SYSTEM 之间插入换行与制表符（XML 允许的空白），
#     打散 WAF 对连续关键字的签名匹配。
#
# 这些字节级变形只对“整个请求 body 就是 XML”的注入点有意义；对“XML 塞在某个 URL 参数值里”的
# 注入点，换编码会破坏参数传输，scanner 会跳过 tamper（见 xxe_scanner 的 use_tamper 判断）。
# 只做确定性变形，方便复现。

import codecs
import re


_XML_DECL_RE = re.compile(r"^\s*<\?xml\b[^>]*\?>", re.IGNORECASE)


def _set_encoding(payload, encoding):
    """把 XML 声明里的 encoding 改成指定编码；没有声明就补一个。"""
    match = _XML_DECL_RE.search(payload)
    if match:
        decl = match.group(0)
        if re.search(r"encoding\s*=", decl, re.IGNORECASE):
            new_decl = re.sub(
                r"encoding\s*=\s*['\"][^'\"]*['\"]",
                f'encoding="{encoding}"',
                decl,
                count=1,
                flags=re.IGNORECASE,
            )
        else:
            new_decl = decl[:-2].rstrip() + f' encoding="{encoding}"?>'
        return payload[: match.start()] + new_decl + payload[match.end():]
    return f'<?xml version="1.0" encoding="{encoding}"?>' + payload


def utf16_reencode(payload):
    """整段 XML 换成 UTF-16 编码（带 BOM）。绕过按 UTF-8 字节匹配关键字的 WAF。"""
    text = _set_encoding(payload, "UTF-16")
    # 显式 UTF-16 LE + BOM：BOM 让解析器识别字节序，声明与 BOM 双保险。
    return codecs.BOM_UTF16_LE + text.encode("utf-16-le", errors="replace")


def utf7_reencode(payload):
    """整段 XML 换成 UTF-7 编码。WAF 基本不解析 UTF-7，libxml2 等解析器却支持。"""
    text = _set_encoding(payload, "UTF-7")
    return text.encode("utf-7", errors="replace")


def doctype_newline(payload):
    """在 DOCTYPE / ENTITY / SYSTEM 关键字之间插入换行 + 制表符（合法 XML 空白）。

    打散 WAF 对 "<!DOCTYPE"/"<!ENTITY x SYSTEM" 这类连续关键字签名的匹配。
    """
    text = payload
    text = re.sub(r"<!DOCTYPE\s+", "<!DOCTYPE\n\t", text, flags=re.IGNORECASE)
    text = re.sub(r"<!ENTITY\s+", "<!ENTITY\n\t", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+SYSTEM\s+", "\n\tSYSTEM\n\t", text, flags=re.IGNORECASE)
    return text.encode("utf-8", errors="replace")


TAMPER_FUNCTIONS = {
    "utf16_reencode": utf16_reencode,
    "utf7_reencode": utf7_reencode,
    "doctype_newline": doctype_newline,
}


def apply_tampers(payload, tamper_names):
    """按顺序执行 tamper，返回请求 body 字节；没有可用 tamper 时返回 None。

    XXE 的 tamper 都是“整段 XML -> bytes”的终态编码器，rules.yaml 里每个 profile 只放一个，
    因此正常只会命中一个。若配置了多个，前一个的字节结果会先按 UTF-8 宽松解码再喂给下一个，
    保证链式调用不报错（实际几乎用不到）。
    """
    data = None
    text = payload
    for name in tamper_names:
        function = TAMPER_FUNCTIONS.get(name)
        if not function:
            continue
        data = function(text)
        text = data.decode("utf-8", errors="replace")
    return data
  
