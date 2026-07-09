# body_paser 的目标是把 mitmproxy 拿到的原始 body bytes，整理成方便阅读和扫描的结构。
#
# 整体流程：
# 1. body_to_record() 是入口，先读取 Content-Type，并取出主类型，例如：
#    application/json、multipart/form-data、video/mp4。
# 2. 如果 body 为空，直接返回 type=empty。
# 3. 如果是 multipart/form-data，就先按 boundary 拆成多个 part。
#    每个 part 都有自己的 headers/body，所以每个 part 单独判断：
#    普通字段按文本显示，视频/图片/压缩包等文件字段按二进制显示。
# 4. 如果不是 multipart，再根据 Content-Type 判断：
#    明确的文本类型按文本处理，明确的二进制类型按二进制处理。
# 5. 文本处理时会先判断 charset，优先级是：
#    Content-Type charset -> BOM（文件开头用来标识文件编码的） -> body 内声明 -> utf-8 -> charset-normalizer 猜测。
# 6. 文本内容会尽量 pretty：
#    JSON 缩进显示，XML 缩进显示，x-www-form-urlencoded 按参数逐行显示。
# 7. 二进制内容不会完整塞进日志，只保存 size、sha256 和前几个 KB 的 base64 预览。
# 8. 如果 Content-Type 不明确，就先尝试解码，再用控制字符比例判断像不像文本；
#    像文本就按文本保存，不像文本就按二进制保存。

import base64
import codecs
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qsl
from xml.dom import minidom


# 从 Content-Type 里提取 charset，例如：
# Content-Type: text/html; charset=gbk
# 提取结果就是 gbk。
CHARSET_RE = re.compile(r"charset\s*=\s*['\"]?([^;'\"]+)", re.IGNORECASE)

# 从 body 内容本身提取编码声明，例如：
# <meta charset="gbk">
# <?xml version="1.0" encoding="utf-8"?>
BODY_CHARSET_RE = re.compile(
    rb"(?:charset|encoding)\s*=\s*['\"]?\s*([A-Za-z0-9._:-]+)",
    re.IGNORECASE,
)

# 这些 Content-Type 通常可以按文本显示。
TEXT_MEDIA_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/xml",
}

# 这些 Content-Type 通常是二进制，不适合直接 decode 成文本。
BINARY_MEDIA_TYPES = {
    "application/gzip",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
}

# 这些前缀通常也是二进制，例如 image/png、font/woff2、video/mp4。
BINARY_MEDIA_PREFIXES = ("audio/", "font/", "image/", "video/")

MAX_TEXT_CHARS = 10000
MAX_BINARY_PREVIEW_BYTES = 3000


def get_header(headers, header_name):
    # mitmproxy 的 headers 对象类似字典，但 header 名大小写不固定。
    # 这里统一转成小写比较，做到大小写不敏感。
    if not headers:
        return ""

    for name, value in headers.items():
        if name.lower() == header_name.lower():
            return value
    return ""


def get_media_type(content_type):
    # 只保留 Content-Type 的主类型，去掉 charset 等参数。
    # 例如：text/html; charset=utf-8 -> text/html
    return content_type.split(";", 1)[0].strip().lower()


def charset_from_content_type(content_type):
    # 优先相信响应头/请求头里声明的 charset。
    match = CHARSET_RE.search(content_type or "")
    if not match:
        return ""
    return match.group(1).strip()


def charset_from_bom(content):
    # BOM 是文件/文本开头用来标识编码的特殊字节。
    # 如果 body 以 BOM 开头，可以比较可靠地判断编码。
    boms = [
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ]

    for bom, charset in boms:
        if content.startswith(bom):
            return charset
    return ""


def charset_from_body(content):
    # 有些 HTML/XML 没在响应头里写 charset，而是在 body 里写。
    # 只检查前 4096 字节，通常编码声明都在开头。
    match = BODY_CHARSET_RE.search(content[:4096])
    if not match:
        return ""
    return match.group(1).decode("ascii", errors="ignore")


def guess_charset(content):
    # 如果 header、BOM、body 声明都没有编码信息，就用 charset-normalizer 猜。
    # 猜编码不是 100% 准确，所以它排在明确声明之后。
    try:
        from charset_normalizer import from_bytes
    except ImportError:
        return ""

    result = from_bytes(content).best()
    if not result:
        return ""
    return result.encoding or ""


def decode_with_candidates(content, candidates):
    # 按候选编码顺序一个个尝试，谁能成功 decode 就用谁。
    # candidates 里可能有重复或空值，所以用 tried 去重。
    tried = set()
    for charset in candidates:
        if not charset:
            continue

        charset = charset.strip().strip("'\"")
        if not charset or charset.lower() in tried:
            continue

        tried.add(charset.lower())
        try:
            return content.decode(charset), charset
        except (LookupError, UnicodeDecodeError):
            continue

    # latin-1 可以把任意 0-255 字节映射成字符，作为最后兜底，
    # 避免遇到未知编码时程序直接报错。
    return content.decode("latin-1"), "latin-1"


def decode_body_text(content, headers):
    # 统一负责把 bytes 类型的 body 解码成 str。
    # 顺序越靠前，可信度越高。
    content_type = get_header(headers, "content-type")
    candidates = [
        charset_from_content_type(content_type),
        charset_from_bom(content),
        charset_from_body(content),
        "utf-8",
        guess_charset(content),
    ]
    return decode_with_candidates(content, candidates)


def is_text_media_type(media_type):
    # 根据 Content-Type 判断这个 body 是否应该按文本处理。
    # application/*+json 和 application/*+xml 也算文本，例如 application/problem+json。
    return (
        media_type.startswith("text/")
        or media_type in TEXT_MEDIA_TYPES
        or media_type.endswith("+json")
        or media_type.endswith("+xml")
    )


def is_binary_media_type(media_type):
    # 根据 Content-Type 判断这个 body 是否应该按二进制处理。
    return media_type in BINARY_MEDIA_TYPES or media_type.startswith(BINARY_MEDIA_PREFIXES)


def is_mostly_text(text):
    # 当 Content-Type 不明确时，用内容本身粗略判断是不是文本。
    if not text:
        return True

    bad_chars = 0
    for char in text:
        if char in "\n\r\t":
            continue
        if ord(char) < 32:
            # ASCII 码小于 32 的大多是不可见控制字符。
            # 控制字符太多，通常说明这是二进制内容。
            bad_chars += 1

    # 控制字符少于 5%，就认为它基本是文本。
    return bad_chars / len(text) < 0.05


def pretty_text(text, media_type):
    # 把已经 decode 出来的文本转换成更适合阅读的 Pretty 格式。
    stripped = text.strip()

    if media_type == "application/x-www-form-urlencoded":
        # 表单 body 例如：a=1&b=hello+world
        # 转成：
        # a=1
        # b=hello world
        pairs = parse_qsl(text, keep_blank_values=True)
        if pairs:
            return "\n".join(f"{name}={value}" for name, value in pairs)

    if media_type == "application/json" or media_type.endswith("+json") or stripped[:1] in ("{", "["):
        # JSON body 转成带缩进的格式。
        # 如果解析失败，就保持原样返回。
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass

    if media_type == "application/xml" or media_type.endswith("+xml") or stripped.startswith("<?xml"):
        # XML body 尝试格式化。
        # minidom 对不规范 XML 比较敏感，所以失败时保持原样。
        try:
            pretty = minidom.parseString(text).toprettyxml(indent="  ")
            return "\n".join(line for line in pretty.splitlines() if line.strip())
        except Exception:
            pass

    return text


def binary_record(content, content_type):
    # 二进制内容不直接塞进 text，避免视频、图片、压缩包把日志刷爆。
    # base64 只保存前几个 KB 作为预览，完整性用 size 和 sha256 辅助判断。
    label = content_type or "unknown"
    preview = content[:MAX_BINARY_PREVIEW_BYTES]

    return {
        "type": "binary",
        "content_type": content_type,
        "charset": "",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "text": f"[Binary body: {label}, {len(content)} bytes]",
        "base64": base64.b64encode(preview).decode("ascii"),
        "truncated": len(content) > MAX_BINARY_PREVIEW_BYTES,
    }


def text_record(content, headers, content_type, media_type):
    text, charset = decode_body_text(content, headers)
    pretty = pretty_text(text, media_type)

    return {
        "type": "text",
        "content_type": content_type,
        "charset": charset,
        "size": len(content),
        "text": pretty[:MAX_TEXT_CHARS],
        "base64": "",
        "truncated": len(pretty) > MAX_TEXT_CHARS,
    }


def get_part_body(part):
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload

    payload = part.get_payload()
    if isinstance(payload, str):
        charset = part.get_content_charset() or "utf-8"
        return payload.encode(charset, errors="replace")

    return b""


def multipart_to_record(content, headers, content_type):
    # multipart/form-data 是一个 body 里包含多个 part。
    # 每个 part 都有自己的 headers 和 body，所以要逐个判断，不能整段一起判。
    message_bytes = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
        + content
    )
    message = BytesParser(policy=policy.default).parsebytes(message_bytes)

    if not message.is_multipart():
        return None

    parts = []
    for index, part in enumerate(message.iter_parts(), start=1):
        part_headers = headers_to_dict(part)
        part_content_type = part.get_content_type()
        part_media_type = get_media_type(part_content_type)
        part_body = get_part_body(part)

        part_record = {
            "index": index,
            "name": part.get_param("name", header="content-disposition") or "",
            "filename": part.get_filename() or "",
            "content_type": part_content_type,
            "headers": part_headers,
        }

        if part.is_multipart():
            nested = multipart_to_record(part_body, part_headers, part_content_type)
            part_record["body"] = nested or binary_record(part_body, part_content_type)
        elif is_binary_media_type(part_media_type):
            part_record["body"] = binary_record(part_body, part_content_type)
        else:
            text, charset = decode_body_text(part_body, part_headers)
            if is_text_media_type(part_media_type) or is_mostly_text(text):
                pretty = pretty_text(text, part_media_type)
                part_record["body"] = {
                    "type": "text",
                    "content_type": part_content_type,
                    "charset": charset,
                    "size": len(part_body),
                    "text": pretty[:MAX_TEXT_CHARS],
                    "base64": "",
                    "truncated": len(pretty) > MAX_TEXT_CHARS,
                }
            else:
                part_record["body"] = binary_record(part_body, part_content_type)

        parts.append(part_record)

    return {
        "type": "multipart",
        "content_type": content_type,
        "charset": "",
        "size": len(content),
        "parts": parts,
        "text": "",
        "base64": "",
        "truncated": False,
    }


def body_to_record(content, headers=None):
    # 主入口：把 mitmproxy 给的 body bytes 转成统一的日志结构。
    # content 是原始 body 内容，headers 用来辅助判断 Content-Type 和 charset。
    headers = headers or {}
    content_type = get_header(headers, "content-type")  # 获取content_type
    media_type = get_media_type(content_type)  # 获取content_type中的类型

    if not content:
        # 没有 body，例如很多 GET 请求或 204 响应。
        return {
            "type": "empty",
            "content_type": content_type,
            "charset": "",
            "size": 0,
            "text": "",
            "base64": "",
            "truncated": False,
        }

    if media_type.startswith("multipart/"):  # multipart/form-data
        record = multipart_to_record(content, headers, content_type)  # 按每个part判断并转成日志
        if record:
            return record

    if is_binary_media_type(media_type):  # 如果是二进制类型
        # 明确是二进制类型时，不尝试转文本。
        # text 字段只放提示信息，真正的二进制内容放到 base64。
        return binary_record(content, content_type)

    # 不是明确二进制时，先尝试按文本解码。
    text, charset = decode_body_text(content, headers)  
    if is_text_media_type(media_type) or is_mostly_text(text):
        # 如果 Content-Type 说明它是文本，或者内容看起来大部分是文本，
        # 就保存到 text 字段，并尽量做 Pretty 格式化。
        return text_record(content, headers, content_type, media_type)

    # 兜底：Content-Type 不明确，且内容看起来不像文本，就按二进制保存。
    return binary_record(content, content_type)


def headers_to_dict(headers):
    # 把 mitmproxy 的 headers 对象转换成普通 dict，方便写入 JSON。
    return {name: value for name, value in headers.items()}
