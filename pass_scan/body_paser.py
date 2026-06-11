import base64
import codecs
import json
import re
from urllib.parse import parse_qsl
from xml.dom import minidom


CHARSET_RE = re.compile(r"charset\s*=\s*['\"]?([^;'\"]+)", re.IGNORECASE)
BODY_CHARSET_RE = re.compile(
    rb"(?:charset|encoding)\s*=\s*['\"]?\s*([A-Za-z0-9._:-]+)",
    re.IGNORECASE,
)
TEXT_MEDIA_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/xml",
}
BINARY_MEDIA_TYPES = {
    "application/gzip",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
}
BINARY_MEDIA_PREFIXES = ("audio/", "font/", "image/", "video/")


def get_header(headers, header_name):
    if not headers:
        return ""

    for name, value in headers.items():
        if name.lower() == header_name.lower():
            return value
    return ""


def get_media_type(content_type):
    return content_type.split(";", 1)[0].strip().lower()


def charset_from_content_type(content_type):
    match = CHARSET_RE.search(content_type or "")
    if not match:
        return ""
    return match.group(1).strip()


def charset_from_bom(content):
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
    match = BODY_CHARSET_RE.search(content[:4096])
    if not match:
        return ""
    return match.group(1).decode("ascii", errors="ignore")


def guess_charset(content):
    try:
        from charset_normalizer import from_bytes
    except ImportError:
        return ""

    result = from_bytes(content).best()
    if not result:
        return ""
    return result.encoding or ""


def decode_with_candidates(content, candidates):
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

    return content.decode("latin-1"), "latin-1"


def decode_body_text(content, headers):
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
    return (
        media_type.startswith("text/")
        or media_type in TEXT_MEDIA_TYPES
        or media_type.endswith("+json")
        or media_type.endswith("+xml")
    )


def is_binary_media_type(media_type):
    return media_type in BINARY_MEDIA_TYPES or media_type.startswith(BINARY_MEDIA_PREFIXES)


def is_mostly_text(text):
    if not text:
        return True

    bad_chars = 0
    for char in text:
        if char in "\n\r\t":
            continue
        if ord(char) < 32:
            bad_chars += 1

    return bad_chars / len(text) < 0.05


def pretty_text(text, media_type):
    stripped = text.strip()

    if media_type == "application/x-www-form-urlencoded":
        pairs = parse_qsl(text, keep_blank_values=True)
        if pairs:
            return "\n".join(f"{name}={value}" for name, value in pairs)

    if media_type == "application/json" or media_type.endswith("+json") or stripped[:1] in ("{", "["):
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass

    if media_type == "application/xml" or media_type.endswith("+xml") or stripped.startswith("<?xml"):
        try:
            pretty = minidom.parseString(text).toprettyxml(indent="  ")
            return "\n".join(line for line in pretty.splitlines() if line.strip())
        except Exception:
            pass

    return text


def body_to_record(content, headers=None):
    headers = headers or {}
    content_type = get_header(headers, "content-type")
    media_type = get_media_type(content_type)

    if not content:
        return {
            "type": "empty",
            "content_type": content_type,
            "charset": "",
            "size": 0,
            "text": "",
            "base64": "",
            "truncated": False,
        }

    if is_binary_media_type(media_type):
        return {
            "type": "binary",
            "content_type": content_type,
            "charset": "",
            "size": len(content),
            "text": f"[Binary body: {content_type}, {len(content)} bytes]",
            "base64": base64.b64encode(content).decode("ascii"),
            "truncated": False,
        }

    text, charset = decode_body_text(content, headers)
    if is_text_media_type(media_type) or is_mostly_text(text):
        pretty = pretty_text(text, media_type)
        return {
            "type": "text",
            "content_type": content_type,
            "charset": charset,
            "size": len(content),
            "text": pretty,
            "base64": "",
            "truncated": False,
        }

    label = content_type or "unknown"
    return {
        "type": "binary",
        "content_type": content_type,
        "charset": "",
        "size": len(content),
        "text": f"[Binary body: {label}, {len(content)} bytes]",
        "base64": base64.b64encode(content).decode("ascii"),
        "truncated": False,
    }


def headers_to_dict(headers):
    return {name: value for name, value in headers.items()}
