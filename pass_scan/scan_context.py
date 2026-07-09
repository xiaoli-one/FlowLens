# 扫描上下文。
#
# xray 这类被动扫描器不会让每个插件自己重复解析请求。
# 它们通常会先把请求/响应标准化成一个上下文对象，再交给插件判断是否感兴趣。
#
# 这里的 ScanContext 就是这个作用：
# - 统一解析 method、url、path、content-type
# - 统一提取 query/form/json/cookie/header 参数
# - 做全局静态资源/无意义响应过滤

import copy
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from pass_scan.body_paser import decode_body_text, get_header, get_media_type


STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp4",
    ".mp3",
    ".avi",
    ".zip",
    ".pdf",
)

BINARY_RESPONSE_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "font/",
)

# 只把少量常见、确实可能进入业务逻辑的请求头拿来扫描。
# 不要把所有 header 都加入候选，否则主动探测请求会膨胀得很快。
HEADER_CANDIDATES = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "Client-IP",
)

JSON_SCALAR_TYPES = (str, int, float, bool)
BODY_PARAMETER_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@dataclass
class ScanContext:
    record: dict
    flow: object
    method: str
    url: str
    scheme: str
    host: str
    path: str
    request_content_type: str
    response_content_type: str
    status_code: int
    parameters: list
    skip_reason: str = ""

    @property
    def is_skipped(self):
        return bool(self.skip_reason)

    @property
    def is_static_resource(self):
        return self.path.lower().endswith(STATIC_SUFFIXES)


def parse_cookie_pairs(cookie_header):
    """把 Cookie 解析成 [(name, value), ...]。"""
    pairs = []
    if not cookie_header:
        return pairs

    for item in cookie_header.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, value = item.split("=", 1)
        else:
            name, value = item, ""
        pairs.append((name.strip(), value.strip()))

    return pairs


def format_json_path(path):
    """把 JSON 路径转换成参数名，例如 user.id 或 items[0].sku。"""
    name = ""
    for token in path:
        if isinstance(token, int):
            name += f"[{token}]"
            continue

        key = str(token)
        if key and all(char.isalnum() or char in "_-" for char in key):
            if name:
                name += "."
            name += key
            continue

        name += f"[{json.dumps(key, ensure_ascii=False)}]"

    return name or "$"


def iter_json_leaf_parameters(data):
    """按原始顺序遍历 JSON 中可注入的叶子标量值。"""
    stack = [((), data)]

    while stack:
        path, value = stack.pop()

        if path and isinstance(value, JSON_SCALAR_TYPES):
            yield path, value
            continue

        if isinstance(value, dict):
            for key, child in reversed(list(value.items())):
                stack.append((path + (key,), child))
            continue

        if isinstance(value, list):
            for index in range(len(value) - 1, -1, -1):
                stack.append((path + (index,), value[index]))


def replace_json_parameter_value(data, parameter, new_value):
    """按 ScanContext 里的 json_path 替换 JSON 参数值。"""
    data = copy.deepcopy(data)
    path = parameter.get("json_path")

    if path:
        current = data
        for token in path[:-1]:
            current = current[token]
        current[path[-1]] = new_value
        return data

    # 兼容旧的顶层 JSON 参数结构。
    if isinstance(data, dict):
        data[parameter["name"]] = new_value
    return data


def replace_json_body_parameter(body, headers, parameter, new_value):
    """解码 JSON body，按参数路径替换值，再按原 charset 编回 bytes。"""
    text, _charset = decode_body_text(body, headers)
    data = replace_json_parameter_value(json.loads(text), parameter, new_value)
    charset = parameter.get("charset") or "utf-8"
    return json.dumps(data, ensure_ascii=False).encode(charset, errors="replace")


def extract_parameters(request, max_params):
    """统一提取请求中的可控参数。"""
    parameters = []
    url_parts = urlsplit(request.pretty_url)

    query_pairs = parse_qsl(url_parts.query, keep_blank_values=True)
    for index, (name, value) in enumerate(query_pairs):
        parameters.append(
            {"place": "query", "index": index, "name": name, "value": value}
        )

    content_type = get_header(request.headers, "content-type")
    media_type = get_media_type(content_type)
    body = request.content or b""

    if (
        request.method.upper() in BODY_PARAMETER_METHODS
        and media_type == "application/x-www-form-urlencoded"
    ):
        text, charset = decode_body_text(body, request.headers)
        form_pairs = parse_qsl(text, keep_blank_values=True)
        for index, (name, value) in enumerate(form_pairs):
            parameters.append(
                {
                    "place": "form",
                    "index": index,
                    "name": name,
                    "value": value,
                    "charset": charset,
                }
            )

    # JSON body 参数。
    # 除了显式声明 application/json 的请求，也兼容“Content-Type 没声明 JSON、
    # 但 body 本身就是合法 JSON”的接口——例如前端用 text/plain 发 JSON 绕过
    # CORS 预检，或干脆漏设 Content-Type。判定分两步：
    #   1. 排除 multipart 和表单（它们由各自分支/逻辑处理，不当 JSON 解析）。
    #   2. 显式声明 JSON，或 body 去空白后以 { / [ 开头，才尝试 json.loads。
    # json.loads 失败自然跳过，不会误伤非 JSON 的 body。
    if (
        request.method.upper() in BODY_PARAMETER_METHODS
        and media_type != "application/x-www-form-urlencoded"
        and not media_type.startswith("multipart/")
    ):
        text, charset = decode_body_text(body, request.headers)
        declared_json = media_type == "application/json" or media_type.endswith("+json")
        looks_like_json = text.lstrip()[:1] in ("{", "[")

        if declared_json or looks_like_json:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None

            if isinstance(data, (dict, list)):
                for path, value in iter_json_leaf_parameters(data):
                    parameters.append(
                        {
                            "place": "json",
                            "name": format_json_path(path),
                            "json_path": list(path),
                            "value": str(value),
                            "charset": charset,
                        }
                    )
                    if len(parameters) >= max_params:
                        break

    cookie_pairs = parse_cookie_pairs(get_header(request.headers, "cookie"))
    for index, (name, value) in enumerate(cookie_pairs):
        parameters.append(
            {"place": "cookie", "index": index, "name": name, "value": value}
        )

    for name in HEADER_CANDIDATES:
        value = get_header(request.headers, name)
        if value:
            parameters.append(
                {"place": "header", "name": name, "value": value}
            )

    return parameters[:max_params]


def build_scan_context(record, flow, config):
    """从 mitmproxy flow 构造 ScanContext。"""
    scan_config = config.get("scan", {})
    max_params = int(scan_config.get("max_params_per_request", 8))

    request = flow.request
    response = getattr(flow, "response", None)
    url_parts = urlsplit(request.pretty_url)
    method = request.method.upper()
    request_content_type = get_header(request.headers, "content-type")
    response_content_type = get_header(response.headers, "content-type") if response else ""
    response_media_type = get_media_type(response_content_type)
    status_code = response.status_code if response else 0

    context = ScanContext(
        record=record,
        flow=flow,
        method=method,
        url=request.pretty_url,
        scheme=url_parts.scheme,
        host=url_parts.netloc,
        path=url_parts.path or "/",
        request_content_type=request_content_type,
        response_content_type=response_content_type,
        status_code=status_code,
        parameters=extract_parameters(request, max_params),
    )

    if method in ("HEAD", "OPTIONS"):
        context.skip_reason = "method_not_useful"
    elif context.is_static_resource:
        context.skip_reason = "static_resource"
    elif status_code in (204, 304):
        context.skip_reason = "empty_response_status"
    elif response_media_type.startswith(BINARY_RESPONSE_PREFIXES):
        context.skip_reason = "binary_response"

    return context
