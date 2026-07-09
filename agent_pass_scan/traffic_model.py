import hashlib
import json
import re
from urllib.parse import parse_qsl


ID_NAME_RE = re.compile(
    r"(^id$|(?:^|[_\-.])(id|uid|user|account|member|tenant|org|company|project|order|invoice|file|doc|ticket|role|status)(?:$|[_\-.]))",
    re.I,
)
TENANT_NAME_RE = re.compile(r"(tenant|org|company|corp|workspace|department|dept)", re.I)
ROLE_NAME_RE = re.compile(
    r"(role|permission|privilege|admin|isadmin|is_admin|superuser|is_superuser|staff|is_staff|group|acl|scope|access[_-]?level)",
    re.I,
)
STATE_NAME_RE = re.compile(
    r"(status|state|step|stage|approved|approve|review|audit|workflow|publish|published|enabled|disabled|deleted|locked|verified)",
    re.I,
)
OWNER_NAME_RE = re.compile(
    r"(owner|owner_id|creator|created_by|user_id|uid|account_id|member_id|assignee|customer_id)",
    re.I,
)
BUSINESS_VALUE_RE = re.compile(
    r"(price|amount|total|balance|credit|quota|discount|rate|fee|limit|level)",
    re.I,
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
NUM_RE = re.compile(r"^\d{2,}$")

SENSITIVE_ACTION_RE = re.compile(
    r"(admin|manage|permission|role|user|account|tenant|org|order|invoice|pay|refund|approve|audit|export|download|delete|remove|update|create|invite)",
    re.I,
)


def stable_hash(value, length=20):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def text_body(body):
    if isinstance(body, dict):
        return body.get("text") or ""
    if isinstance(body, str):
        return body
    return ""


def body_truncated(body):
    return bool(isinstance(body, dict) and body.get("truncated"))


def header_value(headers, name):
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return ""


def classify_auth(headers):
    headers = headers or {}
    auth = header_value(headers, "authorization")
    cookie = header_value(headers, "cookie")
    api_key = (
        header_value(headers, "x-api-key")
        or header_value(headers, "x-auth-token")
        or header_value(headers, "x-csrf-token")
    )
    material = []
    auth_type = []

    if auth:
        material.append(("authorization", auth))
        auth_type.append("authorization")
    if cookie:
        cookie_pairs = []
        for item in cookie.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                name, value = item.split("=", 1)
            else:
                name, value = item, ""
            cookie_pairs.append((name.strip(), value.strip()))
        if cookie_pairs:
            material.append(("cookie", cookie_pairs))
            auth_type.append("cookie")
    if api_key:
        material.append(("api_key", api_key))
        auth_type.append("api_key")

    if not material:
        return {
            "auth_type": "anonymous",
            "auth_fingerprint": "anonymous",
            "cookie_names": "",
            "token_hint": "",
        }

    cookie_names = []
    for kind, value in material:
        if kind == "cookie":
            cookie_names = [name for name, _cookie_value in value]

    return {
        "auth_type": "+".join(auth_type),
        "auth_fingerprint": stable_hash(material, 24),
        "cookie_names": ",".join(cookie_names),
        "token_hint": ",".join(auth_type),
    }


def normalize_path(path):
    parts = []
    resources = []
    for index, segment in enumerate((path or "/").split("/")):
        if not segment:
            parts.append(segment)
            continue
        semantic = ""
        replacement = segment
        if UUID_RE.match(segment):
            replacement = "{uuid}"
            semantic = "uuid"
        elif NUM_RE.match(segment):
            replacement = "{id}"
            semantic = "id"
        elif HEX_RE.match(segment):
            replacement = "{hash}"
            semantic = "hash"

        if semantic:
            resources.append(
                {
                    "name": f"path[{index}]",
                    "value": segment,
                    "source": "path",
                    "semantic_type": semantic,
                }
            )
        parts.append(replacement)

    normalized = "/".join(parts) or "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized, resources


def semantic_type_for_name(name):
    name = str(name or "")
    if TENANT_NAME_RE.search(name):
        return "tenant"
    if ROLE_NAME_RE.search(name):
        return "role"
    if STATE_NAME_RE.search(name):
        return "workflow_state"
    if OWNER_NAME_RE.search(name):
        return "owner"
    if BUSINESS_VALUE_RE.search(name):
        return "business_value"
    if ID_NAME_RE.search(name):
        return "resource_id"
    return ""


def extract_query_resources(query):
    refs = []
    for name, value in parse_qsl(query or "", keep_blank_values=True):
        semantic = semantic_type_for_name(name)
        if semantic and value:
            refs.append(
                {
                    "name": name,
                    "value": value,
                    "source": "query",
                    "semantic_type": semantic,
                }
            )
    return refs


def parameter_resource_refs(parameters):
    refs = []
    for parameter in parameters or []:
        name = parameter.get("name", "")
        value = parameter.get("value", "")
        semantic = semantic_type_for_name(name)
        if semantic and value:
            refs.append(
                {
                    "name": name,
                    "value": str(value),
                    "source": parameter.get("place", ""),
                    "semantic_type": semantic,
                }
            )
    return refs


def looks_sensitive_endpoint(method, normalized_path, parameters):
    method = (method or "").upper()
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    if SENSITIVE_ACTION_RE.search(normalized_path or ""):
        return True
    for parameter in parameters or []:
        if semantic_type_for_name(parameter.get("name")):
            return True
    return False


def trim_text(value, limit=3000):
    value = "" if value is None else str(value)
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"
