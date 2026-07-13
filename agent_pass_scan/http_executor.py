import gzip
import json
import re
import ssl
import time
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, Request, build_opener

from agent_pass_scan.detector_base import DEFAULT_ACTIVE_VERIFICATION_METHODS
from agent_pass_scan.traffic_model import header_value, trim_text
from pass_scan.body_paser import decode_body_text, get_header


def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
}

REPLAY_STRIPPED_HEADERS = HOP_BY_HOP_HEADERS | {
    "accept-encoding",
}

AUTH_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}


class LogicHttpExecutor:
    def __init__(self, config):
        self.config = config or {}
        self.timeout = float(self.config.get("request_timeout_seconds", 12))
        self.max_body = int(self.config.get("max_response_body_bytes", 262144))
        self.allowed_methods = {
            method.upper()
            for method in self.config.get(
                "active_verification_methods",
                sorted(DEFAULT_ACTIVE_VERIFICATION_METHODS),
            )
        }
        self.max_alternate_identities = int(
            self.config.get("max_alternate_identities_per_candidate", 3)
        )
        self.postcondition_readback = truthy(self.config.get("postcondition_readback", True))
        self.max_postcondition_checks = int(
            self.config.get("max_postcondition_checks_per_candidate", 2)
        )

    def strip_auth_headers(self, headers):
        return {
            key: value
            for key, value in (headers or {}).items()
            if key.lower() not in AUTH_HEADERS
        }

    def swap_auth_headers(self, source_headers, alternate_headers):
        headers = dict(source_headers or {})
        for key in list(headers):
            if key.lower() in AUTH_HEADERS:
                headers.pop(key, None)
        for key, value in (alternate_headers or {}).items():
            if key.lower() in AUTH_HEADERS:
                headers[key] = value
        return headers

    def verification_actions(self, candidate):
        verification = candidate.verification or {}
        kind = verification.get("kind") or "passive_only"
        source_flow = candidate.runtime_source_flow or candidate.source_flow or {}
        related_flows = candidate.runtime_related_flows or candidate.related_flows or []
        method = (source_flow.get("method") or "GET").upper()

        if kind == "strip_auth":
            return [{"id": "strip-auth", "kind": kind, "method": method}]
        if kind == "swap_auth":
            return [
                {
                    "id": f"swap-auth-{index}",
                    "kind": kind,
                    "method": method,
                    "related_flow": related,
                    "identity_index": index,
                }
                for index, related in enumerate(
                    related_flows[: self.max_alternate_identities],
                    start=1,
                )
            ]
        if kind == "same_auth_replay":
            return [{"id": "same-auth-replay", "kind": kind, "method": method}]
        if kind == "mutate_param":
            return [
                {
                    "id": f"mutate-{index}",
                    "kind": kind,
                    "method": method,
                    "new_value": value,
                }
                for index, value in enumerate(verification.get("mutations") or [], start=1)
            ]
        return []

    def execute_candidate_verification(self, candidate):
        observations = []
        postcondition_checks = 0
        for action in self.verification_actions(candidate):
            allow_postcondition = postcondition_checks < self.max_postcondition_checks
            action_observations = self.execute_verification_action(
                candidate,
                action,
                allow_postcondition=allow_postcondition,
            )
            observations.extend(action_observations)
            postcondition_checks += sum(
                1 for item in action_observations if item.get("postcondition")
            )
        return observations

    def execute_verification_action(self, candidate, action, allow_postcondition=True):
        verification = candidate.verification or {}
        kind = action.get("kind") or verification.get("kind")
        source_flow = candidate.runtime_source_flow or candidate.source_flow
        if kind == "strip_auth":
            observations = [self.replay(
                source_flow,
                self.strip_auth_headers(source_flow.get("request_headers") or {}),
                "去除认证信息后重放原始请求",
            )]
        if kind == "swap_auth":
            related = action.get("related_flow") or {}
            observations = [self.replay(
                source_flow,
                self.swap_auth_headers(
                    source_flow.get("request_headers") or {},
                    related.get("request_headers") or {},
                ),
                f"使用其他身份认证信息访问原资源 #{action.get('identity_index') or 1}",
                related_flow=related,
            )]
        if kind == "same_auth_replay":
            observations = [self.replay(
                source_flow,
                source_flow.get("request_headers") or {},
                "使用原认证信息重放包含敏感业务字段的请求",
            )]
        if kind == "mutate_param":
            observation = self.replay_with_mutation(
                source_flow,
                source_flow.get("request_headers") or {},
                candidate.resource or verification.get("parameter") or {},
                action.get("new_value"),
            )
            observations = [observation]
            if allow_postcondition and self.should_postcondition_readback(
                source_flow,
                observation,
                0,
            ):
                observations.append(
                    self.postcondition_readback_request(
                        source_flow,
                        source_flow.get("request_headers") or {},
                        observation,
                    )
                )
        if kind not in ("strip_auth", "swap_auth", "same_auth_replay", "mutate_param"):
            return []

        for observation in observations:
            observation["action_id"] = action.get("id") or ""
            observation["verification_kind"] = kind
        return observations

    def replay_with_mutation(self, flow, headers, parameter, new_value):
        mutated_flow, mutation = self.mutated_flow(flow, parameter, new_value)
        if mutation.get("error"):
            return {
                "purpose": "篡改敏感业务字段后重放请求",
                "ok": False,
                "blocked": True,
                "error": mutation["error"],
                "method": flow.get("method") or "",
                "url": flow.get("url") or "",
                "mutation": mutation,
            }

        result = self.replay(
            mutated_flow,
            headers,
            "篡改敏感业务字段后重放请求",
        )
        result["mutation"] = mutation
        return result

    def should_postcondition_readback(self, flow, observation, checks_sent):
        if not self.postcondition_readback:
            return False
        if checks_sent >= self.max_postcondition_checks:
            return False
        if "GET" not in self.allowed_methods:
            return False
        if (flow.get("method") or "").upper() in ("GET", "HEAD"):
            return False
        if observation.get("blocked") or observation.get("error"):
            return False
        status = int(observation.get("status_code") or 0)
        return 200 <= status < 400

    def postcondition_readback_request(self, flow, headers, parent_observation):
        readback_url = self.postcondition_url(flow.get("url") or "", parent_observation)
        if not readback_url:
            return {
                "purpose": "写操作后只读复查资源状态",
                "ok": False,
                "blocked": True,
                "error": "no same-origin readback URL available",
                "method": "GET",
                "url": "",
                "postcondition": True,
                "parent_mutation": parent_observation.get("mutation") or {},
            }

        readback_flow = dict(flow or {})
        readback_flow["method"] = "GET"
        readback_flow["url"] = readback_url
        readback_flow["request_body_text"] = ""
        observation = self.replay(
            readback_flow,
            headers,
            "写操作后只读复查资源状态",
        )
        observation["postcondition"] = True
        observation["parent_mutation"] = parent_observation.get("mutation") or {}
        observation["parent_status_code"] = parent_observation.get("status_code")
        return observation

    def postcondition_url(self, base_url, observation):
        location = observation.get("location") or ""
        if location:
            candidate = urljoin(base_url, location)
            if self.same_origin(base_url, candidate):
                return candidate
        return base_url if self.same_origin(base_url, base_url) else ""

    def same_origin(self, left, right):
        left_parts = urlsplit(left or "")
        right_parts = urlsplit(right or "")
        return bool(
            left_parts.scheme
            and left_parts.netloc
            and left_parts.scheme == right_parts.scheme
            and left_parts.netloc == right_parts.netloc
        )

    def mutated_flow(self, flow, parameter, new_value):
        parameter = parameter or {}
        place = (parameter.get("place") or parameter.get("source") or "").lower()
        name = parameter.get("name") or ""
        if not name:
            return dict(flow or {}), {"error": "missing parameter name"}

        mutated = dict(flow or {})
        mutation = {
            "place": place,
            "name": name,
            "old_value": parameter.get("value") or parameter.get("value_preview") or "",
            "new_value": str(new_value),
        }
        if parameter.get("json_path") is not None:
            mutation["json_path"] = parameter.get("json_path")

        if place == "query":
            mutated["url"] = self.replace_url_query_value(
                mutated.get("url") or "",
                parameter,
                str(new_value),
            )
            return mutated, mutation

        body = mutated.get("request_body_text") or ""
        headers = mutated.get("request_headers") or {}
        content_type = get_header(headers, "content-type").lower()
        if place == "json" or "json" in content_type or body.lstrip()[:1] in ("{", "["):
            new_body = self.replace_json_body_value(body, parameter, new_value)
            if new_body is None:
                return mutated, {"error": f"cannot mutate JSON parameter {name}"}
            mutated["request_body_text"] = new_body
            return mutated, mutation

        if place == "form" or "application/x-www-form-urlencoded" in content_type:
            mutated["request_body_text"] = self.replace_form_value(body, parameter, str(new_value))
            return mutated, mutation

        return mutated, {"error": f"unsupported mutation place {place or '-'} for {name}"}

    def replace_url_query_value(self, url, parameter, new_value):
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        index = parameter.get("index")
        name = parameter.get("name") or ""
        replaced = False
        updated = []
        for pair_index, (key, value) in enumerate(pairs):
            if (index is not None and pair_index == int(index)) or (index is None and key == name):
                updated.append((key, new_value))
                replaced = True
            else:
                updated.append((key, value))
        if not replaced:
            updated.append((name, new_value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment))

    def replace_form_value(self, body, parameter, new_value):
        pairs = parse_qsl(body or "", keep_blank_values=True)
        index = parameter.get("index")
        name = parameter.get("name") or ""
        replaced = False
        updated = []
        for pair_index, (key, value) in enumerate(pairs):
            if (index is not None and pair_index == int(index)) or (index is None and key == name):
                updated.append((key, new_value))
                replaced = True
            else:
                updated.append((key, value))
        if not replaced:
            updated.append((name, new_value))
        return urlencode(updated)

    def replace_json_body_value(self, body, parameter, new_value):
        try:
            data = json.loads(body or "")
        except json.JSONDecodeError:
            return None

        path = self.normalize_json_path(parameter.get("json_path"))
        if path:
            current = data
            try:
                for token in path[:-1]:
                    current = current[token]
                current[path[-1]] = self.coerce_json_value(new_value)
            except (KeyError, IndexError, TypeError):
                return None
        elif isinstance(data, dict):
            if not self.assign_json_named_value(data, parameter.get("name") or "", new_value):
                data[parameter.get("name") or ""] = self.coerce_json_value(new_value)
        else:
            return None
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def assign_json_named_value(self, data, name, new_value):
        path = self.parse_json_name_path(name)
        if not path:
            return False
        current = data
        try:
            for token in path[:-1]:
                current = current[token]
            current[path[-1]] = self.coerce_json_value(new_value)
            return True
        except (KeyError, IndexError, TypeError):
            return False

    def parse_json_name_path(self, name):
        name = str(name or "")
        if not name or name == "$":
            return []

        tokens = []
        current = []
        index = 0

        def flush_current():
            if current:
                tokens.append("".join(current))
                current.clear()

        while index < len(name):
            char = name[index]
            if char == ".":
                flush_current()
                index += 1
                continue
            if char == "[":
                flush_current()
                end = self.find_json_path_bracket_end(name, index)
                if end < 0:
                    return []
                raw_token = name[index + 1 : end].strip()
                token = self.parse_json_path_bracket_token(raw_token)
                if token is None:
                    return []
                tokens.append(token)
                index = end + 1
                continue
            current.append(char)
            index += 1
        flush_current()
        return tokens

    def normalize_json_path(self, value):
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, str) and value.strip():
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return self.parse_json_name_path(value)
            if isinstance(parsed, list):
                return parsed
        return []

    def find_json_path_bracket_end(self, text, start):
        quote = ""
        escape = False
        for index in range(start + 1, len(text)):
            char = text[index]
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if quote:
                if char == quote:
                    quote = ""
                continue
            if char in ("'", '"'):
                quote = char
                continue
            if char == "]":
                return index
        return -1

    def parse_json_path_bracket_token(self, raw_token):
        if not raw_token:
            return None
        if re.fullmatch(r"\d+", raw_token):
            return int(raw_token)
        try:
            return json.loads(raw_token)
        except json.JSONDecodeError:
            return raw_token.strip("\"'")

    def coerce_json_value(self, value):
        if isinstance(value, str):
            lowered = value.lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
            try:
                if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
                    return int(value)
            except AttributeError:
                pass
        return value

    def replay(self, flow, headers, purpose, related_flow=None):
        method = (flow.get("method") or "GET").upper()
        if method not in self.allowed_methods:
            return {
                "purpose": purpose,
                "ok": False,
                "blocked": True,
                "error": f"method {method} is not allowed for active logic verification",
                "method": method,
                "url": flow.get("url") or "",
            }

        safe_headers = {}
        for key, value in (headers or {}).items():
            if key.lower() in REPLAY_STRIPPED_HEADERS:
                continue
            safe_headers[key] = value

        data = None
        body = flow.get("request_body_text") or ""
        if method not in ("GET", "HEAD") and body:
            data = body.encode("utf-8", errors="replace")

        started = time.time()
        request = Request(flow.get("url") or "", data=data, headers=safe_headers, method=method)
        opener = build_opener(HTTPSHandler(context=ssl._create_unverified_context()))

        try:
            response = opener.open(request, timeout=self.timeout)
            status_code = response.getcode()
            response_headers = dict(response.headers.items())
            response_body = self.decode_response_body(response.read(self.max_body), response_headers)
            ok = True
            error = ""
        except HTTPError as exc:
            status_code = exc.code
            response_headers = dict(exc.headers.items())
            response_body = self.decode_response_body(exc.read(self.max_body), response_headers)
            ok = False
            error = f"HTTP {exc.code}"
        except URLError as exc:
            return {
                "purpose": purpose,
                "ok": False,
                "blocked": False,
                "error": str(exc.reason),
                "method": method,
                "url": flow.get("url") or "",
            }
        except Exception as exc:
            return {
                "purpose": purpose,
                "ok": False,
                "blocked": False,
                "error": str(exc),
                "method": method,
                "url": flow.get("url") or "",
            }

        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "purpose": purpose,
            "ok": ok,
            "blocked": False,
            "error": error,
            "method": method,
            "url": flow.get("url") or "",
            "status_code": status_code,
            "elapsed_ms": elapsed_ms,
            "request": self.render_request(method, flow.get("url") or "", safe_headers, data),
            "response": self.render_response(status_code, response_headers, response_body),
            "response_excerpt": trim_text(response_body, 5000),
            "location": header_value(response_headers, "location"),
            "baseline_status_code": flow.get("status_code"),
            "baseline_response_excerpt": trim_text(flow.get("response_body_text") or "", 3000),
            "source_flow_id": flow.get("id"),
            "related_flow_id": (related_flow or {}).get("id"),
            "related_auth_fingerprint": (related_flow or {}).get("auth_fingerprint"),
            "alternate_baseline_response_excerpt": trim_text(
                (related_flow or {}).get("response_body_text") or "",
                3000,
            ),
            "auth_header_present": bool(
                header_value(safe_headers, "authorization")
                or header_value(safe_headers, "cookie")
                or header_value(safe_headers, "x-api-key")
                or header_value(safe_headers, "x-auth-token")
                or header_value(safe_headers, "x-csrf-token")
            ),
        }

    def render_request(self, method, url, headers, data):
        lines = [f"{method} {url} HTTP/1.1"]
        for key, value in (headers or {}).items():
            lines.append(f"{key}: {value}")
        body = ""
        if data:
            body = data.decode("utf-8", errors="replace")
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def render_response(self, status_code, headers, body):
        lines = [f"HTTP/1.1 {status_code}"]
        for key, value in (headers or {}).items():
            lines.append(f"{key}: {value}")
        return "\r\n".join(lines) + "\r\n\r\n" + (body or "")

    def decode_response_body(self, raw_body, headers):
        body = self.decompress_response_body(raw_body or b"", headers)
        text, _charset = decode_body_text(body, headers or {})
        return text

    def decompress_response_body(self, raw_body, headers):
        encodings = [
            item.strip().lower()
            for item in get_header(headers or {}, "content-encoding").split(",")
            if item.strip()
        ]
        body = raw_body or b""

        for encoding in reversed(encodings):
            try:
                if encoding in ("gzip", "x-gzip"):
                    body = gzip.decompress(body)
                elif encoding == "deflate":
                    body = self.decompress_deflate(body)
                elif encoding == "br":
                    body = self.decompress_brotli(body)
            except Exception:
                return raw_body or b""

        return body

    def decompress_deflate(self, body):
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)

    def decompress_brotli(self, body):
        try:
            import brotli
        except ImportError:
            return body
        return brotli.decompress(body)
