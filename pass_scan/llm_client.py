import json
import os
import re
import string
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ENV_FILE = os.path.join(PROJECT_ROOT, ".env")
OPENAI_COMPATIBLE_PROTOCOLS = {"openai", "openai_compatible", "chat_completions"}


def resolve_project_path(path):
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def load_dotenv(path):
    values = {}
    path = resolve_project_path(path or DEFAULT_ENV_FILE)
    if not path or not os.path.exists(path):
        return values

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
            if key:
                values[key] = os.environ.get(key, value)
    return values


def trim_text(text, max_chars):
    text = str(text or "")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"


def escape_invalid_json_backslashes(text):
    valid_escapes = {'"', "\\", "/", "b", "f", "n", "r", "t"}
    hex_digits = set(string.hexdigits)
    chars = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            chars.append(char)
            index += 1
            continue

        next_char = text[index + 1] if index + 1 < len(text) else ""
        if next_char in valid_escapes:
            chars.append(char)
            index += 1
            continue
        if next_char == "u":
            seq = text[index + 2:index + 6]
            chars.append(char if len(seq) == 4 and all(item in hex_digits for item in seq) else "\\\\")
            index += 1
            continue

        chars.append("\\\\")
        index += 1
    return "".join(chars)


def safe_json_loads(text):
    if isinstance(text, dict):
        return text
    text = str(text or "").strip()
    if not text:
        raise ValueError("empty json")
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
        text = re.sub(r"```$", "", text).strip()
    candidates = [text]
    match = re.search(r"\{.*\}", text, re.S)
    if match and match.group(0) != text:
        candidates.append(match.group(0))
    last_error = None
    for candidate in candidates:
        for repaired in (candidate, escape_invalid_json_backslashes(candidate)):
            try:
                return json.loads(repaired)
            except json.JSONDecodeError as error:
                last_error = error
    if last_error:
        raise last_error
    raise ValueError("invalid json")


def config_value(config, env_name, *config_names, default=""):
    env_value = os.environ.get(env_name)
    if env_value not in (None, ""):
        return env_value
    for name in config_names:
        value = (config or {}).get(name)
        if value not in (None, ""):
            return value
    return default


def normalize_protocol(value):
    value = str(value or "openai").strip().lower().replace("-", "_")
    aliases = {
        "openai_chat": "openai",
        "chat_completion": "openai",
        "chat_completions": "openai",
        "openai_compatible": "openai",
        "responses": "openai_responses",
        "anthropic_messages": "anthropic",
        "claude": "anthropic",
        "google": "gemini",
        "google_gemini": "gemini",
        "azure": "azure_openai",
        "azure_openai_chat": "azure_openai",
        "ollama_chat": "ollama",
    }
    return aliases.get(value, value)


def append_path(base_url, suffix):
    base_url = str(base_url or "").rstrip("/")
    suffix = "/" + suffix.strip("/")
    if not base_url:
        return suffix
    parts = urlsplit(base_url)
    if parts.query:
        return base_url
    return base_url + suffix


def add_query_param(url, name, value):
    if not value:
        return url
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if any(key == name for key, _value in pairs):
        return url
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


class LLMClient:
    def __init__(self, config=None, opener=None):
        self.config = config or {}
        env_file = resolve_project_path(self.config.get("env_file") or DEFAULT_ENV_FILE)
        load_dotenv(env_file)

        self.protocol = normalize_protocol(
            config_value(self.config, "LLM_PROTOCOL", "llm_protocol", "protocol", default="openai")
        )
        self.api_key = str(config_value(self.config, "LLM_API_KEY", "llm_api_key", "api_key"))
        self.model = str(config_value(self.config, "LLM_MODEL_ID", "llm_model_id", "model"))
        self.base_url = str(config_value(self.config, "LLM_BASE_URL", "llm_base_url", "base_url"))
        self.deployment = str(config_value(self.config, "LLM_DEPLOYMENT", "llm_deployment", "deployment"))
        self.api_version = str(config_value(self.config, "LLM_API_VERSION", "llm_api_version", "api_version"))
        self.temperature = float(config_value(self.config, "LLM_TEMPERATURE", "temperature", default=0.1))
        self.timeout = float(config_value(self.config, "LLM_TIMEOUT_SECONDS", "llm_timeout_seconds", default=60))
        self.max_tokens = int(config_value(self.config, "LLM_MAX_TOKENS", "llm_max_tokens", default=4096))
        self.opener = opener or build_opener(ProxyHandler({}))

    @property
    def ready(self):
        if not self.model:
            return False
        if self.protocol in OPENAI_COMPATIBLE_PROTOCOLS | {"openai_responses", "azure_openai"}:
            return bool(self.base_url)
        if self.protocol in {"anthropic", "gemini"}:
            return bool(self.base_url)
        if self.protocol == "ollama":
            return True
        return bool(self.base_url)

    def chat(self, messages):
        if not self.ready:
            raise RuntimeError("LLM client is not configured")
        endpoint, headers, payload = self.build_request(messages)
        request = Request(
            endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
            data = json.loads(response.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"LLM API HTTP {exc.code} ({self.protocol}): {trim_text(body, 1200)}"
            ) from exc

        return self.parse_response(data)

    def complete_json(self, messages):
        content = self.chat(messages)
        try:
            return safe_json_loads(content)
        except Exception:
            repair_messages = list(messages)
            repair_messages.append({"role": "assistant", "content": trim_text(content, 12000)})
            repair_messages.append({
                "role": "user",
                "content": "上一次回复不是合法 JSON。请只输出一个合法 JSON 对象，不要 Markdown，不要解释。",
            })
            return safe_json_loads(self.chat(repair_messages))

    def build_request(self, messages):
        if self.protocol in OPENAI_COMPATIBLE_PROTOCOLS:
            return self.openai_chat_request(messages)
        if self.protocol == "openai_responses":
            return self.openai_responses_request(messages)
        if self.protocol == "azure_openai":
            return self.azure_openai_request(messages)
        if self.protocol == "anthropic":
            return self.anthropic_request(messages)
        if self.protocol == "gemini":
            return self.gemini_request(messages)
        if self.protocol == "ollama":
            return self.ollama_request(messages)
        raise RuntimeError(f"Unsupported LLM protocol: {self.protocol}")

    def parse_response(self, data):
        if self.protocol in OPENAI_COMPATIBLE_PROTOCOLS | {"azure_openai"}:
            return self.parse_openai_chat_response(data)
        if self.protocol == "openai_responses":
            return self.parse_openai_responses_response(data)
        if self.protocol == "anthropic":
            return self.parse_anthropic_response(data)
        if self.protocol == "gemini":
            return self.parse_gemini_response(data)
        if self.protocol == "ollama":
            return self.parse_ollama_response(data)
        raise RuntimeError(f"Unsupported LLM protocol: {self.protocol}")

    def openai_chat_request(self, messages):
        endpoint = self.chat_completions_endpoint(self.base_url)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        return endpoint, headers, payload

    def openai_responses_request(self, messages):
        endpoint = self.responses_endpoint(self.base_url)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "input": messages,
            "temperature": self.temperature,
        }
        if self.max_tokens:
            payload["max_output_tokens"] = self.max_tokens
        return endpoint, headers, payload

    def azure_openai_request(self, messages):
        endpoint = self.azure_openai_endpoint()
        if self.api_version:
            endpoint = add_query_param(endpoint, "api-version", self.api_version)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key
        payload = {
            "messages": messages,
            "temperature": self.temperature,
        }
        if self.model:
            payload["model"] = self.model
        return endpoint, headers, payload

    def anthropic_request(self, messages):
        endpoint = self.anthropic_endpoint(self.base_url)
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": self.api_version or "2023-06-01",
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        system, converted = self.anthropic_messages(messages)
        payload = {
            "model": self.model,
            "messages": converted,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system:
            payload["system"] = system
        return endpoint, headers, payload

    def gemini_request(self, messages):
        endpoint = self.gemini_endpoint(self.base_url)
        endpoint = add_query_param(endpoint, "key", self.api_key)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-goog-api-key"] = self.api_key
        system, contents = self.gemini_contents(messages)
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        return endpoint, headers, payload

    def ollama_request(self, messages):
        endpoint = self.ollama_endpoint(self.base_url)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
            },
        }
        return endpoint, headers, payload

    def chat_completions_endpoint(self, base_url):
        base_url = str(base_url or "").rstrip("/")
        if "/chat/completions" in base_url:
            return base_url
        return append_path(base_url, "chat/completions")

    def responses_endpoint(self, base_url):
        base_url = str(base_url or "").rstrip("/")
        if base_url.endswith("/responses") or "/responses?" in base_url:
            return base_url
        return append_path(base_url, "responses")

    def azure_openai_endpoint(self):
        base_url = str(self.base_url or "").rstrip("/")
        if "/chat/completions" in base_url:
            return base_url
        if "/deployments/" not in base_url:
            deployment = self.deployment or self.model
            if deployment:
                if base_url.endswith("/openai"):
                    base_url = f"{base_url}/deployments/{deployment}"
                else:
                    base_url = f"{base_url}/openai/deployments/{deployment}"
        return append_path(base_url, "chat/completions")

    def anthropic_endpoint(self, base_url):
        base_url = str(base_url or "").rstrip("/")
        if base_url.endswith("/v1/messages") or "/v1/messages?" in base_url:
            return base_url
        if base_url.endswith("/v1"):
            return base_url + "/messages"
        return append_path(base_url, "v1/messages")

    def gemini_endpoint(self, base_url):
        base_url = str(base_url or "").rstrip("/")
        if ":generateContent" in base_url:
            return base_url
        model_path = f"models/{self.model}:generateContent"
        if base_url.endswith("/models/" + self.model):
            return base_url + ":generateContent"
        return append_path(base_url, model_path)

    def ollama_endpoint(self, base_url):
        base_url = str(base_url or "http://127.0.0.1:11434").rstrip("/")
        if base_url.endswith("/api/chat") or "/api/chat?" in base_url:
            return base_url
        return append_path(base_url, "api/chat")

    def parse_openai_chat_response(self, data):
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise self.unexpected_response(data) from exc

    def parse_openai_responses_response(self, data):
        output_text = data.get("output_text")
        if output_text:
            return output_text
        chunks = []
        for item in data.get("output") or []:
            for content in item.get("content") or []:
                text = content.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        if chunks:
            return "".join(chunks)
        raise self.unexpected_response(data)

    def parse_anthropic_response(self, data):
        chunks = []
        for item in data.get("content") or []:
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                chunks.append(item["text"])
        if chunks:
            return "".join(chunks)
        raise self.unexpected_response(data)

    def parse_gemini_response(self, data):
        try:
            parts = data["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError, TypeError) as exc:
            raise self.unexpected_response(data) from exc
        chunks = [part.get("text", "") for part in parts if isinstance(part, dict)]
        if any(chunks):
            return "".join(chunks)
        raise self.unexpected_response(data)

    def parse_ollama_response(self, data):
        try:
            return data["message"]["content"]
        except (KeyError, TypeError):
            response = data.get("response")
            if isinstance(response, str):
                return response
        raise self.unexpected_response(data)

    def unexpected_response(self, data):
        return RuntimeError(
            "Unexpected LLM API response "
            f"({self.protocol}): {trim_text(json.dumps(data, ensure_ascii=False), 1200)}"
        )

    def anthropic_messages(self, messages):
        system_parts = []
        converted = []
        for message in messages or []:
            role = message.get("role") or "user"
            content = self.message_text(message.get("content"))
            if role == "system":
                if content:
                    system_parts.append(content)
                continue
            converted.append({
                "role": "assistant" if role == "assistant" else "user",
                "content": content,
            })
        return "\n\n".join(system_parts), self.merge_adjacent_messages(converted)

    def gemini_contents(self, messages):
        system_parts = []
        contents = []
        for message in messages or []:
            role = message.get("role") or "user"
            content = self.message_text(message.get("content"))
            if role == "system":
                if content:
                    system_parts.append(content)
                continue
            contents.append({
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": content}],
            })
        return "\n\n".join(system_parts), self.merge_adjacent_gemini_contents(contents)

    def merge_adjacent_messages(self, messages):
        merged = []
        for message in messages:
            if merged and merged[-1]["role"] == message["role"]:
                merged[-1]["content"] += "\n\n" + message.get("content", "")
            else:
                merged.append(dict(message))
        return merged

    def merge_adjacent_gemini_contents(self, contents):
        merged = []
        for content in contents:
            if merged and merged[-1]["role"] == content["role"]:
                merged[-1]["parts"].extend(content.get("parts") or [])
            else:
                merged.append({"role": content["role"], "parts": list(content.get("parts") or [])})
        return merged

    def message_text(self, content):
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks = []
            for item in content:
                if isinstance(item, str):
                    chunks.append(item)
                elif isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        chunks.append(text)
            return "\n".join(chunks)
        return str(content or "")
