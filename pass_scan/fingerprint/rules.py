# 指纹规则加载器。
#
# 真正的规则内容在 rules.yaml（手写高置信度规则）。
# 如果存在 rules.generated.yaml（用 tools/import_rules.py 从 Wappalyzer / EHole /
# FingerprintHub 等公开指纹库导入生成），也会一起加载并合并。
#
# 这个文件只做三件事：
# 1. 读取 YAML 并缓存。
# 2. 把每条 matcher 的正则预编译好，避免每个 host 都重新编译。
# 3. 计算 favicon 的 mmh3 hash（Shodan / FOFA 同款约定），用于精确识别开源项目。

import base64
import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_FP_RULE_FILE",
    os.path.join(os.path.dirname(__file__), "rules.yaml"),
)

# 公开库导入后生成的规则文件。存在就一起加载，不存在就忽略。
GENERATED_RULE_FILE = os.environ.get(
    "PASS_SCAN_FP_GENERATED_RULE_FILE",
    os.path.join(os.path.dirname(__file__), "rules.generated.yaml"),
)

# 合法的 matcher 来源。
VALID_SOURCES = {"header", "cookie", "body", "url", "title", "favicon"}


def _load_yaml_file(path):
    """读取单个 YAML 文件，不存在或为空时返回 {}。"""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


@lru_cache(maxsize=1)
def load_rules():
    """读取并合并所有指纹规则文件。

    使用缓存避免每个 host 都重新读盘和编译正则。
    改了 rules.yaml 需要重启 run.py 才会生效。
    """
    base = _load_yaml_file(RULE_FILE).get("fingerprints", []) or []
    generated = _load_yaml_file(GENERATED_RULE_FILE).get("fingerprints", []) or []
    return base + generated


@lru_cache(maxsize=1)
def compiled_fingerprints():
    """把 YAML 规则编译成方便匹配的结构。

    每个指纹返回：
    {
      "name": str,
      "category": str,
      "implies": [str, ...],
      "matchers": [
        {
          "source": str,
          "name": str,            # header / cookie 名，小写
          "name_pattern": 已编译正则 或 None,  # cookie 名正则
          "pattern": 已编译正则 或 None,
          "version": 已编译正则 或 None,
          "hash": int 或 None,    # favicon hash
          "all_of": [str, ...] 或 None,  # 必须全部出现的字面子串（小写），AND 关系
        },
        ...
      ],
    }
    """
    import re

    compiled = []
    for entry in load_rules():
        name = entry.get("name")
        if not name:
            continue

        matchers = []
        for matcher in entry.get("matchers", []) or []:
            source = (matcher.get("source") or "").lower()
            if source not in VALID_SOURCES:
                continue

            raw_pattern = matcher.get("pattern")
            raw_version = matcher.get("version")
            raw_name = matcher.get("name") or ""
            try:
                pattern = re.compile(raw_pattern, re.IGNORECASE) if raw_pattern else None
                version = re.compile(raw_version, re.IGNORECASE) if raw_version else None
                name_pattern = _cookie_name_pattern(raw_name) if source == "cookie" else None
            except re.error:
                # 规则写错了不要让整个插件崩，跳过这条 matcher。
                continue

            # all_of：一组必须全部出现的字面子串（用纯子串匹配，不走正则，
            # 避免 EHole 多关键字用正则前瞻导致灾难性回溯）。统一转小写做大小写不敏感。
            raw_all_of = matcher.get("all_of")
            all_of = None
            if raw_all_of:
                all_of = [str(item).lower() for item in raw_all_of if str(item)]
                if not all_of:
                    all_of = None

            # 一条 matcher 至少要有一种判定依据，否则跳过。
            favicon_hash = matcher.get("hash")
            if (
                pattern is None
                and all_of is None
                and favicon_hash is None
                and source not in ("header", "cookie")
            ):
                continue

            matchers.append(
                {
                    "source": source,
                    "name": str(raw_name).lower(),
                    "name_pattern": name_pattern,
                    "pattern": pattern,
                    "version": version,
                    "hash": int(favicon_hash) if favicon_hash is not None else None,
                    "all_of": all_of,
                    # 预过滤字面量：正则里最长的一段固定字符串（小写）。
                    # 匹配前先用它做一次极快的子串判断，不存在就直接跳过正则，
                    # 既加速又避免在不匹配的长正文上触发灾难性回溯。
                    "literal": _longest_literal(raw_pattern) if raw_pattern else "",
                }
            )

        if not matchers:
            continue

        compiled.append(
            {
                "name": name,
                "category": entry.get("category", "未分类"),
                "implies": list(entry.get("implies", []) or []),
                "matchers": matchers,
            }
        )

    return compiled


def _cookie_name_pattern(name):
    """把带正则语义的 cookie 名编译成完整匹配正则。

    Wappalyzer 的 cookies key 既可能是普通 cookie 名，也可能是
    wordpress_[a-f0-9]+ 这类模式。普通名称继续走精确匹配，避免把 "." 等
    合法 cookie 字符当成正则通配符。
    """
    import re

    text = str(name or "")
    if not re.search(r"[\\[\]()+*?{}|^$]", text):
        return None
    return re.compile(rf"^(?:{text})$", re.IGNORECASE)


def _longest_literal(pattern):
    """从正则里抽取最长的一段连续字面字符，作为匹配前的快速预过滤。

    只在“安全字符”串上累积：遇到任何正则元字符就断开，取最长的一段。
    例如 ".+\\.twic\\.pics" -> "twic"（.pics 被 . 断开后取较长段，足够预过滤）。
    返回小写串；抽不出足够长(>=4)的字面就返回空，表示不做预过滤。
    """
    import re

    # 去掉转义反斜杠对字面字符的影响：\. -> . 这类先简单处理。
    # 这里只为预过滤，不要求精确，所以保守地按“安全字符”切段。
    safe = re.split(r"[^A-Za-z0-9_/\-]+", pattern)
    longest = ""
    for piece in safe:
        # piece 里可能仍有正则残留，过滤掉非字面常见字符。
        if len(piece) > len(longest):
            longest = piece
    return longest.lower() if len(longest) >= 4 else ""


def favicon_mmh3(content):
    """计算 favicon 的 mmh3 hash。

    遵循 Shodan / FOFA 的约定：
    先对 favicon 原始字节做 base64（标准 base64，每 76 字符换行 + 结尾换行），
    再对这个 base64 文本算 mmh3 32 位有符号 hash。

    优先用 mmh3 库（C 实现，快且准）；没装时退回纯 Python 实现，
    保证 mmh3 始终是可选依赖。
    """
    if not content:
        return None

    encoded = base64.encodebytes(content)

    try:
        import mmh3

        return mmh3.hash(encoded)
    except ImportError:
        return _murmur3_x86_32(encoded)


def _murmur3_x86_32(data, seed=0):
    """纯 Python 版 MurmurHash3 x86 32 位，返回有符号结果。

    仅作为没有安装 mmh3 库时的兜底，结果与 mmh3.hash() 一致。
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC  # 4 字节对齐

    for block_start in range(0, rounded_end, 4):
        k1 = (
            data[block_start]
            | (data[block_start + 1] << 8)
            | (data[block_start + 2] << 16)
            | (data[block_start + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # 处理结尾不足 4 字节的部分。
    k1 = 0
    tail_index = rounded_end
    remaining = length & 3
    if remaining >= 3:
        k1 ^= data[tail_index + 2] << 16
    if remaining >= 2:
        k1 ^= data[tail_index + 1] << 8
    if remaining >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # 收尾混淆。
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # 转成有符号 32 位，和 mmh3.hash() 保持一致。
    if h1 & 0x80000000:
        return -((h1 ^ 0xFFFFFFFF) + 1)
    return h1
