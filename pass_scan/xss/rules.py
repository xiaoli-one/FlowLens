# XSS 规则加载器。
#
# 真正的规则内容在 rules.yaml：
# - marker 前后缀
# - 各上下文的反射探测 payload
# - DOM source/sink 列表
# - WAF 拦截指纹和 payload 变形策略
#
# 这个文件只负责读取 YAML，并把 {marker}、{value} 这类占位符替换成实际值。
# 和 sql_injection/rules.py 的定位一致：很薄的一层。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_XSS_RULE_FILE",
    os.path.join(os.path.dirname(__file__), "rules.yaml"),
)


@lru_cache(maxsize=1)
def load_rules():
    """读取 YAML 规则文件。

    使用缓存避免每次扫描都重新读文件。
    改了 rules.yaml 需要重启 run.py 才会生效。
    """
    with open(RULE_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def rule_value(name, default=None):
    """从 YAML 顶层读取一个配置项。"""
    return load_rules().get(name, default)


def marker_config():
    """读取 marker 前后缀等配置。"""
    return rule_value("marker", {}) or {}


def render_template(template, marker="", value="", tag=""):
    """替换 payload 模板里的占位符。

    {marker} 换成本次随机标记，{tag} 换成外层标签名（RAWTEXT 闭合用）。
    """
    replacements = {"marker": marker, "value": value, "tag": tag}
    for name, replacement in replacements.items():
        template = template.replace("{" + name + "}", str(replacement))
    return template


def build_reflect_contexts(marker, value="", tag=""):
    """生成反射型各上下文的探测 payload。

    返回 [{method, context, payloads: [{payload, required_chars, sample}, ...]}, ...]。
    method 会作为 finding 的 method。
    每个上下文下可以有多条 payload，检测时按顺序尝试，命中即停。
    """
    contexts = []
    for group in rule_value("reflect_contexts", []) or []:
        payloads = []
        for item in group.get("payloads", []) or []:
            payloads.append(
                {
                    "payload": render_template(item["payload"], marker, value, tag),
                    "required_chars": list(item.get("required_chars", [])),
                    "sample": item.get("sample", ""),
                }
            )
        contexts.append(
            {
                "method": group["method"],
                "context": group["context"],
                "payloads": payloads,
            }
        )
    return contexts
