# SSTI 规则加载器。
#
# rules.yaml 只描述 payload、预期输出、错误指纹和 tamper 策略。
# scanner.py 负责调度、发包和判定。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_SSTI_RULE_FILE",
    os.path.join(os.path.dirname(__file__), "rules.yaml"),
)


@lru_cache(maxsize=1)
def load_rules():
    """读取 YAML 规则文件（带缓存）。"""
    with open(RULE_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def rule_value(name, default=None):
    """读取 YAML 顶层配置项。"""
    return load_rules().get(name, default)


def waf_detection_rules():
    """WAF 拦截识别规则。"""
    return rule_value("waf_detection", {})


def tamper_profiles():
    """WAF / 深度检测场景下的 payload 变形策略。"""
    return rule_value("tamper_profiles", [])


def max_tampered_payloads_per_probe():
    """单个 payload 最多尝试多少个变形版本。"""
    return int(rule_value("max_tampered_payloads_per_probe", 2))


def template_error_patterns():
    """模板引擎报错指纹。"""
    return rule_value("template_error_patterns", [])


def _render(template, replacements):
    """把 {name} 占位符替换成实际值。"""
    for name, value in replacements.items():
        template = template.replace("{" + name + "}", str(value))
    return template


def _expected_value(entry, values):
    expected = entry.get("expected", "product")
    if expected == "product":
        return values["product"]
    if expected == "sum":
        return values["sum"]
    if expected == "upper_marker":
        return values["upper_marker"]
    return _render(str(expected), values)


def build_probe_groups(value, a, b, marker):
    """为一次参数扫描生成全部 SSTI 输出型 payload。

    payload 分为两类：
    - arithmetic_echo：模板引擎执行算术表达式，响应里出现乘积/和。
    - string_transform：模板引擎执行字符串方法/过滤器，响应里出现大写 marker。

    预期输出都不直接出现在 payload 里，参数被原样反射时不会误报。
    """
    values = {
        "value": value,
        "a": a,
        "b": b,
        "product": str(a * b),
        "sum": str(a + b),
        "marker": marker,
        "upper_marker": marker.upper(),
    }
    groups = []
    for entry in rule_value("probe_payloads", []):
        groups.append(
            {
                "name": entry["name"],
                "family": entry.get("family", "unknown"),
                "technique": entry.get("technique", "arithmetic_echo"),
                "payload": _render(entry["template"], values),
                "expected": _expected_value(entry, values),
            }
        )
    return groups


def build_error_groups(value, marker):
    """生成模板语法错误探测 payload。"""
    values = {"value": value, "marker": marker}
    groups = []
    for entry in rule_value("error_payloads", []):
        groups.append(
            {
                "name": entry["name"],
                "family": entry.get("family", "unknown"),
                "technique": "template_error",
                "payload": _render(entry["template"], values),
            }
        )
    return groups
