# 目录遍历 / 任意文件读取规则加载器。
#
# 真正的 payload、文件 signature、WAF 指纹、tamper 策略都在 rules.yaml。
# 这个文件只负责读取 YAML，并把 {value} 占位符替换成实际值。
#
# 改了 rules.yaml 需要重启 run.py 才会生效（load_rules 有缓存）。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_PT_RULE_FILE",
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


def targets():
    """目标文件表：{名字: {os, signature}}。"""
    return rule_value("targets", {})


def waf_detection_rules():
    """WAF 拦截识别规则。"""
    return rule_value("waf_detection", {})


def tamper_profiles():
    """WAF / 深度检测场景下的 payload 变形策略。"""
    return rule_value("tamper_profiles", [])


def max_tampered_payloads_per_probe():
    """单个 payload 最多尝试多少个变形版本。"""
    return int(rule_value("max_tampered_payloads_per_probe", 3))


def _render(template, replacements):
    """把 {name} 占位符替换成实际值。"""
    for name, value in replacements.items():
        template = template.replace("{" + name + "}", str(value))
    return template


def build_probe_groups(value):
    """为一次参数扫描生成全部探测 payload 组（基础 payload 已含绕过编码）。

    每组带上 target 对应的 signature，扫描器直接拿去在响应里做命中判定，
    不用再回查 rules。technique 缺省为 content（文件内容回显）。
    """
    target_map = targets()
    groups = []
    for entry in rule_value("payloads", []):
        target_name = entry.get("target")
        target = target_map.get(target_name, {})
        groups.append(
            {
                "name": entry["name"],
                "os": entry.get("os", "any"),
                "technique": entry.get("technique", "content"),
                "target": target_name,
                "signature": target.get("signature", ""),
                "payload": _render(entry["template"], {"value": value}),
            }
        )
    return groups
