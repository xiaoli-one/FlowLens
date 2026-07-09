# XXE 规则加载器。
#
# 真正的 payload 模板、文件 signature、WAF 指纹、tamper 策略都在 rules.yaml。
# 这个文件只负责读取 YAML，并把 {root} {entity} {uri} {domain} 占位符替换成实际值。
#
# 改了 rules.yaml 需要重启 run.py 才会生效（load_rules 有缓存）。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_XXE_RULE_FILE",
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


def inband_files():
    """带内文件读取目标列表：[{name, os, uri, signature}, ...]。"""
    return list(rule_value("files", []))


def inband_templates():
    """带内注入模板列表：[{name, doctype, ref}, ...]。"""
    return list(rule_value("inband_templates", []))


def inband_specials():
    """scanner 内建的带内特殊形态名（如 xinclude）。"""
    return list(rule_value("inband_specials", []))


def oob_templates(extra=False):
    """带外模板列表：[{name, doctype, ref}, ...]。

    extra=True 时把 oob_templates_extra 里的额外变体也一起返回，
    用于 full_payload_scan / deep 场景。
    """
    templates = list(rule_value("oob_templates", []))
    if extra:
        templates += list(rule_value("oob_templates_extra", []))
    return templates


def waf_detection_rules():
    """WAF 拦截识别规则。"""
    return rule_value("waf_detection", {})


def tamper_profiles():
    """WAF / 深度检测场景下的 payload 变形策略。"""
    return list(rule_value("tamper_profiles", []))


def max_tampered_payloads_per_probe():
    """单个 payload 最多尝试多少个变形版本。"""
    return int(rule_value("max_tampered_payloads_per_probe", 3))


def render_template(template, root="", entity="xxe", uri="", domain=""):
    """把模板里的 {root} {entity} {uri} {domain} 占位符替换成实际值。"""
    replacements = {
        "root": root,
        "entity": entity,
        "uri": uri,
        "domain": domain,
    }
    for name, value in replacements.items():
        template = template.replace("{" + name + "}", str(value))
    return template
