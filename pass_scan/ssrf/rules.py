# SSRF 规则加载器。
#
# 真正的带外 payload 模板都在 rules.yaml（纯 OOB 检测，无响应回显/元数据那一套）。
# 这个文件只负责读取 YAML，并把 {domain} {value} {allow} 占位符替换成实际值。
#
# 改了 rules.yaml 需要重启 run.py 才会生效（load_rules 有缓存）。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_SSRF_RULE_FILE",
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


def _render(template, replacements):
    """把 {name} 占位符替换成实际值。"""
    for name, value in replacements.items():
        template = template.replace("{" + name + "}", str(value))
    return template


def build_oob_templates(extra=False):
    """返回带外 payload 模板列表（只含 name/template，不含 domain）。

    extra=True 时把 oob_templates_extra 里的额外绕过变体也一起返回，
    用于 full_payload_scan / deep 场景。
    """
    templates = list(rule_value("oob_templates", []))
    if extra:
        templates += list(rule_value("oob_templates_extra", []))
    return templates


def render_oob(template, domain, value="", allow=""):
    """渲染单个带外 payload，把 {domain} {value} {allow} 替换成实际值。"""
    return _render(template, {"domain": domain, "value": value, "allow": allow})
