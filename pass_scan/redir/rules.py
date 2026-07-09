# 开放重定向 / CRLF 响应头注入规则加载器。
#
# rules.yaml 只放 payload 模板；扫描器负责生成唯一 marker、发送请求和判定响应。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_REDIR_RULE_FILE",
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


def build_redirect_payloads(host, marker, target_url, allow, extra=False):
    """生成开放重定向 payload 列表。"""
    entries = list(rule_value("redirect_payloads", []))
    if extra:
        entries += list(rule_value("redirect_payloads_extra", []))

    payloads = []
    replacements = {
        "host": host,
        "marker": marker,
        "target_url": target_url,
        "allow": allow,
    }
    for entry in entries:
        payloads.append(
            {
                "name": entry["name"],
                "payload": _render(entry["template"], replacements),
            }
        )
    return payloads


def build_crlf_payloads(value, marker, target_url, header_name, header_value, extra=False):
    """生成 CRLF / 响应头注入 payload 列表。"""
    entries = list(rule_value("crlf_payloads", []))
    if extra:
        entries += list(rule_value("crlf_payloads_extra", []))

    payloads = []
    replacements = {
        "value": value or marker,
        "marker": marker,
        "target_url": target_url,
        "header_name": header_name,
        "header_value": header_value,
        "crlf": "\r\n",
        "lf": "\n",
        "cr": "\r",
    }
    for entry in entries:
        payloads.append(
            {
                "name": entry["name"],
                "payload": _render(entry["template"], replacements),
            }
        )
    return payloads
