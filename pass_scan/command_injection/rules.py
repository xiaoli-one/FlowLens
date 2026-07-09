# 命令注入规则加载器。
#
# 真正的 payload、WAF 指纹、tamper 策略都在 rules.yaml。
# 这个文件只负责读取 YAML，并把 {value} {a} {b} {delay} {ping_count} {domain}
# 这些占位符替换成实际值。
#
# 改了 rules.yaml 需要重启 run.py 才会生效（load_rules 有缓存）。

import os
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_CMDI_RULE_FILE",
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


def time_delay():
    """时间盲注延时秒数。"""
    return int(rule_value("time_delay", 5))


def time_threshold():
    """判定命中的最小延时差（秒）。"""
    return float(rule_value("time_threshold", 3))


def echo_random_range():
    """算术回显随机数范围 (min, max)。"""
    return int(rule_value("echo_random_min", 1000)), int(rule_value("echo_random_max", 99999))


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


def echo_templates():
    """返回算术回显 payload 模板列表。"""
    return rule_value("echo_templates", [])


def render_echo(template, value, a, b):
    """渲染单个算术回显 payload。

    模板里的 {value} {a} {b} 会被替换。乘积 a*b 不出现在 payload 里，
    而是作为“命中标志”由扫描器在响应正文中查找。
    """
    return _render(template, {"value": value, "a": a, "b": b})


def build_echo_groups(value, a, b):
    """为一次参数扫描生成全部算术回显 payload 组（基础 payload，绕过变形交给 tamper 阶段）。"""
    groups = []
    for entry in echo_templates():
        groups.append(
            {
                "name": entry["name"],
                "os": entry.get("os", "any"),
                "payload": render_echo(entry["template"], value, a, b),
            }
        )
    return groups


def time_templates():
    """返回时间盲注 payload 模板列表。"""
    return rule_value("time_templates", [])


def build_time_groups(value, delay=None):
    """为一次参数扫描生成全部时间盲注 payload 组（control / delay 成对，基础 payload）。"""
    delay = int(delay if delay is not None else time_delay())
    # ping 每次约 1 秒，多留 1 次余量，保证 ping 总耗时明显超过阈值。
    ping_count = max(2, delay + 1)
    replacements = {"value": value, "delay": delay, "ping_count": ping_count}

    groups = []
    for entry in time_templates():
        groups.append(
            {
                "name": entry["name"],
                "os": entry.get("os", "any"),
                "control": _render(entry["control"], replacements),
                "delay": _render(entry["delay"], replacements),
            }
        )
    return groups


def oob_templates():
    """返回 OOB payload 模板列表。"""
    return rule_value("oob_templates", [])


def render_oob(template, value, domain):
    """渲染单个 OOB payload，把 {value} {domain} 替换成实际值。"""
    return _render(template, {"value": value, "domain": domain})
