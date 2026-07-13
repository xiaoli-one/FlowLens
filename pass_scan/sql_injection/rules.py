# SQL 注入规则加载器。
#
# 真正的规则内容在 rules.yaml：
# - 数据库报错指纹
# - 报错型 payload 后缀
# - 布尔盲注 payload 模板
# - inline query marker payload 模板
# - UNION query marker payload 模板
# - stacked query 延时 payload 模板
# - 时间盲注 payload 模板
# - Header 场景专用 payload 模板
# - WAF 拦截指纹和 payload 变形策略
#
# 这个文件只负责读取 YAML，并把 {value}、{time_delay}、{marker}、{columns}
# 这类占位符替换成实际值。

import os
import re
from functools import lru_cache

import yaml


RULE_FILE = os.environ.get(
    "PASS_SCAN_SQLI_RULE_FILE",
    os.path.join(os.path.dirname(__file__), "rules.yaml"),
)


@lru_cache(maxsize=1)
def load_rules():
    """读取 YAML 规则文件。

    使用缓存是为了避免每次扫描参数都重新读一次文件。
    如果你改了 rules.yaml，需要重启 run.py 才会加载新规则。
    """
    with open(RULE_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def rule_value(name, default=None):
    """从 YAML 顶层读取一个配置项。"""
    return load_rules().get(name, default)


def waf_detection_rules():
    """读取 WAF 拦截识别规则。"""
    return rule_value("waf_detection", {})


def tamper_profiles():
    """读取 WAF 场景下的 payload 变形策略。"""
    return rule_value("tamper_profiles", [])


def max_tampered_payloads_per_probe():
    """单个 payload 最多尝试多少个 WAF 变形版本。"""
    return int(rule_value("max_tampered_payloads_per_probe", 3))


def render_template(template, value="", extra=None):
    """替换规则里的占位符。

    {value} 会替换成原始参数值。
    {time_delay} 会替换成 YAML 里配置的延迟秒数。
    """
    replacements = {
        "value": value,
        "time_delay": str(rule_value("time_delay", 4)),
    }
    replacements.update(extra or {})

    for name, replacement in replacements.items():
        template = template.replace("{" + name + "}", str(replacement))

    return template


def get_group_value(group, name):
    """读取规则组里的字段。

    YAML 会把 true/false 这种 key 当成布尔值。
    所以这里同时兼容 "true"/"false" 和 True/False 两种 key。
    """
    if name in group:
        return group[name]
    if name == "true" and True in group:
        return group[True]
    if name == "false" and False in group:
        return group[False]
    raise KeyError(name)


def build_payloads_from_rules(value, suffix_rule, template_rule):
    """根据 suffix 和 template 两类规则生成 payload。"""
    suffixes = rule_value(suffix_rule, [])
    templates = rule_value(template_rule, [])
    payloads = [value + suffix for suffix in suffixes]
    payloads.extend(render_template(template, value) for template in templates)
    return dedupe_preserving_order(payloads)


def dedupe_preserving_order(items, key=None):
    """按最终 payload 内容去重，同时保持规则里的优先级顺序。"""
    result = []
    seen = set()
    key = key or (lambda item: item)

    for item in items:
        item_key = key(item)
        if item_key in seen:
            continue
        seen.add(item_key)
        result.append(item)

    return result


def build_error_payloads(value):
    """生成普通参数的报错型 SQL 注入 payload。"""
    return build_payloads_from_rules(
        value,
        "error_payload_suffixes",
        "error_payload_templates",
    )


def build_header_error_payloads(value):
    """生成 Header 参数的报错型 SQL 注入 payload。"""
    return build_payloads_from_rules(
        value,
        "header_error_payload_suffixes",
        "header_error_payload_templates",
    )


def build_boolean_payload_groups(value):
    """生成普通参数的布尔盲注 payload。"""
    groups = []
    for group in rule_value("boolean_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "true": render_template(get_group_value(group, "true"), value),
                "false": render_template(get_group_value(group, "false"), value),
            }
        )
    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["true"], group["false"]),
    )


def build_header_boolean_payload_groups(value):
    """生成 Header 参数的布尔盲注 payload。"""
    groups = []
    for group in rule_value("header_boolean_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "true": render_template(get_group_value(group, "true"), value),
                "false": render_template(get_group_value(group, "false"), value),
            }
        )
    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["true"], group["false"]),
    )


def build_time_payload_groups(value):
    """生成普通参数的时间盲注 payload。"""
    groups = []
    for group in rule_value("time_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "dbms": group["dbms"],
                "control": render_template(group["control"], value),
                "delay": render_template(group["delay"], value),
            }
        )
    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["control"], group["delay"]),
    )


def build_header_time_payload_groups(value):
    """生成 Header 参数的时间盲注 payload。"""
    groups = []
    for group in rule_value("header_time_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "dbms": group["dbms"],
                "control": render_template(group["control"], value),
                "delay": render_template(group["delay"], value),
            }
        )
    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["control"], group["delay"]),
    )


def build_inline_payload_groups(value):
    """生成 inline query 注入 payload。

    inline query 通常是把整个参数值替换成一个子查询，例如：
    (SELECT 'PASS_SCAN_INLINE_7311')
    """
    inline_rules = rule_value("inline_query", {})
    marker = inline_rules.get("marker", "PASS_SCAN_INLINE_7311")
    groups = []

    for group in inline_rules.get("payloads", []):
        groups.append(
            {
                "name": group["name"],
                "dbms": group.get("dbms", "generic"),
                "marker": marker,
                "payload": render_template(group["payload"], value, {"marker": marker}),
            }
        )

    return dedupe_preserving_order(groups, key=lambda group: group["payload"])


def build_union_payload_groups(value, exhaustive=False):
    """生成 UNION query 注入 payload。

    UNION 检测需要猜列数。默认对每个闭合方式/列数组合选择一个 marker
    位置，确认场景覆盖；exhaustive=True 时枚举所有 marker 位置：
    UNION SELECT NULL,'MARKER',NULL-- 
    只要响应里出现 MARKER，就说明 UNION 查询结果进入了页面。
    """
    union_rules = rule_value("union_query", {})
    marker = union_rules.get("marker", "PASS_SCAN_UNION_7311")
    max_columns = int(union_rules.get("max_columns", 6))
    groups = []

    for template_index, template_rule in enumerate(
        union_rules.get("payload_templates", [])
    ):
        for column_count in range(1, max_columns + 1):
            # 默认模式的目标是确认“存在 SQL 注入”，不是完整枚举可回显列。
            # 每种闭合方式、每个列数保留一个 marker 位置，并在不同闭合方式间
            # 轮换位置，形成覆盖集。--full-payload-scan 再枚举所有位置。
            if exhaustive:
                marker_indexes = range(column_count)
            else:
                marker_indexes = (template_index % column_count,)

            for marker_index in marker_indexes:
                columns = ["NULL"] * column_count
                columns[marker_index] = f"'{marker}'"
                payload = render_template(
                    template_rule["template"],
                    value,
                    {
                        "columns": ",".join(columns),
                        "marker": marker,
                    },
                )
                groups.append(
                    {
                        "name": template_rule["name"],
                        "marker": marker,
                        "columns": column_count,
                        "marker_index": marker_index + 1,
                        "payload": payload,
                    }
                )

    return dedupe_preserving_order(groups, key=lambda group: group["payload"])


def build_stacked_payload_groups(value):
    """生成普通参数的 stacked query 注入 payload。

    stacked query 的特点是用分号追加第二条 SQL。
    这里仍然用延时函数做验证，不做任何写库操作。
    """
    groups = []
    for group in rule_value("stacked_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "dbms": group["dbms"],
                "control": render_template(group["control"], value),
                "delay": render_template(group["delay"], value),
            }
        )

    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["control"], group["delay"]),
    )


def build_header_stacked_payload_groups(value):
    """生成 Header 参数的 stacked query 注入 payload。"""
    groups = []
    for group in rule_value("header_stacked_payload_groups", []):
        groups.append(
            {
                "name": group["name"],
                "dbms": group["dbms"],
                "control": render_template(group["control"], value),
                "delay": render_template(group["delay"], value),
            }
        )

    return dedupe_preserving_order(
        groups,
        key=lambda group: (group["control"], group["delay"]),
    )


@lru_cache(maxsize=1)
def compiled_sql_error_rules():
    """把 YAML 里的数据库错误指纹编译成正则。"""
    compiled = []
    for rule in rule_value("sql_error_rules", []):
        pattern = "|".join(rule.get("patterns", []))
        compiled.append((rule["dbms"], re.compile(pattern, re.IGNORECASE)))
    return compiled


def find_sql_error(text):
    """从响应正文中识别数据库错误。

    返回 None 表示没有发现明显数据库错误。
    返回 dict 表示命中了哪个数据库类型，以及命中的文本片段。
    """
    for dbms, pattern in compiled_sql_error_rules():
        match = pattern.search(text)
        if match:
            return {
                "dbms": dbms,
                "matched": match.group(0)[:120],
            }

    return None
