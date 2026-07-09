import os

import yaml


RULE_FILE = os.path.join(os.path.dirname(__file__), "rules.yaml")


def load_rules():
    with open(RULE_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


RULES = load_rules()


def rule_value(name, default=None):
    return RULES.get(name, default)


def upload_name_keywords():
    return list(rule_value("upload_name_keywords", []))


def upload_path_keywords():
    return list(rule_value("upload_path_keywords", []))


def success_keywords():
    return list(rule_value("success_keywords", []))


def failure_keywords():
    return list(rule_value("failure_keywords", []))


def script_extensions():
    return list(rule_value("script_extensions", []))


def script_bypass_filenames():
    return list(rule_value("script_bypass_filenames", []))


def active_content_extensions():
    return list(rule_value("active_content_extensions", []))


def dangerous_extensions():
    return list(rule_value("dangerous_extensions", []))


def binary_media_prefixes():
    return tuple(rule_value("binary_media_prefixes", []))


def binary_media_types():
    return set(rule_value("binary_media_types", []))


def url_json_keys():
    return set(rule_value("url_json_keys", []))


def common_upload_dirs():
    return list(rule_value("common_upload_dirs", []))
