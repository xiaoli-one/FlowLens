# 终端输出工具。

import os


YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
PURPLE = "\033[35m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color_text(text, color):
    """给终端文本加颜色；设置 NO_COLOR 时关闭颜色。"""
    if os.environ.get("NO_COLOR"):
        return text
    return f"{color}{text}{RESET}"


def yellow(text):
    return color_text(text, YELLOW)


def green(text):
    return color_text(text, GREEN)


def red(text):
    return color_text(text, RED)


def cyan(text):
    return color_text(text, CYAN)


def purple(text):
    return color_text(text, PURPLE)


def bold(text):
    return color_text(text, BOLD)
