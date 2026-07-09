from pass_scan.terminal import color_text


PURPLE = "\033[35m"


def purple(text):
    return color_text(text, PURPLE)
