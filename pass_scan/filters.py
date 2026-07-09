# 流量过滤规则。
#
# 浏览器会自己访问很多后台服务，例如 Firefox Push、更新、遥测、SafeBrowsing。
# 这些请求不是目标业务流量，还可能因为证书信任问题刷屏。
# 这里用 host 黑名单过滤它们：不记录日志，也不提交漏洞扫描。

from fnmatch import fnmatch
from urllib.parse import urlsplit


def normalize_host(host):
    """把 host 统一成小写，并去掉端口。"""
    host = (host or "").strip().lower()
    if not host:
        return ""

    if host.startswith("["):
        return host

    return host.split(":", 1)[0]


def host_from_flow(flow):
    """从 mitmproxy flow 里取目标 host。"""
    request = getattr(flow, "request", None)
    if not request:
        return ""

    host = getattr(request, "host", "") or getattr(request, "pretty_host", "")
    if host:
        return normalize_host(host)

    url = getattr(request, "pretty_url", "") or getattr(request, "url", "")
    return normalize_host(urlsplit(url).netloc)


def is_ignored_host(host, patterns):
    """判断 host 是否命中忽略列表。

    patterns 支持普通域名和通配符：
    - push.services.mozilla.com
    - *.telemetry.mozilla.org
    - clients*.google.com
    """
    host = normalize_host(host)
    if not host:
        return False

    for pattern in patterns or []:
        pattern = normalize_host(pattern)
        if not pattern:
            continue
        if host == pattern or fnmatch(host, pattern):
            return True

    return False
