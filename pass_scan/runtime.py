# 运行时状态。
#
# 这里不放漏洞检测逻辑，只放扫描过程中需要共享的小状态：
# - WAF 冷却时间：确认当前 IP/会话被封后，后续主动探测先等一会。

import threading
import time

from pass_scan.terminal import yellow


class WafBlockedTask(Exception):
    """当前目标确认多次被 WAF 封禁，结束本次扫描任务。"""


class WafState:
    """记录每个 host 的 WAF 冷却时间。"""

    def __init__(self, backoff_seconds=1800, max_block_attempts=3):
        self.backoff_seconds = max(0, int(backoff_seconds))
        self.max_block_attempts = max(1, int(max_block_attempts))
        self.blocked_until = {}
        self.block_attempts = {}
        self.last_check_time = {}
        self.lock = threading.Lock()

    def wait_if_needed(self, host):
        """如果 host 正在冷却，就等待到冷却结束。"""
        if not host or self.backoff_seconds <= 0:
            return

        while True:
            with self.lock:
                if self.block_attempts.get(host, 0) >= self.max_block_attempts:
                    raise WafBlockedTask(host)

                until = self.blocked_until.get(host, 0)
                wait_seconds = until - time.time()

            if wait_seconds <= 0:
                return

            time.sleep(min(wait_seconds, 1))

    def should_check_ip_blocked(self, host, interval_seconds=5):
        """限制 IP 封禁确认频率，避免每个 WAF 响应都重放原始请求。"""
        if not host or self.backoff_seconds <= 0:
            return False

        now = time.time()
        with self.lock:
            if self.block_attempts.get(host, 0) >= self.max_block_attempts:
                return False

            if self.blocked_until.get(host, 0) > now:
                return False

            last_check = self.last_check_time.get(host, 0)
            if now - last_check < interval_seconds:
                return False

            self.last_check_time[host] = now
            return True

    def block_host(self, host, reasons):
        """确认当前 IP/会话被封后，按次数决定等待或结束任务。"""
        if not host or self.backoff_seconds <= 0:
            return

        now = time.time()
        reason_text = ", ".join(reasons[:3]) if reasons else "unknown"

        with self.lock:
            attempt = self.block_attempts.get(host, 0) + 1
            self.block_attempts[host] = attempt

            if attempt < self.max_block_attempts:
                until = now + self.backoff_seconds
                old_until = self.blocked_until.get(host, 0)
                self.blocked_until[host] = max(old_until, until)
            else:
                self.blocked_until.pop(host, None)

        if attempt < self.max_block_attempts:
            wait_minutes = max(1, self.backoff_seconds // 60)
            print(
                yellow(
                    f"[WAF] {host} 疑似当前 IP/会话已被 WAF 封禁，"
                    f"原因: {reason_text}；第 {attempt}/{self.max_block_attempts} 次，"
                    f"等待 {wait_minutes} 分钟后继续"
                ),
                flush=True,
            )
            return

        print(
            yellow(
                f"[WAF] {host} 第 {attempt}/{self.max_block_attempts} 次确认仍被 WAF 封禁，"
                "结束当前扫描任务"
            ),
            flush=True,
        )
        raise WafBlockedTask(host)
