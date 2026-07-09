# 扫描任务去重。
#
# 被动扫描器会不断看到重复请求。如果不去重，主动检测会很快爆炸。

import threading
import time


class Deduper:
    def __init__(self, ttl_seconds):
        self.ttl_seconds = ttl_seconds
        self.seen = {}
        self.lock = threading.Lock()

    def seen_or_add(self, key):
        """如果 key 在 TTL 内出现过，返回 True；否则记录并返回 False。"""
        now = time.time()

        with self.lock:
            self.cleanup(now)
            if key in self.seen:
                return True

            self.seen[key] = now
            return False

    def cleanup(self, now):
        expired = [
            key for key, created_at in self.seen.items()
            if now - created_at > self.ttl_seconds
        ]
        for key in expired:
            self.seen.pop(key, None)
