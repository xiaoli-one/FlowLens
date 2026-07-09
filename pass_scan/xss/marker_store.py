# 存储型 XSS 的 marker 登记表。
#
# 存储型 XSS 的特点：payload 在 A 请求里提交、被后端保存，之后在 B 页面
# （可能是完全不同的 URL）被渲染出来。被动扫描器要发现它，必须：
#   1. 在扫描某个参数时，额外注入一个可辨识的“存储 marker”，并登记下来。
#   2. 对之后每一个 HTML 响应，回扫是否出现任何已登记的 marker。
#      出现 -> 说明我们注入的内容被存储并渲染到了这个页面。
#
# 这个模块只负责“记住我们注入过哪些 marker、注入点是什么”，
# 并提供跨请求的回扫查询。真正的注入和回扫判定在 xss_scanner.py。
#
# marker 同时写入内存和 logs/xss_markers.jsonl：
#   - 内存：本次运行内快速回扫。
#   - 文件：进程重启后仍能识别历史注入（例如昨天注入、今天才浏览到展示页）。

import json
import os
import threading


class MarkerStore:
    """存储型 XSS marker 登记表（内存 + JSONL 持久化）。"""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        # marker -> 注入点信息 dict
        self.markers = {}
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._load()

    def _load(self):
        """启动时从 JSONL 恢复历史 marker。"""
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    marker = record.get("marker")
                    if marker:
                        self.markers[marker] = record
        except OSError:
            # 读取失败不影响扫描主流程，退化为只用内存。
            pass

    def register(self, marker, info):
        """登记一个已注入的存储 marker。

        info 至少包含 injected_url / param_place / param_name / payload / required_chars。
        重复登记同一个 marker 时只保留第一次。
        """
        with self.lock:
            if marker in self.markers:
                return
            record = dict(info)
            record["marker"] = marker
            self.markers[marker] = record
            self._append(record)

    def _append(self, record):
        """把新 marker 追加写入 JSONL。"""
        try:
            with open(self.path, "a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def snapshot(self):
        """返回当前所有已登记 marker 的浅拷贝，供回扫遍历。"""
        with self.lock:
            return dict(self.markers)

    def find_in_text(self, text):
        """回扫：返回响应正文里出现的所有已登记 marker 的注入点信息。

        为控制开销，先用最便宜的子串查找；命中才会被上层进一步分析。
        """
        if not text:
            return []
        hits = []
        for marker, info in self.snapshot().items():
            if marker in text:
                hits.append(info)
        return hits
