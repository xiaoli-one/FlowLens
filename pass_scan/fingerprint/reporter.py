# 指纹识别结果输出。
#
# 指纹不是漏洞，所以不写进 vulns.jsonl，也不进漏洞 HTML 报告。
# 这里单独输出：
# - fingerprints.jsonl：每个 host 一条，记录识别到的框架/服务/开源应用。
# - fingerprints_unknown.jsonl：抓到了 favicon 但规则库没命中的 host + hash，
#   方便你后续把这些 hash 补进 rules.yaml，扩充开源项目识别能力。

import json
import os
import threading


# 写文件加锁，多个 worker 线程可能同时识别不同 host。
_write_lock = threading.Lock()


def write_jsonl(path, record):
    """追加写入一条 JSON 记录。"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _write_lock:
        with open(path, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
