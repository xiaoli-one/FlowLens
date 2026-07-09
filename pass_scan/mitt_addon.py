import json
import os
import sys
import time
from urllib.parse import urlsplit

from mitmproxy import http

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pass_scan.body_paser import body_to_record,headers_to_dict
from pass_scan.scanner import PassiveScanner

LOG_FILE = os.environ.get("PASS_SCAN_LOG_FILE", os.path.join("logs", "flows.jsonl"))


class MitmTrafficAddon:
    def __init__(self):
        self.scanner = PassiveScanner()

    def load(self, loader):  
        os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)

    def request(self, flow: http.HTTPFlow):  # 处理请求，记录开始时间
        flow.metadata["pass_scan_start_time"] = time.time()

    def response(self, flow: http.HTTPFlow):
        if self.scanner.should_ignore_flow(flow):
            return

        record = self.build_record(flow)
        self.write_record(record)
        scan_flow = flow.copy()
        self.scanner.check(record, scan_flow)

    def error(self, flow: http.HTTPFlow):
        if self.scanner.should_ignore_flow(flow):
            return

        if flow.error:
            return

    def build_record(self, flow: http.HTTPFlow):
        started_at = flow.metadata.get("pass_scan_start_time", time.time())
        request = flow.request
        response = flow.response
        parsed_url = urlsplit(request.pretty_url) # 把url拆开，https -> example.com -> /api/user -> id=123

        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "duration_ms": int((time.time() - started_at) * 1000),  # 请求耗时
            "request": {
                "method": request.method,  # HTTP 方法
                "scheme": parsed_url.scheme,  # 协议
                "host": parsed_url.netloc,  # 域名 example.com
                "path": parsed_url.path or "/",  # 路径 /api/user
                "query": parsed_url.query,  # 参数 id=123
                "url": request.pretty_url,  # 完整url
                "headers": headers_to_dict(request.headers),  # 请求头，转成普通字典
                "body": body_to_record(request.content, request.headers),  # 请求体，文本直接保存，二进制转base64
            },
            "response": {
                "status_code": response.status_code,  # 响应状态码
                "reason": response.reason,  # 状态吗说明：OK，NOT FOUND
                "headers": headers_to_dict(response.headers),  # 响应头，转成普通字典
                "body": body_to_record(response.content, response.headers),  # 响应体，文本直接保存，二进制转base64
            },
        }

    def write_record(self, record):
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [MitmTrafficAddon()] 

# mitmproxy生命周期
# load() -> request() -> response() -> error()
