# pass_scan

一个独立运行的被动扫描工具雏形。当前第一步只做一件事：通过 `mitmproxy` 接收 BurpSuite 转发过来的 HTTP/HTTPS 流量，并把请求、响应记录到本地文件。

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## 启动

```bash
python3 run.py
```

默认监听：

```text
127.0.0.1:8081
```

默认保存流量到：

```text
logs/flows.jsonl
```

## BurpSuite 联动方式

推荐链路：

```text
浏览器 -> BurpSuite(127.0.0.1:8080) -> pass_scan/mitmproxy(127.0.0.1:8081) -> 目标网站
```

在 BurpSuite 中配置：

1. 打开 `Settings`。
2. 找到 `Network` -> `Connections` -> `Upstream Proxy Servers`。
3. 添加一条规则：
   - Destination host: `*`
   - Proxy host: `127.0.0.1`
   - Proxy port: `8081`
4. 浏览器继续使用 BurpSuite 代理，也就是 `127.0.0.1:8080`。

如果 HTTPS 请求失败，通常是 BurpSuite 不信任 mitmproxy 生成的证书。可以先在 BurpSuite 里关闭上游 TLS 证书校验，或把 mitmproxy CA 证书导入 BurpSuite 信任区。mitmproxy 证书一般在：

```text
~/.mitmproxy/mitmproxy-ca-cert.pem
```

## 查看流量

启动后访问任意网站，终端会看到类似：

```text
200 GET https://example.com/
```

完整请求/响应会以 JSON Lines 形式写入：

```bash
tail -f logs/flows.jsonl
```

## 后续加检测规则

后续漏洞检测逻辑可以直接写在：

```text
pass_scan/scanner.py
```

当前 `PassiveScanner.check()` 会收到一个完整的 `record`，里面包含：

- `record["request"]`
- `record["response"]`
