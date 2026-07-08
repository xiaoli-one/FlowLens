# FlowLens

`FlowLens` 是一个基于 `mitmproxy/mitmdump` 的被动流量安全检测工具。它通过本地代理接收浏览器、BurpSuite 或其他客户端转发的 HTTP/HTTPS 流量，记录请求与响应，并将符合条件的流量提交给漏洞插件进行后台验证，最终输出 JSONL 结果和静态 HTML 报告。

> 仅在已授权的资产和测试环境中使用。本工具会重放请求并注入 payload，部分插件会发起带外探测或写入 canary 文件。

## 功能特性

当前已内置以下检测能力：

| 能力 | 命令行开关 | 说明 |
| --- | --- | --- |
| SQL 注入 | `--sqli` | 报错、布尔、inline、UNION、stacked、时间盲注, 支持 tamper  |
| XSS | `--xss` | 反射/存储统一检测，支持 marker 回扫 |
| 命令注入 / RCE | `--rce` | 命令回显、时间盲注、OOB 带外确认 |
| LFI / 任意文件读取 | `--lfi` | 目录遍历、任意文件读取、`php://filter` 源码读取 |
| XXE | `--xxe` | 带内文件读取、OOB 外部实体解析 |
| 指纹识别 | `--fp` | 框架、语言、中间件、CMS、开源应用、favicon hash |
| 开放重定向 / CRLF | `--redir` | 开放重定向、响应头注入 |
| 敏感信息泄漏 | `--sensitive` | AK/SK、API key、Token、私钥、配置文件、Swagger、Actuator 等 |
| SSRF | `--ssrf` | 多协议和绕过变体，基于 OOB 回连确认 |
| OSS / 对象存储 | `--oss` | 桶发现、匿名列举、匿名上传/覆盖、AK/SK 泄漏 |
| SSTI | `--ssti` | 算术回显、字符串转换、模板错误指纹 |
| 文件上传 | `--upload` | 上传点识别、危险扩展、双扩展、图片马、解析绕过、`.htaccess` 链 |
| JWT | `--jwt` | `alg=none`、签名绕过、弱 HMAC 密钥、claim风险 |
| 全量扫描 | `--full-payload-scan` | 使用更完整的 payload/tamper，并启用更多 Cookie/Header 检测
| 校验证书 | `--verify-upstream-cert` | 校验目标站TLS证书，默认忽略自签名或无效证书

不指定任何检测开关时，默认按 `config.yaml` 中启用的插件全部运行。指定一个或多个检测开关后，只运行被指定的插件。

## 工作方式

```text
浏览器 / BurpSuite
  -> pass_scan mitmproxy 127.0.0.1:8081
  -> 目标站点

目标响应
  -> pass_scan 记录流量、入队检测、刷新报告
  -> 浏览器 / BurpSuite
```

核心流程：

```text
run.py
  -> 启动 mitmdump 并加载 pass_scan/mitm_addon.py
  -> 写入 logs/flows.jsonl
  -> PassiveScanner 构建 ScanContext
  -> 插件 observe / interested / check
  -> 写入 logs/vulns.jsonl、logs/fingerprints.jsonl
  -> 生成 report.html
```

## 环境要求

- Python 3.10+

```bash
python3 -m pip install -r requirements.txt
```

## 快速开始

启动默认扫描代理：

```bash
python3 run.py
```

默认监听地址为 `127.0.0.1:8081`，流量日志写入 `logs/flows.jsonl`，漏洞报告写入 `report.html`。

然后将浏览器或上游代理指向：

```text
HTTP 代理: 127.0.0.1
端口: 8081
```

检测 HTTPS 站点时，需要安装 mitmproxy CA 证书。代理启动后访问 `http://mitm.it`，按系统或浏览器提示安装证书。

## 常用命令

开启更完整的 payload 扫描：

```bash
python3 run.py --full-payload-scan
```

只做 SQL 注入检测：

```bash
python3 run.py --sqli
```

同时做 SQL 注入、XSS 和 RCE：

```bash
python3 run.py --sqli --xss --rce
```

默认会忽略目标站自签名或无效 TLS 证书，避免 mitmproxy 返回 502。需要强制校验证书时：

```bash
python3 run.py --verify-upstream-cert
```

## 配置说明

全局配置位于 `config.yaml`：

| 配置区域 | 说明 |
| --- | --- |
| `scan` | 调度模式、worker 数、队列长度、去重、限速、WAF 冷却、全量扫描 |
| `report` | 默认 HTML 报告路径 |
| `plugins` | 各检测插件的启用状态和插件级参数 |

常用配置项：

| 配置项 | 说明 |
| --- | --- |
| `scan.worker_count` | 每个插件默认 worker 数 |
| `scan.queue_size` | 每个插件默认队列长度 |
| `scan.dedup_ttl_seconds` | 同一扫描点去重时间 |
| `scan.per_host_interval_seconds` | 同一 host 主动任务间隔 |
| `scan.max_params_per_request` | 单条请求最多提取的参数数量 |
| `scan.full_payload_scan` | 启用完整 payload 与 Cookie/Header 注入点 |
| `scan.ignored_hosts` | 忽略浏览器、系统后台流量 |

命令行插件开关会覆盖 `config.yaml` 中的插件选择。例如 `python3 run.py --jwt` 表示只运行 JWT 检测。

## 项目结构

```text
.
├── run.py                         # 启动入口，负责拉起 mitmdump
├── config.yaml                    # 全局配置与插件配置
├── pass_scan/
│   ├── mitm_addon.py              # mitmproxy addon
│   ├── scanner.py                 # 插件加载与调度
│   ├── scan_context.py            # 请求响应标准化和参数提取
│   ├── scan_queue.py              # 插件队列、worker、限速
│   ├── reporter.py                # JSONL 写入和 HTML 报告生成
│   ├── sql_injection/             # SQL 注入插件
│   ├── xss/                       # XSS 插件
│   ├── command_injection/         # 命令注入插件
│   ├── path_traversal/            # LFI / 文件读取插件
│   ├── ssrf/                      # SSRF 插件
│   ├── xxe/                       # XXE 插件
│   ├── ssti/                      # SSTI 插件
│   ├── redir/                     # 重定向 / CRLF 插件
│   ├── sensitive_info/            # 敏感信息插件
│   ├── object_storage/            # OSS / 对象存储插件
│   ├── file_upload/               # 文件上传插件
│   ├── jwt/                       # JWT 插件
│   └── fingerprint/               # 指纹识别插件
├── tools/                         # 辅助工具
├── logs/                          # 运行日志
└── report.html                    # 默认报告文件
```

## 扩展新插件

新增插件的一般步骤：

1. 新建 `pass_scan/<plugin>/` 目录。
2. 实现 `<plugin>_scanner.py`，提供 `name`、`interested(context)`、`dedup_key(context)`、`check(context)`。
3. 如需 payload 或规则，添加 `rules.yaml` 和 `rules.py`。
4. 在 `pass_scan/scanner.py` 注册插件。
5. 在 `run.py` 添加命令行开关。
6. 在 `config.yaml` 添加 `plugins.<name>` 配置。
7. 在 `pass_scan/reporter.py` 添加中文展示名称、证据字段和报告渲染逻辑。

更多架构细节见 `pass_scan/TECHNICAL_DOC.md`，各插件目录中也包含对应的技术文档。

## 使用注意

- 请控制 `worker_count`、`queue_size` 和 `--full-payload-scan` 的使用，避免对目标造成过高压力。
- OOB 类检测依赖目标能访问外网 DNS/HTTP 服务；内网无出网环境下可能无法确认盲打漏洞。
- 文件上传和对象存储检测可能产生测试文件或 canary 对象，请确认授权范围。
- 主动探测请求默认不走系统代理，避免扫描流量再次绕回本地代理形成回环。
