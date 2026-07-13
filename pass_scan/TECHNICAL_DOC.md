# pass_scan 总体技术文档

本文档是 `pass_scan` 模块的总体技术报告。它不按源码逐行解释，而是从实现者视角说明这个被动扫描核心是怎么设计的：如何接入流量、如何构造扫描上下文、如何调度插件、如何做主动验证、如何控制误报、如何输出报告，以及每类漏洞插件在整个体系中的位置。

## 1. 总体定位

`pass_scan` 是 FlowLens 的传统漏洞扫描核心。它运行在 mitmproxy/mitmdump 代理之后，以真实 HTTP/HTTPS 流量为触发源，把请求响应标准化成统一上下文，再交给各类漏洞插件做后台主动验证。

它的定位不是爬虫，也不是纯离线日志分析，而是：

```text
真实业务流量触发
  -> 被动记录请求响应
  -> 插件判断是否值得扫描
  -> 后台 worker 主动重放和注入 payload
  -> 生成 JSONL finding
  -> 刷新静态 HTML 报告
```

这种架构的核心价值是：扫描器不用自己猜测站点结构，而是跟随测试者、浏览器或 BurpSuite 已经访问到的真实业务路径进行检测。

## 2. 设计目标

`pass_scan` 的设计目标包括：

1. **被动触发**  
   不主动爬站，只基于经过代理的真实请求触发检测，降低无关流量和越界扫描风险。

2. **主动验证**  
   插件不是只做静态匹配，而是在后台重放请求、注入 payload，并用响应证据确认漏洞。

3. **插件化**  
   每类漏洞独立实现 interested、dedup、check 逻辑，调度层只负责统一上下文、队列和限速。

4. **低阻塞**  
   mitmproxy 回调只做轻量记录和入队，真正发包由后台 worker 执行，避免阻塞代理链路。

5. **证据优先**  
   finding 不只写“存在漏洞”，还保存 payload、请求包、响应包、差异指标、OOB 交互和 technique。

6. **安全可控**  
   worker 数、队列长度、host 限速、WAF 冷却、全量扫描模式都可配置。

7. **可扩展**  
   新插件只要遵守统一契约，就能接入调度、报告、验证 Agent 和配置体系。

## 3. 整体运行链路

外部链路：

```text
浏览器 / BurpSuite / 其他客户端
        |
        v
FlowLens mitmproxy 代理
        |
        v
目标网站
```

内部链路：

```text
mitmproxy response flow
  -> 构造 record
  -> 写 logs/flows.jsonl
  -> PassiveScanner.check(record, flow.copy())
  -> build_scan_context()
  -> 全局过滤
  -> 插件 observe(context)
  -> 插件 interested(context)
  -> dedup_key 去重
  -> ScanQueue.enqueue()
  -> 插件 worker 调用 check()
  -> 主动发 payload / OOB / canary
  -> write_jsonl()
  -> write_html_report()
```

这个链路里有两个关键原则：

- 代理回调尽量轻，只负责标准化和入队。
- 漏洞验证异步化，每个插件独立队列，互不阻塞。

## 4. 核心模块边界

| 模块 | 作用 |
| --- | --- |
| `mitm_addon.py` | mitmproxy addon，记录 flow 并触发扫描 |
| `scanner.py` | 插件加载、配置选择、调度入口 |
| `scan_context.py` | 标准化请求响应，提取参数和全局过滤 |
| `scan_queue.py` | 每插件独立队列、worker、host 限速、状态输出 |
| `dedup.py` | TTL 去重 |
| `runtime.py` | WAF 冷却和运行期异常 |
| `reporter.py` | JSONL 写入、HTML 报告生成、结果聚合 |
| `filters.py` | 浏览器和系统后台 host 过滤 |
| `body_paser.py` | body 解码、content-type 处理、二进制记录 |
| 各插件目录 | 具体漏洞检测能力 |

这些模块形成一个清晰分层：

```text
流量层 -> 上下文层 -> 调度层 -> 插件层 -> 报告层
```

## 5. ScanContext：统一扫描输入

每个插件不应该重复解析请求，所以 `pass_scan` 先把 flow 统一成 `ScanContext`。

`ScanContext` 包含：

| 字段 | 说明 |
| --- | --- |
| method | HTTP 方法 |
| url | 完整 URL |
| scheme | http / https |
| host | host:port |
| path | URL path |
| request_content_type | 请求 Content-Type |
| response_content_type | 响应 Content-Type |
| status_code | 响应状态码 |
| parameters | 可控参数列表 |
| skip_reason | 全局过滤原因 |

### 5.1 参数提取

统一提取以下参数：

| 来源 | 说明 |
| --- | --- |
| query | URL 查询参数 |
| form | `application/x-www-form-urlencoded` |
| json | JSON 叶子标量，支持嵌套路径 |
| cookie | Cookie 键值 |
| header | 少量业务相关 header |

JSON 参数会被格式化成路径，例如：

```text
user.id
items[0].sku
profile["display-name"]
```

这样插件可以只替换目标叶子节点，而不破坏整个 JSON body。

### 5.2 Header 选择

Header 不会全量扫描，只选择少量确实可能进入业务逻辑的字段：

- `User-Agent`
- `Referer`
- `X-Forwarded-For`
- `X-Real-IP`
- `Client-IP`

这是一个安全和成本取舍。全量 Header 注入会显著增加请求量，也容易打到日志、网关和中间件噪声。

### 5.3 全局过滤

全局会跳过：

- `HEAD`
- `OPTIONS`
- 静态资源后缀。
- 204 / 304。
- 图片、音频、视频、字体等二进制响应。

不同插件可以选择是否尊重 `context.is_skipped`。例如敏感信息检测会额外关注 JS、JSON 和配置类文本资源；逻辑漏洞 Agent 会跳过全局无意义流量。

## 6. 插件调度模型

普通插件遵守三个核心方法：

```text
interested(context)
dedup_key(context)
check(context)
```

含义是：

| 方法 | 作用 |
| --- | --- |
| `interested` | 判断当前流量是否值得入队 |
| `dedup_key` | 生成去重 key，避免重复扫同一类入口 |
| `check` | 在后台 worker 中执行主动检测 |

部分插件使用扩展模式：

| 扩展 | 适用场景 |
| --- | --- |
| `observe(context)` | 从流量中派生目标，而不是直接扫描当前请求 |
| `observer_only = True` | 插件只观察和派生任务 |
| `task_label()` | 自定义入队日志 |
| `enqueue_log_key()` | 控制入队日志去重 |

observer-only 插件包括：

- JWT：先提取 token，再检测 token 目标。
- 对象存储：先发现桶，再检测桶目标。
- 业务逻辑 Agent：先索引流量，再分析 endpoint。

## 7. 队列与并发设计

每个插件都有独立队列和独立 worker。这么做有几个好处：

- SQL 注入的时间盲注不会阻塞 XSS。
- OOB 类插件等待回连不会卡住其他插件。
- 文件上传等重插件可以单独调小 worker。
- 指纹识别这类轻插件可以快速完成。

调度层提供：

| 能力 | 说明 |
| --- | --- |
| worker_count | 每插件 worker 数 |
| queue_size | 每插件队列长度 |
| per_host_interval_seconds | 同 host 主动请求间隔 |
| status_interval_seconds | 终端状态输出间隔 |
| WAF 冷却 | 确认封禁后暂停该 host |

队列满时直接丢弃新任务，这是保护代理主流程的设计选择。被动扫描器不应该因为目标太多或 payload 太慢而拖死浏览器代理。

## 8. 去重策略

去重分两层：

1. 调度层 TTL 去重：同一插件、同一 dedup key 在一段时间内不重复入队。
2. 插件内部去重：同一参数、同一 payload 组、同一 OOB token 或同一上传目标避免重复报告。

dedup key 通常包含：

- method。
- host。
- 归一路径。
- content-type。
- 参数位置和参数形态。
- 插件特有目标信息。

去重不是为了漏扫，而是为了避免同一页面每次刷新都触发完整 payload 集。

## 9. 主动请求原则

插件主动发包时遵循几个原则：

- 基于原始请求重放，保留必要 Cookie/Header。
- 一次只改变一个变量。
- 不走系统代理，避免再次绕回本地代理形成回环。
- HTTPS 默认忽略上游证书校验，适配测试环境自签名证书。
- 请求和响应都记录成 proof，便于复现。
- 对同一 host 做间隔控制。

这种设计让主动验证尽量接近真实业务上下文，同时不阻塞代理链路。

## 10. WAF 与冷却策略

部分插件会识别 WAF 或拦截页面，例如：

- 特定状态码。
- 响应头。
- 响应体关键词。
- CAPTCHA / forbidden / blocked。

WAF 处理分两类：

1. **普通拦截**  
   当前 payload 被拦截，可以尝试 tamper 变体。

2. **确认封禁**  
   当前 IP 或会话被封禁，进入 host 冷却，暂停该 host 的后续主动任务。

配置项：

- `scan.waf_backoff_seconds`
- `scan.waf_max_block_attempts`

这样能避免扫描器在已被封禁时继续对目标造成压力。

## 11. 全量扫描模式

默认扫描模式偏保守：

- query。
- form。
- json。

开启 `--full-payload-scan` 后，会扩大范围：

- Cookie。
- 常见 Header。
- 更多 payload。
- 更多 tamper。

全量扫描适合靶场、专项测试和授权范围明确的环境。生产或灰度环境更适合默认模式，避免请求量和误报上升。

## 12. OOB 机制

多个插件需要带外确认：

- 命令注入。
- SSRF。
- XXE。
- JWT 远程 key 获取扩展项。

OOB 的基本模型：

```text
生成唯一 token
  -> 构造 token.domain
  -> 注入 payload
  -> 目标解析或访问域名
  -> interactsh 轮询收到交互
  -> 根据 token 关联到插件、参数和 payload
```

OOB 能把不可见的服务端行为变成可观察证据。报告中会记录协议、来源、域名和原始交互。

## 13. Canary 机制

文件上传和对象存储需要写入验证，但写入必须可控。项目使用 canary 机制：

- 文件名或对象 key 使用随机 UUID。
- 路径带 `pass-scan`、`canary` 等标记。
- 内容是 harmless marker。
- 只操作新建对象，不覆盖真实对象。
- 成功后尽量清理。

Canary 的作用是证明写入能力，同时降低对真实业务数据的影响。

## 14. 报告与输出

主要输出：

| 文件 | 说明 |
| --- | --- |
| `logs/flows.jsonl` | 标准化流量记录 |
| `logs/vulns.jsonl` | 传统漏洞 finding |
| `logs/fingerprints.jsonl` | 指纹结果 |
| `logs/fingerprints_unknown.jsonl` | 未识别 favicon 线索 |
| `logs/xss_markers.jsonl` | XSS marker 存储 |
| `logs/verifications.jsonl` | 主动验证 Agent 结果 |
| `logs/logic_vulns.jsonl` | 业务逻辑漏洞 Agent 结果 |
| `report.html` | 静态报告 |

典型 finding 字段：

| 字段 | 说明 |
| --- | --- |
| type | 漏洞大类 |
| method | 子类型或检测方法 |
| url | 触发 URL |
| request_method | 原始 HTTP 方法 |
| param_place | 参数位置 |
| param_name | 参数名 |
| evidence | 判定证据 |
| proof | 关键请求响应 |
| extra_proofs | 辅助证据，如 OOB、二次确认 |

报告层会把不同插件的 finding 统一渲染，并根据类型展示不同证据字段。

## 15. 插件能力总览

| 插件 | 命令行 | 核心检测思路 | 专项文档 |
| --- | --- | --- | --- |
| SQL 注入 | `--sqli` | 报错、布尔、inline、UNION、stacked、时间盲注 | `sql_injection/SQL_INJECTION_TECHNICAL_DOC.md` |
| XSS | `--xss` | locator、上下文识别、payload 闭合、marker 回扫 | `xss/XSS_TECHNICAL_DOC.md` |
| 命令注入 | `--rce` | 命令回显、延时、OOB | `command_injection/COMMAND_INJECTION_TECHNICAL_DOC.md` |
| 任意文件读取 | `--lfi` | 文件 signature、PHP filter、路径 tamper | `path_traversal/PATH_TRAVERSAL_TECHNICAL_DOC.md` |
| SSRF | `--ssrf` | 唯一 OOB 域名确认服务端请求 | `ssrf/SSRF_TECHNICAL_DOC.md` |
| XXE | `--xxe` | XML 外部实体、OOB、带内文件读取 | `xxe/XXE_TECHNICAL_DOC.md` |
| SSTI | `--ssti` | 算术回显、字符串转换、模板错误 | `ssti/SSTI_TECHNICAL_DOC.md` |
| 重定向/CRLF | `--redir` | Location/Refresh/meta/header 控制确认 | `redir/REDIR_TECHNICAL_DOC.md` |
| 敏感信息 | `--sensitive` | 被动正则 + 常见泄漏端点轻量探测 | `sensitive_info/SENSITIVE_INFO_TECHNICAL_DOC.md` |
| 对象存储 | `--oss` | 桶发现、匿名列举、canary 写入、AK/SK | `object_storage/OBJECT_STORAGE_TECHNICAL_DOC.md` |
| 文件上传 | `--upload` | canary、落点解析、危险扩展、解析绕过 | `file_upload/FILE_UPLOAD_TECHNICAL_DOC.md` |
| JWT | `--jwt` | token 提取、baseline/negative、签名绕过 | `jwt/JWT_TECHNICAL_DOC.md` |
| 指纹识别 | `--fp` | header/cookie/body/title/url/favicon 规则识别 | `fingerprint/FINGERPRINT_TECHNICAL_DOC.md` |

## 16. 各类插件的设计定位

### 16.1 注入执行类

包括：

- SQL 注入。
- 命令注入。
- SSTI。

共同特点：

- 可控输入进入解释器。
- 需要 baseline 区分正常响应和执行结果。
- payload 需要按技术分层。
- 高风险利用深度交给主动验证 Agent 继续推进。

### 16.2 前端执行类

包括 XSS。

核心不是 payload 是否反射，而是是否进入可执行上下文。XSS 插件通过 locator 和上下文识别避免把普通文本反射误报成漏洞。

### 16.3 服务端资源访问类

包括：

- SSRF。
- XXE。
- 任意文件读取。

共同特点：

- 服务端访问了外部资源、XML 实体或本地文件。
- 确认证据通常不是状态码，而是 OOB 回连或文件 signature。
- 安全边界要求不读取高敏感文件、不做内网破坏性探测。

### 16.4 响应控制类

包括开放重定向和 CRLF。

核心是用户输入是否进入响应控制语义位置，例如 Location、Refresh、meta refresh 或响应头结构。正文反射不算漏洞。

### 16.5 暴露面和配置类

包括：

- 敏感信息。
- 指纹识别。
- 对象存储。

这些插件更多承担资产和暴露面识别职责。它们通常被动优先，主动补包轻量，并强调规则质量和低误报。

### 16.6 认证与文件处理类

包括：

- JWT。
- 文件上传。

JWT 需要 baseline/negative control 证明服务端确实依赖 token。文件上传需要 canary 和落点确认，不能只看上传接口返回 200。

## 17. 误报控制体系

项目整体的误报控制不是单一机制，而是多层组合：

| 层级 | 控制方式 |
| --- | --- |
| 流量层 | 静态资源、二进制、后台 host 过滤 |
| 参数层 | max params、Header 白名单、插件语义筛选 |
| 调度层 | TTL 去重、队列限制、host 限速 |
| 检测层 | baseline、单变量变异、二次确认 |
| 证据层 | OOB token、文件 signature、marker、响应头结构 |
| 报告层 | technique、confidence、proof、extra_proofs |

不同插件有自己的确认终点：

- SQL 注入需要错误、差异、marker 或延时。
- XSS 需要上下文可执行性。
- SSRF/XXE/命令注入 OOB 需要唯一 token。
- 文件读取需要文件内容 signature。
- 文件上传需要 canary 可访问或执行 marker。
- JWT 需要 baseline/negative 成立后绕过被接受。
- 重定向/CRLF 需要进入响应控制位置。

## 18. 安全边界

`pass_scan` 会主动发 payload，因此必须在授权范围内使用。

安全控制包括：

- 默认不爬站。
- 插件队列和 worker 可控。
- 同 host 请求间隔。
- WAF 冷却。
- OOB 只证明回连。
- 文件上传和对象存储只写 canary。
- 默认不对 Header/Cookie 做全量扫描。
- SSTI 默认不做 RCE payload。
- JWT 远程 key 类检测默认关闭。

使用建议：

| 场景 | 建议 |
| --- | --- |
| 日常代理辅助 | 默认模式 |
| 靶场或专项测试 | 开启指定插件和全量扫描 |
| 生产授权验证 | 调低 worker，限制插件范围 |
| OOB 受限网络 | 不依赖 SSRF/XXE/OOB 类结论 |
| 上传/OSS 测试 | 确认 canary 写入授权和清理策略 |

## 19. 配置体系

核心配置在 `config.yaml`。

### 19.1 scan

`scan` 控制全局调度：

- `mode`
- `worker_count`
- `queue_size`
- `dedup_ttl_seconds`
- `per_host_interval_seconds`
- `max_params_per_request`
- `status_interval_seconds`
- `full_payload_scan`
- `waf_backoff_seconds`
- `waf_max_block_attempts`
- `ignored_hosts`

### 19.2 plugins

`plugins` 控制每个插件：

- enabled。
- worker_count。
- queue_size。
- payload 深度。
- OOB。
- 主动探测。
- 写入探测。
- 规则文件。

命令行插件开关优先级高于配置。例如 `--sqli --xss` 会只启用 SQL 注入和 XSS。

### 19.3 report

`report.html_file` 控制 HTML 报告路径。命令行 `--report-file` 可以覆盖。

### 19.4 verification

`verification` 属于主动漏洞验证 Agent 配置。传统插件发现 finding 后，如果启用 `--verify`，会把 finding 入队给 `vuln_verify` 继续验证利用深度。

## 20. 和 Agent 模块的协作

`pass_scan` 与两个 Agent 模块协作：

| 模块 | 协作方式 |
| --- | --- |
| `vuln_verify` | 传统插件发现 finding 后，可交给主动验证 Agent 推进利用链 |
| `agent_pass_scan` | 作为逻辑漏洞 observer 插件接入调度，复用流量上下文和报告 |

传统插件提供技术漏洞 finding，`vuln_verify` 进一步确认深度；逻辑 Agent 则独立从流量中挖业务逻辑漏洞。三者共用报告体系。

## 21. 新插件扩展方法

新增插件建议遵循以下步骤：

1. 新建 `pass_scan/<plugin>/`。
2. 明确插件类型：普通扫描插件还是 observer-only。
3. 定义 `name`。
4. 实现 `interested(context)` 或 `observe(context)`。
5. 设计 `dedup_key(context)`。
6. 在 `check(context)` 中完成主动验证。
7. 使用统一 finding 结构输出。
8. 在 `scanner.py` 注册插件。
9. 在 `run.py` 添加命令行开关。
10. 在 `config.yaml` 添加插件配置。
11. 在 `reporter.py` 添加展示标签和证据字段。
12. 添加专项技术文档。

新插件设计时要先回答几个问题：

- 它的确认终点是什么？
- baseline 如何建立？
- 哪些响应差异能证明漏洞？
- 哪些情况必须降级为人工复核？
- 是否需要 OOB？
- 是否会写入 canary？
- 如何限制请求量？
- 如何避免同一入口重复扫描？

## 22. 总体方案讲解重点

`pass_scan` 的核心不是“堆 payload”，而是一个被动扫描工程框架：

1. **真实流量触发**  
   只扫描测试者已经访问到的业务入口。

2. **统一上下文**  
   所有插件共享 method、URL、content-type、参数、响应状态等标准化信息。

3. **异步插件队列**  
   重插件不会阻塞轻插件，也不会阻塞代理回调。

4. **单变量主动验证**  
   每次只改变一个参数，用 baseline 和 proof 证明结果。

5. **证据驱动输出**  
   finding 中保留 payload、请求、响应、差异和 technique。

6. **分层安全控制**  
   默认保守，深度扫描、Header/Cookie、写入 canary、OOB 都由配置控制。

7. **可被 Agent 接续**  
   传统 finding 可以继续交给 `vuln_verify`，业务上下文可以交给 `agent_pass_scan`。

## 23. 一句话总结

`pass_scan` 是 FlowLens 的传统漏洞检测底座。它把 mitmproxy 捕获到的真实流量转成统一扫描上下文，通过插件队列异步执行主动验证，再用结构化 finding 和 HTML 报告呈现证据。每个插件都有自己的确认终点和误报控制策略，整体上形成一个可扩展、可限速、证据优先的被动安全扫描框架。
