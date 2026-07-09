# vuln_verify 技术文档

本文档是一份方案说明型技术报告。它不按源码逐行解释，而是从实现者视角说明主动漏洞验证 Agent 是怎么设计、怎么规划验证动作、怎么执行 HTTP 请求、怎么使用提示词、怎么生成利用链，以及怎么控制安全边界。

## 1. 总体说明

`vuln_verify` 的定位可以这样概括：

`vuln_verify` 是 FlowLens 的主动漏洞验证 Agent。传统扫描插件发现漏洞后，通常只能给出一个“命中证据”，例如 SQL 报错、XSS 反射、SSRF OOB、文件读取特征等。但在真实安全评估里，我们还需要进一步回答：

- 这个漏洞是不是误报？
- 它能利用到什么深度？
- 有没有完整、可复现的利用链？
- payload 是什么？
- 哪些请求证明了结论？
- 验证过程中有没有破坏性动作？

所以我把 `vuln_verify` 设计成一个“LLM 规划 + 本地受控 HTTP 执行器 + 多轮观察反馈 + 结构化结论”的验证系统。它不是从零扫描目标，而是接收传统插件已经发现的 finding，在授权边界内继续推进到一个非破坏性的可利用终点。

一句话概括：

> 普通插件负责发现疑似漏洞，`vuln_verify` 负责把疑似漏洞推进成带 payload、请求包、响应包和利用链的验证结论。

## 2. 它和 agent_pass_scan 的区别

FlowLens 里有两个 Agent，容易混淆：

| 模块 | 输入 | 目标 | 典型动作 |
| --- | --- | --- | --- |
| `agent_pass_scan` | 被动流量上下文 | 发现业务逻辑漏洞 | 去认证、换认证、篡改业务字段 |
| `vuln_verify` | 已发现的传统漏洞 finding | 主动验证漏洞深度和利用链 | 变异 payload、尝试绕过、OOB、访问上传文件 |

`agent_pass_scan` 更像“业务逻辑漏洞发现器”，它先找问题；`vuln_verify` 更像“漏洞验证专家”，它基于已有发现继续问：这个 finding 能证明到什么程度？

## 3. 设计目标

我设计这个模块时有几个目标：

1. **非破坏性验证**  
   不做删除、修改真实业务数据、破坏可用性、写 webshell、反弹 shell、横向移动等行为。

2. **多轮推进**  
   不止复现一次基础 payload。如果基础 payload 不够，要根据响应差异继续尝试编码、闭合、绕过或切换验证技术。

3. **利用链输出**  
   结果里要有 exploit chain、payloads、successful request ids 和复现步骤，而不是只写“存在漏洞”。

4. **本地工具执行**  
   LLM 不能直接发网络请求，只能输出 JSON action，由本地执行器执行。

5. **强结构化结果**  
   输出状态、置信度、利用深度、影响、成功请求、验证请求列表，方便报告渲染和后续审计。

6. **安全可控**  
   本地执行器做方法白名单、危险 payload 拦截、PUT canary 限制、跨源敏感头隔离。

## 4. 整体架构

整体链路如下：

```text
传统扫描插件发现 finding
  -> PassiveScanner.handle_finding()
  -> VerificationQueue.enqueue()
  -> 验证 worker
  -> LLMVerificationAgent.verify()
  -> 构造系统提示词 + 漏洞专项提示词 + finding 证据
  -> LLM 输出 actions
  -> HttpExecutor 执行动作
  -> 把 observation 反馈给 LLM
  -> 多轮循环直到 final 或达到限制
  -> 生成 verification result
  -> 写 logs/verifications.jsonl
  -> 刷新 report.html 的验证标签页
```

架构可以分成五层：

| 层级 | 作用 |
| --- | --- |
| 队列层 | 接收 finding，去重，异步验证 |
| Agent 层 | 组织 prompt、多轮调用 LLM、控制轮次和请求数 |
| 提示词层 | 定义安全边界、动作格式、各漏洞验证路线 |
| 执行器层 | 把 JSON action 转成 HTTP 请求，并返回 observation |
| 结果层 | 校验 final，关联成功请求，写 JSONL 和报告 |

## 5. 输入：finding 是验证的起点

`vuln_verify` 不直接从原始流量扫描，它的输入是其他插件产出的 finding。finding 通常包含：

| 字段 | 说明 |
| --- | --- |
| `type` | 漏洞大类，例如 `sql_injection`、`xss`、`ssrf` |
| `method` | 漏洞子类型或检测技术 |
| `url` | 命中的 URL |
| `request_method` | 原始请求方法 |
| `param_place` | 参数位置，例如 query、form、json、cookie、header |
| `param_name` | 参数名 |
| `evidence` | 原插件的判定证据 |
| `proof.request` | 原始或验证请求包 |
| `proof.response` | 原始或验证响应包 |
| `extra_proofs` | 辅助证据，例如 OOB 交互、二次确认包 |

Agent 会对 finding 做脱敏和裁剪：

- 请求包中的 Cookie、Authorization、API Key 会脱敏后给模型看。
- 响应正文会截断，避免 prompt 过长。
- extra proofs 也会分别裁剪。

注意：模型看到的是脱敏证据，但本地执行器仍能基于原 finding 中的原始请求继承必要 Header 发包。这是为了兼顾安全和可复现性。

## 6. 队列层设计

`VerificationQueue` 负责异步化验证流程。它做几件事：

1. 读取 `verification` 配置。
2. 判断是否启用 `--verify` 或 `PASS_SCAN_VERIFY`。
3. 检查 LLM 是否配置完整。
4. 启动多个验证 worker。
5. 对 finding 做稳定 key 去重。
6. 跳过 fingerprint，因为指纹不是漏洞，不需要主动验证。
7. 验证完成后写入 `logs/verifications.jsonl` 并刷新报告。

为什么要做异步队列？

因为主动验证可能需要多轮 LLM 请求、多次 HTTP 发包、OOB 等待。如果直接阻塞扫描插件，会影响代理流量转发和常规扫描。所以它是独立 worker 异步消费。

### 6.1 finding 去重

验证 key 由漏洞位置和核心证据组成，例如：

- 漏洞类型。
- 方法。
- 请求方法。
- URL。
- 参数位置。
- 参数名。
- payload、marker、technique 等证据。

这样相同注入点不会被重复验证，避免 LLM 成本和目标请求量失控。

## 7. Agent 多轮决策模型

`LLMVerificationAgent` 的工作方式是典型的 observe-act loop：

```text
第 1 轮：
  输入 finding + 漏洞专项提示词
  LLM 输出 actions
  执行器发包
  返回 observations

第 2 轮：
  输入上一轮 observations
  LLM 判断是否继续绕过/换技术/结束
  再输出 actions 或 final

...

结束：
  LLM 输出 final
  系统校验 final 并生成结果
```

关键限制：

| 限制 | 作用 |
| --- | --- |
| `max_rounds` | 限制最大 LLM 轮次 |
| `max_requests_per_finding` | 限制每个 finding 最大发包数 |
| `prompt_chars` | 限制 prompt 最大字符数 |
| `request_timeout_seconds` | 限制单个 HTTP 请求时间 |
| `max_response_body_bytes` | 限制响应读取大小 |
| `observation_chars` | 限制反馈给模型的观察文本长度 |

如果达到最大轮次还没有 final，系统会保守输出 `needs_manual_review`，并保留已发请求证据。

## 8. 动作空间设计

我没有让 LLM 输出自然语言命令，而是规定它只能输出 JSON action。动作类型固定，执行器只认这些动作。

### 8.1 send_mutation

`send_mutation` 是最常用动作。它基于原始请求修改某个参数，并保留原始 Cookie/Header。

支持的位置：

- query
- form
- json
- cookie
- header
- body
- multipart

适用场景：

- SQL 注入继续尝试闭合和注释。
- XSS 根据上下文替换参数。
- 命令注入替换命令参数。
- SSRF 替换 URL 参数。
- 文件读取替换路径参数。
- JWT 替换 token。

这个动作的设计目的是让模型专注于“payload 应该是什么”，而不是操心如何重建完整 HTTP 请求。

### 8.2 send_request

`send_request` 用于模型需要完整控制方法、URL、Header、body 的情况。

适用场景：

- 访问上传后的文件 URL。
- 请求同源只读接口。
- 访问对象存储 canary URL。
- 构造与原始请求不同的验证链路。

Header 继承策略：

- 同源 URL 默认继承原始 Cookie/Authorization。
- 跨源 URL 不继承敏感认证头。
- 可以通过 `inherit_headers` 显式控制。

这个策略可以避免把用户 Cookie 泄漏到外部域名。

### 8.3 send_raw

`send_raw` 用于需要完全控制 HTTP 原始报文的场景，例如：

- XML/XXE 原始 body。
- 特殊 Header 注入。
- 非标准请求格式。
- 需要保持非常具体的报文结构。

执行器会把 raw packet 解析成 method、URL、headers、body，再走统一安全检查和发送流程。

### 8.4 send_oob_mutation

`send_oob_mutation` 用于需要带外确认的漏洞：

- 无回显命令执行。
- SSRF。
- XXE。
- 某些远程 key fetch 类 JWT 问题。

模型在 payload 中写 `{domain}` 占位符。执行器会：

1. 从 OOB 客户端申请唯一域名。
2. 把 `{domain}` 替换成真实 OOB 域名。
3. 发出请求。
4. 轮询 interactsh。
5. 把 DNS/HTTP 回连作为 observation 返回给 LLM。

这样模型不用管理 OOB 客户端，只需要说明“哪里需要触发回连”。

## 9. HTTP 执行器设计

`HttpExecutor` 是安全边界的核心。LLM 只能输出 action，真正发包必须经过执行器。

执行器负责：

- 从 finding 中恢复原始请求。
- 应用参数变异。
- 构造 multipart 请求。
- 继承或隔离 Header。
- 禁止自动跳转，保留 3xx 证据。
- 忽略上游证书校验，适配测试环境自签名证书。
- 不走系统代理，避免请求绕回本地代理形成回环。
- 对请求做安全检查。
- 发送请求并裁剪响应。
- 返回标准 observation。

### 9.1 原始请求恢复

如果 finding 里有 `proof.request`，执行器会从原始 HTTP 包恢复：

- method
- URL
- headers
- body

如果没有原始请求包，就用 finding 的 `url` 和 `request_method` 构造一个基础请求。

### 9.2 参数变异

不同参数位置有不同处理：

| 位置 | 处理方式 |
| --- | --- |
| query | 替换 URL 查询参数 |
| form | 替换 `application/x-www-form-urlencoded` body |
| json | 修改 JSON 顶层字段 |
| cookie | 替换 Cookie 键值 |
| header | 替换或新增 Header |
| body | 整体替换 body |
| multipart | 解析 multipart parts 后替换目标 part 或追加 part |

multipart 支持文件名、content type、body 和 canary 标记，主要用于文件上传验证。

### 9.3 响应处理

执行器返回 observation，包含：

- action id。
- 是否执行成功。
- 是否被安全策略阻断。
- 错误信息。
- payload。
- 目的。
- 绕过策略。
- method 和 URL。
- 状态码。
- 耗时。
- 脱敏后的请求包。
- 响应包。
- 响应正文摘要。
- OOB 命中信息。

这些 observation 会反馈给 LLM，作为下一轮决策依据，也会写入最终验证结果。

## 10. 安全边界设计

这是整个模块最重要的部分。因为 LLM 会建议发包，所以必须把危险动作挡在执行器层。

### 10.1 系统提示词里的安全边界

系统提示词明确要求：

- 只能通过 JSON action 发包。
- 不能请求执行 shell、本地文件读取或外部工具。
- 不破坏系统或业务状态。
- SQL 只允许只读验证。
- 命令执行只允许只读命令或 OOB 探测。
- 上传和对象存储只允许随机 canary。
- 指纹识别不做主动验证。

提示词是第一层约束，但不是唯一约束。

### 10.2 执行器安全检查

执行器还会做硬拦截：

| 检查 | 说明 |
| --- | --- |
| HTTP 方法白名单 | 默认只允许配置里的方法 |
| PUT canary 限制 | PUT 只能写带 canary 标记的验证对象 |
| 破坏性 SQL 拦截 | 阻断 INSERT、UPDATE、DELETE、DROP、ALTER、TRUNCATE 等 |
| 破坏性命令拦截 | 阻断 shutdown、reboot、rm -rf、mkfs、dd 等 |
| 敏感头跨源隔离 | 跨源请求不继承 Cookie/Authorization |
| 请求数限制 | 每个 finding 最大发包数 |
| 响应大小限制 | 避免读取大量敏感数据或内存膨胀 |

我在面试里会强调：安全不能只靠 prompt。prompt 会告诉模型不要做危险事，但真正的安全边界必须由本地执行器强制实现。

### 10.3 canary 写入原则

文件上传和对象存储验证允许“写入”，但只允许写随机 canary：

- 文件名或路径必须带 `pass-scan`、`passscan`、`canary`、`verify` 等标记。
- action 必须声明 `canary=true`。
- 禁止覆盖真实资源。
- 只写 harmless 内容。

这能在验证写权限的同时降低业务影响。

## 11. 提示词体系

`vuln_verify` 的提示词分三类：

| 提示词 | 作用 |
| --- | --- |
| 系统提示词 | 安全红线、动作格式、final 格式、通用要求 |
| 漏洞专项提示词 | 每类漏洞的验证路线、绕过路线、确认终点 |
| 观察反馈提示词 | 把上一轮 HTTP 结果给模型，要求继续或 final |

### 11.1 系统提示词

系统提示词定义了动作协议。模型每轮只能输出两种结构之一：

1. `actions` 非空，`final` 为 null：继续发包。
2. `actions` 为空，`final` 非空：结束验证。

它还要求：

- confirmed 或 likely 必须填写 `successful_request_ids`。
- payloads 必须写完整 payload。
- 如果基础 payload 不到终点，必须尝试绕过或切换技术。
- 输出必须是严格 JSON。
- 反斜杠必须合法转义。

这让模型输出可以被程序可靠解析。

### 11.2 漏洞专项提示词

每类漏洞都有自己的验证策略：

| 漏洞 | 验证目标 |
| --- | --- |
| SQL 注入 | 只读读取 DBMS、当前库、schema 或少量样例 |
| XSS | 证明 JS 能在目标上下文执行 |
| 命令注入 | 只读命令回显或 OOB 确认 |
| SSRF | 证明服务端可访问受控 URL 或只读内网响应 |
| XXE | 证明外部实体解析、OOB 或非敏感文件读取 |
| 路径遍历 | 读取非敏感系统文件特征或应用只读片段 |
| SSTI | 确认表达式执行、对象访问或只读命令边界 |
| 开放重定向/CRLF | 构造可控 Location/Refresh/Header |
| 文件上传 | 上传 canary、访问 canary、验证解析能力 |
| JWT | 证明 token 可伪造、claim 可篡改或权限变化 |
| 敏感信息泄漏 | 确认泄露内容真实、归属和权限范围 |
| 对象存储 | 确认桶存在、匿名列举、读取或 canary 写入 |

每个专项提示词都包含五类内容：

1. 目标：要验证到什么深度。
2. 基础路线：从原始证据怎么推进。
3. 绕过路线：基础 payload 不成功时怎么换技术。
4. 终点：什么证据可以 confirmed 或 likely。
5. 禁止动作：哪些事情不能做。

这种“按漏洞类型给策略”的方式，比让模型泛泛地思考更稳定。

### 11.3 观察反馈提示词

每轮发包后，系统会把 observation 压缩成 JSON 给模型。内容包括：

- action id。
- 状态码。
- 耗时。
- 是否 OOB 命中。
- payload。
- 目的。
- 绕过策略。
- 响应摘要。

观察反馈提示词会提醒模型：

- 如果还没到漏洞终点，不要停在基础 payload。
- 可以尝试绕过、编码、上下文闭合或切换验证技术。
- 如果已经到终点，就输出 final。

## 12. 各漏洞类型的验证思路

### 12.1 SQL 注入

验证目标不是“再打一次报错 payload”，而是尽量推进到只读数据读取：

1. 复现原始 payload。
2. 判断闭合方式：数字、单引号、双引号、括号。
3. 根据响应选择 error、boolean、union、time 路线。
4. 只读读取 DBMS、当前库、当前用户或版本。
5. 能继续时枚举库名、表名、字段名。
6. 最多读取少量样例数据。

如果基础 payload 受阻，尝试：

- 注释变体。
- 大小写混淆。
- 内联注释。
- URL 编码和双编码。
- 空白替代。
- 函数替代。
- UNION 列数探测。
- 布尔/时间路线切换。

禁止所有写操作和破坏性 SQL。

### 12.2 XSS

验证目标是证明完整 JavaScript payload 能在目标页面上下文执行。

流程：

1. 判断参数落点。
2. 判断上下文：HTML 文本、属性、JS 字符串、URL、DOM sink。
3. 构造闭合。
4. 使用 benign marker。
5. 记录触发 URL 和触发条件。

如果被过滤，尝试：

- 标签体 payload。
- 属性事件。
- SVG/IMG/onerror。
- `javascript:`。
- HTML 实体。
- 大小写。
- 编码组合。

禁止窃取 Cookie 或外传真实凭据。

### 12.3 命令注入

验证目标是确认命令执行边界，但只允许只读命令：

- `whoami`
- `id`
- `uname`
- `pwd`
- 少量 `env`

流程：

1. 复现原始命中。
2. 判断 Linux/Windows。
3. 优先尝试回显命令。
4. 无回显时使用时间或 OOB。
5. 记录命令分隔符和 payload。

绕过方向：

- `;`
- `&&`
- `||`
- `|`
- 换行。
- 反引号。
- `$()`
- `${IFS}`
- tab。
- URL 编码。

禁止写文件、下载执行、反弹 shell、删除或修改系统。

### 12.4 SSRF

验证目标是证明服务端会访问受控 URL，并尽量确认协议和来源信息。

流程：

1. 使用 OOB URL 复现。
2. 记录来源 IP 和 Header。
3. 尝试协议、URL 形态和白名单绕过。
4. 必要时访问非敏感只读内网端点。

绕过方向：

- http/https。
- 协议相对 URL。
- 裸 host。
- userinfo。
- fragment/path 白名单绕过。
- scheme 大小写。
- URL 编码。
- 重定向链。
- IPv4 整数、八进制、十六进制。
- localhost 变体。

禁止打爆端口、执行内网状态变更、读取云凭据内容。

### 12.5 XXE

验证目标是确认 XML 解析器处理了外部实体。

路线：

1. 判断 XML 注入点。
2. 尝试普通外部实体。
3. 尝试参数实体和外部 DTD。
4. OOB 优先确认。
5. 无 OOB 时尝试非敏感本地文件片段。

禁止读取私钥、云凭据、数据库配置和业务敏感文件。

### 12.6 路径遍历 / 任意文件读取

验证目标是确认可读取非敏感系统文件或应用只读文件片段。

路线：

1. 复现原始读取。
2. 判断系统类型。
3. 调整 `../` 层级。
4. 尝试编码和路径变体。
5. 读取非敏感文件特征。

绕过方向：

- `../`
- `....//`
- URL 单/双编码。
- 反斜杠。
- 绝对路径。
- `file://`
- 空字节兼容形式。
- Linux/Windows 路径差异。

禁止读取私钥、云凭据、数据库配置和用户隐私文件全文。

### 12.7 SSTI

验证目标是从模板表达式执行推进到对象访问或只读命令边界。

路线：

1. 算术表达式确认。
2. 判断模板家族。
3. 字符串或对象访问。
4. 必要时只读命令边界确认。

绕过方向：

- 不同模板语法。
- 表达式分隔符变化。
- 引号过滤绕过。
- 属性访问变体。
- 对象链枚举。
- 编码和字符串拼接。

禁止写文件、下载执行、反弹 shell、修改系统。

### 12.8 开放重定向 / CRLF

验证目标是生成可复现的跳转或响应头注入证据。

路线：

1. 复现 Location、Refresh 或 Header 命中。
2. 判断 sink。
3. 构造 benign 外部跳转或 marker header。
4. 保留 3xx 响应，不自动跳转。

绕过方向：

- 协议相对 URL。
- userinfo。
- scheme 大小写。
- URL 编码和双编码。
- CRLF 编码。
- 白名单前缀/后缀绕过。

### 12.9 文件上传

验证目标是确认 canary 文件能否上传、访问、解析或执行。

路线：

1. 复现上传点。
2. 上传 harmless canary。
3. 访问返回的 URL 或 Location。
4. 尝试扩展名、Content-Type、图片马、解析后缀、`.htaccess` canary 链。
5. 判断是否只是上传成功，还是达到脚本执行。

动作要求：

- multipart 上传优先用 `send_mutation`。
- 设置 filename、content_type、body。
- `canary=true`。
- 上传后用 `send_request` 访问同源文件 URL。

禁止上传 webshell、持久化后门、覆盖真实文件。

### 12.10 JWT

验证目标是确认 token 是否可伪造、claim 是否可篡改、权限是否变化。

路线：

1. 解析 token header 和 payload。
2. 判断 alg、kid、jwk、jku、claim 风险。
3. 构造只读验证 token。
4. 调用只读接口确认服务端是否接受。

验证方向：

- `alg=none`。
- 签名未校验。
- 弱 HMAC。
- kid/jku/jwk 头。
- claim 只读篡改。
- 时间 claim。
- iss/aud 校验缺失。

禁止执行写操作或用提升后的 token 修改业务数据。

### 12.11 敏感信息泄漏

验证目标是确认泄露内容的真实性和影响范围。

路线：

1. 复现泄露响应。
2. 判断信息类型。
3. 做格式、归属或只读可用性验证。
4. 排除 SPA 兜底页和假阳性模板。

禁止消耗额度、修改远程资源、调用破坏性 API 或泄露完整密钥。

### 12.12 对象存储

验证目标是确认桶存在、匿名列举、匿名读取或 canary 写能力。

路线：

1. 复现桶 URL。
2. 判断 provider。
3. 匿名 HEAD/GET/List。
4. 只写随机 canary object。
5. 访问 canary。
6. 给出清理建议。

PUT 只能用于随机 canary key，并且必须包含 canary 标记。

## 13. final 结果设计

LLM 最终必须输出 final。系统会把 final 规范化成验证结果。

关键字段：

| 字段 | 说明 |
| --- | --- |
| `status` | confirmed、likely、false_positive、needs_manual_review |
| `confidence` | high、medium、low |
| `exploitability` | 利用类型，例如 data_read、code_execution、ssrf_oob |
| `depth` | 达到的利用深度 |
| `endpoint` | 验证终点 |
| `summary` | 简短结论 |
| `impact` | 安全影响 |
| `safety_notes` | 安全边界说明 |
| `exploit_chain` | 利用链步骤 |
| `payloads` | 每一步 payload 和结果 |
| `successful_request_ids` | 支撑结论的 action id |
| `reproduction` | 复现步骤 |

系统还会附加：

- source finding 摘要。
- 所有请求 observation。
- 成功请求详情。
- 请求数。
- 使用的模型。
- 校验警告。

## 14. confirmed/likely 的结果校验

我没有完全相信 LLM 的 final。系统会做一个关键校验：

如果 status 是 `confirmed` 或 `likely`，必须提供 `successful_request_ids`，并且这些 id 必须能在实际执行过的 observations 中找到。

如果缺失，系统会：

1. 加入 validation warning。
2. 把结果降级为 `needs_manual_review`。
3. 把 confidence 降为 `low`。
4. 在 summary 中说明降级原因。

这样可以避免模型凭空说“已确认”，但没有对应成功请求证据。

## 15. JSON 修复机制

LLM 偶尔会输出不合法 JSON，尤其是 payload 中包含反斜杠时。模块做了两层处理：

1. 尝试从 Markdown 代码块或文本中提取 JSON 对象。
2. 自动修复常见非法反斜杠，例如 `\.`、`\p`、`C:\path`。
3. 如果仍失败，会追加 JSON repair prompt，让模型只输出修复后的 JSON。

这个机制是为了提高 Agent 的工程稳定性。安全扫描里 payload 经常包含反斜杠、Windows 路径、正则或编码字符，如果没有修复层，很容易因为 JSON 解析失败中断验证。

## 16. OOB 设计

OOB 主要用于无回显漏洞，例如：

- SSRF。
- XXE。
- 无回显命令执行。
- 远程 key fetch。

OOB 客户端复用命令注入插件里的 interactsh 配置。流程：

1. 根据配置注册 interactsh client。
2. 每次 OOB action 申请唯一域名。
3. 把 `{domain}` 替换进 payload。
4. 发包。
5. 在 `oob_wait_seconds` 时间窗口内轮询。
6. 如果命中，把协议、remote address、timestamp、raw request 等写入 observation。

OOB 命中会把 observation 的 `ok` 标记为 true，并把 OOB 交互作为响应证据交给模型。

## 17. 报告输出

验证结果写入：

```text
logs/verifications.jsonl
```

报告会展示：

- 原始 finding。
- 验证状态。
- 利用深度。
- exploit chain。
- payloads。
- successful requests。
- 请求和响应证据。
- 安全说明。

这让报告从“扫描器发现了某个漏洞”升级为“这个漏洞被验证到了什么程度，哪些包能复现”。

## 18. 配置项说明

常用配置在 `config.yaml` 的 `verification` 下：

| 配置项 | 说明 |
| --- | --- |
| `enabled` | 配置层启用主动验证，命令行 `--verify` 也可启用 |
| `worker_count` | 验证 worker 数 |
| `queue_size` | 验证队列大小 |
| `output_file` | 验证结果 JSONL 输出路径 |
| `env_file` | LLM 配置文件 |
| `llm_protocol` | LLM 协议 |
| `max_rounds` | 每个 finding 最大 LLM 轮次 |
| `max_requests_per_finding` | 每个 finding 最大发包数 |
| `request_timeout_seconds` | HTTP 请求超时 |
| `llm_timeout_seconds` | LLM 请求超时 |
| `llm_max_tokens` | LLM 输出 token 限制 |
| `oob_wait_seconds` | OOB 等待时间 |
| `max_response_body_bytes` | 单次响应最大读取字节 |
| `observation_chars` | observation 文本最大字符数 |
| `prompt_chars` | prompt 最大字符数 |
| `allowed_methods` | 验证允许的 HTTP 方法 |

LLM 相关配置可以放在 `.env`：

```text
LLM_PROTOCOL=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL_ID=...
LLM_API_KEY=...
```

## 19. 典型验证过程示例

### 19.1 SQL 注入示例

```text
输入 finding：
  参数 id 存在布尔盲注差异

第 1 轮：
  LLM 请求发送闭合 payload 验证 true/false 差异
  执行器返回响应长度和状态差异

第 2 轮：
  LLM 尝试只读读取数据库版本
  执行器返回版本字段或差异

final：
  status=confirmed
  exploitability=data_read
  successful_request_ids=[step-1, step-2]
  payloads 写出完整 payload
```

### 19.2 SSRF 示例

```text
输入 finding：
  参数 url 疑似 SSRF

第 1 轮：
  LLM 使用 send_oob_mutation，把 url 改成 http://{domain}/verify
  执行器分配 interactsh 域名并发包

观察：
  OOB 收到 DNS/HTTP 回连

final：
  status=confirmed
  exploitability=ssrf_oob
  successful_request_ids=[step-oob-1]
```

### 19.3 文件上传示例

```text
输入 finding：
  multipart 上传点可上传文件

第 1 轮：
  LLM 使用 send_mutation 替换文件 part，上传 canary txt

第 2 轮：
  LLM 根据响应中的 URL 使用 send_request 访问 canary

final：
  如果 canary 可访问，confirmed 为 upload readable
  如果脚本 canary 被执行，confirmed 为 upload_exec
```

## 20. 误报控制

这个模块通过以下方式控制误报：

1. 不从零扫描，只验证已有 finding。
2. 每类漏洞有明确 confirmed 终点。
3. LLM 必须引用 successful request id。
4. 执行器返回真实请求响应，不让模型臆测。
5. final 会被程序校验，不满足证据要求会降级。
6. false_positive 和 needs_manual_review 是正常输出状态，不强行确认。

对传统漏洞来说，`vuln_verify` 的价值不是“发现更多”，而是“确认更准、证据更完整”。

## 21. 安全和局限

安全边界：

- 默认关闭，只有 `--verify` 或配置启用才运行。
- LLM 不能直接发包。
- 执行器有方法白名单和破坏性模式阻断。
- PUT 写入必须是 canary。
- 跨源不继承敏感认证头。
- 响应读取大小有限制。

局限：

- LLM 可能选择不够好的验证路线，所以需要 max rounds 和人工复核状态。
- 对复杂业务链路，单个 finding 的原始请求可能不足以完成利用链。
- OOB 依赖 interactsh 可用和目标能出网。
- 对需要真实业务前置状态的漏洞，可能只能到 likely 或 needs_manual_review。
- Prompt 能约束行为，但真正的安全仍依赖执行器和授权环境。

## 22. 方案讲解重点

这里使用 LLM 的原因是：

传统插件能发现一个点，但验证深度需要策略选择：SQL 用 error 还是 boolean，XSS 是属性上下文还是 JS 上下文，命令注入是回显还是 OOB，SSRF 是否需要 URL 绕过。LLM 擅长根据响应观察选择下一步，所以我让它做验证规划。

避免 LLM 失控的关键设计是：

LLM 只输出 JSON action，不能直接执行网络或系统命令；执行器做方法白名单、危险语句阻断、PUT canary 限制和跨源敏感头隔离；confirmed/likely 还必须引用真实执行过的 action id，否则结果会降级。

这个模块的工程难点包括：

- 第一是动作协议设计，既要足够表达各种漏洞验证，又不能给模型过大自由度。
- 第二是安全执行器，必须把 prompt 约束变成硬约束。
- 第三是多轮观察压缩，要把 HTTP 结果反馈给模型但不能塞爆上下文。
- 第四是结果校验，不能让模型没有证据就确认漏洞。
- 第五是 OOB 编排，要把唯一域名、发包、轮询和证据关联起来。

## 23. 一句话总结

`vuln_verify` 的本质是一个受控的漏洞验证 Agent：LLM 负责根据 finding 和响应观察规划下一步，HTTP 执行器负责安全地落地请求，结果层负责把成功请求、payload 和利用链结构化。它把传统扫描器的“命中点”提升成可复现、可审计、非破坏性的验证报告。
