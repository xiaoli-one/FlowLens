# agent_pass_scan 技术文档

本文档是一份方案说明型技术报告。它不按源码逐行解释，而是站在实现者的角度，说明业务逻辑漏洞 Agent 是怎么设计、怎么判断、怎么验证、怎么让 LLM 参与以及怎么控制误报和风险。

## 1. 总体说明

这个模块解决的问题可以这样概括：

`agent_pass_scan` 是 FlowLens 里的业务逻辑漏洞检测 Agent。传统被动扫描插件擅长检测 SQL 注入、XSS、SSRF 这类“单请求、单参数、强 payload 特征”的漏洞，但业务逻辑漏洞往往不是一个 payload 能证明的，它需要理解账号身份、资源归属、租户边界、流程状态和历史请求上下文。所以我把这个模块设计成一个“被动流量索引 + 候选风险生成 + 主动差分验证 + LLM 语义裁决”的混合系统。

它的核心思想不是让大模型直接扫所有流量，而是把确定性的工程逻辑放在前面：

1. 先把被动流量结构化进 SQLite。
2. 把接口、身份、参数、资源 ID、租户字段、角色字段、流程字段抽出来。
3. 用规则化 detector 生成少量高价值候选。
4. 对候选做受控的主动差分验证，比如去认证、换认证、篡改敏感字段。
5. 把候选、历史上下文、验证结果和专项判断标准一起交给 LLM。
6. 让 LLM 只做最后的业务语义判断，输出 confirmed、likely、needs_manual_review 或 false_positive。

这样做的好处是：规则负责可解释、可控和低成本筛选，LLM 负责业务语义理解和证据归纳，二者各做擅长的部分。

## 2. 为什么业务逻辑漏洞不能用传统插件思路

传统漏洞通常具备明确的技术信号：

| 漏洞类型 | 典型信号 |
| --- | --- |
| SQL 注入 | 报错、布尔差异、时间延迟、UNION 数据 |
| XSS | payload 被反射到可执行上下文 |
| SSRF | 带外回连 |
| 文件读取 | 响应中出现系统文件特征 |

业务逻辑漏洞不一样。它的关键不是 payload 是否命中，而是“系统是否错误地接受了一个不应该被接受的业务动作”。例如：

- 去掉 Cookie 后仍能访问订单详情。
- 用户 B 替换认证后仍能访问用户 A 的文件。
- 普通用户能访问管理接口。
- 改 `tenant_id` 后能看到其他租户数据。
- 把 `status=pending` 改成 `approved` 后流程被推进。
- 客户端提交 `role=admin` 或 `price=1` 后服务端采纳。

这些问题都必须回答几个上下文问题：

- 当前请求是谁发的？
- 这个资源属于谁？
- 另一个身份是谁？
- 响应内容是原对象，还是当前身份自己的对象？
- 这个接口是读操作还是写操作？
- 字段是查询筛选，还是服务端信任的业务字段？
- 状态变化是否真的生效？

所以我没有把它做成简单 payload 插件，而是做成一个带记忆和差分验证能力的 Agent。

## 3. 整体架构

`agent_pass_scan` 作为 FlowLens 的一个扫描插件接入，但它是 observer-only 模式。也就是说，它观察每条被动流量，持续建设上下文，并在合适的时机生成分析任务。

整体链路如下：

```text
被动 HTTP 流量
  -> 统一 ScanContext
  -> LogicAgentScanner.observe()
  -> FlowStore 写入 SQLite
  -> 判断是否敏感、是否需要重新分析
  -> 生成 LogicTask
  -> ScanQueue 后台 worker
  -> 加载 endpoint bundle
  -> 多个 detector 生成候选风险
  -> LogicHttpExecutor 主动差分验证
  -> LLM 根据候选 + 验证结果 + 专项提示词裁决
  -> 生成逻辑漏洞 finding
  -> 写 logs/logic_vulns.jsonl 和 report.html
```

我会把这个系统拆成四层讲：

| 层级 | 作用 | 设计重点 |
| --- | --- | --- |
| 流量记忆层 | 把请求、身份、资源、参数持久化 | 业务逻辑需要跨请求、跨账号比较 |
| 候选生成层 | 根据启发式生成有限候选 | 降低 LLM 成本和误报 |
| 主动验证层 | 去认证、换认证、篡改参数后重放 | 用差分证据代替猜测 |
| LLM 裁决层 | 根据业务语义判断漏洞状态 | 让模型做“归属/权限/流程”判断 |

## 4. 入口和启用方式

该模块默认关闭，只有以下情况才启用：

- 运行 `python3 run.py --logic`：常规扫描插件继续运行，同时额外启用逻辑漏洞 Agent。
- 运行 `python3 run.py --only-logic`：只运行逻辑漏洞 Agent，不跑其他漏洞插件。
- 设置环境变量 `PASS_SCAN_ENABLE_LOGIC=1`。

启用后，它会产生两个主要输出：

| 输出 | 作用 |
| --- | --- |
| `logs/logic_pass_scan.db` | SQLite 流量索引和候选状态 |
| `logs/logic_vulns.jsonl` | 逻辑漏洞 finding |

报告层会把逻辑漏洞渲染到 `report.html` 的独立标签页。

如果 LLM 配置不完整，模块仍会继续把流量写入 SQLite 索引，但不会进入 Agent 判断和主动差分验证。这是一个有意设计的降级路径：即使暂时没有模型，也能先积累业务流量上下文，后续补齐模型配置后再进行分析。

## 5. 智能体的设计原则

这个 Agent 的设计不是“让模型自己点鼠标或随意发包”，而是一个受控智能体：

1. 模型不直接访问网络。
2. 模型看不到无限上下文，只看经过裁剪的候选包、历史摘要和验证观察。
3. 模型不能随便决定扫描范围，候选由 detector 产生。
4. 主动验证动作由本地执行器按配置执行。
5. 写方法是否允许重放由 `active_verification_methods` 控制。
6. 最终结论必须落在固定状态集合里。
7. confirmed 必须有闭环证据。

这里需要强调，所谓的“Agent”并不是一个黑盒大模型，而是一个有限状态、有限动作、强约束输入输出的判断器。它的自由度被工程系统框住了，这样才能在安全扫描场景里可控地使用 LLM。

## 6. 数据建模：先把流量变成业务知识

业务逻辑漏洞的第一步是把 HTTP 流量变成可比较的业务对象。这个模块会把每条流量拆成以下几类信息：

| 信息 | 用途 |
| --- | --- |
| endpoint | 按 host、method、normalized_path 聚合接口 |
| identity | 按认证材料生成认证指纹 |
| parameters | 保存 query/form/json/cookie/header 中的参数摘要 |
| resource_refs | 提取资源 ID、租户字段、owner 字段、角色字段、状态字段等 |
| flow | 保存请求响应摘要和原始证明材料 |
| candidate state | 记录某个候选是否分析过，避免重复消耗 |
| logic finding | 保存最终逻辑漏洞结论 |

### 6.1 接口归一化

业务接口通常包含动态 ID，例如：

```text
/api/orders/12345
/api/orders/67890
```

如果直接按完整 path 聚合，会把同一个接口拆成多个接口。这里会把明显的数字、UUID、长 hash 替换成占位符：

```text
/api/orders/{id}
/api/files/{uuid}
/api/sessions/{hash}
```

这样同一个接口的多次访问可以聚合到一个 endpoint 下，后续才能比较不同账号访问同一接口的差异。

### 6.2 身份指纹

业务逻辑漏洞必须知道请求来自哪个身份。模块会从以下认证材料里提取身份特征：

- `Authorization`
- `Cookie`
- `X-API-Key`
- `X-Auth-Token`
- `X-CSRF-Token`

这些材料不会直接作为明文身份 ID 使用，而是组合后生成稳定的 `auth_fingerprint`。如果没有任何认证材料，就标记为 `anonymous`。

这样可以做到：

- 识别同一 host 下出现了几个不同登录态。
- 给水平越权和租户隔离检测提供“另一个身份”。
- 判断一个接口是否匿名可访问。
- 在报告里引用身份指纹而不泄漏真实 Cookie。

### 6.3 资源引用抽取

业务漏洞检测的核心是资源边界。模块会从 path、query 和参数中抽取资源引用，并给字段打语义标签。

| 语义类型 | 典型字段 |
| --- | --- |
| resource_id | `id`、`order_id`、`file_id`、`project_id` |
| owner | `owner_id`、`user_id`、`account_id`、`customer_id` |
| tenant | `tenant_id`、`org_id`、`company_id`、`workspace_id` |
| role | `role`、`permission`、`is_admin`、`scope` |
| workflow_state | `status`、`state`、`approved`、`published`、`paid` |
| business_value | `price`、`amount`、`discount`、`quota`、`balance` |

这些语义标签决定后续由哪个 detector 生成候选。例如出现 `tenant_id` 更适合租户隔离检测，出现 `status` 更适合流程绕过检测，出现 `role` 更适合敏感字段绑定检测。

### 6.4 敏感接口筛选

Agent 不会分析所有流量。它会优先分析具备以下特征的接口：

- 方法是 `POST`、`PUT`、`PATCH`、`DELETE`。
- path 里出现管理、订单、支付、审批、导出等敏感动作词。
- 参数名具备资源、租户、角色、流程、金额等语义。
- path 中包含动态 ID、UUID 或 hash。

这一步的目的是把 LLM 调用集中在“可能有业务意义”的接口上。

### 6.5 分析签名和重复控制

同一个 endpoint 可能不断有新流量进入，但不是每一条都值得重新分析。模块会根据 endpoint 的聚合统计生成分析签名：

- 当前流量量级。
- 身份数量。
- 资源引用数量。
- 成功响应数量。

当签名没有变化时，不重新入队；当出现新身份、新资源或成功样本增长时，再触发新一轮分析。这样可以避免每条请求都调用 LLM。

## 7. Endpoint Bundle：给 detector 和 LLM 的上下文包

当某个 endpoint 需要分析时，系统会加载一个 endpoint bundle。它不是简单的一条请求，而是一组上下文：

| 内容 | 说明 |
| --- | --- |
| endpoint | host、method、normalized_path、访问次数 |
| flows | 当前 endpoint 的最近若干条流量 |
| identity_flows | 同 host 下不同身份的代表流量 |
| stats | 流量数、身份数、资源数、成功数 |
| identity_memory | 身份和资源的历史摘要 |

`identity_memory` 是业务逻辑 Agent 的关键。它让 LLM 能看到类似这样的背景：

- 身份 A 访问过哪些接口。
- 身份 B 访问过哪些接口。
- 不同身份出现过哪些资源 ID。
- 某个资源值出现在哪些身份下。
- 某个身份历史上更像普通用户还是管理员。

这对垂直越权、IDOR 和租户隔离非常重要。否则模型只能看到一个孤立请求，很难判断角色和归属。

## 8. 候选生成：六类 detector

候选生成层有一个统一思路：先用确定性启发式发现“值得验证的问题”，然后用统一的候选结构表达出来。

候选里会包含：

- 漏洞类型。
- 风险标题。
- 源请求。
- 资源字段。
- 相关身份请求。
- 初始证据。
- 推荐验证方式。
- 专项 detector prompt。

目前默认有六类 detector：

| Detector | 漏洞类型 | 核心问题 |
| --- | --- | --- |
| UnauthorizedDetector | 未授权访问 | 去掉认证后还能不能访问原资源 |
| IDORDetector | 水平越权/IDOR | 用户 B 能不能访问用户 A 的资源 ID |
| TenantIsolationDetector | 租户隔离 | 其他租户身份能不能访问当前租户资源 |
| VerticalAuthzDetector | 垂直越权 | 普通身份能不能访问管理/审批/权限接口 |
| WorkflowBypassDetector | 流程绕过 | 客户端能不能直接推进状态字段 |
| MassAssignmentDetector | 敏感字段绑定 | 服务端是否信任客户端提交的敏感字段 |

### 8.1 未授权访问检测

未授权访问检测的候选条件：

- 原始请求带认证信息。
- 原始响应是成功状态。
- 请求包含资源引用、业务参数，或接口路径看起来敏感。
- 当前方法允许主动验证。

验证方式是 `strip_auth`：删除 Cookie、Authorization、API Key 等认证信息后重放原请求。

判断重点不是“去认证后是否 200”，而是：

- 响应是否仍然包含原登录态下的敏感对象。
- 是否不是登录页、公开模板或空数据。
- 对写方法，是否有明确成功标志或后续状态变化。

典型 confirmed 证据链：

```text
认证用户访问订单详情 -> 响应里有订单号和金额
去除认证后重放同一 URL -> 仍返回同一订单号和金额
=> 未授权访问 confirmed
```

### 8.2 水平越权/IDOR 检测

IDOR 检测的候选条件：

- 同一个接口出现多个不同认证身份。
- 源请求中存在资源 ID、owner ID、path ID、UUID 或 hash。
- 原始响应成功。
- 存在可用于替换认证的其他身份流量。

验证方式是 `swap_auth`：保留用户 A 的 URL、path ID、query/body 资源参数，但把认证头替换成用户 B 的认证材料。

判断重点：

- 用户 B 访问后拿到的是不是用户 A 的原资源。
- 响应中的 owner/user/account/customer 是否仍指向 A。
- 订单号、文件名、金额、手机号、邮箱等关键字段是否和 A 的基线一致。
- 如果返回的是 B 自己的对象，不能算漏洞。

典型 confirmed 证据链：

```text
A 请求 /api/orders/1001 -> 返回 order_id=1001, owner=A
B 的 Cookie 来源包存在
用 B Cookie 重放 /api/orders/1001 -> 仍返回 order_id=1001, owner=A
=> IDOR confirmed
```

### 8.3 租户隔离检测

租户隔离检测专门关注多租户边界字段：

- `tenant`
- `org`
- `company`
- `workspace`
- `department`
- `dept`

候选条件：

- 请求中存在租户语义字段。
- 同一 host 下存在多个认证身份。
- 原始响应成功。

验证方式也是 `swap_auth`，但判断目标不是个人资源，而是租户边界是否被跨过。

判断重点：

- 替换身份后是否仍能看到原租户 ID、原租户名称或原租户成员数据。
- 两个身份是否可能本来就在同一租户或共享工作区。
- 写操作是否作用于原租户资源。

典型 confirmed 证据链：

```text
A 属于 tenant=101，请求租户成员列表
B 的认证来源包存在
用 B 认证访问 A 的 tenant=101 成员列表
响应仍包含 tenant=101 和成员数据
=> 租户隔离漏洞 confirmed
```

### 8.4 垂直越权检测

垂直越权关注的是角色和功能权限，而不是资源归属。候选生成会先看接口路径是否有高权限特征：

- `admin`
- `manage`
- `permission`
- `role`
- `rbac`
- `acl`
- `audit`
- `approve`
- `config`
- `settings`
- `system`
- `console`
- `dashboard`
- `users`

如果接口看起来像管理、审批、权限或配置类功能，并且成功响应，就生成候选。

验证方式分两种：

- 如果有其他身份，使用 `swap_auth` 尝试低权限身份访问高权限接口。
- 如果没有其他身份，就先做 `passive_only`，交给 LLM 根据上下文判断是否需要人工复核。

判断重点：

- 当前或替换身份是否有低权限证据。
- 响应是否包含高权限数据，比如用户列表、角色配置、审计日志、系统配置。
- 写方法是否产生高权限动作，比如禁用用户、审批通过、角色变更。
- 如果当前账号本来就是管理员，不算漏洞。

垂直越权是最依赖上下文的一类，因此这里特别依赖 `identity_memory`。

### 8.5 流程绕过检测

流程绕过关注客户端是否能提交或篡改流程状态字段：

- `status`
- `state`
- `step`
- `stage`
- `approved`
- `review`
- `audit`
- `published`
- `paid`
- `enabled`
- `verified`
- `deleted`

候选条件：

- 请求参数或资源引用中存在流程语义字段。
- 原始响应成功。
- 当前方法允许主动验证。

验证方式是 `mutate_param`：把状态字段改成目标状态后重放。

mutation 值会根据字段名选择，例如：

| 字段语义 | 常见变异值 |
| --- | --- |
| 支付 | `paid`、`completed`、`success`、`true`、`1` |
| 发布 | `published`、`enabled`、`true`、`1` |
| 审批 | `approved`、`passed`、`verified`、`true`、`1` |
| 启停 | `enabled`、`active`、`false`、`0`、`true`、`1` |
| 删除 | `deleted`、`true`、`1` |

判断重点：

- 服务端是否真的接受了新状态。
- 响应或后续流量是否显示流程被推进。
- 字段是否只是查询筛选或前端缓存。
- 当前接口是否本来就是合法状态流转接口。

这类检测默认可能重放写方法，因此必须在授权测试环境中使用。

### 8.6 敏感字段绑定 / Mass Assignment 检测

Mass Assignment 关注服务端是否信任客户端提交的敏感字段：

- 角色和权限：`role`、`permission`、`is_admin`、`scope`
- 租户：`tenant_id`、`org_id`
- 归属：`owner_id`、`user_id`、`account_id`
- 业务值：`price`、`amount`、`discount`、`quota`、`balance`

候选条件：

- 请求中存在上述敏感字段。
- 原始响应成功。
- 当前方法允许主动验证。

验证方式是 `mutate_param`，根据字段语义构造少量变异值：

| 语义 | 变异思路 |
| --- | --- |
| role | 尝试 `admin`、`administrator`、`true`、`1` |
| tenant | 尝试 `1`、`2`、`999999` |
| owner | 尝试 `1`、`2`、`999999` |
| business_value | 尝试 `0`、`1`、`999999` |

判断重点：

- 字段是否被服务端采纳。
- 是否产生权限提升、归属切换、租户切换或金额变化。
- 字段是否只是查询条件、排序字段或前端缓存。
- 当前账号是否本来有权限提交该字段。

## 9. 主动差分验证设计

这个模块的主动验证不是任意扫描，而是围绕候选风险执行固定类型的差分请求。

| verification kind | 用途 | 例子 |
| --- | --- | --- |
| `strip_auth` | 未授权访问 | 去掉 Cookie/Authorization 后重放 |
| `swap_auth` | IDOR、租户隔离、垂直越权 | 用 B 的认证访问 A 的资源 |
| `same_auth_replay` | 同身份重放 | 保持原认证重放敏感请求 |
| `mutate_param` | 流程绕过、Mass Assignment | 修改状态、角色、租户、金额字段后重放 |
| `passive_only` | 上下文不足时只做语义判断 | 没有其他身份的垂直越权 |

### 9.1 去认证验证

去认证验证会移除：

- `Authorization`
- `Cookie`
- `X-API-Key`
- `X-Auth-Token`
- `X-CSRF-Token`

然后重放原始请求。重点是看匿名状态是否仍能获得认证状态下的资源。

### 9.2 换认证验证

换认证验证会：

1. 保留源请求的 URL、path、query、body。
2. 移除源请求中的认证材料。
3. 从另一个身份的历史请求中提取认证材料。
4. 用另一个身份的认证材料重放源请求。

这个动作能验证两类问题：

- 用户 B 是否能访问用户 A 的对象。
- 租户 B 是否能访问租户 A 的资源。

### 9.3 参数变异验证

参数变异支持：

- query 参数。
- form 参数。
- JSON 参数。

JSON 参数支持嵌套路径，例如：

```text
user.role
profile.is_staff
items[0].price
tenant.id
```

变异时会尽量保持原始请求结构，只替换目标字段，避免因为请求格式变化导致误判。

### 9.4 方法白名单

主动验证受 `active_verification_methods` 控制。默认配置包含：

```text
GET, HEAD, POST, PUT, PATCH, DELETE
```

从安全角度看，读方法风险较低，写方法可能产生业务副作用。所以需要明确说明：这个能力是给授权测试环境使用的；如果要在生产或灰度环境低风险运行，应把配置收窄到 `GET`、`HEAD`，或者只在明确可回滚的接口上启用写方法。

### 9.5 证据驱动调查循环

候选不再一次性发送全部验证请求，也不依赖固定推理轮数结束。`InvestigationEngine` 每次只执行一个允许的验证动作，拿到响应后重新计算证据状态：

- `confirmed_supported`：正向证据已经闭环，立即停止继续发包，再交给 LLM 做语义裁决。
- `rejected`：所有计划动作已执行，并得到鉴权拒绝、只返回新身份数据或写后回查未生效等明确反证。
- `inconclusive`：动作不可执行、证据仍有缺口，或者步骤、请求、写操作、时间预算已经耗尽。

`max_agent_steps` 只是防止失控的硬上限，不是正常结束条件。正常情况下由证据闭环或明确反证提前结束。写请求即使返回成功并回显新值，也不能直接确认；必须在后续只读回查中看到对应字段的新值。

## 10. LLM 提示词设计

LLM 在这个模块里只负责“裁决”，不负责自由探索。提示词分两层：

### 10.1 系统提示词

系统提示词定义了通用判断边界：

- 只基于输入证据判断，不编造业务规则。
- 必须优先遵守 detector_prompt。
- confirmed 必须证明权限边界被突破。
- likely 只用于证据强但缺少关键字段的情况。
- 只有路径敏感、状态码 200、参数可控，不能直接判漏洞。
- 401、403、404、跳登录、空数据、当前身份自己的数据通常不是漏洞。
- 写方法需要结合响应、Location、业务状态或后续历史判断是否生效。
- 输出必须是固定 JSON。

这相当于给模型定了一套“证据法”。模型不能凭感觉说“这个看起来危险”，必须指出基线包、验证包和关键响应字段。

### 10.2 专项 detector prompt

每类漏洞都有独立的 detector prompt。它们描述：

- 判断目标。
- 覆盖场景。
- confirmed 标准。
- likely 标准。
- needs_manual_review 标准。
- false_positive 标准。
- 不能误判的常见情况。
- evidence 需要包含哪些证据。

这种做法比一个大而全提示词更稳定。原因是 IDOR、未授权、租户隔离、垂直越权、流程绕过、Mass Assignment 的误报点完全不同。每类都要有自己的判定口径。

### 10.3 传给模型的输入

模型看到的是一个 JSON 上下文，主要包含：

| 字段 | 说明 |
| --- | --- |
| candidate | detector 生成的候选风险 |
| detector_prompt | 当前漏洞类型专项标准 |
| active_verification_observations | 主动验证请求和响应摘要 |
| model_context | SQLite 路径、报告策略、endpoint 统计、身份记忆 |

输入会被裁剪到 `prompt_chars` 限制内，避免把大响应或过多历史流量塞给模型。

### 10.4 模型输出

模型必须输出固定 JSON：

| 字段 | 说明 |
| --- | --- |
| status | `confirmed`、`likely`、`needs_manual_review`、`false_positive` |
| confidence | `high`、`medium`、`low` |
| type | 逻辑漏洞类型 |
| severity | 严重程度 |
| title | 简短标题 |
| summary | 结论摘要 |
| impact | 影响 |
| evidence | 证据点列表 |
| verified | 是否经过主动验证 |
| safety_notes | 验证安全说明 |

系统会对 status 和 confidence 做归一化，非法值会降级到保守状态。

## 11. 结论和利用链构建

业务逻辑漏洞报告不能只写一句“存在越权”，还需要给出一条能复现的证据链。模块会把 finding 扩展成 `logic_exploit_chain`。

一条完整链路通常包含：

| 步骤 | 作用 |
| --- | --- |
| 当前用户原始请求与响应 | 证明原资源、原状态、原权限 |
| 其他用户认证来源请求与响应 | 证明存在另一个身份 |
| 主动差分验证请求与响应 | 证明去认证、换认证或篡改后仍成功 |

不同验证方式对完整性的要求不同：

| 验证方式 | confirmed 所需证据 |
| --- | --- |
| `swap_auth` | 源用户基线 + 其他身份基线 + 换认证验证包 |
| `strip_auth` | 源用户基线 + 去认证验证包 |
| `mutate_param` | 源用户基线 + 参数篡改验证包 |
| `same_auth_replay` | 源用户基线 + 同认证重放验证包 |
| `passive_only` | 至少有源用户基线，通常不能直接完整 confirmed |

如果缺少关键证据，链路会标记 missing evidence。例如：

- 缺少其他身份认证来源包。
- 缺少主动验证请求响应。
- LLM 结论没有达到 confirmed。
- 缺少证明原对象归属未变的字段。

这个设计是为了让报告不仅有结论，还有“证据闭环是否完整”的状态。

## 12. 去重和合并策略

业务逻辑漏洞容易重复出现。例如同一个接口的多个订单 ID 都可能触发同类 IDOR。如果每次都写一条报告，会很难阅读。

模块会用稳定 finding key 合并同类问题。key 的核心组成包括：

- detector。
- 漏洞类型。
- host。
- method。
- normalized endpoint。
- verification kind。
- resource 的来源、字段名和语义类型。

合并时会保留更高质量的结果：

- 状态优先级：`confirmed` > `likely` > `needs_manual_review` > `false_positive`。
- 置信度优先级：`high` > `medium` > `low`。
- 严重程度优先级：`critical` > `high` > `medium` > `low` > `info`。
- 证据、验证观察和候选 key 会去重追加。
- 利用链会选择更完整的一条。

这样报告会聚焦在“接口级风险”，而不是被具体样本淹没。

## 13. 误报控制

这个模块从多个层面控制误报。

### 13.1 候选前置筛选

只有敏感接口、资源字段、身份差异、成功响应等条件满足时才生成候选。

### 13.2 主动差分验证

不满足于“看起来危险”，而是尽量做去认证、换认证或参数变异，拿到响应差异。

### 13.3 专项提示词的反例约束

每个 detector prompt 都明确列出 false positive 场景，例如：

- 登录页。
- 权限不足。
- 空数据。
- 当前身份自己的对象。
- 公开资源。
- 同租户共享。
- 管理员正常访问管理接口。
- 字段只是查询筛选。

### 13.4 confirmed 的证据门槛

confirmed 必须能说明：

- 原始基线是什么。
- 差分动作是什么。
- 差分后仍访问到了什么敏感对象或业务结果。
- 为什么这突破了权限、租户、流程或字段控制边界。

### 13.5 状态分层

不是所有风险都强行报 confirmed。系统允许：

- `false_positive`：明确不是漏洞。
- `needs_manual_review`：证据不足，需要人工看业务规则。
- `likely`：证据强但缺少关键字段。
- `confirmed`：证据闭环。

这个状态分层对业务逻辑漏洞很重要，因为很多业务判断天然需要人工上下文。

## 14. 安全控制

该模块会重放请求，尤其在流程绕过和敏感字段绑定场景下可能重放写方法。安全边界主要通过配置和约束实现：

- 默认只在用户显式启用 `--logic` 或 `--only-logic` 时运行。
- 主动验证方法由 `active_verification_methods` 控制。
- 请求超时和响应读取大小有限制。
- 只针对 detector 生成的候选发包，不做全站爬取。
- 候选数量由 `max_candidates_per_endpoint` 限制。
- 每个 endpoint 参与上下文的流量数量由 `max_flows_per_endpoint` 限制。
- 可替换身份数量由 `max_alternate_identities_per_candidate` 限制。

实际使用建议：

| 场景 | 建议 |
| --- | --- |
| 生产只读观察 | 只开 SQLite 索引或限制为 `GET`、`HEAD` |
| 授权测试环境 | 可以启用完整方法集合 |
| 多账号越权测试 | 至少准备两个不同权限/租户账号 |
| 流程/金额/角色类测试 | 确认数据可回滚或使用靶场数据 |

## 15. 配置项说明

常用配置在 `config.yaml` 的 `plugins.logic_agent` 下：

| 配置项 | 说明 |
| --- | --- |
| `enabled` | 配置层开关，命令行 `--logic` 会额外启用 |
| `worker_count` | 逻辑漏洞分析 worker 数 |
| `queue_size` | 候选任务队列大小 |
| `output_file` | 逻辑漏洞 JSONL 输出路径 |
| `sqlite_file` | SQLite 流量索引路径 |
| `env_file` | LLM 配置文件 |
| `llm_protocol` | LLM 协议 |
| `temperature` | LLM 温度，建议低温 |
| `llm_timeout_seconds` | LLM 请求超时 |
| `llm_max_tokens` | LLM 输出 token 限制 |
| `request_timeout_seconds` | 主动验证 HTTP 超时 |
| `max_response_body_bytes` | 主动验证响应最大读取字节 |
| `prompt_chars` | 给 LLM 的 prompt 最大字符数 |
| `max_flows_per_endpoint` | 每个 endpoint 最多加载的历史流量 |
| `max_candidates_per_endpoint` | 每个 endpoint 最多调查的候选数，仅作为硬保护上限 |
| `max_http_requests_per_endpoint` | 每个 endpoint 的逻辑验证 HTTP 请求总预算 |
| `max_candidates_per_detector` | 每个 detector 先进入统一排序池的候选数 |
| `max_alternate_identities_per_candidate` | 每个候选最多尝试几个其他身份 |
| `max_agent_steps` | 单候选最多执行多少个验证动作，仅作为防死循环上限 |
| `max_http_requests_per_candidate` | 单候选主动验证 HTTP 请求预算 |
| `max_write_requests_per_candidate` | 单候选最多允许多少个写请求，限制副作用 |
| `max_investigation_seconds` | 单候选调查最长时间 |
| `postcondition_readback` | 写/状态篡改验证成功后是否追加同源 GET 只读复查 |
| `max_postcondition_checks_per_candidate` | 每个候选最多追加几次只读复查 |
| `active_verification_methods` | 主动差分验证允许的 HTTP 方法 |

## 16. 和普通漏洞插件的区别

| 维度 | 普通插件 | 业务逻辑 Agent |
| --- | --- | --- |
| 输入 | 单条请求响应 | 一个 endpoint 的历史上下文 |
| 核心证据 | payload 命中 | 权限/归属/状态差分 |
| 主要技术 | payload、规则、响应特征 | 身份记忆、资源建模、差分验证、LLM 裁决 |
| 输出 | 传统 finding | 逻辑 finding + exploit chain |
| 误报控制 | 技术特征匹配 | confirmed/likely/review 分层 |
| 对账号要求 | 通常一个账号即可 | 多账号、多角色、多租户样本越多越好 |

## 17. 方案讲解重点

这个 Agent 的可靠性主要体现在四点：

1. 我没有让 LLM 裸奔。LLM 只处理经过规则筛选的候选。
2. 业务上下文被结构化了。接口、身份、资源、参数都进入 SQLite，支持跨请求分析。
3. 判断前尽量做差分验证。未授权、IDOR、租户隔离不靠猜，而是去认证或换认证重放。
4. prompt 不是泛泛地问“有没有漏洞”，而是每类漏洞都有 confirmed、likely、review、false_positive 的判定标准。

这个方案的主要难点包括：

- 第一是身份建模，因为 Cookie、Token、API Key 都可能代表身份，而且不能泄漏敏感值。
- 第二是资源归属判断，因为响应里不一定明确写 owner，需要模型结合多个字段判断。
- 第三是写方法验证的安全性，要通过配置和授权边界控制。
- 第四是误报分层，业务逻辑漏洞不能简单二分类，必须允许人工复核状态。

后续可以继续优化的方向包括：

- 增加角色画像，让系统更稳定地区分管理员、普通用户、运营、租户管理员。
- 增加后置状态确认，比如写方法后自动查询详情页确认状态是否真的变化。
- 加入更强的响应相似度和对象字段对齐算法，减少 LLM 对长文本的依赖。
- 支持用户手动标注账号所属租户、角色、资源归属，提高 confirmed 率。
- 给每类 detector 加可配置的风险预算，按目标环境选择只读或写验证。

## 18. 一句话总结

`agent_pass_scan` 的本质是把业务逻辑漏洞检测拆成“工程确定性”和“模型语义判断”两部分：工程层负责收集上下文、找候选和做差分验证，模型层负责在明确证据和专项标准下判断是否真的突破了业务边界。这种设计既利用了 LLM 的语义理解能力，又避免让它直接承担不可控的扫描决策。
