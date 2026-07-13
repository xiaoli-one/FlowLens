# SQL 注入检测技术文档

`pass_scan/sql_injection` 是被动流量触发、主动重放验证的 SQL 注入插件。它从真实请求中提取可控参数，构造 baseline，再按参数逐个注入 payload，通过报错、页面差异、marker 回显和稳定延时确认漏洞。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `sql_injection` |
| 命令行 | `python3 run.py --sqli` |
| 默认输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/sql_injection/rules.yaml` |
| 环境覆盖 | `PASS_SCAN_SQLI_RULE_FILE`、`PASS_SCAN_VULN_FILE`、`PASS_SCAN_REPORT_FILE` |

调度接口：

- `interested(context)`：只在 GET/POST 且存在候选参数时入队。
- `dedup_key(context)`：按 method、host、归一路径、content-type、参数形态去重。
- `check(context)`：后台 worker 中重放 baseline 和 payload。

## 候选参数

普通模式扫描：

- `query`
- `form`
- `json`，含嵌套对象和数组叶子标量

`--full-payload-scan` 或 `scan.full_payload_scan: true` 额外扫描：

- `cookie`
- 常见业务 header：`User-Agent`、`Referer`、`X-Forwarded-For`、`X-Real-IP`、`Client-IP`

Cookie 会按下标替换指定值；短文本 base64 Cookie 会尽量重新 base64。Header 使用专用规则集，避免把完整 query/form payload 原样打进日志类字段。

## 检测方法

| 方法 | 代码入口 | 判定证据 |
| --- | --- | --- |
| 报错注入 | `check_error_based()` | 响应新增数据库错误指纹 |
| 布尔盲注 | `check_boolean_based()` | true 响应接近 baseline，false 响应显著不同 |
| Inline Query | `check_inline_query()` | SQL 表达式产生的唯一 marker 出现在响应中 |
| UNION Query | `check_union_based()` | 默认覆盖闭合方式/列数，全量模式枚举 marker 列 |
| Stacked Query | `check_stacked_query()` | control/delay 成对稳定延时 |
| 时间盲注 | `check_time_based()` | 两轮 control/delay 差值超过阈值 |

支持的数据库错误特征：

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- Generic SQL error

## WAF 与 tamper

`rules.yaml` 中的 `waf_detection` 定义状态码、响应头和响应体关键词。插件发现疑似 WAF 拦截时，会按 `tamper_profiles` 追发变形 payload，并把 `waf_bypass`、`tamper_profile`、`tampers` 写入证据。

默认模式使用覆盖集，不对每条未命中 payload 主动追加 tamper；明确检测到
WAF 拦截时仍会按需尝试绕过。非 WAF 场景下如需手动开启 deep tamper，
继续使用原有配置：

```yaml
plugins:
  sql_injection:
    deep_tamper: false
    deep_tamper_max_profiles: 4
    deep_tamper_methods:
      - error_based
      - boolean_based
      - inline_query
```

`--full-payload-scan` 是现有的 tamper 模式：额外扫描 Cookie/Header，UNION
从覆盖集切换为完整 marker 位置枚举，并对 UNION 之外的检测类型追加最多 6 个
代表性 tamper。UNION 只有明确被 WAF 拦截时才追加 tamper，避免组合爆炸。

## 默认覆盖集与请求预算

默认模式仍保留报错、布尔、Inline、UNION、Stacked、时间、ORDER BY、
宽字节以及 MySQL/PostgreSQL/MSSQL/Oracle/SQLite 相关场景，但不再把同义
注释、编码和闭合方式做笛卡尔积。稳定阴性、单参数、无 WAF 时的基础上限
约为 167 次请求；任一证据确认后立即停止，实际命中场景通常明显少于此数。

默认 UNION 为 8 种闭合方式 × 6 种列数，每个组合选一个轮换的 marker
位置，共 48 条。`--full-payload-scan` 才恢复 168 条完整位置枚举。
发送前还会按最终 URL/body/header 去重，原始写法不同但线上字节相同的 payload
只发送一次。

## 规则文件

`rules.yaml` 包含：

- `sql_error_rules`
- `error_payload_suffixes`
- `error_payload_templates`
- `boolean_payload_groups`
- `inline_query`
- `union_query`
- `stacked_payload_groups`
- `time_payload_groups`
- `header_error_*`
- `header_boolean_*`
- `header_time_*`
- `header_stacked_*`
- `waf_detection`
- `tamper_profiles`

`rules.py` 负责 YAML 加载、模板渲染和 SQL 错误正则编译。`tamper.py` 提供确定性字符串变形，例如空白替换、关键字大小写、注释切分、URL 编码和 MySQL hex 字符串等。

## 输出结构

典型 finding：

```json
{
  "type": "sql_injection",
  "method": "boolean_based",
  "url": "https://example.com/item?id=1",
  "param_place": "query",
  "param_name": "id",
  "evidence": {
    "message": "boolean payload changed response shape",
    "true_payload": "...",
    "false_payload": "...",
    "true_similarity": 0.97,
    "false_similarity": 0.42,
    "dbms": "mysql"
  },
  "proof": {
    "request": "...",
    "response": "..."
  }
}
```

## 限制

- 只对已通过代理的请求做触发，不会主动爬站。
- 时间类检测依赖目标响应稳定性和网络延时稳定性。
- Header/Cookie 注入默认关闭，需要全量扫描模式。
- 确认 WAF 封禁后会进入 host 冷却，可能延后后续任务。

## 方案设计说明

SQL 注入插件的设计目标不是“尽可能多发 payload”，而是把一次真实业务请求变成一个可比较的实验环境。插件先从代理流量中拿到真实请求，再建立 baseline，然后只改变一个参数，比较响应的错误、结构、相似度、marker 和时间特征。这样能把业务页面本身的随机变化和注入导致的差异分开。

整体方法可以概括为：

1. 用真实流量触发，不主动爬站。
2. 用 baseline 记录原始状态。
3. 单参数、单变量变异。
4. 按低成本到高成本的顺序尝试检测技术。
5. 命中后立刻收敛，避免同一参数继续刷无意义 payload。
6. WAF 或过滤场景下再启用 tamper。
7. 最终 finding 必须包含可复现请求、响应和判定证据。

### 检测技术分层

SQL 注入的检测技术按证据强度和成本分层：

| 层级 | 技术 | 设计理由 |
| --- | --- | --- |
| 低成本 | 报错注入 | 一次请求即可得到数据库错误特征，命中时置信度高 |
| 中成本 | 布尔盲注 | true/false 命中后反序重发确认，不依赖错误回显 |
| 中成本 | inline marker | 让 SQL 表达式产生唯一 marker，适合能回显表达式结果的场景 |
| 较高成本 | time | control/delay 二次确认，优先覆盖无回显盲注 |
| 较高成本 | UNION | 默认使用闭合/列数覆盖集，能推进到数据回显证明 |
| 高成本 | stacked | 作为多语句执行场景的最后兜底 |

这样排序是为了控制请求量。一个普通参数如果报错已经确认，就不需要继续跑
布尔、时间或 UNION。时间盲注放在 UNION 前，避免无回显漏洞先承担 UNION
组合探测；Stacked 最后兜底多语句执行场景。

### Baseline 的作用

baseline 是这个插件降低误报的核心。没有 baseline，就很容易把页面随机变化、验证码、时间戳、广告位、推荐内容误判为注入差异。

baseline 主要用于：

- 判断错误注入是否新增了数据库错误，而不是原页面本来就有错误。
- 判断布尔 true 响应是否接近原响应，false 响应是否明显偏离。
- 判断 marker 是否是 payload 触发产生，而不是原页面已有字符串。
- 判断延时 payload 是否真的比 control payload 慢。
- 记录状态码、响应长度、相似度和关键响应片段。

### 参数模型

插件扫描的参数来自统一 `ScanContext`。普通模式只扫描 query、form、json，这是最常见也最可控的注入点。Cookie 和 Header 默认不扫，因为它们经常被日志、网关、埋点或中间件消费，误报和噪声更高。只有 `--full-payload-scan` 开启后，才把它们纳入。

JSON 参数会保留路径，例如 `user.id`、`items[0].sku`。变异时只替换对应叶子节点，不破坏整体 JSON 结构。

### 报错注入

报错注入的目标是让数据库解析器产生可识别错误。判定不是“响应出现 error 单词”，而是匹配数据库特征：

- MySQL / MariaDB 的 XPath、duplicate entry、syntax error。
- PostgreSQL 的 SQLSTATE、unterminated quoted string。
- MSSQL 的 conversion failed、ODBC SQL Server。
- Oracle 的 ORA 错误。
- SQLite 的 sqlite syntax。

只有 payload 后响应新增这些特征，才作为命中证据。

### 布尔盲注

布尔盲注使用成对 payload：

```text
原始值 + true 条件
原始值 + false 条件
```

确认逻辑是：

- true 响应应该接近 baseline。
- false 响应应该和 true/baseline 明显不同。
- true 和 false 之间要有稳定差异。
- 首轮疑似命中后，以 false/true 反序再发一轮，结论一致才报告。

这种方法适合没有报错但存在条件分支的接口。为了降低误报，插件不会只看状态码，而会综合响应长度、相似度和内容片段。

### Inline 与 UNION

Inline query 和 UNION 都尝试让数据库把唯一 marker 输出到响应里。区别是：

- inline 更像在原 SQL 表达式里追加一个能返回 marker 的表达式。
- UNION 会探测列数，并尝试把 marker 放到可显示列。
- 默认 UNION 对每种闭合方式、每个列数选择一个代表位置；全量模式枚举全部位置。

这两类一旦命中，证据比纯布尔差异更直观，因为报告里能看到 marker 被数据库查询结果带出来。

### 时间盲注

时间盲注是最高成本路线。它必须使用 control/delay 成对请求，而且至少二次确认。这样做是为了抵抗网络抖动和目标偶发慢响应。

判定时关注：

- delay payload 是否显著慢于 control payload。
- 两轮差值是否都超过阈值。
- baseline 是否本身就不稳定。
- WAF 或限流是否影响结果。

### WAF 与 tamper 的设计

Tamper 不应该一开始就全量启用，否则请求量会指数级增长。插件采用按需 tamper：

- 如果响应命中 WAF 规则，说明 payload 被拦截，启用绕过策略。
- 默认不开启非 WAF deep tamper；手动配置时只追加少量变体。
- `--full-payload-scan` 对 UNION 外的场景扩大到 6 个代表性 tamper。
- UNION 仅在明确 WAF 拦截时 tamper，避免 168 组再次成倍扩张。

Tamper 的目标不是“花式 payload”，而是处理常见过滤：

- 空白过滤。
- 关键字大小写或注释切分。
- 引号和括号闭合差异。
- URL 编码。
- MySQL 字符串 hex 表达。

### 确认标准

可以确认 SQL 注入的证据包括：

- 新增数据库错误特征。
- true/false 响应形成稳定差异。
- 数据库计算出的 marker 出现在响应中。
- UNION marker 被回显。
- control/delay 两轮稳定延时。

不作为确认的情况：

- 仅状态码变化但无法解释。
- 原页面本来就有 SQL 错误。
- 只有 WAF 拦截页面。
- 响应随机性导致的长度差异。
- 只有 payload 原样反射，没有数据库执行证据。

### 输出设计

finding 中保留以下证据：

- 漏洞类型和检测方法。
- 参数位置、参数名和原 URL。
- payload 或 payload 对。
- DBMS 或错误特征。
- true/false 相似度。
- 延时差值。
- WAF 绕过信息。
- 请求包和响应包。

这些字段既用于报告展示，也用于 `vuln_verify` 后续主动验证。主动验证 Agent 可以基于这些证据继续推进到只读数据读取。

### 安全边界

SQL 注入插件本身只做验证，不做破坏性操作。规则里虽然覆盖 stacked/time，但用途是延时确认，不应该包含 INSERT、UPDATE、DELETE、DROP、ALTER、TRUNCATE 等破坏性 SQL。后续如果扩展 payload，也应保持只读和非破坏性原则。

### 方案讲解重点

这个插件的关键不是 payload 数量，而是实验设计：

- 一次只改变一个参数。
- 每个 payload 都有明确判定逻辑。
- 低成本技术优先，高成本技术兜底。
- Tamper 按需触发，不一开始爆炸。
- 报告证据可以复现，也能交给主动验证 Agent 继续推进。
