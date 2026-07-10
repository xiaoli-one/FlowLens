# 命令注入/RCE 检测技术文档

`pass_scan/command_injection` 检测 OS Command Injection。报告中统一为 `type=command_injection`，通过 `evidence.technique` 区分命令回显、命令延时和命令带外。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `command_injection` |
| 命令行 | `python3 run.py --rce` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/command_injection/rules.yaml` |
| OOB | `tools/interactsh_client.py` + `command_injection/oob.py` |

## 流量筛选

- 全局层过滤静态资源、二进制响应、HEAD/OPTIONS、204/304。
- 插件层只处理 GET/POST。
- 普通模式扫描 query/form/json。
- `--full-payload-scan` 额外扫描 Cookie/Header。
- 默认不按参数名筛选，覆盖全部可控参数。

## 检测方法

| technique | 判定方式 |
| --- | --- |
| `命令回显` | 注入随机算术表达式，响应出现计算结果且 baseline 不含该结果 |
| `命令延时` | control/delay 成对请求，两轮确认延时差超过阈值 |
| `命令带外` | 注入 nslookup/curl/ping 等带外命令，interactsh 收到唯一 token 回连 |

算术回显覆盖 Unix 和 Windows 表达式。时间盲注覆盖 `sleep`、`ping`、`timeout`、PowerShell sleep 等。OOB 覆盖完全无回显场景。

## OOB 机制

`oob.py` 后台注册 interactsh 会话，按 token 生成唯一域名。payload 发出后，轮询线程收到 DNS/HTTP 回连即关联注入点并异步写入 finding。

配置：

```yaml
plugins:
  command_injection:
    oob:
      enabled: true
      poll_interval: 15
```

目标无法出网时 OOB 不会命中，时间盲注仍可兜底。

## 时间盲注策略

```yaml
plugins:
  command_injection:
    time_delay: 5
    time_threshold: 3
    time_based_mode: always
```

`time_based_mode`：

- `always`：默认，回显未命中后运行时间盲注。
- `fallback`：OOB 可用时跳过时间盲注，OOB 不可用时兜底。
- `off`：关闭时间盲注。

## Tamper

基础 payload 保持干净。出现 WAF 拦截，或开启 `deep_tamper` 且原始 payload 未命中时，按 `rules.yaml` 的 `tamper_profiles` 追加空格绕过，例如 `${IFS}`、`$IFS$9`、Tab、`${IFS%??}`。

配置：

```yaml
plugins:
  command_injection:
    deep_tamper: true
    deep_tamper_max_profiles: 4
```

## 输出结构

```json
{
  "type": "command_injection",
  "method": "command_injection",
  "param_place": "query",
  "param_name": "cmd",
  "evidence": {
    "technique": "命令带外",
    "payload": "...",
    "os": "unix",
    "oob_domain": "...",
    "oob_protocol": "dns",
    "confidence": "high"
  }
}
```

## 限制

- OOB 依赖目标能出网。
- 时间盲注对网络抖动敏感，因此需要二次确认。
- Header/Cookie 注入默认关闭，需要全量扫描模式。

## 方案设计说明

命令注入插件的目标是证明“用户可控参数被拼接进了操作系统命令执行链路”。它采用三条互补验证路线：回显、延时和带外。三条路线覆盖不同应用形态：

- 有命令输出回显时，用算术回显确认。
- 没有输出但请求会等待命令执行时，用时间盲注确认。
- 完全无回显且时间不稳定时，用 OOB 回连确认。

整体检测策略是：

1. 从真实 GET/POST 请求中提取参数。
2. 建立 baseline，记录原响应和耗时。
3. 对每个参数尝试低副作用 payload。
4. 优先使用回显类 payload。
5. 回显不成立时使用时间/OOB。
6. WAF 或过滤迹象出现时再启用 tamper。
7. 最终用 `evidence.technique` 说明命中通道。

### 为什么用算术回显

命令回显不直接使用 `whoami`、`id` 作为基础确认，而是优先使用随机算术表达式。原因是算术结果更适合自动化判定：

- 结果随机，baseline 中几乎不可能天然存在。
- 输出短，不会泄漏系统敏感信息。
- Unix 和 Windows 都能构造对应表达式。
- 误报率低于匹配 `root`、`uid` 等通用词。

只有响应中出现预期计算结果，并且 baseline 不包含该结果，才确认命令回显。

### 时间盲注

时间盲注用于无回显场景。插件使用 control/delay 成对请求，而不是单发 sleep：

```text
control payload -> 理论上不延时
delay payload   -> 理论上延时 N 秒
```

确认时会比较两者耗时差，并做二次确认。这样可以减少网络抖动、服务端偶发慢请求和队列拥塞带来的误报。

时间 payload 覆盖：

- Unix `sleep`
- `ping` 延时
- Windows `timeout`
- PowerShell sleep

### OOB 带外确认

OOB 用于完全盲打。插件通过 interactsh 分配唯一域名，并把该域名嵌入 `nslookup`、`curl`、`ping` 等命令。目标一旦执行命令并访问域名，后台轮询线程会收到 DNS/HTTP 交互。

OOB 证据包括：

- 唯一 token。
- OOB 域名。
- 协议类型。
- 来源 IP。
- 原始交互数据。

HTTP 回连通常比纯 DNS 回连置信度更高，因为 DNS 可能来自解析链路或安全设备预解析。

### Tamper 设计

命令注入的常见过滤点是空格、分隔符和关键命令。插件的 tamper 主要处理：

- 空格替换为 `${IFS}`、`$IFS$9`、tab。
- 命令分隔符变体。
- URL 编码。
- 大小写或 shell 语法变体。

Tamper 不默认全量展开。只有原始 payload 未命中、出现 WAF 拦截或配置允许 deep tamper 时，才追加少量变体。

### 确认标准

confirmed 证据包括：

- 响应出现随机算术结果。
- 两轮时间盲注都稳定超过阈值。
- OOB 收到唯一 token 回连。

不确认的情况：

- 只出现 payload 原文。
- 响应慢但 control 也慢。
- OOB token 不匹配。
- 只有 WAF 拦截或错误页面。
- 输出是通用系统文本但无法证明来自命令执行。

### 安全边界

插件只使用低副作用命令确认执行能力，不写文件、不下载执行、不反弹 shell、不修改系统。OOB 只用于 DNS/HTTP 回连证明，不传输敏感数据。

### 方案讲解重点

这个插件的设计重点是“三通道互补”和“非破坏性证明”。回显确认最直接，时间盲注补无回显，OOB 补完全盲打。每条路线都有自己的确认条件，避免只凭状态码或响应变慢就报 RCE。
