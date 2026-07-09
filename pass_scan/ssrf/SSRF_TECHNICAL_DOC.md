# SSRF 检测技术文档

`pass_scan/ssrf` 检测服务端请求伪造。当前实现只做 OOB 带外确认：把参数替换为唯一 interactsh 域名，目标服务端一旦解析或请求该域名即确认 SSRF。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `ssrf` |
| 命令行 | `python3 run.py --ssrf` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/ssrf/rules.yaml` |
| OOB | `tools/interactsh_client.py` + `ssrf/oob.py` |

## 流量筛选

- 全局层过滤静态资源、二进制响应、HEAD/OPTIONS、204/304。
- 插件层只处理 GET/POST。
- 普通模式扫描 query/form/json。
- `--full-payload-scan` 额外扫描 Cookie/Header。
- 默认不按参数名筛选，覆盖全部可控参数。

## 检测方式

`technique=带外请求`：

1. 为每个 payload 生成唯一 OOB 域名。
2. 将候选参数替换为 URL、裸域名、协议相对 URL、userinfo 等变体。
3. 主动重放请求。
4. 后台轮询 interactsh。
5. 收到包含 token 的 DNS/HTTP 交互后写入 finding。

置信度：

- HTTP/HTTPS 回连：`high`
- 仅 DNS 回连：`medium`

仅 DNS 的情况可能来自解析链路或安全设备预解析，所以报告中会标注协议和来源 IP。

## Payload 变体

基础变体：

- `http://{domain}/`
- `https://{domain}/`
- `{domain}`
- `//{domain}/`
- `http://{allow}@{domain}/`
- 原值是 URL 时替换 host 并保留原 scheme/path

`deep_tamper` 或全量扫描时追加：

- 路径/片段白名单绕过
- 子域名拼接型 sink 击穿
- `gopher://`、`dict://`
- scheme 大小写变形
- scheme URL 编码和双编码

## 配置

```yaml
plugins:
  ssrf:
    enabled: true
    deep_tamper: true
    oob:
      enabled: true
      poll_interval: 15
```

## 输出结构

```json
{
  "type": "ssrf",
  "method": "ssrf",
  "param_place": "json",
  "param_name": "callbackUrl",
  "evidence": {
    "technique": "带外请求",
    "payload": "http://....oast.pro/",
    "oob_domain": "....oast.pro",
    "oob_protocol": "http",
    "oob_remote_address": "1.2.3.4",
    "confidence": "high"
  }
}
```

## 限制

- 目标无法出网时不会产生带外命中。
- 当前不做云元数据回显类兜底检测。
- 大流量场景下全参数 OOB 会带来较多请求，可通过插件 worker 和队列控制节奏。

## 方案设计说明

SSRF 插件的核心目标是证明“目标服务端会基于用户输入向外发起请求”。当前实现选择 OOB 作为主要确认通道，因为 SSRF 很多时候没有响应回显，单靠状态码或页面变化很难确认。

整体方法是：

1. 从真实请求中提取可控参数。
2. 为每个候选 payload 分配唯一 OOB 域名。
3. 把参数替换为指向该域名的 URL 或 URL 变体。
4. 主动重放请求。
5. 后台轮询 interactsh。
6. 收到唯一 token 回连后关联到参数和 payload。
7. 根据 DNS/HTTP 协议和来源信息生成 finding。

### 为什么只做 OOB 确认

SSRF 的判定难点是：服务端访问外部地址后，应用未必会把访问结果返回给客户端。很多真实 SSRF 只表现为：

- 服务端后端发起了 DNS 解析。
- 服务端请求了外部 HTTP URL。
- 应用前端返回一个普通成功或失败响应。

如果只看前端响应，很容易误判。因此插件采用唯一 OOB 域名。只要目标能解析或访问这个域名，就能证明服务端请求链路被触发。

### 参数覆盖策略

插件普通模式扫描 query、form、json。全量模式再扫描 Cookie/Header。默认不只看参数名，因为很多 SSRF sink 的参数名并不固定，例如：

- `url`
- `target`
- `image`
- `avatar`
- `callback`
- `next`
- `endpoint`
- `path`
- `data`

全参数覆盖能提升发现率，但也会增加 OOB 请求量，因此需要依赖队列、worker 和 host 限速控制节奏。

### Payload 设计

SSRF payload 不只是 `http://domain/`。实际应用常有白名单、协议限制或 URL 拼接逻辑，所以 payload 按层次设计：

| 类型 | 目的 |
| --- | --- |
| 完整 HTTP/HTTPS URL | 覆盖常规 URL 参数 |
| 裸域名 | 覆盖后端自动补协议或拼 URL 的场景 |
| 协议相对 URL | 绕过只过滤 `http://` 的逻辑 |
| userinfo 变体 | 绕过白名单 host 前缀检查 |
| 保留原 scheme/path 替换 host | 适配原值本身是 URL 的参数 |
| 路径/fragment 白名单绕过 | 绕过后缀或路径拼接检查 |
| gopher/dict 等协议 | 覆盖协议未限制场景 |
| scheme 大小写/编码 | 绕过简单关键字过滤 |

基础 payload 覆盖常见情况，deep tamper 再追加更激进的变体。

### OOB 置信度

OOB 结果并不是完全同质的。插件会区分协议：

- HTTP/HTTPS 回连：通常说明服务端真的发起了 HTTP 请求，置信度高。
- DNS 回连：说明至少触发了解析，但可能来自 DNS 预解析、安全设备或中间代理，置信度中等。

报告中会保留 remote address 和 raw interaction，方便后续人工判断来源。

### 确认标准

confirmed 需要满足：

- OOB token 与当前 payload 唯一匹配。
- 回连发生在发包后的合理时间窗口。
- 回连域名属于当前候选参数生成的域名。

不确认的情况：

- 没有 OOB 命中。
- 命中的 token 不属于当前请求。
- 只有目标前端响应变化，但没有服务端访问证据。
- OOB 服务不可用或注册失败。

### 安全边界

当前插件不主动探测云 metadata，不扫描内网端口，不对内网管理接口发状态变更请求。它只证明服务端能否访问外部受控域名。更深层的内网利用应由主动验证模块在授权范围内进行。

### 方案讲解重点

SSRF 检测的关键是“服务端侧证据”。OOB 域名把不可见的服务端请求转化为可观察证据；payload 变体解决白名单和 URL 解析差异；协议区分和唯一 token 关联用来控制误报。
