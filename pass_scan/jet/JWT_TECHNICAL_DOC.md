# JWT 检测技术文档

`pass_scan/jwt` 检测 JWT 暴露和常见校验风险。它是 `observer_only` 插件：先从请求/响应中提取 token，再把 token 目标提交到独立 JWT 队列。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `jwt` |
| 命令行 | `python3 run.py --jwt` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 阶段 | `observe(context)` 提取 JWT，`check(target)` 检测风险 |

## Token 来源

请求侧：

- `Authorization: Bearer/JWT/Token`
- Cookie
- query/form/json 参数
- 其它 token 相关请求头

响应侧：

- `Set-Cookie`
- 响应头
- 响应正文

支持 JWS 三段 token 和 JWE 五段 token 的识别；主动检测只对请求侧 JWS 执行。

## 被动风险

| method | 说明 |
| --- | --- |
| `jwt_none_alg` | header 声明 `alg=none` |
| `jwt_sensitive_claim` | payload 中存在敏感 claim 名称 |
| `jwt_token_exposure` | JWT 出现在 URL query，或 Set-Cookie 缺少 HttpOnly/Secure |
| `jwt_time_claim` | 已过期 token 或未来 nbf token 在原始响应中仍被接受 |
| `jwt_weak_secret` | HMAC token 命中轻量弱密钥字典 |

JWT payload 本身是客户端可读的，因此敏感 claim 只记录 key 和脱敏样本。

## 主动验证

主动验证前先建立：

1. baseline：原始 token 请求被接受。
2. negative control：移除 token 或破坏签名后应被拒绝。

只有 baseline 被接受且 negative 被拒绝，才继续检测，降低误报。

默认启用：

- 签名未校验：破坏签名后仍被接受。
- `alg=none` 绕过。
- HMAC 弱密钥字典校验。

默认关闭的扩展项：

- 弱密钥命中后的 claim 篡改确认。
- RS/HS 算法混淆。
- header 内嵌 JWK 信任。
- kid 路径/SQL 注入类绕过。
- jku/x5u/kid 远程 key 获取/OOB。
- JWKS discovery。

## 配置

```yaml
plugins:
  jwt:
    enabled: true
    active_probe: true
    weak_secret_scan: true
    claim_tamper: false
    algorithm_confusion_scan: false
    embedded_jwk_scan: false
    kid_injection_scan: false
    remote_key_fetch_scan: false
    jwks_discovery: false
    max_tokens_per_context: 12
    max_scan_chars: 400000
    max_secret_candidates: 160
    oob:
      enabled: false
      poll_interval: 15
```

## 输出结构

```json
{
  "type": "jwt",
  "method": "jwt_signature_bypass",
  "url": "https://example.com/api/me",
  "param_place": "header",
  "param_name": "Authorization",
  "evidence": {
    "technique": "签名未校验",
    "jwt_alg": "HS256",
    "baseline_status": 200,
    "control_status": 401,
    "probe_status": 200,
    "confidence": "high"
  }
}
```

## 限制

- 主动验证只对请求侧 JWS 生效。
- 弱密钥扫描是轻量字典，不是爆破。
- 远程 key/OOB 相关检测默认关闭，需要专项场景手动开启。

## 方案设计说明

JWT 插件的目标是识别 token 暴露和服务端 JWT 校验缺陷。它分成两个阶段：先观察流量提取 token，再对可验证的请求侧 JWS 做主动校验。这样设计是因为 JWT 可能出现在请求、响应、Cookie、URL、JS 文本里，但不是所有 token 都适合主动验证。

整体方法是：

1. 在请求和响应中识别 JWS/JWE。
2. 对 token 解析 header 和 payload。
3. 记录暴露位置和被动风险。
4. 对请求侧 JWS 建立 baseline。
5. 构造 negative control，确认破坏签名后应被拒绝。
6. 在 baseline/negative 成立后再测试签名绕过、none alg、弱密钥等风险。
7. 扩展高噪声检测默认关闭，由配置显式启用。

### 为什么是 observer-only

JWT 不一定是当前请求参数里的普通字段。它可能分布在：

- Authorization header。
- Cookie。
- query/form/json。
- Set-Cookie。
- 响应正文。
- JS 配置。

所以插件先观察每条流量，从多个位置提取 token，再把 token 目标提交给 JWT 队列。这比只在 `interested(context)` 中扫描参数更完整。

### 被动风险和主动风险分离

JWT 风险分两类：

| 类型 | 示例 |
| --- | --- |
| 被动风险 | token 出现在 URL、Cookie 缺少 HttpOnly/Secure、payload 有敏感 claim |
| 主动校验风险 | 签名未校验、alg=none、弱 HMAC secret、claim 篡改被接受 |

被动风险不一定等于服务端校验漏洞，但仍有安全价值。主动风险必须通过请求重放确认。

### Baseline 和 negative control

JWT 主动验证最重要的是先证明接口真的依赖 token：

1. baseline：原 token 请求成功。
2. negative：移除 token 或破坏签名后被拒绝。

只有 baseline 成功且 negative 失败，后续绕过结果才有意义。否则：

- 如果原接口匿名也能访问，伪造 token 成功没有意义。
- 如果破坏签名仍成功，可能是签名未校验，也可能接口不看 token，需要结合响应差异。

### 默认启用的检测

默认只启用高信号、低误报的检测：

- 签名未校验。
- `alg=none`。
- 弱 HMAC secret。
- 敏感 claim。
- token 暴露位置。
- 过期 token / 未来 nbf token 被接受。

这些检测覆盖最常见风险，同时请求量可控。

### 默认关闭的扩展检测

以下能力默认关闭：

- RS/HS 算法混淆。
- header 内嵌 JWK 信任。
- kid 注入。
- jku/x5u/kid 远程 key 获取。
- JWKS discovery。
- 弱密钥命中后的 claim tamper。

这些检测在靶场或专项测试中价值很高，但真实环境中误报、噪声或副作用更大，所以需要显式开启。

### 弱密钥扫描

弱密钥扫描不是爆破。它只使用轻量候选：

- 常见默认 secret。
- host、issuer、audience 派生词。
- 少量框架默认值。

候选数量由 `max_secret_candidates` 限制。命中后才考虑进一步签名和 claim 验证。

### 确认标准

confirmed 证据包括：

- 破坏签名后仍被接受。
- `alg=none` token 被接受。
- 使用弱密钥重新签名后被接受。
- 篡改 claim 后只读接口体现身份或权限变化。
- 过期/未来 token 在负控制成立时仍被接受。

不确认的情况：

- token 只是样例或前端缓存。
- 接口本身匿名可访问。
- negative control 没有被拒绝且无法判断原因。
- 响应只是通用页面或空数据。

### 安全边界

主动验证只使用只读接口和 token 替换，不执行写操作。远程 key/OOB 类检测默认关闭，避免诱导服务端访问外部资源或产生额外风险。

### 方案讲解重点

JWT 检测的关键是“先证明 token 参与授权，再证明校验缺陷”。baseline/negative control 是降低误报的核心；被动风险和主动校验风险分开输出，可以让报告既覆盖泄漏问题，也覆盖真实认证绕过。
