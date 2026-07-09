# 开放重定向/响应头注入检测技术文档

`pass_scan/redir` 检测开放重定向和 CRLF/响应头注入。报告中统一为 `type=redir`，用 `evidence.technique` 区分具体问题。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `redir` |
| 命令行 | `python3 run.py --redir` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/redir/rules.yaml` |

## 流量筛选

插件只处理 GET/POST，并保留语义筛选：

- 参数名像跳转目标：`redirect`、`url`、`next`、`return`、`goto`、`callback` 等。
- 参数值像 URL、域名、路径、协议相对 URL 或编码后的 URL。
- 参数名像响应头/下载字段：`filename`、`download`、`location`、`header` 等。
- 原始响应头反射了参数值。
- 响应本身是 3xx、Location/Refresh 或路径像登录、OAuth、SSO、下载、导出、跳转入口。

普通模式扫描 query/form/json；全量扫描额外扫描 Cookie/Header，但仍保留语义筛选。

## 检测方法

| technique | 判定方式 |
| --- | --- |
| `开放重定向` | 注入唯一外部域名，不跟随跳转；Location、Refresh 或 meta refresh 解析到该域名才确认 |
| `响应头注入` | 注入唯一 `X-Pass-Scan-*` 响应头；响应头中真实出现该 header 才确认 |

普通页面正文反射不会被当作命中。

## Payload 变体

`rules.yaml` 包含：

- 完整 URL
- 协议相对 URL
- userinfo 白名单绕过
- 路径/片段白名单绕过
- scheme 大小写变形
- 单/双 URL 编码
- 反斜杠归一
- CRLF、LF、双编码、`%u000d%u000a`

`deep_tamper: true` 时启用 extra 绕过变体。

## 配置

```yaml
plugins:
  redir:
    enabled: true
    deep_tamper: true
```

## 输出结构

```json
{
  "type": "redir",
  "method": "redir",
  "param_place": "query",
  "param_name": "next",
  "evidence": {
    "technique": "开放重定向",
    "payload": "https://pass-scan.example.com/",
    "location": "https://pass-scan.example.com/",
    "resolved_url": "https://pass-scan.example.com/"
  }
}
```

## 限制

- 开放重定向只确认响应声明的跳转目标，不执行浏览器跳转链。
- Header 注入只确认 HTTP 响应头中真实出现注入 header。
- 极长 token/纯数字参数会被筛掉以降低噪声。

## 方案设计说明

重定向/响应头注入插件的目标是证明“用户输入能控制 HTTP 跳转语义或响应头结构”。它不把正文反射当成漏洞，而是只关注浏览器或客户端会解释的响应位置：Location、Refresh、meta refresh 和响应头。

整体方法是：

1. 先做语义筛选，找到可能进入跳转或响应头的参数。
2. 建立 baseline，记录原响应头和跳转状态。
3. 对候选参数注入唯一外部域名或唯一 header marker。
4. 不跟随跳转，保留原始 3xx 响应。
5. 解析 Location、Refresh、meta refresh 或响应头。
6. 只有控制目标真实进入这些位置才确认。

### 为什么需要语义筛选

开放重定向和 CRLF 如果对所有参数都打，会产生大量噪声。插件优先关注：

- 参数名像 `url`、`next`、`redirect`、`return`、`goto`。
- 参数值本身像 URL 或路径。
- 接口路径像登录、OAuth、SSO、下载、导出、跳转。
- 响应已有 3xx、Location、Refresh。
- 参数名像 filename、header、download 等可能进入响应头。

这能把检测集中在真正可能影响响应控制语义的位置。

### 开放重定向确认

开放重定向的确认点不是响应正文，而是：

- `Location` header。
- `Refresh` header。
- HTML meta refresh。

插件注入唯一外部域名，并解析最终跳转目标。如果响应声明的跳转目标解析到该域名，就确认开放重定向。

不自动跟随跳转是有意设计：

- 可以保留原始 Location 证据。
- 避免访问外部目标。
- 避免被浏览器行为或二次跳转干扰。

### CRLF/响应头注入确认

响应头注入通过唯一 `X-Pass-Scan-*` header 确认。只有服务端响应头中真的出现该 header，才算命中。

这避免了以下误报：

- payload 在正文中反射。
- payload 被日志页面输出。
- payload 出现在 JSON 字段里。
- 服务端把换行编码显示出来但没有进入响应头结构。

### Payload 变体

开放重定向和 CRLF 都常被简单过滤。payload 覆盖：

- 完整 URL。
- 协议相对 URL。
- userinfo 白名单绕过。
- path/fragment 白名单绕过。
- scheme 大小写。
- 单/双 URL 编码。
- 反斜杠归一。
- CRLF、LF、双编码、`%u000d%u000a`。

基础 payload 处理常规场景，deep tamper 追加更强绕过。

### 确认标准

confirmed 证据包括：

- Location/Refresh/meta refresh 指向唯一外部域名。
- 响应头中出现唯一注入 header。
- payload 和解析后的目标在报告中可对应。

不确认的情况：

- payload 只出现在正文。
- 服务端把 payload 编码后显示。
- 只返回通用错误页面。
- 跳转目标仍在同源或被安全网关改写。

### 安全边界

插件只使用 benign 外部域名和 marker header，不构造钓鱼内容，不尝试缓存投毒，不跟随外部跳转。验证目标是证明控制能力，而不是利用用户行为。

### 方案讲解重点

这个插件的重点是“响应语义位置”。开放重定向必须进入跳转位置，CRLF 必须进入响应头结构。通过不跟随跳转、唯一 marker 和严格解析，插件能把正文反射和真实响应控制区分开。
