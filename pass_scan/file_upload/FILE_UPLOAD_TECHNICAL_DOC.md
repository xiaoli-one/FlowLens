# 文件上传检测技术文档

`pass_scan/file_upload` 检测文件上传入口的危险扩展、脚本执行、主动内容、图片马和 `.htaccess` 绕过。它只让上传语义明显的流量入队。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `file_upload` |
| 命令行 | `python3 run.py --upload` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/file_upload/rules.yaml` |

## 候选入口

支持方法：

- POST
- PUT
- PATCH

候选来源：

- multipart 文件 part
- multipart 中名称像 upload/file/avatar/image 的 part
- 二进制 PUT/PATCH body
- upload/file 路径上的原始 body
- form/json 中的 base64 或 data URI 文件字段

单条原始请求体超过 `max_original_body_bytes` 时跳过，避免复制大型视频或压缩包。

## 检测流程

1. 上传 harmless 文本 canary。
2. 从响应中的 URL、path、key、Location、JSON 字段等解析上传落点。
3. 访问候选 URL，确认 canary 是否可取回或响应是否明确接受上传。
4. 发送危险扩展、主动内容、图片马、`.htaccess`、中间件解析绕过等 payload。
5. 访问上传 URL 和派生 URL，确认 marker、脚本执行结果或 inline 主动内容。
6. 对确认包含自身 marker 的文件尝试 DELETE 清理。
7. 如果当前请求无法确认落点，登记 pending；后续页面出现 marker/文件名时报告延迟上传结果。

## Payload 类型

| kind | technique |
| --- | --- |
| `script` | 脚本文件执行、危险扩展文件可上传、中间件解析执行 |
| `active_content` | HTML/SVG 主动内容文件可上传 |
| `image_polyglot` | 图片马脚本执行、图片马可上传、图片马上传接受 |
| `htaccess` | `.htaccess` 文件可上传、`.htaccess 文件上传接受` |
| `.htaccess chain` | `.htaccess 解析绕过` |
| `canary` | 基线文件上传 |

脚本扩展包括 PHP、JSP、ASP/ASPX/ASHX 等；绕过文件名包括双扩展、大小写、尾随点、分号、Nginx/PHP-FPM PathInfo、Tomcat/IIS/Apache 多后缀等。

## 配置

```yaml
plugins:
  file_upload:
    enabled: true
    max_original_body_bytes: 5242880
    max_payloads_per_candidate: 30
    max_verify_urls: 24
    upload_timeout_seconds: 10
    verify_timeout_seconds: 3
    allow_external_verification: true
    cleanup_uploaded_files: true
```

## 输出结构

```json
{
  "type": "file_upload",
  "method": "file_upload",
  "param_place": "multipart",
  "param_name": "file",
  "evidence": {
    "technique": "脚本文件执行",
    "filename": "pass-scan-xxxx.php",
    "verified_url": "https://example.com/uploads/pass-scan-xxxx.php",
    "marker": "xxxx",
    "confidence": "high"
  }
}
```

## 限制

- 会向目标上传随机 canary 文件，只能在授权范围内使用。
- 上传落点需要能从响应或后续页面中推断。
- 外部 URL 验证默认开启，用于 CDN/对象存储落点；可通过配置关闭。

## 方案设计说明

文件上传插件的目标是验证“上传入口是否允许危险文件进入可访问或可解析位置”。它不把“上传请求返回 200”直接当漏洞，而是继续追踪上传落点、访问上传结果，并判断文件是否可读、可执行或可触发主动内容。

整体方法是：

1. 只让上传语义明显的流量入队。
2. 先上传 harmless canary，确认上传入口和落点。
3. 从响应中提取 URL、path、key、Location 和 JSON 字段。
4. 访问候选落点确认 canary 是否可取回。
5. 再按风险顺序尝试危险扩展、主动内容、图片马、解析绕过和 `.htaccess` 链。
6. 访问原始 URL 和派生 URL，判断 marker、脚本执行结果或 inline 主动内容。
7. 对确认包含自身 marker 的文件尝试清理。

### 为什么先做 canary

上传接口形态差异很大。直接上传危险扩展会带来风险，也可能因为无法确认落点而浪费请求。先上传文本 canary 有几个作用：

- 确认这个入口确实能保存文件。
- 学习响应里如何返回文件 URL 或 key。
- 判断文件是否能被公开访问。
- 为后续危险 payload 生成验证 URL。
- 降低第一步对目标的风险。

### 候选入口筛选

插件只关注明显上传入口：

- multipart 文件 part。
- 文件字段名，如 `file`、`upload`、`avatar`、`image`。
- 二进制 PUT/PATCH。
- upload/file 路径上的原始 body。
- form/json 中 base64 或 data URI 文件字段。

大型请求体会被跳过，避免复制视频、压缩包等大文件造成负担。

### 落点解析

上传是否有风险，关键取决于文件最后在哪里。插件会从多个位置提取落点：

- `Location` header。
- JSON 字段。
- 响应正文中的 URL。
- 相对路径。
- object key。
- 文件名。

还会生成派生 URL，例如：

- 原始返回路径。
- 同目录下危险扩展路径。
- PathInfo 派生路径。
- Nginx/PHP-FPM、Tomcat、IIS、Apache 多后缀解析路径。

### Payload 分层

上传 payload 按风险和验证目标分层：

| 层级 | 目的 |
| --- | --- |
| canary 文本 | 确认上传和可访问落点 |
| 危险扩展 | 验证是否允许上传脚本文件 |
| 主动内容 | 验证 HTML/SVG 是否能 inline 执行 |
| 图片马 | 验证图片格式伪装和解析链 |
| 双扩展/大小写/尾随点 | 验证文件名过滤绕过 |
| PathInfo/目录解析 | 验证中间件解析差异 |
| `.htaccess` | 验证 Apache 解析规则绕过 |

脚本执行只有在访问上传文件后看到执行 marker，才认为是高危执行。

### 延迟结果发现

有些上传接口不会立即返回最终 URL，文件名或 marker 可能出现在后续页面。插件会登记 pending 信息，后续被动页面里如果出现 marker 或文件名，再补充报告延迟上传结果。

这个设计适合头像、附件、工单文件等“上传后在另一个页面展示”的场景。

### 确认标准

不同风险对应不同确认条件：

- 基线文件上传：canary 被上传并可访问。
- 危险扩展可上传：危险文件被接受，但未执行。
- 主动内容：HTML/SVG 被 inline 返回并保留 marker。
- 图片马：真实图片结构被接受并可访问。
- 脚本执行：访问上传文件后返回脚本执行 marker。
- `.htaccess` 链：上传规则文件后，后续文件按新规则解析。

不确认的情况：

- 上传请求 200 但找不到文件落点。
- 响应只是返回前端预览数据。
- 文件内容被服务端改写导致 marker 不存在。
- 危险扩展被改名为安全后缀。

### 安全边界

插件只上传随机 canary 和 harmless marker，不上传真实 webshell，不覆盖已有文件，不持久化后门。清理只尝试删除确认属于自身 marker 的文件，失败则静默记录。

### 方案讲解重点

这个插件的重点是“上传链路闭环”。上传漏洞不能只看接口是否接受文件，而要确认文件是否可访问、是否保持内容、是否被解析执行、是否能通过中间件规则绕过。canary 和落点解析是整个检测的基础。
