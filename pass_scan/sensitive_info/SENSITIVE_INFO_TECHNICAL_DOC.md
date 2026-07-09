# 敏感信息泄漏检测技术文档

`pass_scan/sensitive_info` 负责被动扫描响应中的敏感信息，并对每个 host + 应用路径段轻量探测常见泄漏端点。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `sensitive_info` |
| 命令行 | `python3 run.py --sensitive` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则位置 | 规则正则和端点列表在 `si_scanner.py` |

## 检测范围

被动扫描：

- HTML、JS、JSON、XML、YAML、properties、env、日志等文本响应。
- 响应头。
- 静态 JS、map、配置类文本资源也会进入检测。

主动探测：

- 目录列出
- `.git/`
- `.svn/`
- `.env` 及环境变体
- `.DS_Store`
- Java/Spring 配置文件
- `WEB-INF/web.xml`
- Swagger/OpenAPI 文档
- Spring Boot actuator

主动探测按 host + 路径段去重，避免同一应用重复探测。

## 敏感类型

检测类别包括：

- 私钥
- 云厂商 AccessKey/SecretKey
- 通用 API key/token/client secret
- 地图 key
- 数据库连接串
- `.env` 泄漏
- Java/Spring 配置文件泄漏
- `.DS_Store`
- 目录列出
- `.git` 泄漏
- `.svn` 泄漏
- Swagger/OpenAPI 泄漏
- Actuator 泄漏

规则会过滤常见占位符和示例值，降低误报。

## 配置

```yaml
plugins:
  sensitive_info:
    enabled: true
    active_probe: true
    path_segment_depth: 1
    max_scan_chars: 300000
    max_active_body_bytes: 262144
    # active_endpoints:
    #   - .git/
    #   - .env
```

## 输出结构

```json
{
  "type": "sensitive_info",
  "method": "sensitive_info",
  "url": "https://example.com/app.js",
  "evidence": {
    "technique": "被动响应检测",
    "sensitive_type": "AK/SK",
    "sources": ["response.body"],
    "match_count": 2,
    "subtypes": ["aliyun"]
  }
}
```

## 限制

- 正则匹配会尽量过滤占位符，但仍可能需要人工复核。
- 主动端点探测只做常见路径，不做目录爆破。
- 单个响应按 `max_scan_chars` 截断参与匹配。

## 方案设计说明

敏感信息插件的目标是发现“已经通过当前流量暴露出来的秘密、配置和调试入口”，并用轻量主动探测补充常见泄漏路径。它不是目录爆破器，也不是密钥滥用工具；它只确认泄漏内容是否存在、来源在哪里、类型是什么。

整体方法是：

1. 被动扫描所有适合文本分析的响应。
2. 对 JS、JSON、配置、map、日志等资源保持较高关注。
3. 从响应头和响应正文中匹配敏感规则。
4. 过滤示例值、占位符和低置信模式。
5. 按 host + 路径段主动探测少量高价值泄漏端点。
6. 统一生成敏感类型、来源、匹配数量和证据片段。

### 被动优先

敏感信息最适合被动优先。原因是：

- 真实业务页面和静态资源里经常已经包含泄漏线索。
- 被动扫描不会增加目标压力。
- 可以覆盖前端构建产物、JS 配置、接口响应、错误页面。

插件不会因为全局过滤跳过所有静态资源。JS、map、JSON、配置类文本资源对敏感信息检测很重要，因此会被额外纳入。

### 主动探测边界

主动探测只覆盖少量高价值端点：

- `.git/`
- `.svn/`
- `.env`
- `.DS_Store`
- Swagger/OpenAPI。
- Spring Boot actuator。
- Java/Spring 配置文件。
- 常见目录列出入口。

它不会做字典爆破，也不会递归目录。探测按 host + 应用路径段去重，避免同一个应用重复访问同一批端点。

### 敏感类型建模

检测规则按类型组织，而不是只输出“命中正则”。类型包括：

- 云厂商 AK/SK。
- API key、token、client secret。
- 私钥。
- 数据库连接串。
- 地图 key。
- `.env`。
- Java/Spring 配置。
- Swagger/OpenAPI。
- Actuator。
- Git/SVN。
- 目录列出。

报告里会保留 sensitive type、subtype、来源位置和样本片段，让复核者知道是什么类型的泄漏。

### 误报过滤

敏感信息检测天然容易误报，所以插件做了多层过滤：

- 过滤 `example`、`test`、`demo`、`your_key` 等占位符。
- 对 key/secret 组合做上下文判断。
- 对目录列出检查 HTML 结构而不是普通链接列表。
- 对 Swagger/Actuator 检查特征字段。
- 对 SPA 兜底页和通用 200 页面保持保守。
- 限制单响应最大扫描字符，避免超大资源拖慢正则。

### 确认标准

confirmed 或高置信证据通常需要：

- 敏感值符合格式。
- 上下文表明它是配置、密钥或调试入口。
- 来源是目标站响应或主动探测端点。
- 非明显占位符或示例值。

需要人工复核的情况：

- 只有疑似 token 格式，但没有上下文。
- API key 可能是公开前端 key。
- Swagger 是公开文档但无敏感操作。
- Actuator 只暴露健康检查。

### 安全边界

插件不会使用发现的密钥去调用第三方 API，不验证额度，不修改远程资源，不下载大量文件。它只证明泄漏存在，并给出来源和证据。

### 方案讲解重点

这个插件的重点是“被动发现 + 轻量确认”。敏感信息泄漏不是越多请求越好，而是要把真实流量里已经暴露的高价值线索识别出来，并通过少量常见端点探测补足配置泄漏场景。
