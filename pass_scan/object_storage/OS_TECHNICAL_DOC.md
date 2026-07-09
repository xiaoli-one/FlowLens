# OSS/对象存储检测技术文档

`pass_scan/object_storage` 负责对象存储桶发现和风险检测。它是 `observer_only` 插件：先从流量中被动发现桶线索，确认桶存在后再把桶目标提交到独立队列。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `object_storage` |
| 命令行 | `python3 run.py --oss` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 阶段 | `observe(context)` 发现桶，`check(target)` 检测桶风险 |

## 支持的服务

- Aliyun OSS
- AWS S3 / S3-compatible
- Tencent COS
- Huawei OBS
- Google Cloud Storage
- Azure Blob
- Baidu BOS
- Volcengine TOS
- Qiniu Kodo
- Upyun
- JDCloud OSS
- UCloud UFile
- Kingsoft KS3
- 带对象存储响应头的自定义域名

## 发现阶段

`observe(context)` 会从以下位置提取线索：

- 当前请求 URL
- 响应正文中的 URL 和域名
- JS/JSON 配置里的 bucket、endpoint、uploadUrl、baseUrl 等赋值
- 响应头里的对象存储特征
- 当前流量中的 AK/SK

发现候选后，用短超时 GET 请求确认桶是否存在。确认后立即输出“存在存储桶”，并把桶目标入队。

## 风险检测

| method | 说明 |
| --- | --- |
| `object_storage_bucket` | 确认存在存储桶 |
| `object_storage_listable` | 匿名列举/遍历 |
| `object_storage_upload` | 匿名 PUT 新对象成功 |
| `object_storage_overwrite` | 匿名覆盖同一路径成功 |
| `object_storage_credential` | 当前流量、列举结果或公开文本对象中发现 AK/SK |

写入检测会创建随机 `pass-scan-canary/<uuid>.txt` 小文件，并尽量 DELETE 清理；不会覆盖已有对象。

## 配置

```yaml
plugins:
  object_storage:
    enabled: true
    active_probe: true
    active_write_probe: true
    scan_listed_objects: true
    max_buckets_per_context: 8
    max_domains_per_context: 40
    discovery_timeout: 4
    max_listed_objects_scan: 12
    max_scan_chars: 400000
    max_active_body_bytes: 262144
```

## 输出结构

```json
{
  "type": "object_storage",
  "method": "object_storage_listable",
  "url": "https://bucket.oss-cn-hangzhou.aliyuncs.com/",
  "evidence": {
    "provider": "aliyun_oss",
    "bucket": "bucket",
    "endpoint": "oss-cn-hangzhou.aliyuncs.com",
    "list_url": "https://bucket.oss-cn-hangzhou.aliyuncs.com/?list-type=2",
    "object_count": 10,
    "object_samples": ["a.txt", "public/config.js"]
  }
}
```

## 限制

- 桶发现依赖流量中出现可识别域名、endpoint 或配置。
- 匿名写入检测会触碰目标存储桶，仅应在授权范围内启用。
- 自定义 CDN 域名需要响应头或探测结果足够像对象存储才能确认。

## 方案设计说明

对象存储插件的目标是发现“业务流量中暴露的对象存储桶”和“桶的匿名访问风险”。它采用 observer-only 设计：先在被动流量里找桶线索，确认桶存在后再把桶作为独立目标入队。

整体方法是：

1. 从 URL、响应正文、JS/JSON 配置和响应头中提取对象存储线索。
2. 识别 provider、bucket、endpoint 和访问风格。
3. 用短超时请求确认桶存在。
4. 输出“存在存储桶”信息类结果。
5. 对确认的桶做匿名列举、匿名读、匿名写 canary 和 AK/SK 扫描。
6. 写入 canary 后尽量清理。

### 为什么先发现再入队

对象存储检测对象不是当前 HTTP 参数，而是一个外部桶资源。被动流量中可能出现大量 URL、CDN 域名和配置片段。如果每个线索都进入漏洞队列，会造成请求爆炸。

所以插件先做轻量确认：

- 域名是否符合 provider 规则。
- 响应头是否像对象存储。
- 访问根路径是否返回桶特征。
- URL 是否包含 bucket 和 endpoint。

只有确认足够像桶，才进入后续风险检测。

### Provider 建模

对象存储服务差异很大，插件按 provider 建模：

- Aliyun OSS。
- AWS S3 / S3-compatible。
- Tencent COS。
- Huawei OBS。
- Google Cloud Storage。
- Azure Blob。
- Baidu BOS。
- Volcengine TOS。
- Qiniu。
- Upyun、JDCloud、UCloud、KS3。
- 自定义对象存储域名。

建模内容包括：

- 域名后缀。
- virtual-host style 和 path style。
- list 参数。
- provider 响应头。
- 错误 XML/JSON 特征。

### 风险能力分层

对象存储结果不是一个单一漏洞，而是一组能力：

| 能力 | 风险含义 |
| --- | --- |
| 桶存在 | 暴露了对象存储资产信息 |
| 匿名列举 | 未授权用户可遍历对象列表 |
| 匿名读取 | 公开对象可被访问 |
| 匿名上传 | 未授权用户可写入新对象 |
| 匿名覆盖 | 未授权用户可覆盖同一路径对象 |
| AK/SK 泄漏 | 公开内容中暴露访问凭据 |

报告会用 method 区分这些能力，避免把信息类发现和高危写入混在一起。

### Canary 写入

匿名写入验证必须避免影响真实对象，所以插件只操作随机 canary：

```text
pass-scan-canary/<uuid>.txt
```

流程是：

1. PUT 一个随机小文本对象。
2. GET 该对象确认内容可读。
3. PUT 同一路径新内容确认覆盖 canary 的能力。
4. 尝试 DELETE 清理。

不会覆盖已有对象，也不会递归删除。

### AK/SK 扫描

AK/SK 可能出现在：

- 当前业务响应。
- 公开列举结果。
- 少量公开文本对象。
- JS/JSON 配置。

插件会限制扫描字符数和列举对象数量，避免抓取大量数据。

### 误报控制

对象存储误报常见于 CDN、自定义静态站点和普通下载域名。插件通过以下方式控制：

- provider 域名和响应头双重识别。
- 桶错误 XML/JSON 特征匹配。
- list 参数响应结构校验。
- canary 读写只对确认桶执行。
- 自定义域名需要更多对象存储特征。

### 安全边界

匿名写入是有副作用的能力验证，只能在授权范围启用。插件默认写随机小文件并尽量清理，不覆盖真实对象，不修改 ACL，不读取大量对象。

### 方案讲解重点

这个插件的核心是“资产发现和权限能力拆分”。先把散落在流量里的桶线索归一成对象存储目标，再分别验证存在、列举、读取、写入和凭据泄漏能力。canary 机制用于证明写权限，同时降低对真实数据的影响。
