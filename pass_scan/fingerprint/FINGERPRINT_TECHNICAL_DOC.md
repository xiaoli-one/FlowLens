# 指纹识别技术文档

`pass_scan/fingerprint` 用于识别目标技术栈、框架、中间件、CMS 和开源应用。它被动优先，主动补包为辅，不写漏洞结果，而是写入指纹结果。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `fingerprint` |
| 命令行 | `python3 run.py --fp` |
| 结果输出 | `logs/fingerprints.jsonl` |
| 未知 favicon | `logs/fingerprints_unknown.jsonl` |
| 规则文件 | `pass_scan/fingerprint/rules.yaml`、`rules.generated.yaml` |
| 公开库来源 | Wappalyzer、EHole、FingerprintHub |

## 识别流程

```text
mitm_addon.response()
  -> build_scan_context()
  -> fingerprint.interested(context)
  -> dedup_key(host + 归一真实路径)
  -> ScanQueue worker
  -> collect_passive_signals()
  -> match()
  -> 被动未命中且 active_probe=true 时 add_active_signals()
  -> match()
  -> write_result()
```

## 持续路径采样

指纹识别不会因为同一 host 已经识别到某个指纹就停止。每条后续真实路径仍会继续做被动识别，发现的新指纹会在报告里聚合到同一个 host。

调度去重使用“归一真实路径”：

- `/app/login` 和 `/app/swagger` 会分别识别，便于发现后续路径里的管理后台、API 文档等新指纹。
- `/article/1` 和 `/article/2` 会归一为同一个样本，避免动态 ID 路径爆炸。
- `max_paths_per_host` 控制每个 host 最多识别多少个归一真实路径样本。

## 主动补包限流

`path_segment_depth` 只控制主动补包按几级路径段限流：

- `1`：`/grafana/login` 归为 `/grafana`
- `2`：`/a/b/c` 归为 `/a/b`

同一个路径段只主动补抓一次入口页和 favicon；后续同段新路径仍会继续被动识别，但不会重复主动补包。这样可以持续发现新指纹，同时避免每个 URL 都触发主动请求。

## 信号来源

| 信号 | 来源 | 示例 |
| --- | --- | --- |
| `header` | 响应头 | `Server`、`X-Powered-By` |
| `cookie` | 请求 Cookie 名、Set-Cookie 名 | `JSESSIONID`、`PHPSESSID` |
| `body` | 响应正文 | meta generator、静态资源路径、页面关键字 |
| `title` | HTML title | Jenkins、Grafana 等 |
| `url` | 完整 URL | `/actuator`、`/nacos/` |
| `favicon` | `/favicon.ico` mmh3 hash | 开源应用精确识别 |

## 被动优先

`check()` 先只用当前流量已有信号匹配。若当前路径已识别出值得上报的 CMS、应用框架、管理后台、API 文档或中间件控制台，本路径不主动发包，但同一 host 后续其它路径仍会继续识别。

如果被动阶段只命中 Nginx、PHP、jQuery、HSTS、统计/CDN 等低价值指纹，默认不输出这些结果，也不会让它们截停主动补包。只有过滤后仍未命中且 `active_probe: true` 时，才补抓：

- 当前触发路径
- 归一路径段入口
- 站点级 `/favicon.ico`

favicon hash 使用 Shodan/FOFA 常见的 mmh3 32 位有符号 hash。抓到 favicon 但没有规则命中时，会写入 `fingerprints_unknown.jsonl` 方便补库。

## 规则匹配

单条指纹包含多个 matcher，任一 matcher 命中即识别。matcher 可基于 header、cookie、body、title、url、favicon，并可通过 `version` 正则提取版本。cookie 名支持精确匹配，也支持 Wappalyzer 导入的正则 cookie 名。

生成规则库来自 Wappalyzer、EHole 和 FingerprintHub。当前生成结果为 6646 条规则：Wappalyzer 5259 条、EHole 958 条、FingerprintHub 1546 条，合并前 7763 条；多来源同名规则会合并，并按 matcher 结构去重。FingerprintHub 导入时会先按应用、CMS、框架、后台、API 文档和中间件控制台倾向做过滤。

识别后会处理 `implies` 推导，例如识别 WordPress 后可推导 PHP。默认输出会过滤 PHP/Java/Apache/Nginx/前端库/统计/CDN 等低价值结果，也会过滤未命中高价值类别或关键词的普通技术类结果；设置 `report_low_value: true` 可恢复全量输出。结果按 host 聚合，同名指纹跨路径去重；后续路径识别出的其它新指纹会继续追加到同一目标。

## 配置

```yaml
plugins:
  fingerprint:
    enabled: true
    path_segment_depth: 1
    max_paths_per_host: 25
    active_probe: true
    fetch_favicon: true
    report_low_value: false
    output_file: logs/fingerprints.jsonl
    unknown_file: logs/fingerprints_unknown.jsonl
```

## 输出结构

```json
{
  "host": "example.com",
  "path_segment": "/grafana",
  "url": "https://example.com/grafana/login",
  "detected": [
    {
      "name": "Grafana",
      "category": "Application",
      "version": "10.2.0",
      "evidence": "body:grafana-app"
    }
  ]
}
```

## 限制

- 指纹识别不执行 JavaScript。
- 主动补包只做轻量 GET，不做爬取。
- 同一 host 会持续采样后续真实路径，但受 `max_paths_per_host` 限制。
- 规则准确率取决于规则库质量；未知 favicon 需要后续补充规则。

## 方案设计说明

指纹识别插件不是漏洞检测插件，但它是整个扫描器的重要资产识别能力。它的目标是从被动流量中识别目标技术栈、框架、中间件、CMS、管理后台和 API 文档，并为后续漏洞判断提供上下文。

整体方法是：

1. 被动收集当前响应中的 header、cookie、body、title、url 信号。
2. 使用规则库匹配技术指纹。
3. 如果被动信号不足，按路径段做轻量主动补包。
4. 抓取 favicon 并计算 mmh3 hash。
5. 过滤低价值指纹，优先报告对安全决策有用的应用和组件。
6. 同一 host 持续采样不同路径，最终在报告里聚合。

### 被动优先的原因

指纹识别不需要大量主动请求。真实业务流量里已经包含大量信号：

- `Server`。
- `X-Powered-By`。
- `Set-Cookie` 名称。
- HTML title。
- meta generator。
- 静态资源路径。
- 前端全局变量。
- API 文档路径。
- 管理后台关键字。

被动优先可以降低噪声，并且不会影响目标。

### 持续路径采样

一个站点不同路径可能暴露不同指纹：

- 首页只暴露 Nginx。
- `/grafana/login` 暴露 Grafana。
- `/swagger-ui/` 暴露 Swagger。
- `/actuator` 暴露 Spring Boot Actuator。
- `/nacos/` 暴露 Nacos。

所以插件不会因为 host 已经识别过就停止，而是按归一真实路径持续采样。动态 ID 路径会折叠，避免 `/article/1`、`/article/2` 这类路径吃光预算。

### 主动补包设计

主动补包只在被动结果不足时触发，并按路径段限流。补包对象包括：

- 当前触发路径。
- 路径段入口。
- 站点级 favicon。

它不是爬虫，不会递归抓链接。这样既能提升识别率，又不会造成大量请求。

### 规则库取舍

规则库来源包括 Wappalyzer、EHole、FingerprintHub。不同来源规则质量和粒度不同，所以导入后需要合并和过滤：

- 同名规则合并。
- matcher 去重。
- 支持 implies 推导。
- 默认过滤低价值结果。

低价值指纹如 Nginx、PHP、jQuery、统计脚本、CDN、HSTS 等并不是完全没用，但在漏洞报告中容易淹没真正重要的应用指纹，因此默认不输出。需要全量资产画像时可以开启 `report_low_value`。

### Favicon hash

很多开源应用和管理后台的 favicon 很稳定。插件会抓取 `/favicon.ico`，计算 Shodan/FOFA 常用的 mmh3 hash，用于精确识别。

如果 favicon 抓到了但规则库没有命中，会写入 `fingerprints_unknown.jsonl`，方便后续补充规则。

### 确认标准

指纹结果不是漏洞，所以不使用 confirmed/high 这类漏洞语义。它更关注：

- 命中的规则名。
- 技术类别。
- 版本号。
- 证据来源。
- host 和触发路径。

报告会按 host 聚合，减少重复。

### 误报控制

指纹误报主要来自通用关键词和前端依赖。控制手段包括：

- 高价值类别优先。
- 多来源规则合并去重。
- cookie、header、title、favicon 等强信号优先。
- 低价值技术默认过滤。
- 同一 host 同名指纹跨路径去重。

### 方案讲解重点

这个插件的重点是“资产上下文”。它不直接报漏洞，而是帮助理解目标是什么技术栈、哪些路径暴露了管理后台或 API 文档、后续哪些漏洞插件或人工验证应优先关注。被动持续采样和主动轻量补包之间的平衡，是它的核心设计。
