# XSS 检测技术文档

`pass_scan/xss` 是 XSS 检测插件。它把反射型、存储型和可被 payload 证明的脚本上下文问题统一为 `xss` 一个漏洞类型，用 `evidence.origin` 和 `evidence.xss_context` 描述出现时机与落点。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `xss` |
| 命令行 | `python3 run.py --xss` |
| 漏洞输出 | `logs/vulns.jsonl`、`report.html` |
| marker 输出 | `logs/xss_markers.jsonl` |
| 规则文件 | `pass_scan/xss/rules.yaml` |

核心文件：

| 文件 | 职责 |
| --- | --- |
| `xss_scanner.py` | 调度接口、主动注入、回扫、结果输出 |
| `context.py` | HTML/属性/JS/注释/RAWTEXT 上下文识别 |
| `marker_store.py` | marker 持久化和跨页面回扫 |
| `rules.py` | YAML 规则加载 |
| `rules.yaml` | marker、上下文 payload、闭合字符要求 |

## 流量筛选

`interested(context)` 的逻辑：

1. 全局跳过项不扫描。
2. GET/POST 且存在 query/form/json 参数时，进入主动注入；普通模式不要求当前响应是 HTML。
3. 没有参数但当前响应是 HTML 时，进入 marker 回扫。
4. `--full-payload-scan` 时额外扫描 Cookie/Header。

这样可以覆盖“提交接口返回 JSON，但内容稍后出现在 HTML 页面”的存储型场景。

## 主动注入流程

1. 用纯字母数字 locator 替换参数值并发送请求。
2. 将 locator 登记到 `MarkerStore`，供后续 HTML 响应回扫。
3. 如果 locator 在当前响应出现，调用 `context.py` 判断落点：
   - `html_text`
   - `rawtext:<tag>`
   - `attr_double`
   - `attr_single`
   - `attr_unquoted`
   - `js_string_double`
   - `js_string_single`
   - `js_code`
   - `html_comment`
   - `url_attr`
4. 按落点从 `rules.yaml` 选择 payload。
5. 判断 marker 之间的闭合字符是否原样存活且未被实体编码。

命中后：

- `origin: immediate` 表示当次注入响应命中。
- `confidence: confirmed` 表示闭合字符满足可执行上下文。

## 跨页面回扫

每个 HTML 响应都会查找历史 marker：

- 如果 marker 出现在注入请求自己的响应里，不重复报告。
- 如果出现在后续页面且落在 HTML 文本区，标记 `origin: persisted`、`confidence: confirmed`。
- 如果落在属性、RAWTEXT、JS 字符串等需要额外闭合的位置，标记 `confidence: suspected`，供人工确认。

本插件不做纯 DOM 静态猜测。没有执行浏览器 JS 时，单靠 `innerHTML`、`location.hash` 等关键字容易误报；只有 payload 被证明进入可执行上下文才确认。

## Payload 与绕过

XSS 没有独立 WAF/tamper 阶段。不同标签、事件、闭合方式、无空格写法和通用标签直接放在 `rules.yaml` 的基础 payload 中。判定重点是结构字符是否存活，而不是某个具体标签是否执行。

## 配置

```yaml
plugins:
  xss:
    enabled: true
    rescan: true
    # worker_count: 3
    # queue_size: 200
```

`rescan: false` 会关闭 HTML 响应回扫，降低开销但会漏掉跨页面渲染。

## 输出结构

```json
{
  "type": "xss",
  "method": "xss",
  "url": "https://example.com/profile",
  "param_place": "form",
  "param_name": "bio",
  "evidence": {
    "origin": "persisted",
    "xss_context": "html_text",
    "confidence": "confirmed",
    "marker": "psx...",
    "matched_chars": ["<", ">"],
    "sample_exploit": "<img src=x onerror=alert(1)>"
  }
}
```

## 限制

- 存储型 XSS 只有在后续浏览到展示页面时才能发现。
- 纯 DOM XSS 不做静态猜测。
- Cookie/Header 注入需要全量扫描模式。

## 方案设计说明

XSS 插件的核心目标是证明“可控输入进入了可执行的前端上下文”。它没有把 XSS 简单理解成“响应里反射了 payload”，而是把检测拆成 locator、上下文识别、payload 选择和 marker 回扫四个阶段。

整体方法是：

1. 先注入一个纯字母数字 locator。
2. 观察 locator 是否出现在当前响应。
3. 如果出现，分析它所在的 HTML/JS/属性上下文。
4. 根据上下文选择闭合 payload。
5. 检查关键结构字符是否存活。
6. 同时把 locator 保存起来，用后续 HTML 页面回扫存储型场景。

### 为什么先打 locator

直接打 `<script>alert(1)</script>` 这类 payload 有两个问题：

- 很多页面会过滤尖括号，无法判断过滤发生在哪个阶段。
- payload 出现在响应中并不等于能执行，可能只是文本、属性值、注释或编码后的字符串。

所以插件先注入一个没有特殊字符的 locator。locator 的作用是定位反射点，而不是直接利用。找到反射点后，再根据上下文构造合适 payload。

### 上下文识别

同一个参数在不同位置需要完全不同的 payload。插件会识别以下上下文：

| 上下文 | 风险点 |
| --- | --- |
| HTML 文本 | 需要 `<`、`>` 存活 |
| RAWTEXT | 需要闭合 `textarea`、`title`、`script` 等标签 |
| 双引号属性 | 需要 `"` 和事件属性或标签闭合 |
| 单引号属性 | 需要 `'` 和事件属性或标签闭合 |
| 无引号属性 | 需要空白、`>` 或事件处理器 |
| JS 字符串 | 需要闭合字符串和语句 |
| JS 代码 | 需要形成合法 JS 表达式 |
| HTML 注释 | 需要闭合 `-->` |
| URL 属性 | 需要 `javascript:` 或可执行 URL 语义 |

这个设计比普通反射匹配更可靠，因为它把“反射”升级成“上下文可执行性判断”。

### Payload 选择

payload 规则按上下文组织。每个 payload 都有 required chars，例如 `<`、`>`、`"`、`'`、空白、`=` 等。检测时不仅看 payload 是否反射，还看这些结构字符是否原样存活。

例如：

- HTML 文本区重点检查 `<img ... onerror=...>` 的尖括号和事件结构。
- 属性值中重点检查引号能否闭合。
- JS 字符串中重点检查字符串闭合和语句拼接。
- 注释中重点检查能否跳出注释。

如果结构字符被实体编码或删除，就不能直接 confirmed。

### 即时命中和存储型回扫

XSS 分两类观察路径：

| 路径 | 说明 |
| --- | --- |
| immediate | 注入请求自己的响应中已经出现可执行上下文 |
| persisted | 后续其他 HTML 页面出现历史 marker |

存储型 XSS 的难点在于提交接口和展示接口通常不是同一个 URL。插件通过 `MarkerStore` 保存历史 marker，每个 HTML 响应都会回扫这些 marker。这样只要测试者后续浏览到展示页面，就有机会确认存储型 XSS。

### 为什么不做纯 DOM 猜测

DOM XSS 如果没有浏览器执行环境，单靠静态关键字很容易误报。例如页面里出现 `innerHTML`、`location.hash` 不等于一定可利用。因此当前插件不把“存在 DOM sink 关键字”直接报漏洞。只有 payload 或 marker 进入可执行上下文，才输出结果。

### 确认标准

confirmed 需要满足：

- 可控 marker 出现在响应或后续页面。
- 所在上下文可被识别。
- 对应 payload 所需结构字符存活。
- 样例 payload 能形成可执行结构。

suspected 或人工复核场景包括：

- marker 出现在属性、JS 字符串或 RAWTEXT 中，但缺少关键闭合字符。
- 后续页面出现 marker，但上下文不够明确。
- 响应被编码、压缩或截断导致无法确认。

### 误报控制

插件避免以下误报：

- 只反射 payload 文本但不可执行。
- payload 被 HTML 实体编码。
- marker 出现在注释、JSON 字符串或纯文本日志。
- 注入响应本身重复回扫导致重复报告。
- DOM sink 静态关键词。

### 安全边界

插件只使用 benign marker 和样例 payload，不窃取 Cookie，不外传数据，不加载外部恶意脚本。报告中的 `sample_exploit` 用于说明闭合方式，不代表真实攻击脚本。

### 方案讲解重点

这个插件的核心价值是“上下文感知”。普通 XSS 检测容易停留在反射匹配，而这里把反射点拆解成上下文、闭合字符和跨页面生命周期。这样既能覆盖反射型，也能在被动浏览过程中发现存储型，同时避免把不可执行反射当成漏洞。
