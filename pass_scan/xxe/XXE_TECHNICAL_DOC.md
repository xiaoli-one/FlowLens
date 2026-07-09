# XXE 检测技术文档

`pass_scan/xxe` 检测 XML 外部实体注入。XXE 的注入点不是普通单个参数，而是会被服务端 XML 解析器处理的 XML 文档。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `xxe` |
| 命令行 | `python3 run.py --xxe` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/xxe/rules.yaml` |
| OOB | `tools/interactsh_client.py` + `xxe/oob.py` |

## XML 注入点

`extract_xml_targets(context)` 支持：

1. 整个请求 body 是 XML：
   - Content-Type 是 `application/xml`、`text/xml` 或 `+xml`
   - body 本身看起来像完整 XML
2. 参数值本身是一段完整 XML 文档：
   - 普通模式扫描 query/form/json
   - 全量扫描额外扫描 Cookie/Header

插件支持 GET/POST/PUT/PATCH，只在存在 XML 注入点时入队。

## 检测通道

| technique | 判定方式 |
| --- | --- |
| `带外解析` | 外部实体、参数实体、外部 DTD 或 XInclude 指向唯一 OOB 域名，解析器回连即确认 |
| `带内文件读取` | 外部实体读取 `file:///etc/passwd` 等文件，响应出现文件 signature |
| `PHP 源码读取` | `php://filter` 读取源码，响应中的 base64 解码后出现 PHP 源码特征 |

OOB 优先发出，带内文件读取同步验证。OOB 回连异步到达时会关联 token 写入 finding。

## XML 组装策略

插件不使用完整 XML 解析器改写原请求，因为解析器会转义 `&` 和 DOCTYPE，影响攻击面。当前采用字符串级拆分：

- 保留或补充 XML 声明。
- 识别根元素名。
- 移除原 DOCTYPE，插入测试 DOCTYPE。
- 将实体引用注入叶子文本。
- 对 XInclude 构造最小根元素文档。

## Tamper

外部实体的主要形态放在基础 payload 中。编码类绕过作为独立 tamper：

- UTF-16
- UTF-7
- DOCTYPE 内换行

配置：

```yaml
plugins:
  xxe:
    enabled: true
    deep_tamper: true
    deep_tamper_max_profiles: 2
    oob:
      enabled: true
      poll_interval: 15
```

## 输出结构

```json
{
  "type": "xxe",
  "method": "xxe",
  "param_place": "body",
  "param_name": "body",
  "evidence": {
    "technique": "带外解析",
    "payload": "...",
    "oob_domain": "...",
    "oob_protocol": "dns",
    "confidence": "high"
  }
}
```

## 限制

- OOB 依赖目标可出网。
- 带内文件读取依赖响应回显实体内容。
- 非完整 XML 片段、HTML 片段不会进入 XXE 检测。

## 方案设计说明

XXE 插件的目标是证明“服务端 XML 解析器接受并解析了外部实体”。它和普通参数注入不同，真正的注入点不是某个字符串参数，而是 XML 文档被解析的过程。因此设计重点是先确认 XML 入口，再用带外和带内两条路径验证解析能力。

整体方法是：

1. 判断请求 body 或参数值是否是完整 XML。
2. 构造可被 XML 解析器接受的测试文档。
3. 优先插入外部实体或外部 DTD 指向 OOB 域名。
4. 同时尝试带内文件读取类实体。
5. 对不同 XML 写法、实体类型和编码方式做少量变体。
6. OOB 或文件特征命中后输出 finding。

### XML 入口识别

插件只处理可能进入 XML 解析器的内容：

- Content-Type 明确是 XML。
- body 以 XML 文档形态出现。
- query/form/json 中某个值本身是一段完整 XML。
- 全量扫描时额外考虑 Cookie/Header 中的 XML 片段。

非完整 XML 片段、HTML 片段、普通 JSON 字符串不会进入检测。这个限制是为了避免把普通文本参数错误地当作 XML 注入点。

### 为什么不用 XML 解析器重写请求

攻击载荷里经常需要 DOCTYPE、实体引用、外部 DTD、编码声明等结构。如果用普通 XML 解析器读入再输出，可能会：

- 转义实体引用。
- 丢弃或重排 DOCTYPE。
- 改变 XML 声明。
- 改变命名空间和根节点结构。

这些变化会破坏攻击面。所以插件采用字符串级 XML 组装：识别根元素、移除原 DOCTYPE、插入测试 DOCTYPE，再把实体引用放入叶子文本位置。

### OOB 解析确认

OOB 是最通用的 XXE 确认方式。payload 会让外部实体、参数实体或外部 DTD 指向唯一 OOB 域名。只要解析器尝试解析外部资源，就会触发 DNS/HTTP 回连。

OOB 能覆盖：

- 响应不回显实体内容。
- XML 解析发生在异步后端。
- 解析失败但已经尝试访问外部 DTD。
- 盲 XXE。

### 带内文件读取

如果目标不能出网，OOB 不会命中。带内文件读取提供另一条确认路径：

- Unix 读取 `/etc/passwd` 片段。
- Windows 读取 `win.ini` 片段。
- PHP 环境尝试 `php://filter` 读取源码并 base64 编码。

确认时只相信文件内容 signature，不把 payload 原样反射当命中。

### Payload 与 tamper

XXE payload 覆盖：

- 普通外部实体。
- 参数实体。
- 外部 DTD。
- XInclude。
- `file://`。
- `php://filter`。

Tamper 主要处理解析器和 WAF 差异：

- UTF-16。
- UTF-7。
- DOCTYPE 内换行和空白变化。

这些变体只在 deep tamper 或 WAF 场景中追加，避免请求量膨胀。

### 确认标准

confirmed 证据包括：

- OOB 收到与当前 token 匹配的 DNS/HTTP 回连。
- 响应出现目标文件 signature。
- PHP filter 的 base64 内容解码后出现 PHP 源码特征。

不确认的情况：

- XML payload 原样出现在响应里。
- 只有 XML 解析错误但没有外部实体证据。
- OOB 未命中。
- 响应只显示通用错误页。

### 安全边界

带内读取只使用低敏感系统文件片段或源码读取证明能力，不读取私钥、云凭据、数据库配置等敏感文件。OOB 只用于解析确认，不外传业务数据。

### 方案讲解重点

XXE 检测的关键在于“XML 解析器行为证明”。插件先确认 XML 入口，再用 OOB 证明外部资源解析，用带内 signature 证明实体内容回显，并通过字符串级组装避免 XML 序列化破坏载荷。
