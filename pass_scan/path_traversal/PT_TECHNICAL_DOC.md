# LFI/目录遍历/任意文件读取检测技术文档

`pass_scan/path_traversal` 检测目录遍历和任意文件读取。报告中统一为 `type=path_traversal`，展示为“任意文件读取”，具体命中方式写在 `evidence.technique`。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `path_traversal` |
| 命令行 | `python3 run.py --lfi` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/path_traversal/rules.yaml` |

核心文件：

- `pt_scanner.py`：主动检测流程、发包、判定、报告。
- `rules.py`：规则加载和 payload 组装。
- `rules.yaml`：文件读取 payload、WAF 规则、tamper 配置。
- `tamper.py`：编码和路径变形。

## 流量筛选

- 全局层过滤静态资源、二进制响应、HEAD/OPTIONS、204/304。
- 插件层只处理 GET/POST。
- 普通模式扫描 query/form/json。
- `--full-payload-scan` 额外扫描 Cookie/Header。
- 默认不按参数名筛选，覆盖全部可控参数。

## 检测方法

| technique | 判定方式 |
| --- | --- |
| `文件内容回显` | 注入读取 `/etc/passwd`、`win.ini` 等文件的 payload，响应出现唯一 signature 且 baseline 不含 |
| `PHP 源码读取` | 使用 `php://filter` 读取 PHP 文件 base64，解码后出现 `<?php`、`<?=` 或 passwd 特征 |

关键点是只相信“文件内容特征”，不把 payload 原样反射当漏洞。因此普通页面反射 `../../etc/passwd` 不会误报。

## OS 记忆

插件会记录每个 host 已确认的 OS：

- 命中 `/etc/passwd` 类 signature 后记为 `unix`
- 命中 `win.ini` 类 signature 后记为 `windows`

后续同 host 会按 OS 裁剪 payload，减少无效请求。

## Tamper

主流路径绕过已经放入基础 payload，例如：

- `../`
- URL 编码斜杠/点
- 双编码
- `....//`
- 反斜杠
- `%00`
- `file://`

在 WAF 拦截或 deep tamper 开启时，额外按 `tamper_profiles` 追发少量变体。

配置：

```yaml
plugins:
  path_traversal:
    enabled: true
    deep_tamper: true
    deep_tamper_max_profiles: 3
```

## 输出结构

```json
{
  "type": "path_traversal",
  "method": "path_traversal",
  "param_place": "query",
  "param_name": "file",
  "evidence": {
    "technique": "文件内容回显",
    "target_file": "/etc/passwd",
    "matched_content": "root:x:0:0:",
    "payload": "../../../../../etc/passwd"
  }
}
```

## 限制

- 只确认“可读且回显”的文件读取；目标读到文件但不回显时不会命中。
- PHP 源码读取依赖目标支持对应 wrapper。
- Cookie/Header 注入需要全量扫描模式。

## 方案设计说明

路径遍历插件的目标是证明“用户可控输入影响了服务端文件路径解析，并能读取非预期文件内容”。它不把 `../` 被反射当作漏洞，而是要求响应中出现真实文件内容 signature。

整体方法是：

1. 从真实请求提取候选参数。
2. 建立 baseline。
3. 用文件读取 payload 替换单个参数。
4. 按 Unix、Windows 和 PHP wrapper 分组检测。
5. 响应中出现目标文件 signature 才确认。
6. 命中后记录 host OS，后续按 OS 裁剪 payload。
7. WAF 或 deep tamper 场景追加编码变体。

### 为什么使用文件 signature

路径遍历最常见误报是 payload 被页面原样反射。例如响应里出现 `../../etc/passwd` 并不能说明服务端读了文件。插件只看目标文件内容特征：

- `/etc/passwd` 中的 `root:x:0:0:`。
- Windows `win.ini` 中的 `[fonts]` 等特征。
- PHP filter 解码后出现 `<?php`、`<?=` 等源码特征。

只有这些 signature 新增出现，才认为文件读取成立。

### Payload 分组

payload 按目标能力分组：

| 分组 | 目的 |
| --- | --- |
| Unix 文件读取 | 读取 `/etc/passwd` 等低敏感系统文件片段 |
| Windows 文件读取 | 读取 `win.ini` 等系统文件片段 |
| PHP filter | 读取 PHP 源码并 base64 编码 |
| 编码/变形路径 | 绕过路径过滤和 WAF |

这种分组便于命中后收敛。例如同一 host 已确认是 Unix，就不必继续大量发送 Windows payload。

### OS 记忆

插件会根据命中的 signature 记录 host OS。OS 记忆用于：

- 减少后续无效 payload。
- 提高扫描效率。
- 在报告中说明目标文件类型。
- 避免同一 host 上 Unix/Windows payload 全量交叉。

### PHP 源码读取

`php://filter` 是路径遍历里的特殊能力。它不一定读取系统文件，而是利用 PHP stream wrapper 把脚本源码 base64 编码后返回。插件会尝试：

- 基于原参数值读取。
- 读取常见入口文件。
- 读取相对路径下的 PHP 文件。

确认时会解码 base64，并检查 PHP 源码特征，而不是只看 base64 字符串。

### Tamper 设计

路径绕过常见变体包括：

- 多级 `../`。
- `....//`。
- URL 编码点和斜杠。
- 双编码。
- 反斜杠。
- `%00` 兼容形式。
- `file://`。

基础 payload 已经包含主流变体。deep tamper 只追加少量编码策略，用于处理 WAF 或过滤器。

### 确认标准

confirmed 需要满足：

- 响应新增目标文件 signature。
- signature 不存在于 baseline。
- payload 对应的目标文件和 technique 可解释。
- 证明请求和响应可以复现。

不确认的情况：

- payload 字符串被原样反射。
- 响应出现通用错误。
- 只出现文件名，没有文件内容。
- 目标读了文件但没有回显，这类当前无法自动确认。

### 安全边界

默认读取低敏感系统文件片段或源码特征，不读取私钥、云凭据、数据库配置等高敏感文件。插件只做能力确认，不做批量下载。

### 方案讲解重点

这个插件的核心是“内容 signature 判定”。路径遍历检测不能停留在 payload 反射层面，必须证明服务端文件读取结果进入响应。OS 记忆和 payload 分组则用于减少请求量和提升证据解释性。
