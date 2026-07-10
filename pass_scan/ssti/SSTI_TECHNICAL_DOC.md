# SSTI 检测技术文档

`pass_scan/ssti` 检测服务端模板注入。它只把疑似进入模板渲染链路的参数入队，避免对普通 ID、token 参数发大量模板 payload。

## 插件边界

| 项 | 说明 |
| --- | --- |
| 插件名 | `ssti` |
| 命令行 | `python3 run.py --ssti` |
| 输出 | `logs/vulns.jsonl`、`report.html` |
| 规则文件 | `pass_scan/ssti/rules.yaml` |

核心文件：

- `ssti_scanner.py`：筛选、主动检测、模板错误识别。
- `rules.py`：构造算术、字符串转换、错误 payload。
- `rules.yaml`：模板语法和错误指纹。
- `tamper.py`：URL 编码类绕过。

## 流量筛选

插件只处理 GET/POST 且响应可作为文本比较的流量。候选参数需要满足至少一个条件：

- 参数值包含模板分隔符，如 `{{`、`${`、`#{`、`<%`。
- 参数名像内容或模板入口，如 `template`、`content`、`message`、`preview`、`search`。
- URL 路径像渲染入口，如 `/template`、`/preview`、`/render`。
- 原始响应反射了文本参数值。
- 响应中出现模板引擎线索。

默认扫描 query/form/json；全量扫描时额外纳入 Cookie/Header。

## 检测方法

| technique | 判定方式 |
| --- | --- |
| `算术回显` | 注入模板表达式计算随机乘积/加和，响应出现预期结果且 baseline 不含 |
| `字符串转换` | 注入 upper/upcase/toUpperCase 等转换表达式，响应出现随机大写 marker |
| `模板错误` | 输出型未命中时发送非法模板语法，响应新增模板引擎错误指纹 |

覆盖模板家族包括 Jinja、Twig、Freemarker、Thymeleaf、Velocity、Smarty、Mako、Liquid、Razor、EJS、ERB 等。

插件默认不使用命令执行或 sleep 类 payload，避免把 SSTI 探测升级成 RCE 探测。

## Tamper

基础 payload 覆盖主流语法。URL 编码类绕过只在 WAF 拦截、`deep_tamper` 或全量扫描时追加。

配置：

```yaml
plugins:
  ssti:
    enabled: true
    deep_tamper: false
    deep_tamper_max_profiles: 2
    error_detection: true
    max_candidate_value_length: 2000
```

## 输出结构

```json
{
  "type": "ssti",
  "method": "ssti",
  "param_place": "query",
  "param_name": "name",
  "evidence": {
    "technique": "算术回显",
    "template_family": "jinja",
    "payload": "{{1234*5678}}",
    "expected_output": "7006652",
    "matched_output": "..."
  }
}
```

## 限制

- 需要响应中能观察到模板输出或错误。
- 默认不做 RCE/sleep payload。
- 参数筛选是保守降噪策略，极少数隐蔽模板入口可能需要全量扫描或扩展筛选词。

## 方案设计说明

SSTI 插件的目标是证明“用户输入进入了服务端模板引擎解释”。它的设计重点是低副作用确认，而不是直接追求 RCE。很多模板注入最终可以走到命令执行，但在被动扫描器里直接使用 RCE payload 风险过高，所以插件默认只做表达式执行、字符串转换和模板错误指纹。

整体策略是：

1. 先做语义筛选，只让疑似模板入口入队。
2. 用 baseline 记录原响应。
3. 发送算术表达式 payload。
4. 如果算术不适配，尝试字符串转换类 payload。
5. 输出型不命中时，再用模板错误指纹辅助判断。
6. 只在 WAF 或 deep tamper 场景追加编码变体。

### 为什么需要入口筛选

SSTI payload 数量多，模板语法差异大，如果对所有参数都打，会产生大量请求和误报。插件只优先扫描以下输入：

- 参数名像 `template`、`content`、`message`、`preview`、`search`。
- 参数值本身已有 `{{`、`${`、`#{`、`<%` 等模板分隔符。
- URL 路径像渲染、预览、模板、通知、消息入口。
- 原始响应反射了参数文本。
- 响应中出现模板引擎线索。

这样能把检测范围集中到真正可能进入模板渲染链路的参数。

### 算术回显

算术回显是最主要确认方式。插件会生成随机数字表达式，例如乘法或加法，预期输出是一个随机结果。

这种方式的优点：

- 不需要执行系统命令。
- 输出结果随机，baseline 中自然出现概率低。
- 可覆盖 Jinja、Twig、Freemarker、Thymeleaf、Velocity、Smarty、Mako、Liquid、Razor、EJS、ERB 等多种模板家族。

确认条件是响应出现预期结果，并且 baseline 不包含该结果。

### 字符串转换

有些模板引擎不适合简单算术，或者算术表达式被过滤。字符串转换用随机 marker 和 upper/upcase/toUpperCase 等方法确认模板表达式执行。

判断逻辑是：

- payload 中包含小写随机 marker。
- 预期输出是大写 marker。
- 响应出现大写 marker，而 baseline 不包含。

这能证明模板表达式不仅被反射，还被解释执行。

### 模板错误指纹

如果输出型 payload 没有命中，插件可以发送少量非法模板语法，观察响应是否新增模板引擎错误。这个方法置信度低于输出确认，但对发现隐藏模板入口有价值。

模板错误只能说明“输入可能进入模板解析器”，不能等同于可利用 RCE。因此报告里会把 technique 标为模板错误，并给相对保守的置信度。

### Tamper 与编码

SSTI 的基础 payload 已经覆盖多种分隔符和模板语法。额外 tamper 主要处理：

- 分隔符 URL 编码。
- 空白变化。
- 过滤器绕过。
- WAF 拦截后的少量变形。

默认 `deep_tamper` 关闭，是为了控制请求量。遇到强过滤目标时可以手动开启。

### 确认标准

confirmed 证据包括：

- 算术表达式输出正确随机结果。
- 字符串转换输出预期大写 marker。
- 模板错误和其他上下文证据共同支持模板解析。

不确认的情况：

- payload 原样反射。
- 输出数字本来就在 baseline 中。
- 只有通用 500 错误，没有模板特征。
- 参数只是前端模板或客户端渲染。

### 安全边界

默认不使用 sleep、命令执行、文件读取、对象链枚举等高风险 payload。SSTI 如果需要进一步验证到 RCE 深度，应交给 `vuln_verify` 在授权条件下使用只读命令继续推进。

### 方案讲解重点

这个插件的核心是把 SSTI 拆成“表达式执行证明”和“模板错误辅助证明”。它不追求一步打到系统命令，而是在被动扫描阶段用低风险证据确认模板解释能力，再把更深利用交给主动验证模块。
