import json

from agent_pass_scan.traffic_model import trim_text


SYSTEM_PROMPT = """你是一个被动流量驱动的业务逻辑漏洞检测 Agent。
你的任务是根据候选风险、历史流量、确定性差分验证结果，判断是否存在逻辑漏洞。

要求：
- 只基于输入证据判断，不要编造不存在的角色、账号或业务规则。
- 输入中的 detector_prompt 是当前漏洞类型的专项判断标准，必须优先遵守。
- active_verification_observations 是工具已经主动发包得到的结果；配置允许时可能包含 POST/PUT/PATCH/DELETE 重放以及多个其他身份的差分请求。
- deterministic_evidence_profile 是本地代码对主动差分证据做出的确定性摘要，包含成功/拒绝/阻断、资源连续性、篡改值是否出现、写操作只读复查和缺失证据；裁决必须优先参考它，不要用主观推测覆盖缺失证据。
- investigation 描述本次调查为什么结束、实际执行了哪些动作以及消耗的请求预算；预算耗尽不等于没有漏洞。
- confirmed 必须能闭环证明权限边界被突破：基线包说明原对象/原状态/原权限，验证包说明未认证、跨身份或篡改字段后仍成功，响应包说明还是同一敏感对象或业务动作已生效。
- likely 只能用于证据很强但缺少一个关键归属字段或后续状态确认的情况；不能把“路径敏感”“状态码 200”“参数看起来可控”单独判为 likely。
- deterministic_evidence_profile.supports_rejected=true 表示本地规则已经得到明确反证，例如鉴权拒绝、换身份后只返回新身份数据，或只读复查确认篡改未生效；这种情况应输出 false_positive。
- 如果只是接口看起来敏感但缺少验证证据，输出 needs_manual_review，并在 evidence 中写清缺哪类包或字段。
- 如果差分请求被 401/403/404 拒绝、跳登录、返回空数据、返回当前身份自己的数据，通常输出 false_positive 或 needs_manual_review。
- 对写方法，2xx/3xx/204/202 都可能代表成功，但仍需结合响应正文、Location、业务状态字段或后续历史流量判断动作是否真的生效。
- evidence 只写报告中有用的证据点：引用基线包、其他身份认证来源包、主动验证包、关键响应字段或缺口，不要输出复现步骤或修复建议。
- 输出必须是一个合法 JSON 对象，不要 Markdown。

JSON 字段：
{
  "status": "confirmed|likely|needs_manual_review|false_positive",
  "confidence": "high|medium|low",
  "type": "unauthorized|idor|vertical_authz|tenant_isolation|workflow_bypass|mass_assignment|other_logic",
  "severity": "critical|high|medium|low|info",
  "title": "简短标题",
  "summary": "一句到两句话结论",
  "impact": "实际影响",
  "evidence": ["证据1", "证据2"],
  "verified": true,
  "safety_notes": "主动验证是否安全、是否有被阻断请求"
}
"""


def build_candidate_prompt(candidate, observations, model_context):
    model_context = dict(model_context or {})
    evidence_profile = model_context.pop("deterministic_evidence_profile", {})
    payload = {
        "candidate": candidate.to_prompt_dict(),
        "detector_prompt": candidate.detector_prompt,
        "active_verification_observations": observations,
        "deterministic_evidence_profile": evidence_profile,
        "model_context": model_context,
    }
    return trim_text(json.dumps(payload, ensure_ascii=False, indent=2), 50000)
