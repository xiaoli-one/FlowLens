import re

from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.vertical_authz.vertical_authz_prompts import DETECTOR_PROMPT


ADMIN_RE = re.compile(
    r"(admin|manage|management|permission|permissions|role|roles|privilege|"
    r"rbac|acl|audit|approve|approval|review|config|settings?|system|staff|"
    r"operator|ops|console|dashboard|/users?(?:/|$))",
    re.I,
)


class VerticalAuthzDetector(BaseLogicDetector):
    name = "vertical_authz"
    vuln_type = "vertical_authz"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        endpoint = bundle.get("endpoint") or {}
        normalized_path = endpoint.get("normalized_path") or ""
        if not ADMIN_RE.search(normalized_path):
            return []

        candidates = []
        flows = [
            flow
            for flow in self.successful_flows(bundle)
            if self.method_allowed_for_active_verification(flow)
            and (flow.get("auth_fingerprint") or "") != "anonymous"
        ]
        identity_pool = self.identity_pool(bundle, flows)
        for flow in flows:
            if (flow.get("auth_fingerprint") or "") == "anonymous":
                continue
            alternates = self.alternate_identity_flows(flow, identity_pool)
            verification = {"kind": "passive_only", "safety": "缺少其他身份，暂时只能结合角色上下文判断"}
            if alternates:
                verification = {"kind": "swap_auth", "safety": "configured_methods"}
            candidates.append(
                self.make_candidate(
                    bundle,
                    flow,
                    "垂直越权风险",
                    "普通认证身份可能访问管理、审批、权限或配置类接口。",
                    [
                        "接口路径包含管理/权限/审批类关键词。",
                        "该接口返回成功状态码，需结合账号角色判断是否越权。",
                    ],
                    verification=verification,
                    related_flows=alternates,
                    notes=[
                        "如果当前身份本身就是管理员，这不是漏洞。",
                        "优先结合 identity_memory 中其他身份的历史路径判断低权限身份。",
                    ],
                )
            )
            break
        return candidates
