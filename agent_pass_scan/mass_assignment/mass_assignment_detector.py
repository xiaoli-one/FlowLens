from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.mass_assignment.mass_assignment_prompts import DETECTOR_PROMPT


class MassAssignmentDetector(BaseLogicDetector):
    name = "mass_assignment"
    vuln_type = "mass_assignment"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        candidates = []
        for flow in self.successful_flows(bundle):
            if not self.method_allowed_for_active_verification(flow):
                continue
            sensitive_params = [
                parameter
                for parameter in flow.get("parameters") or []
                if parameter.get("semantic_type")
                in ("role", "tenant", "owner", "business_value")
            ]
            if not sensitive_params:
                continue
            candidates.append(
                self.make_candidate(
                    bundle,
                    flow,
                    "敏感字段绑定/参数篡改风险",
                    "客户端可提交 role/status/tenant/owner/amount 等敏感字段，可能存在越权赋值或业务状态篡改。",
                    [
                        "请求参数中存在角色、权限、租户、归属人、金额或状态类字段。",
                        "当前配置允许主动篡改并重放敏感字段，以补强该字段是否被服务端接受的证据。",
                    ],
                    verification={
                        "kind": "mutate_param",
                        "safety": "configured_methods_destructive",
                        "mutations": self.mutation_values_for(sensitive_params[0]),
                    },
                    resource=sensitive_params[0],
                )
            )
            if len(candidates) >= 2:
                break
        return candidates

    def mutation_values_for(self, parameter):
        semantic = parameter.get("semantic_type")
        name = str(parameter.get("name") or "").lower()
        old_value = str(parameter.get("value") or parameter.get("value_preview") or "").lower()
        if semantic == "role":
            if "admin" in name or "staff" in name or "superuser" in name:
                values = ["true", "1"]
            else:
                values = ["admin", "administrator", "true", "1"]
            return [value for value in values if value.lower() != old_value]
        if semantic == "tenant":
            values = ["1", "2", "999999"]
            return [value for value in values if value.lower() != old_value]
        if semantic == "owner":
            values = ["1", "2", "999999"]
            return [value for value in values if value.lower() != old_value]
        if semantic == "business_value":
            values = ["0", "1", "999999"]
            return [value for value in values if value.lower() != old_value]
        values = ["1", "true"]
        return [value for value in values if value.lower() != old_value]
