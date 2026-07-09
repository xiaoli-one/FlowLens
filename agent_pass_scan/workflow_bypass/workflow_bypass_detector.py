from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.workflow_bypass.workflow_bypass_prompts import DETECTOR_PROMPT


class WorkflowBypassDetector(BaseLogicDetector):
    name = "workflow_bypass"
    vuln_type = "workflow_bypass"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        candidates = []
        for flow in self.successful_flows(bundle):
            if not self.method_allowed_for_active_verification(flow):
                continue
            refs = [
                ref
                for ref in flow.get("resource_refs") or []
                if ref.get("semantic_type") == "workflow_state"
            ]
            params = [
                parameter
                for parameter in flow.get("parameters") or []
                if parameter.get("semantic_type") == "workflow_state"
            ]
            if not refs and not params:
                continue
            resource = (params or refs or [{}])[0]
            candidates.append(
                self.make_candidate(
                    bundle,
                    flow,
                    "流程绕过风险",
                    "请求中包含 status/state/approve 等流程状态字段，可能存在跳步骤或状态篡改。",
                    [
                        "接口请求包含流程状态字段。",
                        "当前配置允许主动篡改并重放流程状态字段，以补强是否可跳过业务流程的证据。",
                    ],
                    verification={
                        "kind": "mutate_param",
                        "safety": "configured_methods_destructive",
                        "mutations": self.workflow_mutations_for(resource),
                    },
                    resource=resource,
                )
            )
            if len(candidates) >= 2:
                break
        return candidates

    def workflow_mutations_for(self, parameter):
        name = str(parameter.get("name") or "").lower()
        old_value = str(parameter.get("value") or parameter.get("value_preview") or "").lower()
        if "pay" in name or "paid" in name:
            values = ["paid", "completed", "success", "true", "1"]
        elif "publish" in name or "published" in name:
            values = ["published", "enabled", "true", "1"]
        elif "approve" in name or "review" in name or "audit" in name or "verified" in name:
            values = ["approved", "passed", "verified", "true", "1"]
        elif "enable" in name or "active" in name or "locked" in name:
            values = ["enabled", "active", "false", "0", "true", "1"]
        elif "delete" in name or "deleted" in name:
            values = ["deleted", "true", "1"]
        else:
            values = ["approved", "published", "completed", "paid", "passed", "true", "1"]
        return [value for value in values if value.lower() != old_value]
