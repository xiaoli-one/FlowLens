from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.idor.idor_prompts import DETECTOR_PROMPT


class IDORDetector(BaseLogicDetector):
    name = "idor"
    vuln_type = "idor"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        candidates = []
        flows = [
            flow
            for flow in self.successful_flows(bundle)
            if self.method_allowed_for_active_verification(flow)
            and flow.get("auth_fingerprint")
            and flow.get("auth_fingerprint") != "anonymous"
            and self.idor_resource_refs(flow)
        ]
        identity_pool = self.identity_pool(bundle, flows)
        for source in flows:
            alternates = self.alternate_identity_flows(source, identity_pool)
            if not alternates:
                continue
            resource = self.idor_resource_refs(source)[0]
            candidates.append(
                self.make_candidate(
                    bundle,
                    source,
                    "水平越权/IDOR 风险",
                    "使用其他身份认证信息访问当前资源 ID，可能读取非本人资源。",
                    [
                        "同一接口被多个不同认证身份访问。",
                        f"原始请求包含资源引用 {resource.get('name')}={resource.get('value')}。",
                    ],
                    verification={"kind": "swap_auth", "safety": "configured_methods"},
                    related_flows=alternates,
                    resource=resource,
                )
            )
            if len(candidates) >= 3:
                break
        return candidates

    def idor_resource_refs(self, flow):
        allowed = {"resource_id", "owner", "id", "uuid", "hash"}
        refs = []
        for ref in flow.get("resource_refs") or []:
            semantic = ref.get("semantic_type") or ""
            source = ref.get("source") or ""
            if semantic in ("tenant", "role", "workflow_state", "business_value"):
                continue
            if semantic in allowed or source == "path":
                refs.append(ref)
        return refs
