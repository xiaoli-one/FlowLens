from agent_pass_scan.detector_base import BaseLogicDetector
from agent_pass_scan.tenant_isolation.tenant_isolation_prompts import DETECTOR_PROMPT


class TenantIsolationDetector(BaseLogicDetector):
    name = "tenant_isolation"
    vuln_type = "tenant_isolation"
    prompt = DETECTOR_PROMPT

    def build_candidates(self, bundle):
        candidates = []
        flows = [
            flow
            for flow in self.successful_flows(bundle)
            if self.method_allowed_for_active_verification(flow)
            and flow.get("auth_fingerprint")
            and flow.get("auth_fingerprint") != "anonymous"
        ]
        for source in flows:
            tenant_refs = [
                ref
                for ref in source.get("resource_refs") or []
                if ref.get("semantic_type") == "tenant"
            ]
            if not tenant_refs:
                continue
            alternates = self.alternate_identity_flows(source, self.identity_pool(bundle, flows))
            if not alternates:
                continue
            candidates.append(
                self.make_candidate(
                    bundle,
                    source,
                    "租户隔离风险",
                    "接口暴露 tenant/org/company 等租户边界参数，需验证跨身份是否可访问同一租户资源。",
                    [
                        "请求中存在疑似租户边界参数。",
                        "同一接口存在多个认证身份的成功访问记录。",
                    ],
                    verification={"kind": "swap_auth", "safety": "configured_methods"},
                    related_flows=alternates,
                    resource=tenant_refs[0],
                )
            )
            if len(candidates) >= 2:
                break
        return candidates
