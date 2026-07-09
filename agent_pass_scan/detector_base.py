from agent_pass_scan.models import LogicCandidate
from agent_pass_scan.traffic_model import stable_hash, trim_text


DEFAULT_ACTIVE_VERIFICATION_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}


class BaseLogicDetector:
    name = "base"
    vuln_type = "other_logic"
    prompt = ""

    def __init__(self, config=None):
        self.config = config or {}
        self.max_alternate_identities = int(
            self.config.get("max_alternate_identities_per_candidate", 3)
        )
        self.active_verification_methods = {
            method.upper()
            for method in self.config.get(
                "active_verification_methods",
                sorted(DEFAULT_ACTIVE_VERIFICATION_METHODS),
            )
        }

    def build_candidates(self, bundle):
        return []

    def compact_endpoint(self, bundle):
        endpoint = bundle["endpoint"]
        return {
            "id": endpoint.get("id"),
            "host": endpoint.get("host"),
            "method": endpoint.get("method"),
            "normalized_path": endpoint.get("normalized_path"),
            "count": endpoint.get("count"),
        }

    def compact_flow(self, flow, include_headers=False):
        data = {
            "id": flow.get("id"),
            "time": flow.get("time"),
            "method": flow.get("method"),
            "url": flow.get("url"),
            "status_code": flow.get("status_code"),
            "auth_type": flow.get("auth_type"),
            "auth_fingerprint": flow.get("auth_fingerprint"),
            "parameters": flow.get("parameters") or [],
            "resource_refs": flow.get("resource_refs") or [],
            "response_excerpt": trim_text(flow.get("response_body_text") or "", 2500),
        }
        if include_headers:
            data["request_headers"] = dict(flow.get("request_headers") or {})
        return data

    def candidate_key(self, *parts):
        return f"{self.name}:" + stable_hash(parts, 24)

    def make_candidate(
        self,
        bundle,
        source_flow,
        title,
        risk,
        evidence,
        verification=None,
        related_flows=None,
        resource=None,
        notes=None,
    ):
        related_flows = related_flows or []
        key = self.candidate_key(
            source_flow.get("id"),
            title,
            resource or {},
            [flow.get("id") for flow in related_flows],
        )
        return LogicCandidate(
            key=key,
            detector=self.name,
            vuln_type=self.vuln_type,
            title=title,
            risk=risk,
            endpoint=self.compact_endpoint(bundle),
            source_flow=self.compact_flow(source_flow, include_headers=True),
            evidence=evidence,
            verification=verification or {},
            related_flows=[self.compact_flow(flow, include_headers=True) for flow in related_flows],
            resource=resource or {},
            notes=notes or [],
            detector_prompt=self.prompt,
            runtime_source_flow=source_flow,
            runtime_related_flows=related_flows,
        )

    def successful_flows(self, bundle):
        return [
            flow
            for flow in bundle.get("flows") or []
            if 200 <= int(flow.get("status_code") or 0) < 400
        ]

    def successful_identity_flows(self, bundle):
        return [
            flow
            for flow in bundle.get("identity_flows") or []
            if 200 <= int(flow.get("status_code") or 0) < 400
        ]

    def identity_pool(self, bundle, endpoint_flows=None):
        pool = []
        seen = set()
        for flow in list(endpoint_flows or []) + self.successful_identity_flows(bundle):
            flow_id = flow.get("id")
            if flow_id in seen:
                continue
            seen.add(flow_id)
            pool.append(flow)
        return pool

    def method_allowed_for_active_verification(self, flow):
        return (flow.get("method") or "").upper() in self.active_verification_methods

    def alternate_identity_flows(self, source, flows, limit=None):
        source_auth = source.get("auth_fingerprint")
        limit = self.max_alternate_identities if limit is None else int(limit)
        alternates = []
        seen_auths = set()
        for flow in flows or []:
            auth = flow.get("auth_fingerprint")
            if not auth or auth == "anonymous" or auth == source_auth:
                continue
            if flow.get("id") == source.get("id") or auth in seen_auths:
                continue
            seen_auths.add(auth)
            alternates.append(flow)
            if len(alternates) >= limit:
                break
        return alternates
