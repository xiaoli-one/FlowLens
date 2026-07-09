from dataclasses import dataclass, field


@dataclass
class LogicTask:
    endpoint_id: int
    signature: str
    host: str
    method: str
    url: str


@dataclass
class LogicCandidate:
    key: str
    detector: str
    vuln_type: str
    title: str
    risk: str
    endpoint: dict
    source_flow: dict
    evidence: list = field(default_factory=list)
    verification: dict = field(default_factory=dict)
    related_flows: list = field(default_factory=list)
    resource: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    detector_prompt: str = ""
    runtime_source_flow: dict = field(default_factory=dict, repr=False)
    runtime_related_flows: list = field(default_factory=list, repr=False)

    def to_prompt_dict(self):
        return {
            "candidate_key": self.key,
            "detector": self.detector,
            "type": self.vuln_type,
            "title": self.title,
            "risk": self.risk,
            "endpoint": self.endpoint,
            "source_flow": self.source_flow,
            "evidence": self.evidence,
            "verification": self.verification,
            "related_flows": self.related_flows,
            "resource": self.resource,
            "notes": self.notes,
            "detector_prompt": self.detector_prompt,
        }
