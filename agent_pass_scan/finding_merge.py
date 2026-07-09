from agent_pass_scan.exploit_chain import best_exploit_chain, normalize_exploit_chain
from agent_pass_scan.traffic_model import stable_hash


STATUS_RANK = {
    "false_positive": 0,
    "needs_manual_review": 1,
    "likely": 2,
    "confirmed": 3,
}

CONFIDENCE_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
}

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def resource_fingerprint(resource):
    resource = resource or {}
    return {
        "source": resource.get("source") or "",
        "name": resource.get("name") or "",
        "semantic_type": resource.get("semantic_type") or "",
    }


def stable_logic_finding_key_from_candidate(candidate):
    endpoint = candidate.endpoint or {}
    material = {
        "detector": candidate.detector,
        "type": candidate.vuln_type,
        "host": endpoint.get("host") or "",
        "method": endpoint.get("method") or "",
        "endpoint": endpoint.get("normalized_path") or "",
        "verification": (candidate.verification or {}).get("kind") or "",
        "resource": resource_fingerprint(candidate.resource),
    }
    return stable_hash(material, 24)


def stable_logic_finding_key_from_result(result):
    candidate = result.get("candidate") or {}
    endpoint = candidate.get("endpoint") or {}
    resource = result.get("resource") or candidate.get("resource") or {}
    material = {
        "detector": result.get("detector") or candidate.get("detector") or "",
        "type": result.get("type") or candidate.get("type") or "",
        "host": result.get("host") or endpoint.get("host") or "",
        "method": result.get("method") or endpoint.get("method") or "",
        "endpoint": result.get("endpoint") or endpoint.get("normalized_path") or "",
        "verification": (candidate.get("verification") or {}).get("kind") or "",
        "resource": resource_fingerprint(resource),
    }
    return stable_hash(material, 24)


def merged_rank_value(result):
    return (
        STATUS_RANK.get(result.get("status"), 0),
        CONFIDENCE_RANK.get(result.get("confidence"), 0),
        SEVERITY_RANK.get(result.get("severity"), 0),
    )


def unique_items(items):
    seen = set()
    unique = []
    for item in items or []:
        key = stable_hash(item, 32)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def merge_unique_field(existing, incoming, field):
    return unique_items((existing.get(field) or []) + (incoming.get(field) or []))


def merge_logic_findings(existing, incoming):
    if not existing:
        merged = dict(incoming)
        chain = normalize_exploit_chain(merged)
        if chain:
            merged["logic_exploit_chain"] = chain
            merged["logic_chain_packets"] = chain.get("steps") or []
        merged["first_seen"] = incoming.get("first_seen") or incoming.get("time") or ""
        merged["last_seen"] = incoming.get("last_seen") or incoming.get("time") or ""
        merged["merged_count"] = int(incoming.get("merged_count") or 1)
        return merged

    merged = dict(existing)
    old_first_seen = existing.get("first_seen") or existing.get("time") or ""
    old_last_seen = existing.get("last_seen") or existing.get("time") or ""
    new_time = incoming.get("time") or ""
    merged["first_seen"] = min([value for value in (old_first_seen, new_time) if value] or [""])
    merged["last_seen"] = max(old_last_seen, new_time)
    merged["time"] = merged["last_seen"] or new_time or existing.get("time") or ""
    merged["merged_count"] = int(existing.get("merged_count") or 1) + int(incoming.get("merged_count") or 1)

    if merged_rank_value(incoming) >= merged_rank_value(existing):
        for field in (
            "status",
            "confidence",
            "severity",
            "title",
            "summary",
            "impact",
            "verified",
            "safety_notes",
            "candidate",
            "model",
            "sqlite_file",
        ):
            if field in incoming:
                merged[field] = incoming[field]

    for field in (
        "evidence",
        "reproduction",
        "remediation",
        "verification_observations",
    ):
        merged[field] = merge_unique_field(existing, incoming, field)

    chain = best_exploit_chain(existing, incoming)
    if chain:
        merged["logic_exploit_chain"] = chain
        merged["logic_chain_packets"] = chain.get("steps") or []

    candidate_keys = []
    for result in (existing, incoming):
        if result.get("candidate_key"):
            candidate_keys.append(result["candidate_key"])
        candidate_keys.extend(result.get("candidate_keys") or [])
    merged["candidate_keys"] = unique_items(candidate_keys)
    merged["finding_key"] = incoming.get("finding_key") or existing.get("finding_key")
    return merged


def merge_logic_result_list(results):
    merged_by_key = {}
    order = []
    for result in results or []:
        key = stable_logic_finding_key_from_result(result)
        normalized = dict(result)
        normalized["finding_key"] = key
        if key not in merged_by_key:
            order.append(key)
            merged_by_key[key] = merge_logic_findings(None, normalized)
            continue
        merged_by_key[key] = merge_logic_findings(merged_by_key[key], normalized)
    return [merged_by_key[key] for key in order]
