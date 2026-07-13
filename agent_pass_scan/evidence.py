import json
import re
from difflib import SequenceMatcher


SUCCESS_MIN = 200
SUCCESS_MAX = 399
DENIED_STATUSES = {401, 403, 404}
LOGIN_RE = re.compile(r"(?:^|[/_-])(login|signin|sign-in|auth)(?:$|[/?#_-])", re.I)
DENIED_RE = re.compile(
    r"(access\s*denied|permission\s*denied|not\s*authorized|unauthori[sz]ed|"
    r"forbidden|authentication\s*required|请先登录|未登录|无权限|没有权限|禁止访问)",
    re.I,
)


def status_code(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def successful_status(value):
    code = status_code(value)
    return SUCCESS_MIN <= code <= SUCCESS_MAX


def denied_status(value):
    return status_code(value) in DENIED_STATUSES


def text_similarity(left, right):
    left = str(left or "")
    right = str(right or "")
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left[:5000], right[:5000]).ratio()


def json_scalar_values(value):
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(json_scalar_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(json_scalar_values(item))
        return values
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    return [str(value)]


def value_seen(value, text):
    expected = str(value if value is not None else "").strip().lower()
    text = str(text or "")
    if not expected or not text:
        return False
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if parsed is not None:
        return expected in {item.strip().lower() for item in json_scalar_values(parsed)}
    return bool(re.search(rf"(?<![\w.-]){re.escape(expected)}(?![\w.-])", text, re.I))


def field_leaf(name):
    parts = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", str(name or ""))
    return parts[-1].lower() if parts else ""


def named_json_values(value, field_name):
    matches = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() == field_name:
                matches.extend(json_scalar_values(item))
            matches.extend(named_json_values(item, field_name))
    elif isinstance(value, list):
        for item in value:
            matches.extend(named_json_values(item, field_name))
    return matches


def field_value_seen(name, value, text, allow_generic=False):
    expected = str(value if value is not None else "").strip().lower()
    text = str(text or "")
    if not expected or not text:
        return False
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return value_seen(value, text)

    leaf = field_leaf(name)
    if leaf:
        values = {item.strip().lower() for item in named_json_values(parsed, leaf)}
        if values:
            return expected in values
    return value_seen(value, text) if allow_generic else False


def looks_like_login(response, location):
    if LOGIN_RE.search(str(location or "")):
        return True
    text = str(response or "")[:5000]
    lowered = text.lower()
    return bool(
        ("password" in lowered and ("login" in lowered or "signin" in lowered))
        or ("密码" in text and ("登录" in text or "登陆" in text))
    )


def looks_denied(response):
    return bool(DENIED_RE.search(str(response or "")[:5000]))


def looks_empty_data(response):
    text = str(response or "").strip()
    if text in ("", "[]", "{}", "null"):
        return True
    try:
        data = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if isinstance(data, dict):
        for key in ("data", "result", "items", "records", "rows", "list"):
            if key in data and data[key] in (None, [], {}):
                return True
    return False


def observation_summary(candidate, observation):
    response = observation.get("response_excerpt") or ""
    baseline = observation.get("baseline_response_excerpt") or ""
    alternate_baseline = observation.get("alternate_baseline_response_excerpt") or ""
    resource = candidate.resource or {}
    mutation = observation.get("mutation") or observation.get("parent_mutation") or {}
    similarity = text_similarity(response, baseline)
    alternate_similarity = text_similarity(response, alternate_baseline)
    resource_value_seen = field_value_seen(
        resource.get("name"),
        resource.get("value"),
        response,
        allow_generic=True,
    )
    mutation_value_seen = field_value_seen(
        mutation.get("name"),
        mutation.get("new_value"),
        response,
    )
    old_value_seen = field_value_seen(
        mutation.get("name"),
        mutation.get("old_value"),
        response,
    )
    status = status_code(observation.get("status_code"))
    method = (observation.get("method") or "GET").upper()
    redirected_to_login = looks_like_login(response, observation.get("location"))
    denied_response = denied_status(status) or looks_denied(response) or redirected_to_login
    empty_business_data = looks_empty_data(response)
    empty_read_result = method in ("GET", "HEAD") and empty_business_data
    returns_alternate_identity_data = bool(
        alternate_baseline
        and response
        and alternate_similarity >= 0.82
        and alternate_similarity > similarity + 0.05
        and not resource_value_seen
    )
    active_success = successful_status(status) and not denied_response and not empty_read_result
    postcondition = bool(observation.get("postcondition"))
    mutation_not_applied = bool(
        postcondition
        and successful_status(status)
        and old_value_seen
        and not mutation_value_seen
    )
    negative_result = bool(
        denied_response
        or empty_read_result
        or returns_alternate_identity_data
        or mutation_not_applied
    )

    signals = []
    gaps = []
    if observation.get("blocked"):
        gaps.append("主动验证被配置或安全策略阻断")
    elif denied_response:
        signals.append("主动验证得到明确拒绝或登录响应")
    elif empty_read_result:
        signals.append("主动验证只返回空业务数据")
    elif active_success:
        signals.append("主动验证返回有效成功响应")
    elif status:
        gaps.append("主动验证未返回有效成功响应")
    else:
        gaps.append("主动验证未获得 HTTP 状态码")

    if resource_value_seen:
        signals.append("响应中保留原资源标识")
    if mutation_value_seen:
        signals.append("响应中出现篡改后的目标值")
    if mutation_not_applied:
        signals.append("只读复查仍保留原值，篡改未生效")
    if returns_alternate_identity_data:
        signals.append("换身份后响应更接近新身份基线，而不是原资源")
    if similarity >= 0.82 and response and baseline:
        signals.append("主动响应与原始基线高度相似")
    elif response and baseline and not negative_result:
        gaps.append("主动响应与原始基线差异较大，需要归属或状态字段补强")

    if postcondition and active_success and not mutation_value_seen and not mutation_not_applied:
        gaps.append("只读复查成功，但未确认目标字段的新值或原值")

    return {
        "action_id": observation.get("action_id") or "",
        "purpose": observation.get("purpose") or "",
        "method": method,
        "url": observation.get("url") or "",
        "status_code": status,
        "ok": bool(observation.get("ok")),
        "blocked": bool(observation.get("blocked")),
        "error": observation.get("error") or "",
        "postcondition": postcondition,
        "auth_header_present": bool(observation.get("auth_header_present")),
        "response_similarity_to_baseline": round(similarity, 3),
        "response_similarity_to_alternate_baseline": round(alternate_similarity, 3),
        "resource_value_seen": resource_value_seen,
        "mutation_value_seen": mutation_value_seen,
        "old_value_seen": old_value_seen,
        "response_changed_from_baseline": similarity < 0.82,
        "redirected_to_login": redirected_to_login,
        "denied_response": denied_response,
        "empty_business_data": empty_business_data,
        "returns_alternate_identity_data": returns_alternate_identity_data,
        "mutation_not_applied": mutation_not_applied,
        "business_success": active_success,
        "negative_result": negative_result,
        "signals": signals,
        "gaps": gaps,
    }


def unique(items):
    values = []
    seen = set()
    for item in items or []:
        if not item or item in seen:
            continue
        seen.add(item)
        values.append(item)
    return values


def build_evidence_profile(candidate, observations, investigation=None):
    observations = [item for item in observations or [] if item]
    summaries = [observation_summary(candidate, item) for item in observations]
    verification_kind = (candidate.verification or {}).get("kind") or "passive_only"
    investigation = dict(investigation or {})
    verification_complete = bool(investigation.get("verification_complete", True))

    active_summaries = [item for item in summaries if not item["postcondition"]]
    postcondition_summaries = [item for item in summaries if item["postcondition"]]
    success_summaries = [item for item in active_summaries if item["business_success"]]
    negative_summaries = [item for item in active_summaries if item["negative_result"]]
    no_auth_success = [item for item in success_summaries if not item["auth_header_present"]]
    continuity_summaries = [
        item for item in success_summaries
        if item["resource_value_seen"] or item["response_similarity_to_baseline"] >= 0.82
    ]
    read_only_mutation_acceptance = [
        item for item in active_summaries
        if item["method"] in ("GET", "HEAD") and item["mutation_value_seen"]
    ]
    postcondition_mutation_acceptance = [
        item for item in postcondition_summaries if item["mutation_value_seen"]
    ]
    mutation_rejections = [item for item in postcondition_summaries if item["mutation_not_applied"]]

    supports_confirmed = False
    supports_likely = False
    observed_rejection = False
    missing = []
    rejection_reasons = []

    if verification_kind == "strip_auth":
        supports_confirmed = bool(no_auth_success and continuity_summaries)
        supports_likely = bool(no_auth_success)
        observed_rejection = bool(negative_summaries)
        if not no_auth_success:
            missing.append("缺少去认证后仍成功访问的响应")
        if no_auth_success and not continuity_summaries:
            missing.append("缺少去认证响应仍对应原敏感对象的字段或高相似基线")
    elif verification_kind == "swap_auth":
        supports_confirmed = bool(success_summaries and continuity_summaries)
        supports_likely = bool(success_summaries)
        observed_rejection = bool(
            active_summaries
            and len(negative_summaries) == len(active_summaries)
        )
        if not success_summaries:
            missing.append("缺少换认证后仍成功访问原资源的响应")
        if success_summaries and not continuity_summaries:
            missing.append("缺少换认证响应仍对应原资源/原租户的标识或高相似基线")
    elif verification_kind == "mutate_param":
        supports_confirmed = bool(
            success_summaries
            and (read_only_mutation_acceptance or postcondition_mutation_acceptance)
        )
        supports_likely = bool(success_summaries)
        observed_rejection = bool(
            mutation_rejections
            or (
                active_summaries
                and len(negative_summaries) == len(active_summaries)
            )
        )
        if not success_summaries:
            missing.append("缺少参数篡改后被服务端接受的成功响应")
        if success_summaries and not (
            read_only_mutation_acceptance or postcondition_mutation_acceptance
        ):
            missing.append("缺少篡改值在只读响应或写后回查中真实生效的证据")
    elif verification_kind == "same_auth_replay":
        supports_confirmed = bool(success_summaries)
        supports_likely = bool(success_summaries)
        observed_rejection = bool(negative_summaries)
        if not success_summaries:
            missing.append("缺少同认证重放成功响应")
    else:
        if verification_kind == "passive_only":
            missing.append("当前候选只有被动证据，不能形成主动验证闭环")

    supports_rejected = bool(observed_rejection and verification_complete)
    if supports_rejected:
        for item in summaries:
            if item["denied_response"]:
                rejection_reasons.append("验证请求被鉴权、权限策略或登录流程明确拒绝")
            if item["empty_business_data"] and item["method"] in ("GET", "HEAD"):
                rejection_reasons.append("验证请求只返回空业务数据")
            if item["returns_alternate_identity_data"]:
                rejection_reasons.append("换身份后只返回新身份自己的数据")
            if item["mutation_not_applied"]:
                rejection_reasons.append("只读复查确认敏感字段未发生变化")

    if not observations:
        missing.append("缺少主动差分验证结果")
    if observations and all(item["blocked"] for item in summaries):
        missing.append("全部主动验证请求被阻断")
    for item in summaries:
        missing.extend(item["gaps"])

    return {
        "verification_kind": verification_kind,
        "verification_complete": verification_complete,
        "active_request_count": len(active_summaries),
        "postcondition_request_count": len(postcondition_summaries),
        "success_count": len(success_summaries),
        "denied_count": sum(1 for item in active_summaries if item["denied_response"]),
        "negative_count": len(negative_summaries),
        "blocked_count": sum(1 for item in summaries if item["blocked"]),
        "supports_confirmed": supports_confirmed,
        "supports_likely": supports_likely,
        "supports_rejected": supports_rejected,
        "rejection_reasons": unique(rejection_reasons),
        "missing_evidence": unique(missing),
        "investigation": investigation,
        "observation_summaries": summaries,
    }
