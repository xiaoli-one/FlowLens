import time

from agent_pass_scan.evidence import build_evidence_profile


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class InvestigationEngine:
    """Run evidence-driven verification behind one small interface."""

    def __init__(self, config, executor, clock=None):
        self.config = config or {}
        self.executor = executor
        self.clock = clock or time.monotonic
        self.max_steps = max(1, int(self.config.get("max_agent_steps", 10)))
        self.max_http_requests = max(
            1,
            int(self.config.get("max_http_requests_per_candidate", 6)),
        )
        self.max_write_requests = max(
            0,
            int(self.config.get("max_write_requests_per_candidate", 1)),
        )
        self.max_seconds = max(
            1.0,
            float(self.config.get("max_investigation_seconds", 90)),
        )

    def investigate(self, candidate, request_budget=None):
        actions = list(self.executor.verification_actions(candidate))
        observations = []
        executed_action_ids = []
        skipped_action_ids = []
        started = self.clock()
        step_count = 0
        http_request_count = 0
        write_request_count = 0
        stop_reason = "actions_exhausted"
        request_limit = self.max_http_requests
        if request_budget is not None:
            request_limit = max(0, min(request_limit, int(request_budget)))

        pending = list(actions)
        while pending:
            profile = build_evidence_profile(candidate, observations)
            if profile.get("supports_confirmed"):
                stop_reason = "evidence_complete"
                break
            if step_count >= self.max_steps:
                stop_reason = "step_budget_exhausted"
                break
            if http_request_count >= request_limit:
                stop_reason = "http_budget_exhausted"
                break
            if self.clock() - started >= self.max_seconds:
                stop_reason = "time_budget_exhausted"
                break

            action = pending.pop(0)
            action_id = action.get("id") or f"action-{step_count + 1}"
            is_write = self.action_is_write(candidate, action)
            if is_write and write_request_count >= self.max_write_requests:
                skipped_action_ids.append(action_id)
                continue

            remaining_requests = request_limit - http_request_count
            allow_postcondition = remaining_requests >= 2
            action_observations = self.executor.execute_verification_action(
                candidate,
                action,
                allow_postcondition=allow_postcondition,
            )
            observations.extend(action_observations)
            executed_action_ids.append(action_id)
            step_count += 1
            http_request_count += len(action_observations)
            if is_write:
                write_request_count += 1

        remaining_action_ids = [
            action.get("id") or ""
            for action in pending
        ]
        remaining_action_ids.extend(skipped_action_ids)
        if skipped_action_ids and stop_reason == "actions_exhausted":
            stop_reason = "write_budget_exhausted"
        verification_complete = not remaining_action_ids
        profile = build_evidence_profile(
            candidate,
            observations,
            investigation={
                "planned_action_count": len(actions),
                "executed_action_count": len(executed_action_ids),
                "remaining_action_count": len(remaining_action_ids),
                "verification_complete": verification_complete,
                "stop_reason": stop_reason,
            },
        )

        if profile.get("supports_confirmed"):
            evidence_state = "confirmed_supported"
            stop_reason = "evidence_complete"
        elif profile.get("supports_rejected"):
            evidence_state = "rejected"
            stop_reason = "decisive_counter_evidence"
        else:
            evidence_state = "inconclusive"
            if not actions:
                stop_reason = "no_safe_verification_action"

        return {
            "evidence_state": evidence_state,
            "stop_reason": stop_reason,
            "observations": observations,
            "evidence_profile": profile,
            "planned_action_ids": [action.get("id") or "" for action in actions],
            "executed_action_ids": executed_action_ids,
            "remaining_action_ids": remaining_action_ids,
            "budget": {
                "max_steps": self.max_steps,
                "used_steps": step_count,
                "max_http_requests": request_limit,
                "used_http_requests": http_request_count,
                "max_write_requests": self.max_write_requests,
                "used_write_requests": write_request_count,
                "max_seconds": self.max_seconds,
                "elapsed_seconds": round(self.clock() - started, 3),
            },
        }

    def action_is_write(self, candidate, action):
        method = action.get("method") or (
            (candidate.runtime_source_flow or candidate.source_flow or {}).get("method")
        )
        return str(method or "").upper() in WRITE_METHODS
