__all__ = ["LogicAgentScanner"]


def __getattr__(name):
    if name == "LogicAgentScanner":
        from agent_pass_scan.logic_plugin import LogicAgentScanner

        return LogicAgentScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
