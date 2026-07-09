from agent_pass_scan.idor import IDORDetector
from agent_pass_scan.mass_assignment import MassAssignmentDetector
from agent_pass_scan.tenant_isolation import TenantIsolationDetector
from agent_pass_scan.unauthorized import UnauthorizedDetector
from agent_pass_scan.vertical_authz import VerticalAuthzDetector
from agent_pass_scan.workflow_bypass import WorkflowBypassDetector


def default_detectors(config=None):
    return [
        UnauthorizedDetector(config),
        IDORDetector(config),
        TenantIsolationDetector(config),
        VerticalAuthzDetector(config),
        WorkflowBypassDetector(config),
        MassAssignmentDetector(config),
    ]
