"""
Human-in-the-Loop (HITL) Checkpoints and Gate Manager for CodeMender ADK Agent.
Intercepts high-stakes actions (critical-severity fixes, file deletions, auth modifications)
and mandates explicit human confirmation before proceeding.
"""

from typing import Any, Dict, List, Optional
from codemender_agent.config import SeverityLevel


class HumanInTheLoopManager:
    """
    Manages human review checkpoints for high-stakes agent remediation actions.
    """

    HIGH_STAKES_SEVERITIES = {SeverityLevel.CRITICAL.value, SeverityLevel.HIGH.value}

    def __init__(self):
        self.pending_approvals: List[Dict[str, Any]] = []
        self.approved_actions: List[Dict[str, Any]] = []

    def requires_human_approval(self, action_type: str, severity: Optional[str] = None) -> bool:
        """Determines if an action is high-stakes and requires a Human-in-the-Loop stop."""
        action_up = action_type.upper()
        if "CRITICAL" in action_up or "DELETE" in action_up or "OVERRIDE" in action_up:
            return True
        if severity and severity.upper() in self.HIGH_STAKES_SEVERITIES:
            return True
        return False

    def create_approval_request(self, action_type: str, vuln_id: str, patch_diff: str, reason: str) -> Dict[str, Any]:
        """Creates a pending approval request for a human security engineer."""
        req = {
            "approval_id": f"HITL-{len(self.pending_approvals) + 1:03d}",
            "action_type": action_type,
            "vuln_id": vuln_id,
            "patch_diff": patch_diff,
            "reason": reason,
            "status": "PENDING_HUMAN_REVIEW",
        }
        self.pending_approvals.append(req)
        return req

    def submit_human_decision(self, approval_id: str, approved: bool, reviewer: str = "Admin") -> Dict[str, Any]:
        """Records human decision for a pending checkpoint."""
        for req in self.pending_approvals:
            if req["approval_id"] == approval_id:
                req["status"] = "APPROVED" if approved else "REJECTED"
                req["reviewer"] = reviewer
                if approved:
                    self.approved_actions.append(req)
                return req
        return {"status": "NOT_FOUND", "approval_id": approval_id}
