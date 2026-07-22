"""
State & Memory Management for CodeMender ADK Agent.
Wraps ADK Context state for managing scan results, vulnerability repair queues,
and session state across multi-agent executions.
"""

import json
from typing import Any, Dict, List, Optional
from codemender_agent.config import Vulnerability, VulnerabilityStatus


class CodeMenderMemory:
    """Helper class for managing CodeMender state inside ADK Context.state."""

    STATE_KEY_VULNS = "codemender_vulnerabilities"
    STATE_KEY_PENDING = "codemender_pending_fix_ids"
    STATE_KEY_FIXED = "codemender_fixed_vulns"
    STATE_KEY_REPO = "codemender_repo_path"
    STATE_KEY_REPORTS = "codemender_reports"

    def __init__(self, state_dict: Dict[str, Any]):
        self.state = state_dict
        if self.STATE_KEY_VULNS not in self.state:
            self.state[self.STATE_KEY_VULNS] = []
        if self.STATE_KEY_PENDING not in self.state:
            self.state[self.STATE_KEY_PENDING] = []
        if self.STATE_KEY_FIXED not in self.state:
            self.state[self.STATE_KEY_FIXED] = []
        if self.STATE_KEY_REPO not in self.state:
            self.state[self.STATE_KEY_REPO] = "."

    def set_repo_path(self, repo_path: str):
        self.state[self.STATE_KEY_REPO] = repo_path

    def get_repo_path(self) -> str:
        return self.state.get(self.STATE_KEY_REPO, ".")

    def add_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """Add newly discovered vulnerabilities to context state."""
        existing_ids = {v.get("vuln_id") for v in self.state[self.STATE_KEY_VULNS]}
        for v in vulns:
            vid = v.get("vuln_id")
            if vid and vid not in existing_ids:
                self.state[self.STATE_KEY_VULNS].append(v)
                if v.get("status") != VulnerabilityStatus.VERIFIED_FIXED.value:
                    self.state[self.STATE_KEY_PENDING].append(vid)
                existing_ids.add(vid)

    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.state.get(self.STATE_KEY_VULNS, [])

    def get_next_pending_vulnerability(self) -> Optional[Dict[str, Any]]:
        """Get the next vulnerability ID from the pending queue."""
        pending_ids = self.state.get(self.STATE_KEY_PENDING, [])
        if not pending_ids:
            return None
        target_id = pending_ids[0]
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == target_id:
                return v
        return None

    def mark_patch_generated(self, vuln_id: str, patch_diff: str):
        """Update vulnerability status when patch is generated."""
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == vuln_id:
                v["status"] = VulnerabilityStatus.PATCH_GENERATED.value
                v["patch_diff"] = patch_diff
                break

    def mark_verified_fixed(self, vuln_id: str):
        """Mark vulnerability as verified fixed and remove from pending queue."""
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == vuln_id:
                v["status"] = VulnerabilityStatus.VERIFIED_FIXED.value
                break
        
        pending = self.state.get(self.STATE_KEY_PENDING, [])
        if vuln_id in pending:
            pending.remove(vuln_id)
        
        fixed = self.state.get(self.STATE_KEY_FIXED, [])
        if vuln_id not in fixed:
            fixed.append(vuln_id)

    def is_repair_complete(self) -> bool:
        """Returns True if no pending vulnerabilities remain in queue."""
        return len(self.state.get(self.STATE_KEY_PENDING, [])) == 0

    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns quick summary statistics from memory."""
        vulns = self.get_all_vulnerabilities()
        pending = self.state.get(self.STATE_KEY_PENDING, [])
        fixed = self.state.get(self.STATE_KEY_FIXED, [])
        return {
            "total_discovered": len(vulns),
            "pending_fixes": len(pending),
            "verified_fixed": len(fixed),
            "repo_path": self.get_repo_path(),
        }
