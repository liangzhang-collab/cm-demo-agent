"""
Policy Guardrail Plugin for CodeMender ADK Agent.
Enforces corporate security policies, blocks unsafe code modifications,
and prevents hardcoded secrets or dangerous commands from being executed.
"""

import re
from typing import Any, Dict, List, Optional
from google.adk.plugins.base_plugin import BasePlugin


class SecurityPolicyGuardrailPlugin(BasePlugin):
    """
    ADK Policy Guardrail Plugin.
    Intercepts and validates tool invocations and code patches against strict security policies.
    """

    DANGEROUS_PATTERNS = [
        re.compile(r"os\.system\s*\(\s*['\"]rm\s+-rf", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"exec\s*\(", re.IGNORECASE),
        re.compile(r"subprocess\.Popen\s*\(\s*['\"][^'\"]*\|\s*bash", re.IGNORECASE),
        re.compile(r"verify\s*=\s*False", re.IGNORECASE),  # Disabling TLS verification
        re.compile(r"(AIza[0-9A-Za-z-_]{35}|sk-[a-zA-Z0-9]{32,})"),  # Hardcoding secrets in patches
    ]

    def __init__(self, plugin_name: str = "security_policy_guardrail"):
        super().__init__(name=plugin_name)
        self.blocked_actions: List[Dict[str, Any]] = []

    def validate_patch_diff(self, patch_diff: str) -> Optional[str]:
        """Check patch diff against dangerous anti-patterns."""
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(patch_diff):
                return f"Security Policy Violation: Proposed patch contains prohibited pattern matching '{pattern.pattern}'."
        return None

    def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        tool_name = getattr(tool, "name", str(tool))

        # 1. Guardrail for Patch Generation & Verification
        if "patch_diff" in tool_args:
            diff = tool_args.get("patch_diff", "")
            violation = self.validate_patch_diff(diff)
            if violation:
                self.blocked_actions.append({"tool": tool_name, "reason": violation})
                raise PermissionError(f"[POLICY GUARDRAIL BLOCKED] {violation}")

        # 2. Guardrail for Repository Boundary Containment
        repo_path = tool_args.get("repo_path", "")
        if repo_path and ("../.." in repo_path or repo_path.startswith("/etc") or repo_path.startswith("/var")):
            violation = f"Path Traversal Blocked: Target path '{repo_path}' attempts to escape permitted repository boundaries."
            self.blocked_actions.append({"tool": tool_name, "reason": violation})
            raise PermissionError(f"[POLICY GUARDRAIL BLOCKED] {violation}")

        return None

    def get_summary(self) -> Dict[str, Any]:
        return {
            "guardrail_status": "ACTIVE",
            "blocked_actions_count": len(self.blocked_actions),
            "blocked_actions": self.blocked_actions,
        }
