"""
Unit tests for Policy Guardrails, Human-in-the-Loop stops, and Model Routing.
"""

import pytest
from unittest.mock import MagicMock
from codemender_agent.plugins.guardrails import SecurityPolicyGuardrailPlugin
from codemender_agent.agents.hitl import HumanInTheLoopManager
from codemender_agent.agents.model_router import ModelRouter, ModelTier
from codemender_agent.config import SeverityLevel


def test_guardrail_blocks_dangerous_payload():
    guard = SecurityPolicyGuardrailPlugin()
    mock_tool = MagicMock()
    mock_tool.name = "generate_vulnerability_fix"

    # Dangerous payload
    with pytest.raises(PermissionError) as exc_info:
        guard.before_tool_callback(
            tool=mock_tool,
            tool_args={"patch_diff": "os.system('rm -rf /')"},
            tool_context=None,
        )
    assert "POLICY GUARDRAIL BLOCKED" in str(exc_info.value)


def test_guardrail_blocks_path_traversal():
    guard = SecurityPolicyGuardrailPlugin()
    mock_tool = MagicMock()
    mock_tool.name = "scan_sast"

    with pytest.raises(PermissionError) as exc_info:
        guard.before_tool_callback(
            tool=mock_tool,
            tool_args={"repo_path": "/etc/passwd"},
            tool_context=None,
        )
    assert "Path Traversal Blocked" in str(exc_info.value)


def test_human_in_the_loop_manager():
    hitl = HumanInTheLoopManager()
    assert hitl.requires_human_approval("APPLY_CRITICAL_PATCH", "CRITICAL") is True
    assert hitl.requires_human_approval("SCAN_SCA", "LOW") is False

    req = hitl.create_approval_request("APPLY_CRITICAL_PATCH", "SAST-SQLI-001", "diff", "Production Fix")
    assert req["status"] == "PENDING_HUMAN_REVIEW"

    dec = hitl.submit_human_decision(req["approval_id"], approved=True, reviewer="LeadSecOps")
    assert dec["status"] == "APPROVED"


def test_model_router():
    # Complex / High-Stakes tasks use Pro
    assert ModelRouter.select_model_for_task("PATCH_SYNTHESIS") == ModelTier.PRO.value
    assert ModelRouter.select_model_for_task("SAST", SeverityLevel.CRITICAL) == ModelTier.PRO.value

    # Lightweight / Low-latency tasks use Flash
    assert ModelRouter.select_model_for_task("AUDIT") == ModelTier.FLASH.value
    assert ModelRouter.select_model_for_task("SCA", SeverityLevel.LOW) == ModelTier.FLASH.value
