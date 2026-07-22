"""
Unit tests for Observability Plugin, OpenTelemetry tracing, PII Redaction,
and Cognitive Intent vs. Observed Outcome tracking.
"""

import pytest
from unittest.mock import MagicMock
from codemender_agent.plugins.observability import CodeMenderObservabilityPlugin, PIIRedactor


def test_pii_redactor():
    secret_text = "Connected using AIzaSyD98734918237491823749 and email test@example.com with password='super_secret_password'"
    redacted = PIIRedactor.redact(secret_text)
    assert "[REDACTED_GCP_KEY]" in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "super_secret_password" not in redacted


def test_observability_plugin_lifecycle():
    plugin = CodeMenderObservabilityPlugin()

    mock_agent = MagicMock()
    mock_agent.name = "test_agent"
    mock_context = MagicMock()

    # Agent start / finish
    plugin.before_agent_callback(agent=mock_agent, callback_context=mock_context)
    plugin.after_agent_callback(agent=mock_agent, callback_context=mock_context)

    # Tool start / finish
    mock_tool = MagicMock()
    mock_tool.name = "test_tool"
    plugin.before_tool_callback(tool=mock_tool, tool_args={"api_key": "AIzaSyD98734918237491823749"}, tool_context=None)
    plugin.after_tool_callback(tool=mock_tool, tool_args={}, tool_context=None, result={"status": "clean"})

    summary = plugin.get_summary()
    assert summary["agent_invocations"]["test_agent"] == 1
    assert summary["tool_call_counts"]["test_tool"] == 1
    assert "test_tool" in summary["average_tool_latencies"]
    assert len(summary["latest_structured_logs"]) >= 4

    # Verify cognitive intent and outcome recorded
    logs = summary["latest_structured_logs"]
    assert any("cognitive_intent" in log and "observed_outcome" in log for log in logs)
