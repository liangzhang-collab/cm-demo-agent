"""
Unit tests for Observability Plugin tracing and latency tracking.
"""

import pytest
from unittest.mock import MagicMock
from codemender_agent.plugins.observability import CodeMenderObservabilityPlugin


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
    plugin.before_tool_callback(tool=mock_tool, tool_args={"param": "val"}, tool_context=None)
    plugin.after_tool_callback(tool=mock_tool, tool_args={"param": "val"}, tool_context=None, result={"res": "ok"})

    summary = plugin.get_summary()
    assert summary["agent_invocations"]["test_agent"] == 1
    assert summary["tool_call_counts"]["test_tool"] == 1
    assert "test_tool" in summary["average_tool_latencies"]
    assert len(summary["latest_logs"]) >= 4
