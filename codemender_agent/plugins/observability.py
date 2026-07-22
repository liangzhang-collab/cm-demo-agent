"""
Observability and Tracing Plugin for CodeMender ADK Agent.
Extends google.adk.plugins.base_plugin.BasePlugin to provide execution metrics,
tool call latency tracking, audit logs, and agent state tracing.
"""

import logging
import time
from typing import Any, Dict, List, Optional
from google.adk.plugins.base_plugin import BasePlugin

logger = logging.getLogger("CodeMenderObservability")


class CodeMenderObservabilityPlugin(BasePlugin):
    """
    Custom Observability & Tracing plugin for CodeMender Agent.
    Tracks performance, tool invocations, agent workflow steps, and audit logs.
    """

    def __init__(self, plugin_name: str = "codemender_observability"):
        super().__init__(name=plugin_name)
        self.audit_logs: List[Dict[str, Any]] = []
        self.tool_call_counts: Dict[str, int] = {}
        self.agent_invocation_counts: Dict[str, int] = {}
        self.tool_latencies: Dict[str, List[float]] = {}
        self._tool_start_times: Dict[str, float] = {}

    def before_agent_callback(self, *, agent: Any, callback_context: Any) -> Optional[Any]:
        agent_name = getattr(agent, "name", "unknown_agent")
        self.agent_invocation_counts[agent_name] = self.agent_invocation_counts.get(agent_name, 0) + 1
        log_entry = {
            "timestamp": time.time(),
            "event": "AGENT_START",
            "agent": agent_name,
        }
        self.audit_logs.append(log_entry)
        logger.info(f"[OBSERVABILITY] Starting Agent: {agent_name}")
        return None

    def after_agent_callback(self, *, agent: Any, callback_context: Any) -> Optional[Any]:
        agent_name = getattr(agent, "name", "unknown_agent")
        log_entry = {
            "timestamp": time.time(),
            "event": "AGENT_FINISH",
            "agent": agent_name,
        }
        self.audit_logs.append(log_entry)
        logger.info(f"[OBSERVABILITY] Finished Agent: {agent_name}")
        return None

    def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        tool_name = getattr(tool, "name", str(tool))
        self.tool_call_counts[tool_name] = self.tool_call_counts.get(tool_name, 0) + 1
        self._tool_start_times[tool_name] = time.time()

        log_entry = {
            "timestamp": time.time(),
            "event": "TOOL_START",
            "tool": tool_name,
            "args": tool_args,
        }
        self.audit_logs.append(log_entry)
        logger.info(f"[OBSERVABILITY] Starting Tool: {tool_name}")
        return None

    def after_tool_callback(
        self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any, result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        tool_name = getattr(tool, "name", str(tool))
        start_time = self._tool_start_times.pop(tool_name, time.time())
        latency = time.time() - start_time

        if tool_name not in self.tool_latencies:
            self.tool_latencies[tool_name] = []
        self.tool_latencies[tool_name].append(latency)

        log_entry = {
            "timestamp": time.time(),
            "event": "TOOL_FINISH",
            "tool": tool_name,
            "latency_seconds": round(latency, 4),
        }
        self.audit_logs.append(log_entry)
        logger.info(f"[OBSERVABILITY] Finished Tool: {tool_name} (latency: {latency:.4f}s)")
        return None

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured observability and performance metrics summary."""
        avg_latencies = {
            tool: round(sum(lats) / len(lats), 4) if lats else 0.0
            for tool, lats in self.tool_latencies.items()
        }
        return {
            "total_audit_events": len(self.audit_logs),
            "agent_invocations": self.agent_invocation_counts,
            "tool_call_counts": self.tool_call_counts,
            "average_tool_latencies": avg_latencies,
            "latest_logs": self.audit_logs[-10:],
        }
