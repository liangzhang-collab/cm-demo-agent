"""
Observability and Tracing Plugin for CodeMender ADK Agent.
Implements structured JSON logging, OpenTelemetry distributed tracing,
PII & sensitive secret redaction, and cognitive intent vs. outcome tracking.
"""

import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from google.adk.plugins.base_plugin import BasePlugin

# OpenTelemetry distributed tracing imports
try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode, Tracer
    from opentelemetry.sdk.trace import TracerProvider

    provider = TracerProvider()
    trace.set_tracer_provider(provider)
    tracer: Optional[Tracer] = trace.get_tracer("codemender.agent", "2.0.0")
except Exception:
    tracer = None


class PIIRedactor:
    """Scrubs sensitive API keys, auth tokens, passwords, and PII from logs and traces."""

    PATTERNS = [
        (re.compile(r"AIza[0-9A-Za-z-_]{20,}"), "[REDACTED_GCP_KEY]"),
        (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "[REDACTED_API_KEY]"),
        (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
        (re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT]"),
        (re.compile(r"(password|secret|token|api_key)[\s:=]+['\"][^'\"]+['\"]", re.IGNORECASE), r"\1='[REDACTED]'"),
        (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[REDACTED_EMAIL]"),
        (re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]+?-----END[ A-Z0-9_-]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    ]

    @classmethod
    def redact(cls, text: Any) -> Any:
        if isinstance(text, str):
            res = text
            for pattern, replacement in cls.PATTERNS:
                res = pattern.sub(replacement, res)
            return res
        elif isinstance(text, dict):
            return {k: cls.redact(v) for k, v in text.items()}
        elif isinstance(text, list):
            return [cls.redact(i) for i in text]
        return text


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": PIIRedactor.redact(record.getMessage()),
        }
        if hasattr(record, "structured_data"):
            payload["data"] = PIIRedactor.redact(getattr(record, "structured_data"))
        return json.dumps(payload)


logger = logging.getLogger("CodeMenderStructuredObservability")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())
    logger.addHandler(handler)


class CodeMenderObservabilityPlugin(BasePlugin):
    """
    Enterprise Observability & Tracing plugin for CodeMender ADK Agent.
    Provides:
    - Structured JSON audit logging
    - OpenTelemetry distributed tracing spans
    - Automated PII and secret redaction
    - Explicit cognitive intent vs. observed outcome tracking
    """

    def __init__(self, plugin_name: str = "codemender_observability"):
        super().__init__(name=plugin_name)
        self.audit_logs: List[Dict[str, Any]] = []
        self.tool_call_counts: Dict[str, int] = {}
        self.agent_invocation_counts: Dict[str, int] = {}
        self.tool_latencies: Dict[str, List[float]] = {}
        self._tool_start_times: Dict[str, float] = {}
        self._active_spans: Dict[str, Any] = {}

    def log_event(self, event_type: str, component: str, cognitive_intent: str, observed_outcome: str, metadata: Optional[Dict[str, Any]] = None):
        """Emits structured JSON log with explicit cognitive intent vs. observed outcome."""
        redacted_meta = PIIRedactor.redact(metadata or {})
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "component": component,
            "cognitive_intent": cognitive_intent,
            "observed_outcome": observed_outcome,
            "metadata": redacted_meta,
        }
        self.audit_logs.append(entry)
        logger.info(
            f"[{event_type}] {component} | Intent: {cognitive_intent} -> Outcome: {observed_outcome}",
            extra={"structured_data": entry},
        )

    def before_agent_callback(self, *, agent: Any, callback_context: Any) -> Optional[Any]:
        agent_name = getattr(agent, "name", "unknown_agent")
        self.agent_invocation_counts[agent_name] = self.agent_invocation_counts.get(agent_name, 0) + 1

        if tracer:
            span = tracer.start_span(f"agent.{agent_name}")
            span.set_attribute("agent.name", agent_name)
            span.set_attribute("event_type", "AGENT_START")
            self._active_spans[f"agent_{agent_name}"] = span

        self.log_event(
            event_type="AGENT_START",
            component=agent_name,
            cognitive_intent=f"Initialize agent '{agent_name}' for security workflow execution",
            observed_outcome="Agent lifecycle hook engaged successfully",
        )
        return None

    def after_agent_callback(self, *, agent: Any, callback_context: Any) -> Optional[Any]:
        agent_name = getattr(agent, "name", "unknown_agent")

        span_key = f"agent_{agent_name}"
        if span_key in self._active_spans:
            span = self._active_spans.pop(span_key)
            span.set_status(Status(StatusCode.OK))
            span.end()

        self.log_event(
            event_type="AGENT_FINISH",
            component=agent_name,
            cognitive_intent=f"Complete execution phase for agent '{agent_name}'",
            observed_outcome="Agent completed successfully with state preserved",
        )
        return None

    def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        tool_name = getattr(tool, "name", str(tool))
        self.tool_call_counts[tool_name] = self.tool_call_counts.get(tool_name, 0) + 1
        self._tool_start_times[tool_name] = time.time()

        redacted_args = PIIRedactor.redact(tool_args)

        if tracer:
            span = tracer.start_span(f"tool.{tool_name}")
            span.set_attribute("tool.name", tool_name)
            span.set_attribute("tool.args", json.dumps(redacted_args))
            self._active_spans[f"tool_{tool_name}"] = span

        intent_desc = f"Execute tool '{tool_name}' to interact with CodeMender engine"
        self.log_event(
            event_type="TOOL_START",
            component=tool_name,
            cognitive_intent=intent_desc,
            observed_outcome="Tool invocation started with validated parameters",
            metadata={"args": redacted_args},
        )
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

        redacted_result = PIIRedactor.redact(result)

        span_key = f"tool_{tool_name}"
        if span_key in self._active_spans:
            span = self._active_spans.pop(span_key)
            span.set_attribute("latency_seconds", round(latency, 4))
            span.set_status(Status(StatusCode.OK))
            span.end()

        outcome_desc = f"Tool '{tool_name}' completed in {latency:.4f}s"
        self.log_event(
            event_type="TOOL_FINISH",
            component=tool_name,
            cognitive_intent=f"Assess output and verification result of '{tool_name}'",
            observed_outcome=outcome_desc,
            metadata={"latency_seconds": round(latency, 4), "result_preview": str(redacted_result)[:200]},
        )
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
            "latest_structured_logs": self.audit_logs[-10:],
            "distributed_tracing_enabled": tracer is not None,
        }
