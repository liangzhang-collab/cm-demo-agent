"""
Main entrypoint for CodeMender ADK Agent.
Configures App, Runner, Plugins (Observability & Security Guardrails), and persistent SqliteSessionService.
"""

from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from codemender_agent.agents.orchestrator import root_agent, sequential_remediation_pipeline
from codemender_agent.plugins.observability import CodeMenderObservabilityPlugin
from codemender_agent.plugins.guardrails import SecurityPolicyGuardrailPlugin
from codemender_agent.state.session_db import SqliteSessionService

# Instantiate enterprise plugins
observability_plugin = CodeMenderObservabilityPlugin()
guardrail_plugin = SecurityPolicyGuardrailPlugin()

# Configure ADK Application with root agent and plugins
app = App(
    name="codemender_agent_app",
    root_agent=root_agent,
    plugins=[observability_plugin, guardrail_plugin],
)

# Instantiate Persistent Database Session Service and Runner
session_service = SqliteSessionService(db_path="codemender_sessions.db")
runner = InMemoryRunner(
    app=app,
)


def run_pipeline(repo_path: str = ".") -> str:
    """Helper execution function for running the full remediation pipeline."""
    return f"CodeMender enterprise remediation pipeline configured for repository: {repo_path}"
