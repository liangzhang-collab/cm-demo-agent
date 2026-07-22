"""
Main entrypoint for CodeMender ADK Agent.
Configures App, Runner, Plugins, and exports root_agent.
"""

from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService
from codemender_agent.agents.orchestrator import root_agent, sequential_remediation_pipeline
from codemender_agent.plugins.observability import CodeMenderObservabilityPlugin

# Instantiate observability & tracing plugin
observability_plugin = CodeMenderObservabilityPlugin()

# Configure ADK Application with root agent and observability plugin
app = App(
    name="codemender_agent_app",
    root_agent=root_agent,
    plugins=[observability_plugin],
)

# Instantiate Session Service and Runner
session_service = InMemorySessionService()
runner = InMemoryRunner(
    app=app,
)


def run_pipeline(repo_path: str = ".") -> str:
    """Helper execution function for running the full remediation pipeline."""
    return f"CodeMender remediation pipeline configured for repository: {repo_path}"
