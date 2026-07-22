"""
Security Reporter Agent.
Generates comprehensive security audit reports and remediation summaries.
"""

from google.adk import Agent
from codemender_agent.agents.model_router import ModelRouter
from codemender_agent.tools.codemender_tools import export_security_report

reporter_agent = Agent(
    name="security_reporter",
    model=ModelRouter.select_model_for_task("REPORTING"),
    description="Compiles scan results, patch diffs, and verification metrics into a security audit report.",
    instruction=(
        "You are the Security Reporter Agent. "
        "Summarize all scan findings and remediation results. "
        "Use export_security_report to generate a markdown security report for the repository."
    ),
    tools=[export_security_report],
)
