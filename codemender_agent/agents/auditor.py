"""
Repo & Environment Auditor Agent.
Validates CodeMender environment, CLI installation, authentication, and target repository.
"""

from google.adk import Agent
from codemender_agent.tools.codemender_tools import check_codemender_env

auditor_agent = Agent(
    name="env_and_repo_auditor",
    description="Audits system environment, verifies CodeMender installation/auth, and checks repository readiness.",
    instruction=(
        "You are the Environment & Repository Auditor Agent for CodeMender. "
        "Use the check_codemender_env tool to check if CodeMender CLI is installed and ready. "
        "Summarize the environment readiness and confirm that scanning can proceed."
    ),
    tools=[check_codemender_env],
)
