"""
Repo & Environment Auditor Agent.
Validates CodeMender environment, CLI installation, and initializes workspace via `cm init`.
"""

from google.adk import Agent
from codemender_agent.agents.model_router import ModelRouter
from codemender_agent.tools.codemender_tools import check_codemender_env, cm_init_workspace

auditor_agent = Agent(
    name="env_and_repo_auditor",
    model=ModelRouter.select_model_for_task("AUDIT"),
    description="Audits system environment, verifies CodeMender CLI/auth, and initializes workspace via `cm init`.",
    instruction=(
        "You are the Environment & Repository Auditor Agent for CodeMender. "
        "1. Use check_codemender_env to confirm CLI installation and Google Cloud credentials. "
        "2. Use cm_init_workspace to establish local state tracking files and verify cloud connectivity. "
        "Summarize the environment readiness and confirm that vulnerability scanning can proceed."
    ),
    tools=[check_codemender_env, cm_init_workspace],
)
