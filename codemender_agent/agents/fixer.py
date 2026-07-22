"""
Iterative Repair & Verification Loop Agents.
Implements patch generator agent, patch verifier agent, and LoopAgent container.
"""

from google.adk import Agent
from google.adk.agents.loop_agent import LoopAgent
from google.adk.tools import exit_loop
from codemender_agent.agents.model_router import ModelRouter
from codemender_agent.tools.codemender_tools import generate_vulnerability_fix, verify_vulnerability_fix

code_fixer_agent = Agent(
    name="code_fixer",
    model=ModelRouter.select_model_for_task("PATCH_SYNTHESIS"),
    description="Generates automated patches and code fixes for detected vulnerabilities.",
    instruction=(
        "You are the Code Repair Agent. "
        "Identify pending vulnerability IDs from previous scan findings. "
        "Use generate_vulnerability_fix to generate unified patch diffs for each vulnerability ID."
    ),
    tools=[generate_vulnerability_fix],
)

fix_verifier_agent = Agent(
    name="fix_verifier",
    model=ModelRouter.select_model_for_task("POLICY_VERIFICATION"),
    description="Verifies applied code patches and exits the repair loop when all vulnerabilities are remediated.",
    instruction=(
        "You are the Patch Verification Agent. "
        "For each vulnerability with a generated patch, call verify_vulnerability_fix to confirm remediation. "
        "If all vulnerabilities have been verified fixed or if no further fixes remain, invoke the exit_loop tool to complete the repair phase."
    ),
    tools=[verify_vulnerability_fix, exit_loop],
)

repair_loop_agent = LoopAgent(
    name="iterative_repair_loop",
    sub_agents=[code_fixer_agent, fix_verifier_agent],
    max_iterations=5,
    description="Iteratively generates fixes and verifies patches until all vulnerabilities are remediated or max iterations reached.",
)
