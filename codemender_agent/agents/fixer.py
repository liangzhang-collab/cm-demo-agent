"""
Iterative Repair & Verification Loop Agents.
Implements patch generator agent, patch verifier agent, and LoopAgent container.
Alings with `cm fix` and `cm find verify` workflows.
"""

from google.adk import Agent
from google.adk.agents.loop_agent import LoopAgent
from google.adk.tools import exit_loop
from codemender_agent.agents.model_router import ModelRouter
from codemender_agent.tools.codemender_tools import (
    generate_vulnerability_fix,
    verify_vulnerability_fix,
    cm_verify_finding,
    cm_build_and_test,
)

code_fixer_agent = Agent(
    name="code_fixer",
    model=ModelRouter.select_model_for_task("PATCH_SYNTHESIS"),
    description="Generates automated patches and code fixes for detected vulnerabilities using `cm fix`.",
    instruction=(
        "You are the Code Repair Agent. "
        "Identify pending vulnerability findings from previous scan results. "
        "Use generate_vulnerability_fix to synthesize unified patch diffs for each vulnerability ID."
    ),
    tools=[generate_vulnerability_fix],
)

fix_verifier_agent = Agent(
    name="fix_verifier",
    model=ModelRouter.select_model_for_task("POLICY_VERIFICATION"),
    description="Verifies applied code patches using `cm find verify` and `cm build`, exiting the repair loop when remediated.",
    instruction=(
        "You are the Patch Verification Agent. "
        "For each vulnerability with a generated patch, call verify_vulnerability_fix and cm_build_and_test to confirm remediation. "
        "If all vulnerabilities have been verified clean or if no further fixes remain, invoke the exit_loop tool."
    ),
    tools=[verify_vulnerability_fix, cm_verify_finding, cm_build_and_test, exit_loop],
)

repair_loop_agent = LoopAgent(
    name="iterative_repair_loop",
    sub_agents=[code_fixer_agent, fix_verifier_agent],
    max_iterations=5,
    description="Iteratively generates fixes and verifies patches until all vulnerabilities are remediated or max iterations reached.",
)
