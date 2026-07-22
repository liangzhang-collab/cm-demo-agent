"""
Parallel Scanner Agents (SAST & SCA).
Implements SAST static analysis agent, SCA dependency scanner agent, and ParallelAgent container.
"""

from google.adk import Agent
from google.adk.agents.parallel_agent import ParallelAgent
from codemender_agent.agents.model_router import ModelRouter
from codemender_agent.tools.codemender_tools import scan_sast_vulnerabilities, scan_sca_dependencies

sast_scanner_agent = Agent(
    name="sast_scanner",
    model=ModelRouter.select_model_for_task("SAST_SCAN"),
    description="Performs Static Application Security Testing (SAST) to discover vulnerabilities in source code.",
    instruction=(
        "You are the SAST Scanner Agent. "
        "Call scan_sast_vulnerabilities for the target repository path. "
        "List all discovered static code vulnerabilities (SQL injection, path traversal, hardcoded secrets, etc.)."
    ),
    tools=[scan_sast_vulnerabilities],
)

sca_scanner_agent = Agent(
    name="sca_scanner",
    model=ModelRouter.select_model_for_task("SCA"),
    description="Performs Software Composition Analysis (SCA) to discover package and dependency vulnerabilities.",
    instruction=(
        "You are the SCA Dependency Scanner Agent. "
        "Call scan_sca_dependencies for the target repository path. "
        "List all discovered third-party library vulnerabilities and outdated dependencies."
    ),
    tools=[scan_sca_dependencies],
)

parallel_scanner_agent = ParallelAgent(
    name="parallel_vulnerability_scanner",
    sub_agents=[sast_scanner_agent, sca_scanner_agent],
    description="Runs SAST static code analysis and SCA dependency scanning concurrently in parallel.",
)
