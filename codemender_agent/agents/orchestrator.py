"""
Orchestration agents combining SequentialAgent, ParallelAgent, LoopAgent, and LLM Orchestrator.
"""

from google.adk import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from codemender_agent.agents.auditor import auditor_agent
from codemender_agent.agents.scanners import parallel_scanner_agent, sast_scanner_agent, sca_scanner_agent
from codemender_agent.agents.fixer import repair_loop_agent
from codemender_agent.agents.reporter import reporter_agent
from codemender_agent.tools.codemender_tools import (
    check_codemender_env,
    scan_sast_vulnerabilities,
    scan_sca_dependencies,
    generate_vulnerability_fix,
    verify_vulnerability_fix,
    export_security_report,
)

# 1. Sequential Pipeline Agent executing full end-to-end security mending
sequential_remediation_pipeline = SequentialAgent(
    name="sequential_remediation_pipeline",
    sub_agents=[
        auditor_agent,
        parallel_scanner_agent,
        repair_loop_agent,
        reporter_agent,
    ],
    description="Full automated end-to-end pipeline: Auditor -> Parallel Scanners -> Iterative Repair Loop -> Security Reporter.",
)

# 2. Root LLM Orchestrator Agent (uses sub-agents and tools)
root_agent = Agent(
    name="codemender_orchestrator",
    model="gemini-2.5-flash",
    description="Root CodeMender LLM Orchestrator coordinating vulnerability scanning, automated repair, and reporting.",
    instruction=(
        "You are the Lead CodeMender Security Orchestrator Agent. "
        "Your role is to manage CodeMender operations for local software repositories. "
        "You orchestrate specialized sub-agents and execute security remediation workflows: "
        "1. For full automated end-to-end audits and fixes, delegate to sequential_remediation_pipeline. "
        "2. For individual direct tasks, use your security tools as appropriate. "
        "Always provide clear, structured feedback on security posture and remediation status."
    ),
    sub_agents=[
        sequential_remediation_pipeline,
    ],
    tools=[
        check_codemender_env,
        scan_sast_vulnerabilities,
        scan_sca_dependencies,
        generate_vulnerability_fix,
        verify_vulnerability_fix,
        export_security_report,
    ],
)
