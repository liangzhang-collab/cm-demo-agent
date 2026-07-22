"""
Orchestration agents combining SequentialAgent, ParallelAgent, LoopAgent, and LLM Orchestrator.
Integrates Strategic Model Routing, Security Policy Guardrails, and Human-in-the-Loop stops.
Fully aligned with the official CodeMender (`cm`) CLI command tree and workflows.
"""

from google.adk import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from codemender_agent.agents.auditor import auditor_agent
from codemender_agent.agents.scanners import parallel_scanner_agent, sast_scanner_agent, sca_scanner_agent
from codemender_agent.agents.fixer import repair_loop_agent
from codemender_agent.agents.reporter import reporter_agent
from codemender_agent.agents.model_router import ModelRouter, ModelTier
from codemender_agent.tools.codemender_tools import (
    check_codemender_env,
    cm_init_workspace,
    scan_sast_vulnerabilities,
    scan_sca_dependencies,
    cm_verify_finding,
    generate_vulnerability_fix,
    verify_vulnerability_fix,
    cm_import_findings,
    cm_vcs_operation,
    cm_build_and_test,
    cm_clean_workspace,
    export_security_report,
    request_human_approval,
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

# 2. Root LLM Orchestrator Agent (Strategic Pro Tier Model with sub-agents and tool calling)
root_agent = Agent(
    name="codemender_orchestrator",
    model=ModelRouter.select_model_for_task("ROOT_ORCHESTRATOR"),
    description="Root CodeMender LLM Orchestrator coordinating vulnerability scanning, strategic model routing, automated repair, and HITL human approvals.",
    instruction=(
        "You are the Lead CodeMender Security Orchestrator Agent. "
        "Your role is to manage CodeMender operations for local software repositories. "
        "You orchestrate specialized sub-agents and execute security remediation workflows: "
        "1. For full automated end-to-end audits and fixes, delegate to sequential_remediation_pipeline. "
        "2. For workspace setup, use cm_init_workspace. "
        "3. For scanning and exploit triage, use scan_sast_vulnerabilities, scan_sca_dependencies, or cm_verify_finding. "
        "4. For patch synthesis and verification, use generate_vulnerability_fix, verify_vulnerability_fix, and cm_build_and_test. "
        "5. For critical-severity patches or high-stakes actions, call request_human_approval before applying changes. "
        "Always validate inputs using strict schemas and provide clear, structured feedback on remediation status."
    ),
    sub_agents=[
        sequential_remediation_pipeline,
    ],
    tools=[
        check_codemender_env,
        cm_init_workspace,
        scan_sast_vulnerabilities,
        scan_sca_dependencies,
        cm_verify_finding,
        generate_vulnerability_fix,
        verify_vulnerability_fix,
        cm_import_findings,
        cm_vcs_operation,
        cm_build_and_test,
        cm_clean_workspace,
        export_security_report,
        request_human_approval,
    ],
)
