"""
Unit tests for CodeMender ADK Agent architecture and multi-agent hierarchy.
"""

import pytest
from google.adk import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from google.adk.agents.parallel_agent import ParallelAgent
from google.adk.agents.loop_agent import LoopAgent

from codemender_agent.agents.auditor import auditor_agent
from codemender_agent.agents.scanners import sast_scanner_agent, sca_scanner_agent, parallel_scanner_agent
from codemender_agent.agents.fixer import code_fixer_agent, fix_verifier_agent, repair_loop_agent
from codemender_agent.agents.reporter import reporter_agent
from codemender_agent.agents.orchestrator import sequential_remediation_pipeline, root_agent


def test_agent_types():
    assert isinstance(auditor_agent, Agent)
    assert isinstance(sast_scanner_agent, Agent)
    assert isinstance(sca_scanner_agent, Agent)
    assert isinstance(parallel_scanner_agent, ParallelAgent)
    assert isinstance(code_fixer_agent, Agent)
    assert isinstance(fix_verifier_agent, Agent)
    assert isinstance(repair_loop_agent, LoopAgent)
    assert isinstance(reporter_agent, Agent)
    assert isinstance(sequential_remediation_pipeline, SequentialAgent)
    assert isinstance(root_agent, Agent)


def test_parallel_agent_sub_agents():
    assert len(parallel_scanner_agent.sub_agents) == 2
    names = [a.name for a in parallel_scanner_agent.sub_agents]
    assert "sast_scanner" in names
    assert "sca_scanner" in names


def test_loop_agent_sub_agents():
    assert len(repair_loop_agent.sub_agents) == 2
    names = [a.name for a in repair_loop_agent.sub_agents]
    assert "code_fixer" in names
    assert "fix_verifier" in names
    assert repair_loop_agent.max_iterations == 5


def test_sequential_agent_pipeline():
    assert len(sequential_remediation_pipeline.sub_agents) == 4
    names = [a.name for a in sequential_remediation_pipeline.sub_agents]
    assert names == [
        "env_and_repo_auditor",
        "parallel_vulnerability_scanner",
        "iterative_repair_loop",
        "security_reporter",
    ]


def test_root_orchestrator():
    assert root_agent.name == "codemender_orchestrator"
    assert len(root_agent.sub_agents) >= 1
    assert len(root_agent.tools) >= 5
