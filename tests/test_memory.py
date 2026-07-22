"""
Unit tests for Context state and CodeMenderMemory manager.
"""

import pytest
from codemender_agent.state.memory import CodeMenderMemory


def test_memory_initialization():
    state = {}
    memory = CodeMenderMemory(state)
    assert memory.get_repo_path() == "."
    assert memory.get_all_vulnerabilities() == []
    assert memory.is_repair_complete() is True


def test_memory_add_vulnerabilities():
    state = {}
    memory = CodeMenderMemory(state)
    vulns = [
        {"vuln_id": "V-1", "severity": "HIGH", "status": "DISCOVERED"},
        {"vuln_id": "V-2", "severity": "MEDIUM", "status": "DISCOVERED"},
    ]
    memory.add_vulnerabilities(vulns)

    assert len(memory.get_all_vulnerabilities()) == 2
    assert memory.get_next_pending_vulnerability()["vuln_id"] == "V-1"
    assert memory.is_repair_complete() is False


def test_memory_patch_and_verify():
    state = {}
    memory = CodeMenderMemory(state)
    memory.add_vulnerabilities([{"vuln_id": "V-1", "severity": "HIGH", "status": "DISCOVERED"}])

    memory.mark_patch_generated("V-1", "diff content")
    assert memory.get_all_vulnerabilities()[0]["status"] == "PATCH_GENERATED"

    memory.mark_verified_fixed("V-1")
    assert memory.get_all_vulnerabilities()[0]["status"] == "VERIFIED_FIXED"
    assert memory.is_repair_complete() is True
    assert memory.get_next_pending_vulnerability() is None
