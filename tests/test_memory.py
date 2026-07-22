"""
Unit tests for Context state, CodeMenderMemory manager, History Compaction,
Async Memory Operations, and SqliteSessionService.
"""

import pytest
import asyncio
from codemender_agent.state.memory import CodeMenderMemory
from codemender_agent.state.session_db import SqliteSessionService


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


def test_history_compaction():
    state = {}
    memory = CodeMenderMemory(state)
    memory.add_vulnerabilities([{"vuln_id": "V-1", "severity": "CRITICAL", "status": "DISCOVERED"}])

    for i in range(15):
        memory.record_event("TRACE_STEP", {"step": i})

    summary = memory.compact_history(max_events=5)
    assert "COMPACTED CONTEXT SUMMARY" in summary
    assert len(state["codemender_event_history"]) <= 5


@pytest.mark.asyncio
async def test_async_memory_operations():
    state = {}
    memory = CodeMenderMemory(state, db_path=":memory:")
    vulns = [{"vuln_id": "V-ASYNC-1", "severity": "HIGH", "status": "DISCOVERED"}]

    await memory.add_vulnerabilities_async(vulns)
    all_vulns = await memory.get_all_vulnerabilities_async()
    assert len(all_vulns) == 1

    await memory.mark_patch_generated_async("V-ASYNC-1", "async diff")
    await memory.mark_verified_fixed_async("V-ASYNC-1")
    stats = await memory.get_summary_stats_async()
    assert stats["verified_fixed"] == 1


@pytest.mark.asyncio
async def test_sqlite_session_service():
    session_svc = SqliteSessionService(db_path=":memory:")
    session = await session_svc.create_session(
        app_name="codemender_test_app",
        user_id="user_123",
        session_id="test_sess_001",
        state={"repo": "."},
    )
    assert session.id == "test_sess_001"

    fetched = await session_svc.get_session(
        app_name="codemender_test_app",
        user_id="user_123",
        session_id="test_sess_001",
    )
    assert fetched is not None
    assert fetched.state.get("repo") == "."
