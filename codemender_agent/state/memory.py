"""
State & Memory Management for CodeMender ADK Agent.
Implements history compaction, async memory operations, and persistent state management.
"""

import asyncio
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional
import aiosqlite

from codemender_agent.config import Vulnerability, VulnerabilityStatus


class CodeMenderMemory:
    """
    Enhanced Context state and Memory Manager for CodeMender ADK Agent.
    Supports history compaction, async memory operations, and persistent database synchronization.
    """

    STATE_KEY_VULNS = "codemender_vulnerabilities"
    STATE_KEY_PENDING = "codemender_pending_fix_ids"
    STATE_KEY_FIXED = "codemender_fixed_vulns"
    STATE_KEY_REPO = "codemender_repo_path"
    STATE_KEY_REPORTS = "codemender_reports"
    STATE_KEY_HISTORY = "codemender_event_history"
    STATE_KEY_COMPACTED = "codemender_compacted_summary"

    def __init__(self, state_dict: Dict[str, Any], db_path: Optional[str] = None):
        self.state = state_dict
        self.db_path = db_path or os.getenv("CODEMENDER_DB_PATH", "codemender_state.db")
        self._lock = asyncio.Lock() if hasattr(asyncio, "Lock") else None

        # Initialize core state partitions
        if self.STATE_KEY_VULNS not in self.state:
            self.state[self.STATE_KEY_VULNS] = []
        if self.STATE_KEY_PENDING not in self.state:
            self.state[self.STATE_KEY_PENDING] = []
        if self.STATE_KEY_FIXED not in self.state:
            self.state[self.STATE_KEY_FIXED] = []
        if self.STATE_KEY_REPO not in self.state:
            self.state[self.STATE_KEY_REPO] = "."
        if self.STATE_KEY_HISTORY not in self.state:
            self.state[self.STATE_KEY_HISTORY] = []
        if self.STATE_KEY_COMPACTED not in self.state:
            self.state[self.STATE_KEY_COMPACTED] = ""

    # =========================================================================
    # Synchronous Memory Operations
    # =========================================================================

    def set_repo_path(self, repo_path: str):
        self.state[self.STATE_KEY_REPO] = repo_path

    def get_repo_path(self) -> str:
        return self.state.get(self.STATE_KEY_REPO, ".")

    def add_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """Add newly discovered vulnerabilities to context state."""
        existing_ids = {v.get("vuln_id") for v in self.state[self.STATE_KEY_VULNS]}
        for v in vulns:
            vid = v.get("vuln_id")
            if vid and vid not in existing_ids:
                self.state[self.STATE_KEY_VULNS].append(v)
                if v.get("status") != VulnerabilityStatus.VERIFIED_FIXED.value:
                    if vid not in self.state[self.STATE_KEY_PENDING]:
                        self.state[self.STATE_KEY_PENDING].append(vid)
                existing_ids.add(vid)
        self.record_event("ADD_VULNERABILITIES", {"count": len(vulns)})

    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.state.get(self.STATE_KEY_VULNS, [])

    def get_next_pending_vulnerability(self) -> Optional[Dict[str, Any]]:
        """Get the next vulnerability record from the pending queue."""
        pending_ids = self.state.get(self.STATE_KEY_PENDING, [])
        if not pending_ids:
            return None
        target_id = pending_ids[0]
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == target_id:
                return v
        return None

    def mark_patch_generated(self, vuln_id: str, patch_diff: str):
        """Update vulnerability status when patch is generated."""
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == vuln_id:
                v["status"] = VulnerabilityStatus.PATCH_GENERATED.value
                v["patch_diff"] = patch_diff
                break
        self.record_event("PATCH_GENERATED", {"vuln_id": vuln_id})

    def mark_verified_fixed(self, vuln_id: str):
        """Mark vulnerability as verified fixed and remove from pending queue."""
        for v in self.state.get(self.STATE_KEY_VULNS, []):
            if v.get("vuln_id") == vuln_id:
                v["status"] = VulnerabilityStatus.VERIFIED_FIXED.value
                break
        
        pending = self.state.get(self.STATE_KEY_PENDING, [])
        if vuln_id in pending:
            pending.remove(vuln_id)
        
        fixed = self.state.get(self.STATE_KEY_FIXED, [])
        if vuln_id not in fixed:
            fixed.append(vuln_id)
        self.record_event("VERIFIED_FIXED", {"vuln_id": vuln_id})

    def is_repair_complete(self) -> bool:
        """Returns True if no pending vulnerabilities remain in queue."""
        return len(self.state.get(self.STATE_KEY_PENDING, [])) == 0

    def record_event(self, event_type: str, metadata: Dict[str, Any]):
        """Record an event into memory history."""
        entry = {
            "event_type": event_type,
            "metadata": metadata,
        }
        self.state[self.STATE_KEY_HISTORY].append(entry)

    def compact_history(self, max_events: int = 5, preserve_critical_findings: bool = True) -> str:
        """
        Compacts verbose agent event history and tool traces into a high-density summary.
        Prunes older granular events while preserving all critical vulnerability records.
        """
        history = self.state.get(self.STATE_KEY_HISTORY, [])
        if len(history) <= max_events:
            return self.state.get(self.STATE_KEY_COMPACTED, "History within retention limits.")

        vulns = self.get_all_vulnerabilities()
        fixed = self.state.get(self.STATE_KEY_FIXED, [])
        pending = self.state.get(self.STATE_KEY_PENDING, [])

        summary_lines = [
            "=== COMPACTED CONTEXT SUMMARY ===",
            f"Repository: {self.get_repo_path()}",
            f"Total Discovered Vulnerabilities: {len(vulns)}",
            f"Remediated & Verified Fixed: {len(fixed)} ({', '.join(fixed) if fixed else 'None'})",
            f"Pending Unresolved Fixes: {len(pending)} ({', '.join(pending) if pending else 'None'})",
            f"Compacted Events Count: {len(history) - max_events}",
        ]

        if preserve_critical_findings:
            crit_vulns = [v for v in vulns if v.get("severity") in ("HIGH", "CRITICAL")]
            summary_lines.append(f"Critical/High Security Findings: {len(crit_vulns)}")

        compacted_text = "\n".join(summary_lines)
        self.state[self.STATE_KEY_COMPACTED] = compacted_text

        # Keep only the most recent events
        self.state[self.STATE_KEY_HISTORY] = history[-max_events:]
        return compacted_text

    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns summary statistics from memory."""
        vulns = self.get_all_vulnerabilities()
        pending = self.state.get(self.STATE_KEY_PENDING, [])
        fixed = self.state.get(self.STATE_KEY_FIXED, [])
        return {
            "total_discovered": len(vulns),
            "pending_fixes": len(pending),
            "verified_fixed": len(fixed),
            "repo_path": self.get_repo_path(),
            "history_events": len(self.state.get(self.STATE_KEY_HISTORY, [])),
            "has_compacted_summary": bool(self.state.get(self.STATE_KEY_COMPACTED)),
        }

    # =========================================================================
    # Asynchronous Memory Operations
    # =========================================================================

    async def add_vulnerabilities_async(self, vulns: List[Dict[str, Any]]):
        """Asynchronously add vulnerabilities to state."""
        await asyncio.sleep(0)  # Yield control to event loop
        self.add_vulnerabilities(vulns)

    async def get_all_vulnerabilities_async(self) -> List[Dict[str, Any]]:
        """Asynchronously retrieve all vulnerabilities."""
        await asyncio.sleep(0)
        return self.get_all_vulnerabilities()

    async def mark_patch_generated_async(self, vuln_id: str, patch_diff: str):
        """Asynchronously update patch status."""
        await asyncio.sleep(0)
        self.mark_patch_generated(vuln_id, patch_diff)

    async def mark_verified_fixed_async(self, vuln_id: str):
        """Asynchronously mark vulnerability verified fixed."""
        await asyncio.sleep(0)
        self.mark_verified_fixed(vuln_id)

    async def compact_history_async(self, max_events: int = 5, preserve_critical_findings: bool = True) -> str:
        """Asynchronously compact history."""
        await asyncio.sleep(0)
        return self.compact_history(max_events=max_events, preserve_critical_findings=preserve_critical_findings)

    async def get_summary_stats_async(self) -> Dict[str, Any]:
        """Asynchronously get memory summary stats."""
        await asyncio.sleep(0)
        return self.get_summary_stats()

    async def save_state_to_db_async(self, session_id: str = "default_session"):
        """Asynchronously persist memory state into SQLite database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS persistent_memory (
                    session_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            state_json = json.dumps(self.state)
            await db.execute("""
                INSERT INTO persistent_memory (session_id, state_json)
                VALUES (?, ?)
                ON CONFLICT(session_id) DO UPDATE SET state_json = excluded.state_json, updated_at = CURRENT_TIMESTAMP
            """, (session_id, state_json))
            await db.commit()

    async def load_state_from_db_async(self, session_id: str = "default_session") -> bool:
        """Asynchronously load memory state from SQLite database."""
        if not os.path.exists(self.db_path):
            return False
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS persistent_memory (
                    session_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            async with db.execute("SELECT state_json FROM persistent_memory WHERE session_id = ?", (session_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    loaded = json.loads(row[0])
                    self.state.update(loaded)
                    return True
        return False
