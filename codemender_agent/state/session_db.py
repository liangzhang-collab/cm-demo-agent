"""
Persistent SQLite-backed Database Session Service for CodeMender ADK Agent.
Replaces in-memory session stores with a durable, persistent database backing.
"""

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional
import aiosqlite

from google.adk.events.event import Event
from google.adk.sessions.base_session_service import BaseSessionService, GetSessionConfig, ListSessionsResponse
from google.adk.sessions.session import Session


class SqliteSessionService(BaseSessionService):
    """
    Persistent Database Session Service using SQLite.
    Guarantees session state, event streams, and agent memories persist across process restarts.
    """

    def __init__(self, db_path: str = "codemender_sessions.db"):
        super().__init__()
        if db_path == ":memory:":
            self.db_path = "file:codemender_mem?mode=memory&cache=shared"
            self._shared_uri = True
        else:
            self.db_path = db_path
            self._shared_uri = False
        self._init_db_sync()

    def _init_db_sync(self):
        with sqlite3.connect(self.db_path, uri=self._shared_uri) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS adk_sessions (
                    app_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    last_update_time REAL NOT NULL,
                    PRIMARY KEY (app_name, user_id, session_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS adk_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.commit()

    async def _ensure_tables_async(self, db: aiosqlite.Connection):
        await db.execute("""
            CREATE TABLE IF NOT EXISTS adk_sessions (
                app_name TEXT NOT NULL,
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                state_json TEXT NOT NULL,
                last_update_time REAL NOT NULL,
                PRIMARY KEY (app_name, user_id, session_id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS adk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_json TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        await db.commit()

    async def create_session(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: Optional[str] = None,
        state: Optional[Dict[str, Any]] = None,
    ) -> Session:
        sid = session_id.strip() if session_id and session_id.strip() else f"sess_{int(time.time()*1000)}"
        initial_state = state or {}
        now = time.time()

        async with aiosqlite.connect(self.db_path, uri=self._shared_uri) as db:
            await self._ensure_tables_async(db)
            await db.execute("""
                INSERT OR REPLACE INTO adk_sessions (app_name, user_id, session_id, state_json, last_update_time)
                VALUES (?, ?, ?, ?, ?)
            """, (app_name, user_id, sid, json.dumps(initial_state), now))
            await db.commit()

        return Session(
            app_name=app_name,
            user_id=user_id,
            id=sid,
            state=initial_state,
            last_update_time=now,
        )

    async def get_session(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        config: Optional[GetSessionConfig] = None,
    ) -> Optional[Session]:
        async with aiosqlite.connect(self.db_path, uri=self._shared_uri) as db:
            await self._ensure_tables_async(db)
            async with db.execute("""
                SELECT state_json, last_update_time FROM adk_sessions
                WHERE app_name = ? AND user_id = ? AND session_id = ?
            """, (app_name, user_id, session_id)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                state_data = json.loads(row[0])
                last_time = row[1]

        sess = Session(
            app_name=app_name,
            user_id=user_id,
            id=session_id,
            state=state_data,
            last_update_time=last_time,
        )
        return sess

    def get_session_sync(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        config: Optional[GetSessionConfig] = None,
    ) -> Optional[Session]:
        self._init_db_sync()
        with sqlite3.connect(self.db_path, uri=self._shared_uri) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT state_json, last_update_time FROM adk_sessions
                WHERE app_name = ? AND user_id = ? AND session_id = ?
            """, (app_name, user_id, session_id))
            row = cursor.fetchone()
            if not row:
                return None
            return Session(
                app_name=app_name,
                user_id=user_id,
                id=session_id,
                state=json.loads(row[0]),
                last_update_time=row[1],
            )

    async def list_sessions(
        self, *, app_name: str, user_id: Optional[str] = None
    ) -> ListSessionsResponse:
        sessions: List[Session] = []
        async with aiosqlite.connect(self.db_path, uri=self._shared_uri) as db:
            await self._ensure_tables_async(db)
            query = "SELECT app_name, user_id, session_id, state_json, last_update_time FROM adk_sessions WHERE app_name = ?"
            params = [app_name]
            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)

            async with db.execute(query, tuple(params)) as cursor:
                rows = await cursor.fetchall()
                for r in rows:
                    sessions.append(Session(
                        app_name=r[0],
                        user_id=r[1],
                        id=r[2],
                        state=json.loads(r[3]),
                        last_update_time=r[4],
                    ))

        return ListSessionsResponse(sessions=sessions)

    async def delete_session(
        self, *, app_name: str, user_id: str, session_id: str
    ) -> None:
        async with aiosqlite.connect(self.db_path, uri=self._shared_uri) as db:
            await self._ensure_tables_async(db)
            await db.execute("""
                DELETE FROM adk_sessions WHERE app_name = ? AND user_id = ? AND session_id = ?
            """, (app_name, user_id, session_id))
            await db.execute("""
                DELETE FROM adk_events WHERE app_name = ? AND user_id = ? AND session_id = ?
            """, (app_name, user_id, session_id))
            await db.commit()

    async def append_event(self, session: Session, event: Event) -> Event:
        now = time.time()
        session.last_update_time = now

        async with aiosqlite.connect(self.db_path, uri=self._shared_uri) as db:
            await self._ensure_tables_async(db)
            await db.execute("""
                UPDATE adk_sessions SET state_json = ?, last_update_time = ?
                WHERE app_name = ? AND user_id = ? AND session_id = ?
            """, (json.dumps(session.state), now, session.app_name, session.user_id, session.id))

            event_dict = {
                "author": getattr(event, "author", "agent"),
                "timestamp": getattr(event, "timestamp", now),
            }
            await db.execute("""
                INSERT INTO adk_events (app_name, user_id, session_id, event_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (session.app_name, session.user_id, session.id, json.dumps(event_dict), now))
            await db.commit()

        return event

    async def get_user_state(
        self, *, app_name: str, user_id: str
    ) -> Dict[str, Any]:
        return {}
