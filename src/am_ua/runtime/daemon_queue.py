"""Always-On Durable Daemon Queue & Webhook Event Trigger (`am_ua.runtime.daemon_queue`).

Provides a crash-safe SQLite WAL persistent task queue (`enqueue`, `claim_next`, `complete`,
`fail` with retry backoff, and `ingest_webhook`) so OmniExecutor can operate as a continuous
background daemon resilient to process restarts and OS reboots.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional


class DurableDaemonQueue:
    """SQLite WAL persistent task & webhook event queue for always-on agent execution."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daemon_tasks (
                    task_id TEXT PRIMARY KEY,
                    objective TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 50,
                    status TEXT NOT NULL DEFAULT 'queued',
                    worker_id TEXT,
                    scheduled_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    result_json TEXT,
                    error_text TEXT,
                    source TEXT DEFAULT 'cli'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daemon_webhooks (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    task_id TEXT,
                    received_at REAL NOT NULL
                )
                """
            )

    def enqueue(
        self,
        objective: str,
        workspace: str,
        *,
        priority: int = 50,
        scheduled_at: Optional[float] = None,
        source: str = "cli",
        task_id: Optional[str] = None,
    ) -> str:
        now = time.time()
        tid = task_id or f"dq-{uuid.uuid4().hex[:12]}"
        sched = now if scheduled_at is None else float(scheduled_at)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO daemon_tasks
                    (task_id, objective, workspace, priority, status, scheduled_at, created_at, updated_at, source)
                VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)
                """,
                (tid, objective, str(workspace), int(priority), sched, now, now, source),
            )
        return tid

    def claim_next(self, worker_id: str, *, now_ts: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Atomically claim the highest-priority due task."""
        now = time.time() if now_ts is None else float(now_ts)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM daemon_tasks
                WHERE status = 'queued' AND scheduled_at <= ?
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE daemon_tasks
                SET status = 'running', worker_id = ?, updated_at = ?, attempts = attempts + 1
                WHERE task_id = ? AND status = 'queued'
                """,
                (worker_id, now, row["task_id"]),
            )
            updated = conn.execute("SELECT * FROM daemon_tasks WHERE task_id = ?", (row["task_id"],)).fetchone()
            return dict(updated) if updated else None

    def complete(self, task_id: str, result: Dict[str, Any]) -> None:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE daemon_tasks
                SET status = 'completed', result_json = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (json.dumps(result, ensure_ascii=False, default=str), now, task_id),
            )

    def fail(self, task_id: str, error: str, *, retry_delay_s: Optional[float] = None) -> None:
        now = time.time()
        if retry_delay_s is not None and retry_delay_s >= 0:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE daemon_tasks
                    SET status = 'queued', error_text = ?, scheduled_at = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (str(error)[:500], now + float(retry_delay_s), now, task_id),
                )
        else:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE daemon_tasks
                    SET status = 'failed', error_text = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (str(error)[:500], now, task_id),
                )

    def ingest_webhook(
        self,
        source: str,
        event_type: str,
        payload: Dict[str, Any],
        *,
        workspace: str = ".",
        priority: int = 80,
    ) -> Dict[str, Any]:
        """Record an external webhook event and convert it into a durable queued task."""
        eid = f"wh-{uuid.uuid4().hex[:12]}"
        objective = f"[WEBHOOK:{source}:{event_type}] {payload.get('summary') or payload.get('title') or json.dumps(payload, ensure_ascii=False)[:200]}"
        tid = self.enqueue(objective, workspace=workspace, priority=priority, source=f"webhook:{source}")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO daemon_webhooks (event_id, source, event_type, payload_json, task_id, received_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (eid, source, event_type, json.dumps(payload, ensure_ascii=False, default=str), tid, time.time()),
            )
        return {"ok": True, "event_id": eid, "task_id": tid, "source": source, "event_type": event_type}

    def stats(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) as cnt FROM daemon_tasks GROUP BY status").fetchall()
            out = {"queued": 0, "running": 0, "completed": 0, "failed": 0}
            for r in rows:
                out[str(r["status"])] = int(r["cnt"])
            return out
