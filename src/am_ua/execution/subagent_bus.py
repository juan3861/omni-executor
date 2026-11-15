"""Sub-Agent Session Spawner & Cross-Agent Bus — OpenClaw Gateway Architecture (F5).

Assimilates `openclaw/openclaw` (`sessions_spawn`, `sessions_send`, multi-agent isolation):
1. Durable SQLite WAL Registry (`subagent_sessions` + `subagent_messages`) tracking parent/child
   lineage, depth, workspace isolation, status, token usage, and structured results.
2. Hard Architectural Guardrails:
   - `MAX_SPAWN_DEPTH = 2`: Prevents recursive sub-agent fork bombs.
   - `MAX_CONCURRENT_WORKERS = 3`: Protects host RAM (~8.4 GB free) via bounded semaphore.
   - `GUIExclusiveLock`: Process-wide lock ensuring at most 1 agent touches physical mouse/keyboard
     at any instant (`acquire_gui_lock`).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional


MAX_SPAWN_DEPTH = 2
MAX_CONCURRENT_WORKERS = 3

_GLOBAL_GUI_LOCK = threading.RLock()


@contextmanager
def acquire_gui_exclusive_lock(timeout_s: float = 30.0) -> Iterator[bool]:
    """Ensure only one agent worker controls physical mouse/keyboard at a time."""
    acquired = _GLOBAL_GUI_LOCK.acquire(timeout=max(0.1, float(timeout_s)))
    try:
        yield acquired
    finally:
        if acquired:
            _GLOBAL_GUI_LOCK.release()


class SubAgentDepthExceededError(PermissionError):
    """Raised when a sub-agent attempts to spawn beyond MAX_SPAWN_DEPTH."""


@dataclass
class SubAgentSessionRecord:
    """Durable record of a spawned sub-agent session."""

    session_id: str
    parent_id: str
    depth: int
    role: str
    objective: str
    workspace: str
    status: str  # RUNNING | COMPLETED | FAILED
    created_at: float
    finished_at: Optional[float] = None
    result_json: str = "{}"
    tokens_used: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        try:
            d["result"] = json.loads(self.result_json)
        except Exception:
            d["result"] = {}
        return d


class SubAgentSessionBus:
    """OpenClaw-style Sub-Agent Spawner & Cross-Agent Messaging Bus backed by SQLite WAL."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        *,
        max_depth: int = MAX_SPAWN_DEPTH,
        max_workers: int = MAX_CONCURRENT_WORKERS,
    ) -> None:
        self.db_path = Path(
            db_path or r"F:\AetherMind_Temp\subagent_bus.db"
        ).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_depth = max(1, int(max_depth))
        self.max_workers = max(1, int(max_workers))
        self._sema = threading.BoundedSemaphore(self.max_workers)
        self._threads: Dict[str, threading.Thread] = {}
        self._db_lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._db_lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_sessions (
                    session_id TEXT PRIMARY KEY,
                    parent_id TEXT NOT NULL,
                    depth INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    finished_at REAL,
                    result_json TEXT NOT NULL DEFAULT '{}',
                    tokens_used INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_messages (
                    msg_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )

    def spawn_session(
        self,
        objective: str,
        worker_fn: Callable[[str, str, Path], Dict[str, Any]],
        *,
        parent_id: str = "root",
        current_depth: int = 0,
        role: str = "general_engineer",
        workspace: Optional[Path | str] = None,
        run_async: bool = True,
    ) -> Dict[str, Any]:
        """Spawn an isolated sub-agent session (`sessions_spawn`)."""
        next_depth = int(current_depth) + 1
        if next_depth > self.max_depth:
            raise SubAgentDepthExceededError(
                f"Sub-agent spawn depth {next_depth} exceeds MAX_SPAWN_DEPTH={self.max_depth}"
            )

        sid = f"sub-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        ws_path = Path(
            workspace or (Path(r"F:\AetherMind_Temp\subagent_workspaces") / sid)
        ).resolve()
        ws_path.mkdir(parents=True, exist_ok=True)
        now = time.time()

        with self._db_lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO subagent_sessions
                (session_id, parent_id, depth, role, objective, workspace, status, created_at, result_json, tokens_used)
                VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', ?, '{}', 0)
                """,
                (sid, parent_id, next_depth, role, objective, str(ws_path), now),
            )

        def _target() -> None:
            with self._sema:
                try:
                    res = worker_fn(sid, objective, ws_path)
                    status = "COMPLETED" if res.get("ok", True) else "FAILED"
                    toks = int(res.get("tokens_used", 0))
                except Exception as exc:
                    res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                    status = "FAILED"
                    toks = 0
                with self._db_lock, self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE subagent_sessions
                        SET status = ?, finished_at = ?, result_json = ?, tokens_used = ?
                        WHERE session_id = ?
                        """,
                        (status, time.time(), json.dumps(res, ensure_ascii=False, default=str), toks, sid),
                    )

        if run_async:
            t = threading.Thread(target=_target, name=f"subagent-{sid}", daemon=True)
            self._threads[sid] = t
            t.start()
        else:
            _target()

        return {
            "ok": True,
            "session_id": sid,
            "parent_id": parent_id,
            "depth": next_depth,
            "role": role,
            "workspace": str(ws_path),
        }

    def send_message(self, sender_id: str, recipient_id: str, content: str) -> Dict[str, Any]:
        """Deliver a cross-agent message (`sessions_send`) persisted in SQLite WAL."""
        mid = f"msg-{uuid.uuid4().hex[:10]}"
        now = time.time()
        with self._db_lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO subagent_messages (msg_id, sender_id, recipient_id, content, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (mid, sender_id, recipient_id, content, now),
            )
        return {"ok": True, "msg_id": mid, "sender_id": sender_id, "recipient_id": recipient_id}

    def read_inbox(self, recipient_id: str) -> List[Dict[str, Any]]:
        """Read all messages sent to `recipient_id` in chronological order."""
        with self._db_lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT msg_id, sender_id, recipient_id, content, created_at
                FROM subagent_messages WHERE recipient_id = ? ORDER BY created_at ASC
                """,
                (recipient_id,),
            ).fetchall()
        return [
            {
                "msg_id": r[0],
                "sender_id": r[1],
                "recipient_id": r[2],
                "content": r[3],
                "created_at": r[4],
            }
            for r in rows
        ]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._db_lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT session_id, parent_id, depth, role, objective, workspace, status,
                       created_at, finished_at, result_json, tokens_used
                FROM subagent_sessions WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if not row:
            return None
        return SubAgentSessionRecord(*row).to_dict()

    def await_sessions(self, session_ids: List[str], *, timeout_s: float = 120.0) -> Dict[str, Any]:
        """Wait for spawned sub-agent sessions to finish and return their aggregated results."""
        deadline = time.monotonic() + max(0.5, float(timeout_s))
        for sid in session_ids:
            th = self._threads.get(sid)
            if th is not None and th.is_alive():
                remaining = max(0.05, deadline - time.monotonic())
                th.join(timeout=remaining)

        results: Dict[str, Any] = {}
        for sid in session_ids:
            info = self.get_session(sid)
            results[sid] = info if info is not None else {"status": "NOT_FOUND"}
        all_done = all(
            results[sid].get("status") in ("COMPLETED", "FAILED") for sid in session_ids
        )
        return {
            "ok": all_done,
            "completed_all": all_done,
            "sessions": results,
        }

    def list_sessions(self, *, parent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._db_lock, self._connect() as conn:
            if parent_id:
                rows = conn.execute(
                    """
                    SELECT session_id, parent_id, depth, role, objective, workspace, status,
                           created_at, finished_at, result_json, tokens_used
                    FROM subagent_sessions WHERE parent_id = ? ORDER BY created_at DESC
                    """,
                    (parent_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT session_id, parent_id, depth, role, objective, workspace, status,
                           created_at, finished_at, result_json, tokens_used
                    FROM subagent_sessions ORDER BY created_at DESC
                    """
                ).fetchall()
        return [SubAgentSessionRecord(*r).to_dict() for r in rows]
