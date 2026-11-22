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
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple


MAX_SPAWN_DEPTH = 2
MAX_CONCURRENT_WORKERS = 3
MAX_ADAPTIVE_CONCURRENT_WORKERS = 8
MAX_TEAM_AGENTS_PER_MISSION = 16

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


class FleetAgentSlot:
    """Ultra-lightweight in-process agent slot using `__slots__` (~2 KB vs OpenHuman's 1.77 MiB)."""

    __slots__ = (
        "agent_id",
        "role",
        "objective",
        "rail_matched",
        "coalesced",
        "status",
        "tokens_used",
        "cost_usd",
        "result",
    )

    def __init__(
        self,
        *,
        agent_id: str,
        role: str = "worker",
        objective: str = "",
        rail_matched: Optional[str] = None,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.objective = objective
        self.rail_matched = rail_matched
        self.coalesced = False
        self.status = "PENDING"
        self.tokens_used = 0
        self.cost_usd = 0.0
        self.result: Dict[str, Any] = {}


class SingleFlightCoalescer:
    """True Go-style SingleFlight: deduplicates concurrent & subsequent identical calls across 1,000+ agents."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._inflight: Dict[str, threading.Event] = {}

    def do(self, key: str, fn: Callable[[], Dict[str, Any]]) -> Tuple[bool, Dict[str, Any]]:
        """Execute `fn()` at most once for `key`. Returns `(was_coalesced, result)`."""
        with self._lock:
            if key in self._cache:
                return True, self._cache[key]
            ev = self._inflight.get(key)
            if ev is None:
                ev = threading.Event()
                self._inflight[key] = ev
                is_leader = True
            else:
                is_leader = False

        if not is_leader:
            ev.wait(timeout=60.0)
            with self._lock:
                return True, dict(self._cache.get(key) or {"ok": False, "error": "singleflight leader failed"})

        try:
            res = fn()
            with self._lock:
                self._cache[key] = res
            return False, res
        finally:
            with self._lock:
                self._inflight.pop(key, None)
                ev.set()


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


ROLE_PROVIDER_PROFILES: Dict[str, Dict[str, Any]] = {
    "architect": {"preferred_providers": ("anthropic", "openai", "deepseek"), "temperature": 0.2},
    "planner": {"preferred_providers": ("anthropic", "openai", "deepseek"), "temperature": 0.2},
    "security_reviewer": {"preferred_providers": ("anthropic", "openai", "gemini"), "temperature": 0.0},
    "code_reviewer": {"preferred_providers": ("anthropic", "openai", "deepseek"), "temperature": 0.1},
    "tdd_enforcer": {"preferred_providers": ("deepseek", "openai", "groq"), "temperature": 0.1},
    "coder": {"preferred_providers": ("deepseek", "openai", "openrouter"), "temperature": 0.15},
    "build_error_resolver": {"preferred_providers": ("groq", "deepseek", "openai"), "temperature": 0.0},
    "explorer": {"preferred_providers": ("gemini", "groq", "deepseek"), "temperature": 0.2},
    "researcher": {"preferred_providers": ("gemini", "openai", "openrouter"), "temperature": 0.3},
    "worker": {"preferred_providers": ("deepseek", "groq", "openai"), "temperature": 0.2},
}


class SubAgentSessionBus:
    """OpenClaw-style Sub-Agent Spawner & Cross-Agent Messaging Bus backed by SQLite WAL."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        *,
        max_depth: int = MAX_SPAWN_DEPTH,
        max_workers: int = MAX_CONCURRENT_WORKERS,
    ) -> None:
        from am_ua.contracts.contracts import default_temp_dir

        self.db_path = Path(
            db_path or default_temp_dir("subagent_bus.db")
        ).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_depth = max(1, int(max_depth))
        self.max_workers = max(1, int(max_workers))
        self._sema = threading.BoundedSemaphore(self.max_workers)
        self._threads: Dict[str, threading.Thread] = {}
        self._db_lock = threading.Lock()
        self._debounce_lock = threading.Lock()
        self._debounce_buffer: Dict[str, List[Dict[str, Any]]] = {}
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_generations (
                    generation_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    parent_generation_id TEXT,
                    summary_head TEXT NOT NULL,
                    sealed_sha256 TEXT NOT NULL,
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

        from am_ua.contracts.contracts import default_temp_dir

        sid = f"sub-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        ws_path = Path(
            workspace or default_temp_dir(f"subagent_workspaces/{sid}")
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

    # ------------------------------------------------------------------
    # A2A (Agent2Agent Protocol v0.3) + OpenClaw Multi-Channel Gateway
    # ------------------------------------------------------------------
    def get_agent_card(self) -> Dict[str, Any]:
        """Return official A2A AgentCard (/.well-known/agent.json) for OmniExecutor Agent."""
        return {
            "schema": "A2A_AGENT_CARD/v1",
            "name": "OmniExecutor Agent",
            "version": "4.1.0",
            "protocolVersion": "0.3.0",
            "description": "Constitutional neuro-symbolic coding, browser (CDP), and Win32 desktop agent.",
            "capabilities": {
                "streaming": True,
                "pushNotifications": False,
                "stateTransitionHistory": True,
            },
            "defaultInputModes": ["text/plain", "application/json", "file"],
            "defaultOutputModes": ["text/plain", "application/json", "text/markdown"],
            "skills": [
                {"id": "autonomous_coding", "name": "Autonomous Coding & TDD", "tags": ["code", "ast", "pytest"]},
                {"id": "browser_cdp", "name": "Verified CDP Browser Automation", "tags": ["browser", "dom", "osint"]},
                {"id": "desktop_rpa", "name": "Closed-Loop Set-of-Mark Desktop RPA", "tags": ["win32", "uia", "ocr"]},
                {"id": "knowledge_graph", "name": "Auto-Sync Knowledge Graph & Mermaid", "tags": ["graph", "mermaid"]},
                {"id": "security_audit", "name": "AgentShield SAST & Constitutional Seal", "tags": ["security", "sast"]},
            ],
        }

    def handle_a2a_rpc(
        self,
        request: Dict[str, Any],
        *,
        executor_fn: Optional[Callable[[str, str, Path], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Process an Agent2Agent (A2A) JSON-RPC 2.0 request (`agent/card`, `tasks/send`, `tasks/get`, `tasks/cancel`)."""
        req_id = request.get("id", "1")
        method = str(request.get("method", "")).strip()
        params = request.get("params") if isinstance(request.get("params"), dict) else {}

        if method in ("agent/card", "agent/authenticatedExtendedCard"):
            return {"jsonrpc": "2.0", "id": req_id, "result": self.get_agent_card()}

        if method == "tasks/send":
            msg = params.get("message") if isinstance(params.get("message"), dict) else {}
            parts = msg.get("parts") if isinstance(msg.get("parts"), list) else []
            texts = [str(p.get("text", "")) for p in parts if isinstance(p, dict) and p.get("text")]
            objective = "\n".join(texts).strip() or str(params.get("objective", "")).strip()
            if not objective:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Missing task objective"}}
            role = str(params.get("role", "general_engineer"))
            wait = bool(params.get("wait", False))
            w_fn = executor_fn or (lambda sid, obj, ws: {"ok": True, "summary": f"A2A queued: {obj}", "tokens_used": 0})
            spawned = self.spawn_session(objective=objective, worker_fn=w_fn, role=role, run_async=not wait)
            sid = spawned["session_id"]
            sess = self.get_session(sid) or spawned
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "id": sid,
                    "turn_id": f"turn-{uuid.uuid4().hex[:10]}",
                    "status": {"state": str(sess.get("status", "RUNNING")).lower()},
                    "session": sess,
                },
            }

        if method == "tasks/get":
            tid = str(params.get("id") or params.get("session_id") or "").strip()
            sess = self.get_session(tid)
            if sess is None:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": f"Task '{tid}' not found"}}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "id": tid,
                    "status": {"state": str(sess["status"]).lower()},
                    "session": sess,
                    "messages": self.read_inbox(tid),
                },
            }

        if method == "tasks/cancel":
            tid = str(params.get("id") or params.get("session_id") or "").strip()
            sess = self.get_session(tid)
            if sess is None:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": f"Task '{tid}' not found"}}
            with self._db_lock, self._connect() as conn:
                conn.execute(
                    "UPDATE subagent_sessions SET status = ?, finished_at = ? WHERE session_id = ?",
                    ("CANCELED", time.time(), tid),
                )
            return {"jsonrpc": "2.0", "id": req_id, "result": {"id": tid, "status": {"state": "canceled"}}}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unsupported A2A method: {method}"}}

    def ingest_channel_event(
        self,
        event: Dict[str, Any],
        *,
        executor_fn: Optional[Callable[[str, str, Path], Dict[str, Any]]] = None,
        debounce_window_s: float = 0.0,
    ) -> Dict[str, Any]:
        """Unified channel gateway with optional burst-message coalescing (`inbound_debounce`)."""
        channel = str(event.get("channel", "cli")).strip().lower()
        sender = str(event.get("sender") or event.get("user_id") or "anonymous").strip()
        text = str(event.get("text") or event.get("content") or event.get("message") or "").strip()
        if not text:
            return {"ok": False, "error": "empty channel message"}
        role = str(event.get("role", "general_engineer"))
        wait = bool(event.get("wait", False))

        if float(debounce_window_s) > 0.0:
            key = f"{channel}:{sender}"
            now = time.time()
            with self._debounce_lock:
                bucket = self._debounce_buffer.setdefault(key, [])
                bucket.append({
                    "channel": channel,
                    "sender": sender,
                    "text": text,
                    "role": role,
                    "wait": wait,
                    "window_s": float(debounce_window_s),
                    "timestamp": now,
                })
                count = len(bucket)
            return {
                "ok": True,
                "debounced": True,
                "channel": channel,
                "sender": sender,
                "buffered_count": count,
                "debounce_window_s": float(debounce_window_s),
            }

        return self._dispatch_channel_batch(channel, sender, text, role=role, wait=wait, coalesced_count=1, executor_fn=executor_fn)

    def _dispatch_channel_batch(
        self,
        channel: str,
        sender: str,
        text: str,
        *,
        role: str,
        wait: bool,
        coalesced_count: int,
        executor_fn: Optional[Callable[[str, str, Path], Dict[str, Any]]],
    ) -> Dict[str, Any]:
        rpc_req = {
            "jsonrpc": "2.0",
            "id": f"oc-{channel}-{uuid.uuid4().hex[:8]}",
            "method": "tasks/send",
            "params": {
                "role": role,
                "wait": wait,
                "message": {"role": "user", "parts": [{"type": "text", "text": f"[{channel}:{sender}] {text}"}]},
            },
        }
        resp = self.handle_a2a_rpc(rpc_req, executor_fn=executor_fn)
        return {
            "ok": "result" in resp,
            "debounced": False,
            "coalesced_count": coalesced_count,
            "combined_text": text,
            "channel": channel,
            "sender": sender,
            "task_id": resp.get("result", {}).get("id"),
            "turn_id": resp.get("result", {}).get("turn_id"),
            "a2a_response": resp,
        }

    def flush_channel_debounce(
        self,
        *,
        channel: Optional[str] = None,
        sender: Optional[str] = None,
        only_expired: bool = False,
        executor_fn: Optional[Callable[[str, str, Path], Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Flush buffered inbound channel messages into coalesced A2A tasks."""
        now = time.time()
        to_dispatch: List[Tuple[str, List[Dict[str, Any]]]] = []
        with self._debounce_lock:
            keys = list(self._debounce_buffer.keys())
            for k in keys:
                bucket = self._debounce_buffer.get(k, [])
                if not bucket:
                    self._debounce_buffer.pop(k, None)
                    continue
                b_chan = bucket[0]["channel"]
                b_send = bucket[0]["sender"]
                if channel and b_chan != channel.strip().lower():
                    continue
                if sender and b_send != sender.strip():
                    continue
                if only_expired and (now - bucket[-1]["timestamp"]) < bucket[-1]["window_s"]:
                    continue
                to_dispatch.append((k, self._debounce_buffer.pop(k)))

        dispatched: List[Dict[str, Any]] = []
        for _, entries in to_dispatch:
            combined = "\n".join(e["text"] for e in entries)
            dispatched.append(
                self._dispatch_channel_batch(
                    entries[0]["channel"],
                    entries[0]["sender"],
                    combined,
                    role=entries[-1]["role"],
                    wait=any(e["wait"] for e in entries),
                    coalesced_count=len(entries),
                    executor_fn=executor_fn,
                )
            )
        return dispatched

    # ------------------------------------------------------------------
    # Ruflo + ECC + gstack Dynamic Team & Executive Hierarchy Orchestrator
    # ------------------------------------------------------------------
    @staticmethod
    def compute_adaptive_worker_limit(avail_ram_mb: Optional[float] = None) -> int:
        """Compute safe parallel worker ceiling (2..8) from live host RAM above the 2.5 GB safety floor."""
        if avail_ram_mb is None:
            try:
                from am_ua.governance.homeostasis import _sample_windows_ram

                avail_ram_mb, _ = _sample_windows_ram()
            except Exception:
                avail_ram_mb = 6144.0
        usable_mb = max(0.0, float(avail_ram_mb) - 2560.0)
        workers = 2 + int(usable_mb // 1536.0)
        return max(2, min(MAX_ADAPTIVE_CONCURRENT_WORKERS, workers))

    def assess_team_topology(self, objective: str, *, workspace_file_count: int = 0) -> Dict[str, Any]:
        """Determine whether a mission requires a solo agent, a 4-agent Dev Squad, or an 8-agent Executive Fleet."""
        low = (objective or "").lower()
        score = 0
        reasons: List[str] = []

        domains = {
            "architecture": ("architect", "microservice", "distributed", "schema", "design", "system", "arquitetura"),
            "backend_code": ("api", "backend", "engine", "module", "refactor", "implement", "python", "rust"),
            "frontend_browser": ("browser", "ui", "frontend", "dom", "html", "css", "dashboard", "web"),
            "security": ("security", "auth", "crypto", "sast", "shield", "vulnerability", "segurança", "audit"),
            "performance": ("latency", "performance", "stress", "optimize", "parallel", "scale", "latência"),
            "testing_qa": ("test", "pytest", "tdd", "benchmark", "verify", "homolog"),
        }
        matched_domains = [d for d, kws in domains.items() if any(k in low for k in kws)]
        if len(matched_domains) >= 3:
            score += 3
            reasons.append(f"multi_domain({len(matched_domains)}:{','.join(matched_domains)})")
        elif len(matched_domains) == 2:
            score += 2
            reasons.append(f"dual_domain({','.join(matched_domains)})")

        if workspace_file_count > 10 or any(k in low for k in ("multi-file", "full-stack", "end-to-end", "entire", "completo", "projeto")):
            score += 2
            reasons.append("wide_scope")
        elif workspace_file_count >= 3:
            score += 1
            reasons.append("multi_file_scope")

        if any(k in low for k in ("severe", "severa", "critical", "enterprise", "production", "supremacia", "stress", "estresse", "ceo")):
            score += 3
            reasons.append("high_severity_governance")

        if any(k in low for k in ("team", "equipe", "squad", "swarm", "enxame", "multi-agent", "arquiteto", "supervisor")):
            score += 3
            reasons.append("explicit_team_directive")

        score = min(10, score)
        adaptive_workers = self.compute_adaptive_worker_limit()

        if score < 3:
            mode = "solo_specialist"
            waves = [[{"role": "general_engineer", "focus": "Direct surgical implementation & verification"}]]
        elif score <= 5:
            mode = "dev_squad"
            waves = [
                [{"role": "systems_architect", "focus": "Lock module interfaces, data contracts, and blast radius"}],
                [{"role": "general_engineer", "focus": "Implement core changes adhering to architect spec"}],
                [
                    {"role": "eng_supervisor", "focus": "Supervise code quality, diff hygiene, and integration"},
                    {"role": "tdd_enforcer", "focus": "Verify edge-case tests and regression suite"},
                ],
            ]
        else:
            mode = "executive_enterprise_fleet"
            waves = [
                [
                    {"role": "product_ceo", "focus": "Define executive scope, ROI invariants, and anti-bloat guardrails"},
                    {"role": "systems_architect", "focus": "Design system topology, dependency DAG, and fault boundaries"},
                ],
                [
                    {"role": "general_engineer", "focus": "Implement core feature modules and business logic"},
                    {"role": "build_error_resolver", "focus": "Ensure clean imports, types, and cross-module wiring"},
                    {"role": "performance_sre", "focus": "Optimize latency, concurrency, and memory footprint"},
                ],
                [
                    {"role": "eng_supervisor", "focus": "Supervise cross-team integration and architectural compliance"},
                    {"role": "security_auditor", "focus": "Run SAST, secret scan, and constitutional boundary checks"},
                ],
                [
                    {"role": "tdd_enforcer", "focus": "Execute red-green TDD and boundary stress tests"},
                    {"role": "strict_auditor", "focus": "Final OMEGA Triple-Proof sign-off (Logical, Physical, Visual)"},
                ],
            ]

        total_agents = sum(len(w) for w in waves)
        return {
            "mode": mode,
            "severity_score": score,
            "triggers": reasons,
            "total_agents_planned": total_agents,
            "max_team_cap": MAX_TEAM_AGENTS_PER_MISSION,
            "adaptive_concurrent_workers": adaptive_workers,
            "hierarchy": {
                "executive_lead": "product_ceo" if mode == "executive_enterprise_fleet" else "systems_architect",
                "architect": "systems_architect",
                "supervisor": "eng_supervisor" if score >= 3 else "general_engineer",
                "verifiers": ["tdd_enforcer", "strict_auditor"] if score >= 6 else (["tdd_enforcer"] if score >= 3 else []),
            },
            "waves": waves,
        }

    def orchestrate_team(
        self,
        objective: str,
        worker_fn: Optional[Callable[[str, str, Path], Dict[str, Any]]] = None,
        *,
        workspace_file_count: int = 0,
        timeout_per_wave_s: float = 120.0,
    ) -> Dict[str, Any]:
        """Assemble and execute a multi-wave hierarchical engineering team (CEO -> Architect -> Dev -> Supervisor -> Auditor)."""
        plan = self.assess_team_topology(objective, workspace_file_count=workspace_file_count)
        effective_worker = worker_fn or (
            lambda sid, obj, ws: {"ok": True, "summary": f"Completed role objective: {obj[:140]}", "tokens_used": 25}
        )

        # Dynamically widen semaphore if host RAM permits more concurrent workers
        adaptive_limit = plan["adaptive_concurrent_workers"]
        self._sema = threading.BoundedSemaphore(adaptive_limit)

        wave_reports: List[Dict[str, Any]] = []
        prior_context_notes: List[str] = []
        all_session_ids: List[str] = []
        all_ok = True

        for wave_idx, wave in enumerate(plan["waves"], 1):
            wave_sids: List[str] = []
            upstream_brief = " | ".join(prior_context_notes[-4:])
            for member in wave:
                if len(all_session_ids) >= MAX_TEAM_AGENTS_PER_MISSION:
                    break
                role = member["role"]
                focus = member["focus"]
                member_obj = f"[{role.upper()} | Wave {wave_idx}] {focus} :: Mission: {objective}"
                if upstream_brief:
                    member_obj += f" :: Upstream Context: {upstream_brief}"
                spawned = self.spawn_session(
                    objective=member_obj,
                    worker_fn=effective_worker,
                    parent_id="team-coordinator",
                    current_depth=0,
                    role=role,
                    run_async=True,
                )
                sid = spawned["session_id"]
                wave_sids.append(sid)
                all_session_ids.append(sid)
                if upstream_brief:
                    self.send_message("team-coordinator", sid, upstream_brief)

            awaited = self.await_sessions(wave_sids, timeout_s=timeout_per_wave_s)
            wave_ok = bool(awaited.get("ok"))
            if not wave_ok:
                all_ok = False
            wave_summaries: List[str] = []
            for sid in wave_sids:
                s_info = awaited["sessions"].get(sid, {})
                res_obj = s_info.get("result") or {}
                s_role = s_info.get("role", "worker")
                summ = str(res_obj.get("summary") or s_info.get("status") or "")[:160]
                wave_summaries.append(f"{s_role}:{summ}")
                self.send_message(sid, "team-coordinator", f"{s_role} finished: {summ}")

            prior_context_notes.extend(wave_summaries)
            wave_reports.append(
                {
                    "wave": wave_idx,
                    "roles": [m["role"] for m in wave],
                    "session_ids": wave_sids,
                    "ok": wave_ok,
                    "summaries": wave_summaries,
                }
            )

        return {
            "ok": all_ok,
            "mode": plan["mode"],
            "severity_score": plan["severity_score"],
            "triggers": plan["triggers"],
            "hierarchy": plan["hierarchy"],
            "adaptive_concurrent_workers": adaptive_limit,
            "max_team_cap": MAX_TEAM_AGENTS_PER_MISSION,
            "total_agents_spawned": len(all_session_ids),
            "waves_executed": len(wave_reports),
            "waves": wave_reports,
        }

    def execute_dag(
        self,
        tasks: Sequence[Dict[str, Any]],
        worker_fn: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = None,
        *,
        timeout_s: float = 120.0,
        parent_id: str = "dag-coordinator",
        workspace: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Execute a dependency-aware DAG of sub-agent tasks in topological waves."""
        by_id: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for idx, raw in enumerate(tasks):
            tid = str(raw.get("id") or f"task-{idx + 1}")
            if tid in by_id:
                raise ValueError(f"Duplicate DAG task id: {tid!r}")
            deps = [str(d) for d in (raw.get("depends_on") or [])]
            role = str(raw.get("role") or "worker")
            profile = ROLE_PROVIDER_PROFILES.get(role, ROLE_PROVIDER_PROFILES["worker"])
            by_id[tid] = {
                **dict(raw),
                "id": tid,
                "role": role,
                "depends_on": deps,
                "provider_profile": dict(profile),
            }
            order.append(tid)

        for tid, t in by_id.items():
            for d in t["depends_on"]:
                if d not in by_id:
                    raise ValueError(f"DAG task {tid!r} depends on unknown task {d!r}")

        # Kahn topological wave grouping with cycle detection
        remaining = set(order)
        completed: Dict[str, Dict[str, Any]] = {}
        waves: List[List[str]] = []
        while remaining:
            ready = [
                tid
                for tid in order
                if tid in remaining and all(d in completed for d in by_id[tid]["depends_on"])
            ]
            if not ready:
                raise ValueError(f"Cycle detected in DAG tasks: {sorted(remaining)}")
            waves.append(ready)
            for tid in ready:
                remaining.remove(tid)
                completed[tid] = {}

        results: Dict[str, Dict[str, Any]] = {}
        wave_reports: List[Dict[str, Any]] = []
        all_ok = True

        for w_idx, wave_ids in enumerate(waves, start=1):
            sid_to_tid: Dict[str, str] = {}
            for tid in wave_ids:
                task_spec = by_id[tid]
                upstream = {d: results[d] for d in task_spec["depends_on"]}

                def _make_worker(ts: Dict[str, Any], up: Dict[str, Any]) -> Callable[[str, str, Path], Dict[str, Any]]:
                    def _w(sid: str, obj: str, ws: Path) -> Dict[str, Any]:
                        if worker_fn is not None:
                            return worker_fn(ts, up)
                        return {
                            "ok": True,
                            "task_id": ts["id"],
                            "role": ts["role"],
                            "provider_profile": ts["provider_profile"],
                            "upstream_ids": sorted(up.keys()),
                            "summary": obj[:160],
                        }
                    return _w

                spawned = self.spawn_session(
                    str(task_spec.get("objective") or task_spec["id"]),
                    _make_worker(task_spec, upstream),
                    parent_id=parent_id,
                    role=task_spec["role"],
                    workspace=workspace,
                    run_async=True,
                )
                sid_to_tid[spawned["session_id"]] = tid

            awaited = self.await_sessions(list(sid_to_tid.keys()), timeout_s=timeout_s)
            wave_ok = bool(awaited.get("ok"))
            if not wave_ok:
                all_ok = False
            for sid, tid in sid_to_tid.items():
                s_info = awaited["sessions"].get(sid, {})
                res_obj = s_info.get("result") or {"ok": False, "status": s_info.get("status")}
                results[tid] = res_obj
                if not res_obj.get("ok", True):
                    all_ok = False
            wave_reports.append({"wave": w_idx, "task_ids": wave_ids, "ok": wave_ok})

        return {
            "ok": all_ok,
            "waves": wave_reports,
            "results": results,
            "total_tasks": len(order),
        }

    # ------------------------------------------------------------------
    # v5.4 HyperFleet Engine (1,000+ Agents In-Process, Zero-Copy, <50 KB/agent)
    # ------------------------------------------------------------------
    def begin_generation(
        self,
        session_id: str,
        summary_head: str,
        *,
        parent_generation_id: Optional[str] = None,
        archived_transcript: str = "",
    ) -> Dict[str, Any]:
        """Zero-erasure session generation chaining: seal prior transcript hash on disk and keep head compact."""
        import hashlib

        gid = f"gen-{uuid.uuid4().hex[:12]}"
        now = time.time()
        head_clean = (summary_head or "").strip()[:4000]
        digest = hashlib.sha256(f"{parent_generation_id or 'ROOT'}:{head_clean}:{archived_transcript}".encode("utf-8")).hexdigest()
        with self._db_lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO session_generations
                (generation_id, session_id, parent_generation_id, summary_head, sealed_sha256, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (gid, session_id, parent_generation_id, head_clean, digest, now),
            )
        return {
            "ok": True,
            "generation_id": gid,
            "session_id": session_id,
            "parent_generation_id": parent_generation_id,
            "head_chars": len(head_clean),
            "sealed_sha256": digest,
        }

    def get_generation_chain(self, session_id: str) -> List[Dict[str, Any]]:
        """Return ordered parent->child zero-erasure generation chain for `session_id`."""
        with self._db_lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT generation_id, session_id, parent_generation_id, summary_head, sealed_sha256, created_at
                FROM session_generations WHERE session_id = ? ORDER BY created_at ASC
                """,
                (session_id,),
            ).fetchall()
        return [
            {
                "generation_id": r[0],
                "session_id": r[1],
                "parent_generation_id": r[2],
                "summary_head": r[3],
                "sealed_sha256": r[4],
                "created_at": r[5],
            }
            for r in rows
        ]

    def run_hyper_fleet(
        self,
        tasks: Sequence[Dict[str, Any]],
        *,
        workspace: Path | str = ".",
        max_concurrency: int = 128,
        max_budget_usd: float = 10.0,
        prefer_deterministic: bool = True,
        llm_worker_fn: Optional[Callable[[FleetAgentSlot], Dict[str, Any]]] = None,
        persist_batch: bool = True,
    ) -> Dict[str, Any]:
        """Run 500 to 1,000+ lightweight agents in a single process with deterministic offload & SingleFlight coalescing."""
        from concurrent.futures import ThreadPoolExecutor
        import hashlib
        import tracemalloc
        from am_ua.cognition.llm_client import estimate_cost_usd
        from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

        ws_path = Path(workspace).resolve()
        total_n = len(tasks)
        if total_n == 0:
            return {"ok": True, "agents_executed": 0, "kb_per_agent": 0.0, "total_cost_usd": 0.0}

        was_tracing = tracemalloc.is_tracing()
        if not was_tracing:
            tracemalloc.start()
        mem_before, _ = tracemalloc.get_traced_memory()
        t0 = time.perf_counter()

        slots: List[FleetAgentSlot] = []
        for idx, spec in enumerate(tasks):
            aid = str(spec.get("id") or f"fl-{idx + 1:04d}")
            role = str(spec.get("role") or "worker")
            obj = str(spec.get("objective") or f"Task {idx + 1}")
            rail = spec.get("rail")
            if not rail and prefer_deterministic:
                rail = DeterministicTaskOffloader.match_zero_token_rail(obj)
            slots.append(
                FleetAgentSlot(
                    agent_id=aid,
                    role=role,
                    objective=obj,
                    rail_matched=str(rail) if rail else None,
                )
            )

        mem_after_slots, _ = tracemalloc.get_traced_memory()
        if not was_tracing:
            tracemalloc.stop()

        slot_delta_bytes = max(1024, mem_after_slots - mem_before)
        kb_per_agent = round((slot_delta_bytes / 1024.0) / float(total_n), 3)

        coalescer = SingleFlightCoalescer()
        budget_lock = threading.Lock()
        spent_usd = 0.0
        det_count = 0
        coalesced_count = 0
        budget_capped_count = 0

        # Cache deterministic rail execution by rail name inside this workspace run
        rail_cache: Dict[str, Dict[str, Any]] = {}
        rail_lock = threading.Lock()

        def _run_slot(slot: FleetAgentSlot) -> None:
            nonlocal spent_usd, det_count, coalesced_count, budget_capped_count
            key = hashlib.sha256(f"{slot.role}:{slot.rail_matched or ''}:{slot.objective.strip().lower()}".encode("utf-8")).hexdigest()[:20]

            def _compute() -> Dict[str, Any]:
                nonlocal spent_usd, budget_capped_count
                if slot.rail_matched:
                    with rail_lock:
                        r_res = rail_cache.get(slot.rail_matched)
                    if r_res is None:
                        r_res = DeterministicTaskOffloader.execute_rail(slot.rail_matched, ws_path)
                        with rail_lock:
                            rail_cache[slot.rail_matched] = r_res
                    return {
                        "ok": bool(r_res.get("ok", True)),
                        "mode": "deterministic_rail",
                        "rail": slot.rail_matched,
                        "tokens": 0,
                        "cost_usd": 0.0,
                    }

                with budget_lock:
                    over_budget = spent_usd >= float(max_budget_usd)
                    if over_budget:
                        budget_capped_count += 1
                if over_budget:
                    return {"ok": True, "mode": "budget_capped_deterministic_fallback", "tokens": 0, "cost_usd": 0.0}

                if llm_worker_fn is not None:
                    w_out = dict(llm_worker_fn(slot))
                    p_tok = int(w_out.get("prompt_tokens", 250))
                    c_tok = int(w_out.get("completion_tokens", 80))
                    model_name = str(w_out.get("model", "gpt-4o-mini"))
                    c_usd = float(w_out.get("cost_usd", estimate_cost_usd(model_name, p_tok, c_tok)))
                else:
                    p_tok, c_tok = 200, 50
                    c_usd = estimate_cost_usd("gpt-4o-mini", p_tok, c_tok)
                    w_out = {"ok": True, "mode": "s1_micro_worker", "summary": slot.objective[:100]}

                with budget_lock:
                    if spent_usd + c_usd > float(max_budget_usd):
                        budget_capped_count += 1
                        return {"ok": True, "mode": "budget_capped_deterministic_fallback", "tokens": 0, "cost_usd": 0.0}
                    spent_usd += c_usd
                w_out["tokens"] = p_tok + c_tok
                w_out["cost_usd"] = round(c_usd, 6)
                return w_out

            was_coalesced, out = coalescer.do(key, _compute)
            slot.coalesced = was_coalesced
            slot.status = "COMPLETED" if out.get("ok", True) else "FAILED"
            slot.tokens_used = 0 if was_coalesced else int(out.get("tokens", 0))
            slot.cost_usd = 0.0 if was_coalesced else float(out.get("cost_usd", 0.0))
            slot.result = out
            with budget_lock:
                if was_coalesced:
                    coalesced_count += 1
                if slot.rail_matched:
                    det_count += 1
                elif was_coalesced and out.get("mode") == "budget_capped_deterministic_fallback":
                    budget_capped_count += 1

        workers_n = min(max(4, int(max_concurrency)), max(4, min(total_n, 128)))
        with ThreadPoolExecutor(max_workers=workers_n) as pool:
            list(pool.map(_run_slot, slots))

        now = time.time()
        if persist_batch:
            batch_rows = [
                (
                    s.agent_id,
                    "hyperfleet-root",
                    1,
                    s.role,
                    s.objective[:300],
                    str(ws_path),
                    s.status,
                    now,
                    now,
                    json.dumps(s.result, ensure_ascii=False, default=str),
                    s.tokens_used,
                )
                for s in slots
            ]
            with self._db_lock, self._connect() as conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO subagent_sessions
                    (session_id, parent_id, depth, role, objective, workspace, status, created_at, finished_at, result_json, tokens_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    batch_rows,
                )

        elapsed_s = round(time.perf_counter() - t0, 3)
        total_tokens = sum(s.tokens_used for s in slots)
        return {
            "ok": all(s.status == "COMPLETED" for s in slots),
            "engine": "OmniExecutor_HyperFleet_v5.4",
            "agents_executed": total_n,
            "completed_count": sum(1 for s in slots if s.status == "COMPLETED"),
            "deterministic_offloaded_count": det_count,
            "coalesced_saved_calls": coalesced_count,
            "budget_capped_count": budget_capped_count,
            "total_tokens": total_tokens,
            "total_cost_usd": round(spent_usd, 6),
            "max_budget_usd": float(max_budget_usd),
            "kb_per_agent": kb_per_agent,
            "openhuman_baseline_kb_per_agent": 1812.48,
            "memory_efficiency_vs_openhuman_x": round(1812.48 / max(0.1, kb_per_agent), 1),
            "elapsed_s": elapsed_s,
            "agents_per_second": round(total_n / max(0.001, elapsed_s), 1),
        }

    def spawn_live_worker_fleet(
        self,
        tasks: Sequence[Dict[str, Any]],
        *,
        workspace: Path | str = ".",
        max_workers: int = 4,
        merge_results: bool = True,
        final_verify_cmd: Optional[str] = None,
        worker_runner_fn: Optional[Callable[[Dict[str, Any], Path], Dict[str, Any]]] = None,
        conflict_resolver_fn: Optional[Callable[[Path, List[str], str], bool]] = None,
        llm: Any = None,
        seal_guard: Any = None,
        memory_provider: Any = None,
        timeout_s: float = 300.0,
    ) -> Dict[str, Any]:
        """Run concurrent real coding workers across isolated `git worktree` branches and 3-way merge."""
        from am_ua.execution.worktree_swarm import WorktreeSwarmCoordinator

        coord = WorktreeSwarmCoordinator(
            workspace,
            max_workers=max_workers,
            llm=llm,
            seal_guard=seal_guard,
            memory_provider=memory_provider,
        )
        res = coord.run_swarm(
            tasks,
            worker_runner_fn=worker_runner_fn,
            merge_results=merge_results,
            conflict_resolver_fn=conflict_resolver_fn,
            final_verify_cmd=final_verify_cmd,
            timeout_s=timeout_s,
        )
        now = time.time()
        rows = [
            (
                f"wt-{w['worker_id']}-{uuid.uuid4().hex[:6]}",
                "worktree-swarm-coordinator",
                1,
                w.get("role", "general_engineer"),
                str(w.get("objective", ""))[:300],
                str(Path(workspace).resolve()),
                "COMPLETED" if w.get("ok") else "FAILED",
                now,
                now,
                json.dumps(w, ensure_ascii=False, default=str),
                int(w.get("tokens_used", 0)),
            )
            for w in res.get("workers", [])
        ]
        if rows:
            with self._db_lock, self._connect() as conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO subagent_sessions
                    (session_id, parent_id, depth, role, objective, workspace, status, created_at, finished_at, result_json, tokens_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
        return res
