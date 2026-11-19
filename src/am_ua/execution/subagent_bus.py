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
        self.db_path = Path(
            db_path or r"F:\AetherMind_Temp\subagent_bus.db"
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
