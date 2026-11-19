"""Durable Execution Engine — LangGraph Checkpoints + MSEA Fencing/Fairness + Astra R08/R16 + URE Sieve.

Unites:
- LangGraph transactional SQLite WAL step checkpointing & crash resume
- MSEA `FairDispatchScheduler` (aging priority boost, zero starvation)
- MSEA `FencedEffectWriter` (monotonic lease_epoch fencing against zombie workers)
- Astra R08 `TIMEOUT -> OUTCOME_UNKNOWN` with mandatory `reconcile_state()` before retry
- Last-Mile Security Gate (closes OpenHands SDK direct-tool bypass via URE `CFGGrammarSieve`
  + R16 `TrustLevel.UNTRUSTED_DATA` taint block + `ConstitutionSealGuard`)
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from am_ua import PROJECT_ROOT
from am_ua.contracts.contracts import (
    CognitiveEnvelope,
    TrustLevel,
    UntrustedDataEscalationError,
)
from am_ua.governance.seal_guard import ConstitutionSealGuard

# Wire real URE Alpha-C10 CFGGrammarSieve (read-only import from F:\AetherMind_Universal_Reasoning_Engine)
_URE_ROOT = r"F:\AetherMind_Universal_Reasoning_Engine"
if Path(_URE_ROOT).is_dir() and _URE_ROOT not in sys.path:
    sys.path.insert(0, _URE_ROOT)

try:
    from grammar.cfg_sieve import CFGGrammarSieve  # type: ignore[import-not-found]
except ImportError:  # standalone / clean CI fallback AST expression sieve
    import ast as _ast

    class CFGGrammarSieve:  # type: ignore[no-redef]
        """Standalone AST-based boolean/comparison expression sieve when external URE is absent."""

        _ALLOWED_NODES = (
            _ast.Expression,
            _ast.BoolOp,
            _ast.And,
            _ast.Or,
            _ast.UnaryOp,
            _ast.Not,
            _ast.USub,
            _ast.Compare,
            _ast.Eq,
            _ast.NotEq,
            _ast.Lt,
            _ast.LtE,
            _ast.Gt,
            _ast.GtE,
            _ast.BinOp,
            _ast.Add,
            _ast.Sub,
            _ast.Mult,
            _ast.Constant,
            _ast.Name,
            _ast.Load,
        )

        def __init__(self) -> None:
            self._allowed_vars: set[str] = set()

        def set_allowed_variables(self, allowed: set[str]) -> None:
            self._allowed_vars = set(allowed or set())

        def validate_expression(self, expr: str) -> tuple[bool, str]:
            try:
                tree = _ast.parse(str(expr), mode="eval")
            except SyntaxError as exc:
                return False, f"SyntaxError: {exc.msg}"
            for node in _ast.walk(tree):
                if not isinstance(node, self._ALLOWED_NODES):
                    return False, f"Disallowed AST node: {type(node).__name__}"
                if isinstance(node, _ast.Name) and node.id not in self._allowed_vars and node.id not in ("True", "False"):
                    return False, f"Undeclared variable: {node.id}"
            return True, ""


class EffectClass(str, Enum):
    """Tool side-effect taxonomy (Astra R07/R08)."""

    PURE_READ = "pure_read"
    IDEMPOTENT_WRITE = "idempotent_write"
    COMPENSATABLE_MUTATION = "compensatable_mutation"
    IRREVERSIBLE_EXTERNAL = "irreversible_external"


class StepStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    RECONCILED_SAFE_TO_RETRY = "RECONCILED_SAFE_TO_RETRY"
    COMPENSATED = "COMPENSATED"


class OutcomeUnknownError(RuntimeError):
    """Raised when attempting blind retry on an OUTCOME_UNKNOWN step before reconciliation."""


class StaleLeaseFenceError(PermissionError):
    """Raised when a stale/expired worker lease epoch attempts to mutate state."""


class LastMileSecurityError(PermissionError):
    """Raised when the Last-Mile Dispatcher blocks an unsafe or tainted tool invocation."""


@dataclass(frozen=True)
class ReconcileObservation:
    effect_occurred: bool
    observed_output: Any = None
    evidence: str = ""


@dataclass
class ToolContract:
    """Typed tool contract with preconditions, effect class, and reconciliation hook (R07/R08)."""

    name: str
    effect_class: EffectClass
    execute_fn: Callable[[Dict[str, Any]], Any]
    required_args: Set[str] = field(default_factory=set)
    reconcile_fn: Optional[Callable[[Dict[str, Any]], ReconcileObservation]] = None
    compensate_fn: Optional[Callable[[Dict[str, Any]], Any]] = None


# ---------------------------------------------------------------------------
# MSEA FairDispatchScheduler (Python implementation of MSEA-FAIR-DISPATCH-1)
# ---------------------------------------------------------------------------

class FairDispatchScheduler:
    """Priority + wait-time aging scheduler preventing low-priority starvation."""

    PROTOCOL = "MSEA-FAIR-DISPATCH-1"

    def __init__(self, *, aging_interval: int = 4, max_priority: int = 100) -> None:
        if aging_interval < 1 or max_priority < 1:
            raise ValueError("Invalid FairDispatchScheduler bounds")
        self.aging_interval = int(aging_interval)
        self.max_priority = int(max_priority)
        self.clock = 0
        self._first_seen: Dict[str, int] = {}

    def observe(self, task_ids: Iterable[str]) -> None:
        for raw in task_ids:
            tid = str(raw)
            if tid not in self._first_seen:
                self._first_seen[tid] = self.clock

    def advance(self, steps: int = 1) -> int:
        if steps < 1:
            raise ValueError("steps must be >= 1")
        self.clock += int(steps)
        return self.clock

    def score(self, task_id: str, priority: int = 0) -> Dict[str, Any]:
        tid = str(task_id)
        base = max(0, min(self.max_priority, int(priority)))
        born = self._first_seen.get(tid, self.clock)
        waited = max(0, self.clock - born)
        age_boost = waited // self.aging_interval
        return {
            "task_id": tid,
            "base_priority": base,
            "wait_ticks": waited,
            "age_boost": age_boost,
            "effective_priority": base + age_boost,
            "first_seen_tick": born,
        }

    def select(self, candidates: List[Dict[str, Any]], *, limit: int = 1) -> Dict[str, Any]:
        self.observe(c["task_id"] for c in candidates)
        scored = [
            {**self.score(c["task_id"], int(c.get("priority", 0))), "index": idx}
            for idx, c in enumerate(candidates)
        ]
        scored.sort(
            key=lambda x: (
                -x["effective_priority"],
                x["first_seen_tick"],
                x["index"],
                x["task_id"],
            )
        )
        chosen = scored[: max(1, int(limit))]
        for item in chosen:
            self._first_seen.pop(item["task_id"], None)
        return {
            "protocol": self.PROTOCOL,
            "clock": self.clock,
            "selected": [x["task_id"] for x in chosen],
            "ranked": scored,
        }


# ---------------------------------------------------------------------------
# MSEA FencedEffectWriter — Monotonic Lease Epoch Fencing
# ---------------------------------------------------------------------------

class FencedEffectWriter:
    """Blocks zombie/timed-out workers with superseded lease_epoch from mutating state."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self.db_path = Path(
            db_path or (Path(PROJECT_ROOT) / "data" / "durable_state.db")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resource_fences (
                    resource_key TEXT PRIMARY KEY,
                    current_epoch INTEGER NOT NULL,
                    holder_worker_id TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    def acquire_lease(self, resource_key: str, worker_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO resource_fences (resource_key, current_epoch, holder_worker_id, updated_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(resource_key) DO UPDATE SET
                    current_epoch = resource_fences.current_epoch + 1,
                    holder_worker_id = excluded.holder_worker_id,
                    updated_at = excluded.updated_at
                RETURNING current_epoch
                """,
                (resource_key, worker_id, time.time()),
            ).fetchone()
            assert row is not None
            return int(row[0])

    def assert_fence_valid(self, resource_key: str, lease_epoch: int) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT current_epoch, holder_worker_id FROM resource_fences WHERE resource_key = ?",
                (resource_key,),
            ).fetchone()
        if row is None or int(row[0]) != int(lease_epoch):
            cur = row[0] if row else None
            raise StaleLeaseFenceError(
                f"Zombie worker blocked on '{resource_key}': presented epoch={lease_epoch}, active epoch={cur}"
            )


# ---------------------------------------------------------------------------
# Last-Mile Security Gate (Closes OpenHands SDK Direct-Tool Bypass)
# ---------------------------------------------------------------------------

class LastMileSecurityGate:
    """Enforces taint, constitutional path/flag locks, and URE CFGGrammarSieve at execution time."""

    def __init__(self, project_root: Optional[Path | str] = None) -> None:
        self.seal_guard = ConstitutionSealGuard(project_root)
        self.cfg_sieve = CFGGrammarSieve()

    def inspect_invocation(
        self,
        *,
        tool: ToolContract,
        args: Dict[str, Any],
        envelope: Optional[CognitiveEnvelope] = None,
    ) -> None:
        missing = tool.required_args - set(args.keys())
        if missing:
            raise LastMileSecurityError(f"Tool '{tool.name}' missing required args: {sorted(missing)}")

        # 1. R16 Indirect Prompt Injection Taint Check
        if tool.effect_class != EffectClass.PURE_READ and envelope is not None:
            try:
                envelope.assert_can_authorize_mutation()
            except UntrustedDataEscalationError as exc:
                raise LastMileSecurityError(str(exc)) from exc

        # 2. Constitutional Path & Command Safety Check
        if "path" in args and tool.effect_class != EffectClass.PURE_READ:
            self.seal_guard.assert_write_allowed(str(args["path"]), actor="tool_dispatcher")
        if "command" in args:
            self.seal_guard.assert_command_safe(str(args["command"]))

        # 3. URE Alpha-C10 CFGGrammarSieve formal policy expression gate
        if "formal_guard_expr" in args and args["formal_guard_expr"] is not None:
            allowed_vars = set(args.get("allowed_vars", []))
            self.cfg_sieve.set_allowed_variables(allowed_vars)
            ok, err = self.cfg_sieve.validate_expression(str(args["formal_guard_expr"]))
            if not ok:
                raise LastMileSecurityError(f"URE CFGGrammarSieve rejected formal guard: {err}")


# ---------------------------------------------------------------------------
# DurableExecutionEngine (LangGraph Checkpoints + Astra R08 OUTCOME_UNKNOWN)
# ---------------------------------------------------------------------------

class DurableExecutionEngine:
    """Transactional state-graph executor with SQLite WAL checkpoints and R08 reconciliation."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self.db_path = Path(
            db_path or (Path(PROJECT_ROOT) / "data" / "durable_state.db")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.fencer = FencedEffectWriter(self.db_path)
        self.security_gate = LastMileSecurityGate()
        self.tools: Dict[str, ToolContract] = {}
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS step_checkpoints (
                    run_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    effect_class TEXT NOT NULL,
                    status TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    output_json TEXT,
                    state_json TEXT NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    error_text TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (run_id, step_id)
                )
                """
            )

    def register_tool(self, contract: ToolContract) -> None:
        self.tools[contract.name] = contract

    def get_step_checkpoint(self, run_id: str, step_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT run_id, step_id, step_index, tool_name, effect_class, status,
                       args_json, output_json, state_json, lease_epoch, error_text, updated_at
                FROM step_checkpoints WHERE run_id = ? AND step_id = ?
                """,
                (run_id, step_id),
            ).fetchone()
        if not row:
            return None
        return {
            "run_id": row[0],
            "step_id": row[1],
            "step_index": row[2],
            "tool_name": row[3],
            "effect_class": row[4],
            "status": row[5],
            "args": json.loads(row[6]),
            "output": json.loads(row[7]) if row[7] is not None else None,
            "state": json.loads(row[8]),
            "lease_epoch": row[9],
            "error_text": row[10],
            "updated_at": row[11],
        }

    def list_run_checkpoints(self, run_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT step_id FROM step_checkpoints WHERE run_id = ? ORDER BY step_index ASC",
                (run_id,),
            ).fetchall()
        return [self.get_step_checkpoint(run_id, r[0]) for r in rows if r]  # type: ignore[misc]

    def _save_checkpoint(
        self,
        *,
        run_id: str,
        step_id: str,
        step_index: int,
        tool_name: str,
        effect_class: EffectClass,
        status: StepStatus,
        args: Dict[str, Any],
        output: Any,
        state: Dict[str, Any],
        lease_epoch: int,
        error_text: Optional[str] = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO step_checkpoints
                (run_id, step_id, step_index, tool_name, effect_class, status, args_json, output_json, state_json, lease_epoch, error_text, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, step_id) DO UPDATE SET
                    status=excluded.status,
                    output_json=excluded.output_json,
                    state_json=excluded.state_json,
                    lease_epoch=excluded.lease_epoch,
                    error_text=excluded.error_text,
                    updated_at=excluded.updated_at
                """,
                (
                    run_id,
                    step_id,
                    step_index,
                    tool_name,
                    effect_class.value,
                    status.value,
                    json.dumps(args, sort_keys=True),
                    json.dumps(output) if output is not None else None,
                    json.dumps(state, sort_keys=True),
                    lease_epoch,
                    error_text,
                    time.time(),
                ),
            )

    def execute_step(
        self,
        *,
        run_id: str,
        step_id: str,
        step_index: int,
        tool_name: str,
        args: Dict[str, Any],
        state: Dict[str, Any],
        lease_epoch: int,
        envelope: Optional[CognitiveEnvelope] = None,
    ) -> Dict[str, Any]:
        if tool_name not in self.tools:
            raise KeyError(f"Unregistered tool: {tool_name}")
        tool = self.tools[tool_name]

        # 1. Check existing checkpoint (idempotent skip or R08 OUTCOME_UNKNOWN lock!)
        existing = self.get_step_checkpoint(run_id, step_id)
        if existing is not None:
            if existing["status"] == StepStatus.COMPLETED.value:
                return existing
            if existing["status"] == StepStatus.OUTCOME_UNKNOWN.value:
                raise OutcomeUnknownError(
                    f"R08 violation: step '{step_id}' in run '{run_id}' has status OUTCOME_UNKNOWN. "
                    "Call reconcile_step() before retrying to avoid duplicate side effects."
                )

        # 2. Enforce monotonic lease fence & last-mile security gate
        self.fencer.assert_fence_valid(run_id, lease_epoch)
        self.security_gate.inspect_invocation(tool=tool, args=args, envelope=envelope)

        self._save_checkpoint(
            run_id=run_id,
            step_id=step_id,
            step_index=step_index,
            tool_name=tool_name,
            effect_class=tool.effect_class,
            status=StepStatus.RUNNING,
            args=args,
            output=None,
            state=state,
            lease_epoch=lease_epoch,
        )

        # 3. Execute tool and classify Timeout as OUTCOME_UNKNOWN for mutative tools (R08)
        try:
            result = tool.execute_fn(args)
        except (TimeoutError, ConnectionError) as exc:
            if tool.effect_class != EffectClass.PURE_READ:
                self._save_checkpoint(
                    run_id=run_id,
                    step_id=step_id,
                    step_index=step_index,
                    tool_name=tool_name,
                    effect_class=tool.effect_class,
                    status=StepStatus.OUTCOME_UNKNOWN,
                    args=args,
                    output=None,
                    state=state,
                    lease_epoch=lease_epoch,
                    error_text=f"OUTCOME_UNKNOWN due to {type(exc).__name__}: {exc}",
                )
                raise OutcomeUnknownError(
                    f"Step '{step_id}' timed out during {tool.effect_class.value}; marked OUTCOME_UNKNOWN"
                ) from exc
            self._save_checkpoint(
                run_id=run_id,
                step_id=step_id,
                step_index=step_index,
                tool_name=tool_name,
                effect_class=tool.effect_class,
                status=StepStatus.FAILED,
                args=args,
                output=None,
                state=state,
                lease_epoch=lease_epoch,
                error_text=str(exc),
            )
            raise
        except Exception as exc:
            self._save_checkpoint(
                run_id=run_id,
                step_id=step_id,
                step_index=step_index,
                tool_name=tool_name,
                effect_class=tool.effect_class,
                status=StepStatus.FAILED,
                args=args,
                output=None,
                state=state,
                lease_epoch=lease_epoch,
                error_text=str(exc),
            )
            raise

        # Re-check fence right before committing output!
        self.fencer.assert_fence_valid(run_id, lease_epoch)
        next_state = {**state, f"step_{step_id}_done": True}
        self._save_checkpoint(
            run_id=run_id,
            step_id=step_id,
            step_index=step_index,
            tool_name=tool_name,
            effect_class=tool.effect_class,
            status=StepStatus.COMPLETED,
            args=args,
            output=result,
            state=next_state,
            lease_epoch=lease_epoch,
        )
        return self.get_step_checkpoint(run_id, step_id)  # type: ignore[return-value]

    def reconcile_step(self, run_id: str, step_id: str, *, lease_epoch: int) -> Dict[str, Any]:
        """Reconcile an OUTCOME_UNKNOWN step by inspecting real world/disk state (R08)."""
        self.fencer.assert_fence_valid(run_id, lease_epoch)
        cp = self.get_step_checkpoint(run_id, step_id)
        if cp is None:
            raise KeyError(f"Missing step checkpoint ({run_id}, {step_id})")
        if cp["status"] != StepStatus.OUTCOME_UNKNOWN.value:
            return cp

        tool = self.tools[cp["tool_name"]]
        if tool.reconcile_fn is None:
            raise OutcomeUnknownError(
                f"Tool '{tool.name}' has no reconcile_fn; human/operator resolution required"
            )

        obs = tool.reconcile_fn(cp["args"])
        if obs.effect_occurred:
            next_state = {**cp["state"], f"step_{step_id}_done": True, "reconciled": True}
            self._save_checkpoint(
                run_id=run_id,
                step_id=step_id,
                step_index=cp["step_index"],
                tool_name=tool.name,
                effect_class=tool.effect_class,
                status=StepStatus.COMPLETED,
                args=cp["args"],
                output=obs.observed_output,
                state=next_state,
                lease_epoch=lease_epoch,
                error_text=None,
            )
        else:
            self._save_checkpoint(
                run_id=run_id,
                step_id=step_id,
                step_index=cp["step_index"],
                tool_name=tool.name,
                effect_class=tool.effect_class,
                status=StepStatus.RECONCILED_SAFE_TO_RETRY,
                args=cp["args"],
                output=None,
                state=cp["state"],
                lease_epoch=lease_epoch,
                error_text=f"Reconciled absent ({obs.evidence}); safe to retry",
            )
        return self.get_step_checkpoint(run_id, step_id)  # type: ignore[return-value]
