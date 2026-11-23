"""Temporal/Restate-Style Deterministic Workflow Record-and-Replay Engine (v11.0).

Records all non-deterministic boundaries (external activity I/O, LLM completions,
wall/monotonic clock ticks, PRNG draws) in an immutable SQLite WAL event log.
During replay (`ReplaySession`):
  - External activities and LLM calls are NOT re-executed; recorded results are injected
  - Virtual clock & deterministic PRNG return exact recorded ticks/draws
  - Any divergence in operation name or argument digest raises `NonDeterminismDriftError`.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import random
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class NonDeterminismDriftError(RuntimeError):
    """Raised during workflow replay when control flow diverges from recorded history."""


def _canonical_sha256(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RecordedEvent:
    seq: int
    event_type: str  # WORKFLOW_START | ACTIVITY_IO | LLM_COMPLETION | CLOCK_TICK | RANDOM_DRAW | WORKFLOW_END
    op_name: str
    args_sha256: str
    result_json: str
    recorded_at: float


class DeterministicRecordReplayEngine:
    """SQLite WAL event store for bit-exact workflow record and replay."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflow_runs (
                    run_id TEXT PRIMARY KEY,
                    workflow_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    seed INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workflow_events (
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    op_name TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    recorded_at REAL NOT NULL,
                    PRIMARY KEY (run_id, seq)
                );
                """
            )

    def start_recording(self, run_id: str, workflow_name: str, *, seed: int = 42) -> "RecorderSession":
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM workflow_events WHERE run_id=?", (run_id,))
            conn.execute(
                "INSERT OR REPLACE INTO workflow_runs (run_id, workflow_name, status, seed, created_at) VALUES (?, ?, ?, ?, ?)",
                (run_id, workflow_name, "RECORDING", int(seed), now),
            )
            conn.execute(
                "INSERT INTO workflow_events (run_id, seq, event_type, op_name, args_sha256, result_json, recorded_at) "
                "VALUES (?, 0, 'WORKFLOW_START', ?, ?, ?, ?)",
                (run_id, workflow_name, _canonical_sha256({"seed": seed}), json.dumps({"seed": seed}), now),
            )
        return RecorderSession(self, run_id=run_id, seed=int(seed))

    def start_replay(self, run_id: str) -> "ReplaySession":
        events = self.load_history(run_id)
        if not events:
            raise KeyError(f"No recorded workflow history for run_id={run_id!r}")
        return ReplaySession(self, run_id=run_id, events=events)

    def _append_event(self, run_id: str, seq: int, event_type: str, op_name: str, args_sha: str, result: Any) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO workflow_events (run_id, seq, event_type, op_name, args_sha256, result_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, seq, event_type, op_name, args_sha, json.dumps(result, ensure_ascii=False, default=str), time.time()),
            )
            if event_type == "WORKFLOW_END":
                conn.execute("UPDATE workflow_runs SET status='COMPLETED' WHERE run_id=?", (run_id,))

    def load_history(self, run_id: str) -> List[RecordedEvent]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, event_type, op_name, args_sha256, result_json, recorded_at "
                "FROM workflow_events WHERE run_id=? ORDER BY seq ASC",
                (run_id,),
            ).fetchall()
        return [
            RecordedEvent(
                seq=int(r[0]),
                event_type=str(r[1]),
                op_name=str(r[2]),
                args_sha256=str(r[3]),
                result_json=str(r[4]),
                recorded_at=float(r[5]),
            )
            for r in rows
        ]


class RecorderSession:
    """Executes non-deterministic calls live while journaling every outcome deterministically."""

    def __init__(self, engine: DeterministicRecordReplayEngine, *, run_id: str, seed: int = 42) -> None:
        self.engine = engine
        self.run_id = run_id
        self.is_replaying = False
        self._rng = random.Random(seed)
        self._seq = 1

    def _record(self, event_type: str, op_name: str, args: Any, result: Any) -> Any:
        self.engine._append_event(self.run_id, self._seq, event_type, op_name, _canonical_sha256(args), result)
        self._seq += 1
        return result

    def activity(self, op_name: str, args: Any, fn: Callable[[], Any]) -> Any:
        res = fn()
        return self._record("ACTIVITY_IO", op_name, args, res)

    def llm_call(self, label: str, prompt_payload: Any, fn: Callable[[], Any]) -> Any:
        res = fn()
        return self._record("LLM_COMPLETION", label, prompt_payload, res)

    def now_timestamp(self) -> float:
        ts = time.time()
        return float(self._record("CLOCK_TICK", "wall_time", {}, ts))

    def random_float(self, label: str = "rng") -> float:
        val = self._rng.random()
        return float(self._record("RANDOM_DRAW", label, {}, val))

    def finish(self, outcome: Any) -> Any:
        return self._record("WORKFLOW_END", "complete", {}, outcome)


class ReplaySession:
    """Replays recorded workflow steps deterministically without running external side effects."""

    def __init__(self, engine: DeterministicRecordReplayEngine, *, run_id: str, events: List[RecordedEvent]) -> None:
        self.engine = engine
        self.run_id = run_id
        self.is_replaying = True
        self._events = events
        self._cursor = 1  # seq 0 is WORKFLOW_START
        self.replayed_events = 0

    def _consume(self, expected_type: str, op_name: str, args: Any) -> Any:
        if self._cursor >= len(self._events):
            raise NonDeterminismDriftError(
                f"Replay exhausted at seq={self._cursor} while expecting {expected_type}:{op_name}"
            )
        ev = self._events[self._cursor]
        args_sha = _canonical_sha256(args)
        if ev.event_type != expected_type or ev.op_name != op_name:
            raise NonDeterminismDriftError(
                f"Control-flow drift at seq={ev.seq}: history has ({ev.event_type}, {ev.op_name!r}), "
                f"code called ({expected_type}, {op_name!r})"
            )
        if ev.args_sha256 != args_sha:
            raise NonDeterminismDriftError(
                f"Argument drift at seq={ev.seq} ({op_name!r}): expected sha={ev.args_sha256[:12]}, got {args_sha[:12]}"
            )
        self._cursor += 1
        self.replayed_events += 1
        return json.loads(ev.result_json)

    def activity(self, op_name: str, args: Any, fn: Callable[[], Any]) -> Any:  # noqa: ARG002
        return self._consume("ACTIVITY_IO", op_name, args)

    def llm_call(self, label: str, prompt_payload: Any, fn: Callable[[], Any]) -> Any:  # noqa: ARG002
        return self._consume("LLM_COMPLETION", label, prompt_payload)

    def now_timestamp(self) -> float:
        return float(self._consume("CLOCK_TICK", "wall_time", {}))

    def random_float(self, label: str = "rng") -> float:
        return float(self._consume("RANDOM_DRAW", label, {}))

    def finish(self, outcome: Any) -> Any:  # noqa: ARG002
        return self._consume("WORKFLOW_END", "complete", {})
