"""Natural-Language Scheduler, Monthly Cost Estimator, Wake Catch-Up & Task Audit Receipts (`am_ua.runtime.scheduler_receipts`, v14.0).

Inspired by Nod (`n8n-io/nod`), closing Nod's laptop-sleep gap on top of `DurableDaemonQueue`:
  - `NaturalScheduleParser`: converts PT/EN phrases ("every weekday at 08:00",
    "every 4 hours", "todo dia as 09:30", or standard 5-field cron) to interval/schedule specs
    and estimates `runs_per_month` & `estimated_monthly_cost_usd`.
  - `RecurringScheduleStore`: SQLite-WAL recurring schedules (`active`/`paused`, model assignment,
    follow-up check-ins, and `detect_wake_catchup` when host slept past scheduled windows).
  - `MonthlyBudgetLedger` & `PerTaskCheckinGuard`: monthly USD budget cap + per-task check-in
    pause threshold (default `$5.00` configurable while keeping `$0.00` free-tier default).
  - `TaskAuditReceipt`: structured signed-digest receipt recording logins/vault aliases used,
    external actions approved/blocked, tokens, TTFT, and exact cost USD.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Sequence
import uuid

from am_ua.contracts.contracts import resolve_omni_temp_dir


@dataclass(frozen=True)
class ParsedSchedule:
    expression: str
    interval_seconds: int
    runs_per_month: float
    kind: str  # "hourly" | "daily" | "weekday" | "weekly" | "cron" | "one_shot"
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NaturalScheduleParser:
    """Deterministic parser converting NL schedules & 5-field cron strings into cadence + monthly cost estimates."""

    @staticmethod
    def parse(expr: str) -> ParsedSchedule:
        raw = (expr or "").strip()
        low = raw.lower()
        if not low:
            raise ValueError("Schedule expression cannot be empty")

        m_hours = re.search(r"(?:every|a\s+cada)\s+(\d+)\s*(?:h|hr|hrs|hour|hours|hora|horas)\b", low)
        if m_hours:
            hrs = max(1, int(m_hours.group(1)))
            sec = hrs * 3600
            return ParsedSchedule(raw, sec, round((30.0 * 24.0) / hrs, 2), "hourly", f"Every {hrs}h")

        m_mins = re.search(r"(?:every|a\s+cada)\s+(\d+)\s*(?:m|min|mins|minute|minutes|minuto|minutos)\b", low)
        if m_mins:
            mins = max(1, int(m_mins.group(1)))
            sec = mins * 60
            return ParsedSchedule(raw, sec, round((30.0 * 24.0 * 60.0) / mins, 2), "hourly", f"Every {mins}m")

        if any(w in low for w in ("weekday", "dias uteis", "dia util", "segunda a sexta", "mon-fri")):
            return ParsedSchedule(raw, 86400, 21.7, "weekday", f"Weekdays ({raw})")

        if any(w in low for w in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
                                  "segunda", "terca", "quarta", "quinta", "sexta", "sabado", "domingo", "weekly", "semanal")):
            return ParsedSchedule(raw, 7 * 86400, 4.33, "weekly", f"Weekly ({raw})")

        if any(w in low for w in ("daily", "every day", "todo dia", "todos os dias", "morning brief", "diario")):
            return ParsedSchedule(raw, 86400, 30.0, "daily", f"Daily ({raw})")

        # Standard 5-field cron (`min hour dom mon dow`)
        parts = raw.split()
        if len(parts) == 5:
            min_f, hr_f, dom_f, _mon_f, dow_f = parts
            if dow_f in ("1-5", "MON-FRI"):
                return ParsedSchedule(raw, 86400, 21.7, "cron", f"Cron weekdays `{raw}`")
            if dow_f != "*":
                return ParsedSchedule(raw, 7 * 86400, 4.33, "cron", f"Cron weekly `{raw}`")
            if hr_f.startswith("*/"):
                step_h = max(1, int(hr_f[2:]))
                return ParsedSchedule(raw, step_h * 3600, round((30.0 * 24.0) / step_h, 2), "cron", f"Cron every {step_h}h")
            if min_f.startswith("*/"):
                step_m = max(1, int(min_f[2:]))
                return ParsedSchedule(raw, step_m * 60, round((30.0 * 24.0 * 60.0) / step_m, 2), "cron", f"Cron every {step_m}m")
            if dom_f == "*":
                return ParsedSchedule(raw, 86400, 30.0, "cron", f"Cron daily `{raw}`")
            return ParsedSchedule(raw, 30 * 86400, 1.0, "cron", f"Cron monthly `{raw}`")

        # Fallback: daily schedule
        return ParsedSchedule(raw, 86400, 30.0, "daily", f"Daily ({raw})")

    @classmethod
    def estimate_monthly_cost_usd(
        cls,
        expr: str,
        *,
        provider: str = "groq",
        estimated_cost_per_run_usd: Optional[float] = None,
    ) -> float:
        parsed = cls.parse(expr)
        prov = (provider or "groq").strip().lower()
        free_provs = {"groq", "openrouter", "nvidia", "cerebras", "ollama", "free"}
        per_run = (
            float(estimated_cost_per_run_usd)
            if estimated_cost_per_run_usd is not None
            else (0.0 if prov in free_provs else 0.05)
        )
        return round(max(0.0, per_run) * parsed.runs_per_month, 4)


class RecurringScheduleStore:
    """SQLite-WAL persistent recurring & follow-up schedule manager with wake catch-up."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        base = resolve_omni_temp_dir("schedules") if db_path is None else None
        self.db_path = Path(db_path or (base / "schedules.db")).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=20.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS recurring_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    expression TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    runs_per_month REAL NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'groq',
                    model TEXT NOT NULL DEFAULT '',
                    estimated_cost_per_run_usd REAL NOT NULL DEFAULT 0.0,
                    estimated_monthly_cost_usd REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL DEFAULT 'active',
                    catchup_policy TEXT NOT NULL DEFAULT 'run_once',
                    next_run_at REAL NOT NULL,
                    last_run_at REAL,
                    missed_windows_recovered INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS task_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    schedule_id TEXT,
                    status TEXT NOT NULL,
                    providers_json TEXT NOT NULL,
                    tokens_prompt INTEGER NOT NULL DEFAULT 0,
                    tokens_completion INTEGER NOT NULL DEFAULT 0,
                    ttft_mean_ms REAL NOT NULL DEFAULT 0.0,
                    cost_usd REAL NOT NULL DEFAULT 0.0,
                    vault_aliases_json TEXT NOT NULL,
                    approved_actions_json TEXT NOT NULL,
                    blocked_actions_json TEXT NOT NULL,
                    changed_files_json TEXT NOT NULL,
                    elapsed_s REAL NOT NULL DEFAULT 0.0,
                    digest_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monthly_budget_ledger (
                    month_key TEXT PRIMARY KEY,
                    monthly_limit_usd REAL,
                    task_checkin_threshold_usd REAL NOT NULL DEFAULT 5.0,
                    spent_usd REAL NOT NULL DEFAULT 0.0,
                    updated_at REAL NOT NULL
                );
                """
            )

    def create_schedule(
        self,
        *,
        name: str,
        objective: str,
        workspace: str,
        expression: str,
        provider: str = "groq",
        model: str = "",
        estimated_cost_per_run_usd: Optional[float] = None,
        catchup_policy: str = "run_once",
        start_immediately: bool = False,
        now_ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        parsed = NaturalScheduleParser.parse(expression)
        est_monthly = NaturalScheduleParser.estimate_monthly_cost_usd(
            expression, provider=provider, estimated_cost_per_run_usd=estimated_cost_per_run_usd
        )
        per_run = round(est_monthly / max(0.01, parsed.runs_per_month), 4) if est_monthly > 0 else 0.0
        now = float(now_ts if now_ts is not None else time.time())
        sid = f"sch-{uuid.uuid4().hex[:10]}"
        next_at = now if start_immediately else (now + parsed.interval_seconds)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recurring_schedules (
                    schedule_id, name, objective, workspace, expression, interval_seconds,
                    runs_per_month, provider, model, estimated_cost_per_run_usd,
                    estimated_monthly_cost_usd, status, catchup_policy, next_run_at,
                    last_run_at, missed_windows_recovered, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL, 0, ?, ?)
                """,
                (
                    sid, name.strip(), objective.strip(), str(workspace), expression.strip(),
                    int(parsed.interval_seconds), float(parsed.runs_per_month),
                    provider.strip().lower(), model.strip(), per_run, est_monthly,
                    catchup_policy, next_at, now, now,
                ),
            )
            row = conn.execute("SELECT * FROM recurring_schedules WHERE schedule_id=?", (sid,)).fetchone()
        return dict(row) if row else {"schedule_id": sid}

    def schedule_followup(
        self,
        *,
        name: str,
        objective: str,
        workspace: str,
        delay_seconds: int = 86400,
        provider: str = "groq",
        now_ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Schedule a one-shot follow-up check-in (e.g. check email reply on Friday)."""
        now = float(now_ts if now_ts is not None else time.time())
        sid = f"flw-{uuid.uuid4().hex[:10]}"
        interval = max(1, int(delay_seconds))
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recurring_schedules (
                    schedule_id, name, objective, workspace, expression, interval_seconds,
                    runs_per_month, provider, model, estimated_cost_per_run_usd,
                    estimated_monthly_cost_usd, status, catchup_policy, next_run_at,
                    last_run_at, missed_windows_recovered, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1.0, ?, '', 0.0, 0.0, 'active', 'run_once', ?, NULL, 0, ?, ?)
                """,
                (sid, name.strip(), objective.strip(), str(workspace), f"followup+{interval}s", interval, provider, now + interval, now, now),
            )
            row = conn.execute("SELECT * FROM recurring_schedules WHERE schedule_id=?", (sid,)).fetchone()
        return dict(row) if row else {"schedule_id": sid}

    def list_schedules(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM recurring_schedules ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def set_status(self, schedule_id: str, status: str) -> bool:
        norm = status.strip().lower()
        if norm not in ("active", "paused", "completed"):
            raise ValueError(f"Unsupported schedule status: {status!r}")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE recurring_schedules SET status=?, updated_at=? WHERE schedule_id=?",
                (norm, time.time(), schedule_id),
            )
            return cur.rowcount > 0

    def set_model(self, schedule_id: str, *, provider: str, model: str = "", estimated_cost_per_run_usd: Optional[float] = None) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM recurring_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
            if not row:
                raise KeyError(f"Unknown schedule_id: {schedule_id!r}")
            est_m = NaturalScheduleParser.estimate_monthly_cost_usd(
                str(row["expression"]), provider=provider, estimated_cost_per_run_usd=estimated_cost_per_run_usd
            )
            per_run = round(est_m / max(0.01, float(row["runs_per_month"])), 4) if est_m > 0 else 0.0
            conn.execute(
                """
                UPDATE recurring_schedules
                SET provider=?, model=?, estimated_cost_per_run_usd=?, estimated_monthly_cost_usd=?, updated_at=?
                WHERE schedule_id=?
                """,
                (provider.strip().lower(), model.strip(), per_run, est_m, time.time(), schedule_id),
            )
            upd = conn.execute("SELECT * FROM recurring_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
            return dict(upd) if upd else {}

    def pop_due_schedules(self, *, now_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """Atomically advance due schedules and report wake-after-sleep catch-up windows."""
        now = float(now_ts if now_ts is not None else time.time())
        due: List[Dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM recurring_schedules WHERE status='active' AND next_run_at <= ?",
                (now,),
            ).fetchall()
            for r in rows:
                item = dict(r)
                interval = max(1, int(item["interval_seconds"]))
                overdue_s = max(0.0, now - float(item["next_run_at"]))
                missed = int(overdue_s // interval)
                item["wake_catchup"] = missed > 0
                item["missed_windows"] = missed
                if str(item["schedule_id"]).startswith("flw-"):
                    conn.execute(
                        "UPDATE recurring_schedules SET status='completed', last_run_at=?, missed_windows_recovered=missed_windows_recovered+?, updated_at=? WHERE schedule_id=?",
                        (now, missed, now, item["schedule_id"]),
                    )
                else:
                    next_at = now + interval
                    conn.execute(
                        "UPDATE recurring_schedules SET last_run_at=?, next_run_at=?, missed_windows_recovered=missed_windows_recovered+?, updated_at=? WHERE schedule_id=?",
                        (now, next_at, missed, now, item["schedule_id"]),
                    )
                due.append(item)
        return due

    # ---- Monthly Budget & Per-Task Checkin Guard ----
    @staticmethod
    def _month_key(ts: Optional[float] = None) -> str:
        t = time.gmtime(ts if ts is not None else time.time())
        return f"{t.tm_year:04d}-{t.tm_mon:02d}"

    def configure_budget(
        self,
        *,
        monthly_limit_usd: Optional[float] = None,
        task_checkin_threshold_usd: float = 5.0,
        month_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        mk = month_key or self._month_key()
        thresh = max(0.0, float(task_checkin_threshold_usd))
        limit_val = float(monthly_limit_usd) if monthly_limit_usd is not None else None
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT * FROM monthly_budget_ledger WHERE month_key=?", (mk,)).fetchone()
            spent = float(cur["spent_usd"]) if cur else 0.0
            conn.execute(
                """
                INSERT OR REPLACE INTO monthly_budget_ledger
                    (month_key, monthly_limit_usd, task_checkin_threshold_usd, spent_usd, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (mk, limit_val, thresh, spent, time.time()),
            )
            row = conn.execute("SELECT * FROM monthly_budget_ledger WHERE month_key=?", (mk,)).fetchone()
        return dict(row) if row else {}

    def check_task_budget_guard(
        self,
        *,
        task_cost_usd: float,
        month_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return whether execution must pause for user cost check-in or monthly cap."""
        mk = month_key or self._month_key()
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM monthly_budget_ledger WHERE month_key=?", (mk,)).fetchone()
        limit_usd = float(row["monthly_limit_usd"]) if (row and row["monthly_limit_usd"] is not None) else None
        thresh = float(row["task_checkin_threshold_usd"]) if row else 5.0
        spent = float(row["spent_usd"]) if row else 0.0
        projected_month = spent + max(0.0, float(task_cost_usd))

        monthly_exceeded = bool(limit_usd is not None and projected_month > limit_usd)
        checkin_triggered = bool(task_cost_usd >= thresh and thresh > 0.0 and task_cost_usd > 0.0)
        return {
            "ok": not (monthly_exceeded or checkin_triggered),
            "month_key": mk,
            "monthly_limit_usd": limit_usd,
            "monthly_spent_usd": round(spent, 4),
            "projected_month_usd": round(projected_month, 4),
            "task_cost_usd": round(float(task_cost_usd), 4),
            "task_checkin_threshold_usd": thresh,
            "monthly_exceeded": monthly_exceeded,
            "task_checkin_triggered": checkin_triggered,
        }

    # ---- Task Audit Receipts ----
    def record_receipt(
        self,
        *,
        mission_id: str,
        status: str,
        providers: Sequence[str] = (),
        tokens_prompt: int = 0,
        tokens_completion: int = 0,
        ttft_mean_ms: float = 0.0,
        cost_usd: float = 0.0,
        vault_aliases_used: Sequence[str] = (),
        approved_actions: Sequence[Dict[str, Any]] = (),
        blocked_actions: Sequence[Dict[str, Any]] = (),
        changed_files: Sequence[str] = (),
        elapsed_s: float = 0.0,
        schedule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        rid = f"rcpt-{uuid.uuid4().hex[:12]}"
        payload = {
            "receipt_id": rid,
            "mission_id": mission_id,
            "schedule_id": schedule_id,
            "status": status,
            "providers": list(providers),
            "tokens_prompt": int(tokens_prompt),
            "tokens_completion": int(tokens_completion),
            "ttft_mean_ms": round(float(ttft_mean_ms), 2),
            "cost_usd": round(float(cost_usd), 6),
            "vault_aliases_used": list(vault_aliases_used),
            "approved_actions": list(approved_actions),
            "blocked_actions": list(blocked_actions),
            "changed_files": list(changed_files),
            "elapsed_s": round(float(elapsed_s), 3),
            "created_at": now,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        payload["digest_sha256"] = digest
        mk = self._month_key(now)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO task_receipts (
                    receipt_id, mission_id, schedule_id, status, providers_json,
                    tokens_prompt, tokens_completion, ttft_mean_ms, cost_usd,
                    vault_aliases_json, approved_actions_json, blocked_actions_json,
                    changed_files_json, elapsed_s, digest_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid, mission_id, schedule_id, status, json.dumps(list(providers)),
                    int(tokens_prompt), int(tokens_completion), float(ttft_mean_ms), float(cost_usd),
                    json.dumps(list(vault_aliases_used)), json.dumps(list(approved_actions), default=str),
                    json.dumps(list(blocked_actions), default=str), json.dumps(list(changed_files)),
                    float(elapsed_s), digest, now,
                ),
            )
            cur = conn.execute("SELECT spent_usd, monthly_limit_usd, task_checkin_threshold_usd FROM monthly_budget_ledger WHERE month_key=?", (mk,)).fetchone()
            new_spent = (float(cur["spent_usd"]) if cur else 0.0) + max(0.0, float(cost_usd))
            lim = cur["monthly_limit_usd"] if cur else None
            thr = float(cur["task_checkin_threshold_usd"]) if cur else 5.0
            conn.execute(
                "INSERT OR REPLACE INTO monthly_budget_ledger (month_key, monthly_limit_usd, task_checkin_threshold_usd, spent_usd, updated_at) VALUES (?, ?, ?, ?, ?)",
                (mk, lim, thr, new_spent, now),
            )
        return payload

    def list_receipts(self, *, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM task_receipts ORDER BY created_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append({
                "receipt_id": r["receipt_id"],
                "mission_id": r["mission_id"],
                "schedule_id": r["schedule_id"],
                "status": r["status"],
                "providers": json.loads(r["providers_json"]),
                "tokens_prompt": r["tokens_prompt"],
                "tokens_completion": r["tokens_completion"],
                "ttft_mean_ms": r["ttft_mean_ms"],
                "cost_usd": r["cost_usd"],
                "vault_aliases_used": json.loads(r["vault_aliases_json"]),
                "approved_actions": json.loads(r["approved_actions_json"]),
                "blocked_actions": json.loads(r["blocked_actions_json"]),
                "changed_files": json.loads(r["changed_files_json"]),
                "elapsed_s": r["elapsed_s"],
                "digest_sha256": r["digest_sha256"],
                "created_at": r["created_at"],
            })
        return out
