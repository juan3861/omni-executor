"""Epistemic Calibration Ledger (Astra R06) — Brier Score & Dynamic Autonomy Gate.

Tracks predicted confidence vs. empirically verified pass/fail outcomes per domain
in SQLite WAL. Adjusts agent autonomy dynamically when a domain exhibits overconfidence.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from am_ua import PROJECT_ROOT


@dataclass(frozen=True)
class DomainCalibrationStats:
    domain: str
    sample_count: int
    mean_predicted_confidence: float
    empirical_accuracy: float
    mean_brier_score: float
    overconfidence_gap: float
    autonomy_tier: str  # FULL_AUTONOMY | CAUTIOUS_VERIFY | REQUIRE_DOUBLE_CHECK


class CalibrationLedger:
    """SQLite-backed Brier score & calibration gate per engineering domain."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self.db_path = Path(
            db_path or (Path(PROJECT_ROOT) / "data" / "calibration_ledger.db")
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
                CREATE TABLE IF NOT EXISTS calibration_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    predicted_conf REAL NOT NULL,
                    actual_pass INTEGER NOT NULL,
                    brier_score REAL NOT NULL,
                    recorded_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cal_domain ON calibration_events(domain)"
            )

    def record(self, *, domain: str, task_id: str, predicted_conf: float, actual_pass: bool) -> float:
        p = max(0.0, min(1.0, float(predicted_conf)))
        y = 1.0 if actual_pass else 0.0
        brier = (p - y) ** 2
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO calibration_events (domain, task_id, predicted_conf, actual_pass, brier_score, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (domain, task_id, p, int(actual_pass), brier, time.time()),
            )
        return brier

    def domain_stats(self, domain: str) -> DomainCalibrationStats:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*), AVG(predicted_conf), AVG(actual_pass), AVG(brier_score)
                FROM calibration_events WHERE domain = ?
                """,
                (domain,),
            ).fetchone()
        n = int(row[0] or 0)
        if n == 0:
            return DomainCalibrationStats(
                domain=domain,
                sample_count=0,
                mean_predicted_confidence=0.5,
                empirical_accuracy=0.5,
                mean_brier_score=0.25,
                overconfidence_gap=0.0,
                autonomy_tier="CAUTIOUS_VERIFY",
            )
        mean_p = float(row[1])
        acc = float(row[2])
        brier = float(row[3])
        gap = max(0.0, mean_p - acc)

        if n >= 3 and (gap > 0.20 or brier > 0.25):
            tier = "REQUIRE_DOUBLE_CHECK"
        elif n >= 3 and brier <= 0.10 and gap <= 0.10:
            tier = "FULL_AUTONOMY"
        else:
            tier = "CAUTIOUS_VERIFY"

        return DomainCalibrationStats(
            domain=domain,
            sample_count=n,
            mean_predicted_confidence=round(mean_p, 4),
            empirical_accuracy=round(acc, 4),
            mean_brier_score=round(brier, 4),
            overconfidence_gap=round(gap, 4),
            autonomy_tier=tier,
        )

    def calibrated_confidence(self, domain: str, raw_confidence: float) -> Dict[str, object]:
        """Shrink raw model confidence toward empirical domain accuracy when overconfident."""
        raw = max(0.0, min(1.0, float(raw_confidence)))
        stats = self.domain_stats(domain)
        if stats.sample_count == 0:
            effective = round(0.7 * raw + 0.3 * 0.5, 4)
        else:
            weight = min(0.8, stats.sample_count / 10.0)
            effective = round(max(0.0, raw - weight * stats.overconfidence_gap), 4)
        return {
            "domain": domain,
            "raw_confidence": raw,
            "calibrated_confidence": effective,
            "autonomy_tier": stats.autonomy_tier,
            "brier_score": stats.mean_brier_score,
            "sample_count": stats.sample_count,
        }
