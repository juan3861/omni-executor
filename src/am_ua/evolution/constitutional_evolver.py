"""Constitutional Self-Evolution Engine (`ASI-Evolve` UCB1/MAP-Elites + `AutoHarness`) (P5.3).

Implements Astra R17 + Sonnet S4 Metric-Gated Admission:
  - Closed `LEARN -> DESIGN -> EXPERIMENT -> ANALYZE` loop persisted in SQLite WAL
  - `UCB1` parent selection + `MAP-Elites` behavioral niche archive `(complexity_bin, speed_bin)`
  - Strict `ConstitutionSealGuard` wall: ANY attempt by the evolver to touch `constitution/`,
    `eval/`, or `seal_guard.py` raises `ConstitutionalViolationError` fail-closed
  - Pareto Non-Regression + Baseline Superiority Gate: candidate only enters the active
    archive if `regression_pass_rate == 1.0` AND it strictly improves measured holdout
    utility over baseline (or matches utility at strictly lower cost/latency)
  - `AutoHarnessSynthesizer`: DeepMind AutoHarness-style deterministic action-validator
    code synthesis with AST sandbox verification and empirical unit-test gating.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua.governance.seal_guard import (
    ConstitutionSealGuard,
    ConstitutionalViolationError,
)


@dataclass
class EvolutionCandidate:
    candidate_id: str
    parent_id: Optional[str]
    target_rel_path: str
    artifact_code: str
    complexity_bin: str
    speed_bin: str
    regression_pass_rate: float
    holdout_score: float
    latency_ms: float
    admitted: bool
    rejection_reason: str = ""


class ConstitutionalEvolver:
    """ASI-Evolve (UCB1 + MAP-Elites) governed by ConstitutionSealGuard & Pareto Gate."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        *,
        seal_guard: Optional[ConstitutionSealGuard] = None,
        ucb_c: float = 1.414,
    ) -> None:
        root = Path(__file__).resolve().parents[3]
        self.db_path = Path(db_path or (root / "data" / "evolver_archive.db")).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.seal_guard = seal_guard or ConstitutionSealGuard(root)
        self.ucb_c = ucb_c
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
                CREATE TABLE IF NOT EXISTS map_elites_archive (
                    candidate_id TEXT PRIMARY KEY,
                    parent_id TEXT,
                    niche_key TEXT NOT NULL,
                    target_rel_path TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    artifact_code TEXT NOT NULL,
                    holdout_score REAL NOT NULL,
                    latency_ms REAL NOT NULL,
                    visits INTEGER NOT NULL DEFAULT 1,
                    reward_sum REAL NOT NULL DEFAULT 0.0,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evolution_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_id TEXT NOT NULL,
                    admitted INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )

    def seed_baseline(
        self,
        candidate_id: str,
        target_rel_path: str,
        artifact_code: str,
        *,
        holdout_score: float,
        latency_ms: float,
        complexity_bin: str = "simple",
        speed_bin: str = "fast",
    ) -> None:
        self.seal_guard.assert_write_allowed(target_rel_path, actor="evolver")
        niche = f"{complexity_bin}:{speed_bin}"
        sha = hashlib.sha256(artifact_code.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO map_elites_archive
                (candidate_id, parent_id, niche_key, target_rel_path, artifact_sha256,
                 artifact_code, holdout_score, latency_ms, visits, reward_sum, created_at)
                VALUES (?, NULL, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    candidate_id,
                    niche,
                    target_rel_path,
                    sha,
                    artifact_code,
                    holdout_score,
                    latency_ms,
                    holdout_score,
                    time.time(),
                ),
            )

    def select_parent_ucb1(self) -> Optional[Dict[str, Any]]:
        """LEARN/DESIGN step: pick parent elite maximizing UCB1 exploration-exploitation."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT candidate_id, niche_key, target_rel_path, artifact_code, holdout_score, latency_ms, visits, reward_sum FROM map_elites_archive"
            ).fetchall()
        if not rows:
            return None
        total_visits = max(1, sum(int(r[6]) for r in rows))
        best_row = None
        best_ucb = -1e18
        for r in rows:
            visits = max(1, int(r[6]))
            mean_reward = float(r[7]) / visits
            ucb = mean_reward + self.ucb_c * math.sqrt(math.log(total_visits + 1.0) / visits)
            if ucb > best_ucb:
                best_ucb = ucb
                best_row = r
        assert best_row is not None
        return {
            "candidate_id": best_row[0],
            "niche_key": best_row[1],
            "target_rel_path": best_row[2],
            "artifact_code": best_row[3],
            "holdout_score": float(best_row[4]),
            "latency_ms": float(best_row[5]),
            "ucb_score": round(best_ucb, 5),
        }

    def evaluate_and_commit_mutation(
        self,
        *,
        candidate_id: str,
        parent_id: Optional[str],
        target_rel_path: str,
        artifact_code: str,
        evaluator_fn: Callable[[str], Dict[str, float]],
        baseline_score: float,
        baseline_latency_ms: float = 1000.0,
    ) -> EvolutionCandidate:
        """EXPERIMENT & ANALYZE step with Constitutional Wall + Pareto Baseline Gate."""
        # 1. Fail-closed Constitutional Seal check BEFORE running or admitting mutation
        self.seal_guard.assert_write_allowed(target_rel_path, actor="evolver")
        seal_ok, seal_errs = self.seal_guard.verify_seal(require_manifest=False)
        if not seal_ok:
            raise ConstitutionalViolationError(f"Active seal broken before evolution: {seal_errs}")

        metrics = evaluator_fn(artifact_code)
        reg_rate = float(metrics.get("regression_pass_rate", 0.0))
        holdout = float(metrics.get("holdout_score", 0.0))
        latency = float(metrics.get("latency_ms", 999.0))
        comp_bin = "compact" if len(artifact_code) < 600 else "elaborate"
        spd_bin = "fast" if latency <= baseline_latency_ms else "thorough"
        niche = f"{comp_bin}:{spd_bin}"

        admitted = False
        reason = "admitted_pareto_improvement"
        if reg_rate < 1.0:
            reason = f"rejected_regression_failure(rate={reg_rate:.2f})"
        elif holdout < baseline_score:
            reason = f"rejected_below_baseline({holdout:.4f} < {baseline_score:.4f})"
        elif holdout == baseline_score and latency >= baseline_latency_ms:
            reason = "rejected_no_pareto_gain_over_baseline"
        else:
            # Check MAP-Elites niche incumbent
            with self._connect() as conn:
                inc = conn.execute(
                    "SELECT candidate_id, holdout_score, latency_ms FROM map_elites_archive WHERE niche_key = ?",
                    (niche,),
                ).fetchone()
                if inc is not None:
                    inc_score, inc_lat = float(inc[1]), float(inc[2])
                    if holdout < inc_score or (holdout == inc_score and latency >= inc_lat):
                        reason = f"rejected_dominated_by_niche_incumbent:{inc[0]}"
                    else:
                        conn.execute(
                            "DELETE FROM map_elites_archive WHERE niche_key = ?", (niche,)
                        )
                        admitted = True
                else:
                    admitted = True

                if admitted:
                    sha = hashlib.sha256(artifact_code.encode("utf-8")).hexdigest()
                    conn.execute(
                        """
                        INSERT INTO map_elites_archive
                        (candidate_id, parent_id, niche_key, target_rel_path, artifact_sha256,
                         artifact_code, holdout_score, latency_ms, visits, reward_sum, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            candidate_id,
                            parent_id,
                            niche,
                            target_rel_path,
                            sha,
                            artifact_code,
                            holdout,
                            latency,
                            holdout,
                            time.time(),
                        ),
                    )
                if parent_id:
                    conn.execute(
                        "UPDATE map_elites_archive SET visits = visits + 1, reward_sum = reward_sum + ? WHERE candidate_id = ?",
                        (holdout if admitted else 0.0, parent_id),
                    )

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO evolution_ledger (candidate_id, admitted, reason, metrics_json, ts) VALUES (?, ?, ?, ?, ?)",
                (
                    candidate_id,
                    1 if admitted else 0,
                    reason,
                    json.dumps(
                        {
                            "regression_pass_rate": reg_rate,
                            "holdout_score": holdout,
                            "latency_ms": latency,
                            "niche": niche,
                        }
                    ),
                    time.time(),
                ),
            )

        return EvolutionCandidate(
            candidate_id=candidate_id,
            parent_id=parent_id,
            target_rel_path=target_rel_path,
            artifact_code=artifact_code,
            complexity_bin=comp_bin,
            speed_bin=spd_bin,
            regression_pass_rate=reg_rate,
            holdout_score=holdout,
            latency_ms=latency,
            admitted=admitted,
            rejection_reason="" if admitted else reason,
        )


class AutoHarnessSynthesizer:
    """DeepMind AutoHarness-style deterministic action-filter synthesizer & verifier."""

    FORBIDDEN_AST_NODES = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)
    SAFE_BUILTINS = {
        "isinstance": isinstance,
        "len": len,
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "set": set,
        "dict": dict,
        "list": list,
        "tuple": tuple,
        "any": any,
        "all": all,
        "min": min,
        "max": max,
    }

    def compile_and_verify_harness(
        self,
        harness_source: str,
        test_vectors: List[Tuple[Dict[str, Any], bool]],
    ) -> Dict[str, Any]:
        """Verify AST purity of `validate_action(action)` and test against valid/illegal actions."""
        tree = ast.parse(harness_source)
        for node in ast.walk(tree):
            if isinstance(node, self.FORBIDDEN_AST_NODES):
                raise ValueError(
                    f"AutoHarness forbids import/global statements ({type(node).__name__})"
                )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec", "open", "__import__", "compile"):
                    raise ValueError(f"AutoHarness forbids call to '{node.func.id}'")

        ns: Dict[str, Any] = {"__builtins__": dict(self.SAFE_BUILTINS)}
        exec(compile(tree, "<autoharness>", "exec"), ns, ns)  # noqa: S102 - AST-verified pure function
        fn = ns.get("validate_action")
        if not callable(fn):
            raise ValueError("Harness must define callable `validate_action(action)`")

        passed = 0
        failures: List[Dict[str, Any]] = []
        for idx, (sample_action, expected_ok) in enumerate(test_vectors):
            verdict_ok, reason = fn(sample_action)
            if bool(verdict_ok) == expected_ok:
                passed += 1
            else:
                failures.append(
                    {
                        "index": idx,
                        "expected": expected_ok,
                        "actual": bool(verdict_ok),
                        "reason": str(reason),
                    }
                )
        total = max(1, len(test_vectors))
        return {
            "ok": len(failures) == 0,
            "pass_rate": round(passed / total, 4),
            "failures": failures,
            "fn": fn if len(failures) == 0 else None,
        }
