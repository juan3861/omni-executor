"""MASTER PROMPT ALPHA-C13 — STATEFUL-SELECTION Engine (am_ua.governance.alpha_c13).

Builder/Auditor · Discovery-100 por linhagem · Repeated Rollouts · Cluster-Aware Evals
Scoped Approvals · Anti-Goodhart Promotion · Pareto Multi-Objective · Benchmark Sanity

Invariants:
  1. Priority order: platform/security > scope > contract > gates > evidence > optimization > style.
  2. AcceptanceContract: versioned, frozen SHA-256, explicit REQUIRED/OPTIONAL/N_A_ALLOWED gates.
     A REQUIRED gate NEVER converts to NOT_APPLICABLE. UNKNOWN is never PASS.
  3. StatefulSelectionLedger: SQLite WAL with non-replayable slots bound to (baseline, candidate, eval_plan).
     Slot consumption is atomic and prior to rollout (crashes never refund slots).
     Family-wise alpha control (Bonferroni / Holm-Bonferroni) to defeat Winner's Curse.
  4. Discovery100LineageEngine: Deduplicates forks/mirrors/wrappers from counting as distinct lineages.
     Scorecard: Relevance (gap 40, fit 30, impact 20, modularity 10) + Readiness.
  5. ClusterAwareRolloutManager: Aggregates across independent clusters to prevent pseudoreplication.
  6. AntiGoodhartPromoter: Strict Pareto gates on (Q quality, F critical failures, C cost, L latency, K coordination, P prompt).
     Rejects non-finite metrics (NaN, Inf) and boolean-string tampering.
  7. AGIASIDivergenceEngine: AGI-Pragmatic vs ASI-Systemic dual-lens dialectic generating empirical experiments.
  8. BenchmarkSanityOracle: Enforces that known-good passes and injected mutants fail; otherwise flags INVALID_EVAL.
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


class GateRequirement(str, Enum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    N_A_ALLOWED = "N_A_ALLOWED"


class GateStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PromotionVerdict(str, Enum):
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    RESOURCE_TRADEOFF_REVIEW = "RESOURCE_TRADEOFF_REVIEW"
    BLOCKED = "BLOCKED"


class ContractIntegrityError(RuntimeError):
    """Raised when a contract, gate specification, or immutable rule is violated."""


class InvalidEvalError(RuntimeError):
    """Raised when an evaluation harness fails sanity checking (known-good fails or mutant passes)."""


class SelectionBudgetExhaustedError(RuntimeError):
    """Raised when a candidate attempts evaluation after comparison budget is exhausted."""


@dataclass(frozen=True)
class GateSpec:
    gate_id: str
    requirement: GateRequirement
    description: str


@dataclass
class AcceptanceContract:
    contract_id: str
    version: str
    requirements: Dict[str, str]
    invariants: List[str]
    non_functional_goals: Dict[str, float]
    prohibited_operations: List[str]
    budget_tokens: int
    budget_time_s: float
    rollback_plan: str
    gates: Dict[str, GateSpec]
    rubric_weights: Dict[str, float]
    sha256_hash: str = field(init=False)

    def __post_init__(self) -> None:
        canonical = json.dumps(
            {
                "contract_id": self.contract_id,
                "version": self.version,
                "requirements": sorted(self.requirements.items()),
                "invariants": sorted(self.invariants),
                "non_functional_goals": sorted(self.non_functional_goals.items()),
                "prohibited_operations": sorted(self.prohibited_operations),
                "budget_tokens": self.budget_tokens,
                "budget_time_s": self.budget_time_s,
                "rollback_plan": self.rollback_plan,
                "gates": sorted([(k, v.requirement.value, v.description) for k, v in self.gates.items()]),
                "rubric_weights": sorted(self.rubric_weights.items()),
            },
            sort_keys=True,
            ensure_ascii=True,
        )
        object.__setattr__(self, "sha256_hash", hashlib.sha256(canonical.encode("utf-8")).hexdigest())

    def validate_gate_assignment(self, gate_id: str, status: GateStatus) -> GateStatus:
        if gate_id not in self.gates:
            raise ContractIntegrityError(f"Gate '{gate_id}' is not registered in contract {self.contract_id}")
        spec = self.gates[gate_id]
        if spec.requirement == GateRequirement.REQUIRED:
            if status == GateStatus.NOT_APPLICABLE:
                raise ContractIntegrityError(
                    f"Violation: Gate '{gate_id}' is REQUIRED and cannot be set to NOT_APPLICABLE"
                )
            if status == GateStatus.UNKNOWN:
                raise ContractIntegrityError(
                    f"Violation: Gate '{gate_id}' is REQUIRED; UNKNOWN is never treated as PASS"
                )
        elif spec.requirement == GateRequirement.OPTIONAL:
            if status == GateStatus.NOT_APPLICABLE:
                raise ContractIntegrityError(
                    f"Violation: Gate '{gate_id}' is OPTIONAL; N_A is only permitted when N_A_ALLOWED is explicit"
                )
        return status


class StatefulSelectionLedger:
    """Stateful SQLite WAL ledger tracking non-replayable evaluation slots and multi-comparison family alpha."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS comparison_families (
                    family_id TEXT PRIMARY KEY,
                    comparison_budget INTEGER NOT NULL,
                    consumed_slots INTEGER NOT NULL DEFAULT 0,
                    family_alpha REAL NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_slots (
                    slot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    family_id TEXT NOT NULL,
                    baseline_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    eval_plan_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    allocated_at REAL NOT NULL,
                    completed_at REAL,
                    metrics_json TEXT,
                    p_value REAL,
                    FOREIGN KEY(family_id) REFERENCES comparison_families(family_id)
                )
                """
            )

    def register_family(self, family_id: str, comparison_budget: int, family_alpha: float = 0.05) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO comparison_families
                (family_id, comparison_budget, consumed_slots, family_alpha, created_at)
                VALUES (?, ?, 0, ?, ?)
                """,
                (family_id, comparison_budget, family_alpha, time.time()),
            )

    def allocate_slot(
        self,
        family_id: str,
        baseline_id: str,
        candidate_id: str,
        eval_plan_hash: str,
    ) -> int:
        """Atomically allocates a non-replayable slot BEFORE evaluation begins.

        Crash or interruption does NOT refund the slot.
        """
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT comparison_budget, consumed_slots FROM comparison_families WHERE family_id = ?",
                (family_id,),
            )
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Comparison family '{family_id}' is not registered.")
            budget, consumed = row
            if consumed >= budget:
                raise SelectionBudgetExhaustedError(
                    f"Comparison budget exhausted for family '{family_id}' ({consumed}/{budget} consumed)."
                )

            # Consume slot atomically
            cur.execute(
                "UPDATE comparison_families SET consumed_slots = consumed_slots + 1 WHERE family_id = ?",
                (family_id,),
            )
            cur.execute(
                """
                INSERT INTO evaluation_slots
                (family_id, baseline_id, candidate_id, eval_plan_hash, status, allocated_at)
                VALUES (?, ?, ?, ?, 'CONSUMED_IN_FLIGHT', ?)
                """,
                (family_id, baseline_id, candidate_id, eval_plan_hash, time.time()),
            )
            slot_id = cur.lastrowid
            assert slot_id is not None
            return slot_id

    def record_outcome(
        self,
        slot_id: int,
        metrics: Dict[str, Any],
        p_value: Optional[float] = None,
    ) -> None:
        """Records outcome and enforces finite numbers only."""
        # Sanitize metrics: reject NaN, Inf, string booleans
        for k, v in metrics.items():
            if isinstance(v, float):
                if math.isnan(v) or math.isinf(v):
                    raise ValueError(f"Metric '{k}' contains non-finite float: {v}")
            elif isinstance(v, str) and v.lower() in ("true", "false"):
                raise ValueError(f"Metric '{k}' uses ambiguous string boolean '{v}'; must be a true bool.")

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE evaluation_slots
                SET status = 'COMPLETED', completed_at = ?, metrics_json = ?, p_value = ?
                WHERE slot_id = ?
                """,
                (time.time(), json.dumps(metrics, sort_keys=True), p_value, slot_id),
            )

    def compute_holm_bonferroni(self, family_id: str) -> Dict[str, Any]:
        """Calculates Holm-Bonferroni adjusted alpha thresholds for all completed slots in family."""
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT family_alpha FROM comparison_families WHERE family_id = ?", (family_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Family {family_id} not found.")
            family_alpha = row[0]

            cur.execute(
                """
                SELECT slot_id, candidate_id, p_value
                FROM evaluation_slots
                WHERE family_id = ? AND status = 'COMPLETED' AND p_value IS NOT NULL
                ORDER BY p_value ASC
                """,
                (family_id,),
            )
            rows = cur.fetchall()

        m = len(rows)
        if m == 0:
            return {"family_id": family_id, "m": 0, "results": []}

        results = []
        rejected = True
        for i, (slot_id, cand_id, p_val) in enumerate(rows):
            # Holm-Bonferroni threshold: alpha / (m - i)
            threshold = family_alpha / (m - i)
            is_significant = (p_val <= threshold) and rejected
            if not is_significant:
                rejected = False  # Step-down stops on first failure
            results.append(
                {
                    "slot_id": slot_id,
                    "candidate_id": cand_id,
                    "p_value": p_val,
                    "threshold": threshold,
                    "statistically_significant": is_significant,
                }
            )

        return {
            "family_id": family_id,
            "m": m,
            "family_alpha": family_alpha,
            "bonferroni_single_alpha": family_alpha / m,
            "results": results,
        }


@dataclass
class LineageCandidate:
    candidate_id: str
    canonical_repo: str
    canonical_upstream: str
    release_or_commit: str
    capability_family: str
    license_spdx: str
    is_fork_or_mirror: bool
    relevance_gap: float  # 0..40
    relevance_fit: float  # 0..30
    relevance_impact: float  # 0..20
    relevance_modularity: float  # 0..10
    readiness_compatibility: float  # 0..30
    readiness_maturity: float  # 0..20
    readiness_low_friction: float  # 0..20
    readiness_proven_gain: float  # 0..20
    readiness_reversibility: float  # 0..10

    @property
    def relevance_score(self) -> float:
        return (
            self.relevance_gap
            + self.relevance_fit
            + self.relevance_impact
            + self.relevance_modularity
        )

    @property
    def readiness_score(self) -> float:
        return (
            self.readiness_compatibility
            + self.readiness_maturity
            + self.readiness_low_friction
            + self.readiness_proven_gain
            + self.readiness_reversibility
        )


class Discovery100LineageEngine:
    """Discovery-100 Pipeline: RAW -> CANONICAL -> LINEAGE_DEDUP -> PREVIEWED -> DEEP_REVIEWED -> STAGED -> VALIDATED.

    Rejects mirrors/forks/wrappers as separate lineages.
    """

    def __init__(self, max_lineages: int = 100) -> None:
        self.max_lineages = max_lineages
        self._lineages_by_upstream: Dict[str, LineageCandidate] = {}
        self._discarded_reservoir: List[LineageCandidate] = []

    def ingest_candidate(self, cand: LineageCandidate) -> Dict[str, Any]:
        """Tries to admit candidate into the lineage frontier."""
        # 1. Deduplication check: same upstream?
        upstream_key = cand.canonical_upstream.strip().lower()
        if upstream_key in self._lineages_by_upstream:
            existing = self._lineages_by_upstream[upstream_key]
            # Must demonstrably elevate Pareto frontier (relevance * readiness)
            existing_frontier = existing.relevance_score * existing.readiness_score
            new_frontier = cand.relevance_score * cand.readiness_score
            if new_frontier <= existing_frontier:
                self._discarded_reservoir.append(cand)
                return {
                    "admitted": False,
                    "reason": f"DEDUPLICATED: Upstream '{upstream_key}' already represented by '{existing.candidate_id}' with equal/higher Pareto frontier ({existing_frontier:.1f} >= {new_frontier:.1f})",
                }
            # Replaces with superior candidate of same lineage
            self._lineages_by_upstream[upstream_key] = cand
            return {
                "admitted": True,
                "reason": f"UPGRADED: Replaced '{existing.candidate_id}' in upstream '{upstream_key}' (Pareto frontier elevated: {existing_frontier:.1f} -> {new_frontier:.1f})",
                "priority_review": cand.relevance_score >= 80.0,
            }

        if len(self._lineages_by_upstream) >= self.max_lineages:
            self._discarded_reservoir.append(cand)
            return {"admitted": False, "reason": f"BUDGET_SATURATED: Max {self.max_lineages} distinct lineages reached."}

        self._lineages_by_upstream[upstream_key] = cand
        return {
            "admitted": True,
            "reason": "ADMITTED: Distinct canonical lineage established.",
            "priority_review": cand.relevance_score >= 80.0,
        }

    def sample_discarded_false_negative_rate(self, ground_truth_useful: Set[str]) -> float:
        """Estimates false negative rate by sampling the discarded reservoir."""
        if not self._discarded_reservoir:
            return 0.0
        false_negatives = sum(1 for c in self._discarded_reservoir if c.candidate_id in ground_truth_useful)
        return false_negatives / len(self._discarded_reservoir)

    @property
    def active_lineage_count(self) -> int:
        return len(self._lineages_by_upstream)


@dataclass
class ClusterRolloutMetrics:
    cluster_id: str
    rollout_index: int
    quality_q: float
    critical_failures_f: int
    cost_usd: float
    latency_ms: float
    coordination_k: int
    prompt_tokens_p: int


class ClusterAwareRolloutManager:
    """Manages repeated rollouts and aggregates metrics at the cluster level to avoid pseudoreplication."""

    def __init__(self) -> None:
        self.rollouts: List[ClusterRolloutMetrics] = []

    def record_rollout(self, metrics: ClusterRolloutMetrics) -> None:
        self.rollouts.append(metrics)

    def aggregate_cluster_level(self) -> Dict[str, Any]:
        """Calculates true independent cluster-level means."""
        if not self.rollouts:
            return {
                "total_rollouts": 0,
                "cluster_count": 0,
                "mean_q": 0.0,
                "total_f": 0,
                "mean_cost": 0.0,
                "mean_latency": 0.0,
                "total_k": 0,
                "mean_p": 0.0,
            }

        by_cluster: Dict[str, List[ClusterRolloutMetrics]] = {}
        for r in self.rollouts:
            by_cluster.setdefault(r.cluster_id, []).append(r)

        cluster_q_means = []
        cluster_cost_means = []
        cluster_lat_means = []
        cluster_p_means = []
        total_f = 0
        total_k = 0

        for cid, items in by_cluster.items():
            cluster_q_means.append(sum(x.quality_q for x in items) / len(items))
            cluster_cost_means.append(sum(x.cost_usd for x in items) / len(items))
            cluster_lat_means.append(sum(x.latency_ms for x in items) / len(items))
            cluster_p_means.append(sum(x.prompt_tokens_p for x in items) / len(items))
            total_f += sum(x.critical_failures_f for x in items)
            total_k += sum(x.coordination_k for x in items)

        num_clusters = len(by_cluster)
        return {
            "total_rollouts": len(self.rollouts),
            "cluster_count": num_clusters,
            "mean_q": sum(cluster_q_means) / num_clusters,
            "total_f": total_f,
            "mean_cost": sum(cluster_cost_means) / num_clusters,
            "mean_latency": sum(cluster_lat_means) / num_clusters,
            "total_k": total_k,
            "mean_p": sum(cluster_p_means) / num_clusters,
        }


class AntiGoodhartPromoter:
    """Multi-objective Pareto evaluation preventing Goodhart's law regressions."""

    def __init__(
        self,
        *,
        epsilon_q: float = 0.02,
        min_quality_gain: float = 0.05,
        min_resource_gain: float = 0.10,
        max_resource_regression: float = 0.25,
    ) -> None:
        self.epsilon_q = epsilon_q
        self.min_quality_gain = min_quality_gain
        self.min_resource_gain = min_resource_gain
        self.max_resource_regression = max_resource_regression

    def evaluate_promotion(
        self,
        baseline: Dict[str, float],
        candidate: Dict[str, float],
        gates_passed: bool,
    ) -> Dict[str, Any]:
        """Evaluates whether candidate strictly earns promotion over baseline."""
        # 1. Gates are eliminatory
        if not gates_passed:
            return {
                "verdict": PromotionVerdict.REJECTED,
                "reason": "ELIMINATORY_GATE_FAILURE: One or more required gates failed.",
            }

        # 2. Critical failures cannot increase
        f_base = baseline.get("total_f", 0)
        f_cand = candidate.get("total_f", 0)
        if f_cand > f_base:
            return {
                "verdict": PromotionVerdict.REJECTED,
                "reason": f"SAFETY_REGRESSION: Critical failures increased ({f_cand} > {f_base}).",
            }

        q_base = baseline["mean_q"]
        q_cand = candidate["mean_q"]
        c_base = baseline.get("mean_cost", 1.0)
        c_cand = candidate.get("mean_cost", 1.0)
        l_base = baseline.get("mean_latency", 1.0)
        l_cand = candidate.get("mean_latency", 1.0)

        cost_ratio = (c_cand - c_base) / max(0.0001, c_base)
        lat_ratio = (l_cand - l_base) / max(0.0001, l_base)

        # 3. Candidate is more expensive or slower
        if cost_ratio > 0.0 or lat_ratio > 0.0:
            quality_delta = q_cand - q_base
            if quality_delta < self.min_quality_gain:
                return {
                    "verdict": PromotionVerdict.REJECTED,
                    "reason": f"INSUFFICIENT_QUALITY_GAIN: Quality delta ({quality_delta:.4f}) is below minimum required ({self.min_quality_gain}) for a more expensive/slower candidate.",
                }
            if cost_ratio > self.max_resource_regression or lat_ratio > self.max_resource_regression:
                return {
                    "verdict": PromotionVerdict.RESOURCE_TRADEOFF_REVIEW,
                    "reason": f"RESOURCE_TRADEOFF_REVIEW: High quality gain (+{quality_delta:.4f}) but resource regression exceeds threshold (Cost +{cost_ratio*100:.1f}%, Lat +{lat_ratio*100:.1f}%). Requires explicit signoff.",
                }
            return {
                "verdict": PromotionVerdict.PROMOTED,
                "reason": f"PROMOTED: Significant quality improvement (+{quality_delta:.4f}) with acceptable resource overhead.",
            }

        # 4. Candidate is cheaper / faster (resource reduction variant)
        # Must be non-inferior within epsilon_q
        if q_cand < (q_base - self.epsilon_q):
            return {
                "verdict": PromotionVerdict.REJECTED,
                "reason": f"QUALITY_EROSION: Cheaper candidate violates non-inferiority margin (Q_cand {q_cand:.4f} < Q_base - eps {q_base - self.epsilon_q:.4f}).",
            }

        resource_gain = max(-cost_ratio, -lat_ratio)
        if resource_gain < self.min_resource_gain and (q_cand - q_base) <= 0:
            return {
                "verdict": PromotionVerdict.REJECTED,
                "reason": f"TRIVIAL_VARIATION: Candidate offers neither sufficient resource reduction ({resource_gain*100:.1f}% < {self.min_resource_gain*100:.1f}%) nor quality gain.",
            }

        return {
            "verdict": PromotionVerdict.PROMOTED,
            "reason": f"PROMOTED: Non-inferior candidate with demonstrable resource savings (Cost {cost_ratio*100:.1f}%, Lat {lat_ratio*100:.1f}%).",
        }


class BenchmarkSanityOracle:
    """Enforces that known-good passes and injected mutants fail; otherwise raises InvalidEvalError."""

    @staticmethod
    def verify_benchmark(
        runner_fn: Any,
        known_good_impl: Any,
        known_mutants: List[Any],
    ) -> Dict[str, Any]:
        # Test known-good
        good_pass = runner_fn(known_good_impl)
        if not good_pass:
            raise InvalidEvalError("INVALID_EVAL: Known-good implementation failed benchmark. Eval is broken.")

        # Test mutants
        mutant_failures = 0
        for i, mutant in enumerate(known_mutants):
            mutant_pass = runner_fn(mutant)
            if not mutant_pass:
                mutant_failures += 1
            else:
                raise InvalidEvalError(
                    f"INVALID_EVAL: Mutant #{i} passed benchmark! Eval harness is insensitive/blind to bugs."
                )

        return {
            "sanity_valid": True,
            "known_good_passed": True,
            "mutants_rejected_count": mutant_failures,
        }


class AGIASIDivergenceEngine:
    """Synthesizes AGI-Pragmatic vs ASI-Systemic perspectives, producing empirical falsification experiments."""

    @staticmethod
    def analyze_change(
        change_description: str,
        pragmatic_thesis: str,
        systemic_thesis: str,
    ) -> Dict[str, Any]:
        # Formulate explicit falsification experiment
        experiment_id = f"EXP_{hashlib.sha256(change_description.encode('utf-8')).hexdigest()[:8]}"
        return {
            "experiment_id": experiment_id,
            "change": change_description,
            "lenses": {
                "AGI_PRAGMATIC": {
                    "focus": "Immediate simplicity, testability, reversibility, local gain",
                    "thesis": pragmatic_thesis,
                },
                "ASI_SYSTEMIC": {
                    "focus": "Second/third-order effects, scaling limits, nonlinear risk, dependency trap",
                    "thesis": systemic_thesis,
                },
            },
            "empirical_experiment": {
                "null_hypothesis": "The change adds cognitive complexity without improving Pareto frontier in production.",
                "falsification_metric": "Holdout Q delta >= 0.05 AND Latency degradation <= 15%",
                "rollback_trigger": "Any critical failure or regression in cold recovery time.",
            },
        }
