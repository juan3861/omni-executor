"""Empirical Verification Suite for MASTER PROMPT ALPHA-C13 — STATEFUL-SELECTION.

Tests:
  1. AcceptanceContract Gate Immutability (REQUIRED cannot be N/A, UNKNOWN is never PASS)
  2. StatefulSelectionLedger Non-Replayable Slots, Crash Integrity, Finite-Only Sanitization & Holm-Bonferroni
  3. Discovery100 Lineage Deduplication & Upstream Pareto Frontier
  4. ClusterAwareRolloutManager True Cluster-Level Mean Aggregation (Anti-Pseudoreplication)
  5. AntiGoodhartPromoter Multi-Objective Pareto Frontier, Safety Floor & Resource Regression Review
  6. BenchmarkSanityOracle Known-Good vs Mutant Sensitivity (Rejection of Blind Evals)
  7. AGIASIDivergenceEngine Dialectical Synthesis & Falsification Experiment Generation
"""

import math
import tempfile
from pathlib import Path
import sys

# Ensure src is in sys.path
root = Path(__file__).resolve().parents[1]
src = root / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from am_ua.governance.alpha_c13 import (
    AcceptanceContract,
    GateSpec,
    GateRequirement,
    GateStatus,
    PromotionVerdict,
    ContractIntegrityError,
    InvalidEvalError,
    SelectionBudgetExhaustedError,
    StatefulSelectionLedger,
    LineageCandidate,
    Discovery100LineageEngine,
    ClusterRolloutMetrics,
    ClusterAwareRolloutManager,
    AntiGoodhartPromoter,
    BenchmarkSanityOracle,
    AGIASIDivergenceEngine,
)


def run_all_tests() -> bool:
    print("[ALPHA-C13 TEST SUITE] Starting Hostile Empirical Verification...")

    # 1. Acceptance Contract Immutability
    print("  -> Testing AcceptanceContract Gate Immutability...")
    contract = AcceptanceContract(
        contract_id="alpha-c13-gov-v1",
        version="1.0.0",
        requirements={"R01": "Deterministic Selection", "R02": "Zero Winner Curse"},
        invariants=["No NaN/Inf", "Crash never refunds slot", "REQUIRED cannot be N/A"],
        non_functional_goals={"latency_overhead_ms": 5.0},
        prohibited_operations=["silent_fallback", "mutant_bypass"],
        budget_tokens=10000,
        budget_time_s=60.0,
        rollback_plan="Revert to previous git commit & purge uncommitted ledger slot",
        gates={
            "G1_SAFETY": GateSpec("G1_SAFETY", GateRequirement.REQUIRED, "Zero security regressions"),
            "G2_BENCH": GateSpec("G2_BENCH", GateRequirement.REQUIRED, "Sanity oracle verified"),
            "G3_OPT": GateSpec("G3_OPT", GateRequirement.OPTIONAL, "Optional micro-optimization"),
        },
        rubric_weights={"Q": 0.5, "C": 0.2, "L": 0.2, "K": 0.1},
    )
    assert len(contract.sha256_hash) == 64, "Contract sha256 hash invalid"

    # Attempt to set REQUIRED gate to NOT_APPLICABLE -> must raise ContractIntegrityError
    try:
        contract.validate_gate_assignment("G1_SAFETY", GateStatus.NOT_APPLICABLE)
        assert False, "FAILED: Setting REQUIRED gate to NOT_APPLICABLE should have raised ContractIntegrityError"
    except ContractIntegrityError:
        pass

    # Attempt to set REQUIRED gate to UNKNOWN -> must raise ContractIntegrityError
    try:
        contract.validate_gate_assignment("G1_SAFETY", GateStatus.UNKNOWN)
        assert False, "FAILED: Setting REQUIRED gate to UNKNOWN should have raised ContractIntegrityError"
    except ContractIntegrityError:
        pass

    # Valid PASS
    assert contract.validate_gate_assignment("G1_SAFETY", GateStatus.PASS) == GateStatus.PASS
    print("     [OK] Gate immutability and contract hash integrity verified.")

    # 2. StatefulSelectionLedger & Holm-Bonferroni
    print("  -> Testing StatefulSelectionLedger (Atomic Slots, Crash-Resilience, Sanitization)...")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        ledger_db = Path(tmp_dir) / "test_ledger.db"
        ledger = StatefulSelectionLedger(ledger_db)
        family_id = "fam_optim_round_1"
        ledger.register_family(family_id, comparison_budget=3, family_alpha=0.05)

        # Allocate slot 1
        s1 = ledger.allocate_slot(family_id, "base_v1", "cand_v2a", "eval_hash_001")
        assert s1 == 1, f"Expected slot 1, got {s1}"

        # Crash simulation: candidate crashed without recording outcome!
        # Slot 2 allocated
        s2 = ledger.allocate_slot(family_id, "base_v1", "cand_v2b", "eval_hash_001")
        assert s2 == 2

        # Record outcome for s2
        ledger.record_outcome(s2, {"accuracy": 0.92, "cost": 0.04}, p_value=0.012)

        # Allocate slot 3 (reaches budget)
        s3 = ledger.allocate_slot(family_id, "base_v1", "cand_v2c", "eval_hash_001")
        assert s3 == 3
        ledger.record_outcome(s3, {"accuracy": 0.94, "cost": 0.05}, p_value=0.045)

        # Slot 4 must fail with SelectionBudgetExhaustedError
        try:
            ledger.allocate_slot(family_id, "base_v1", "cand_v2d", "eval_hash_001")
            assert False, "FAILED: Selection budget was exceeded without raising SelectionBudgetExhaustedError"
        except SelectionBudgetExhaustedError:
            pass

        # Metric sanitization: NaN/Inf rejection
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir2:
            l2 = StatefulSelectionLedger(Path(tmp_dir2) / "sanitization.db")
            l2.register_family("fam_test", comparison_budget=5)
            s_test = l2.allocate_slot("fam_test", "b", "c", "h")
            try:
                l2.record_outcome(s_test, {"invalid_metric": float("nan")})
                assert False, "FAILED: NaN metric was accepted into ledger!"
            except ValueError:
                pass

            try:
                l2.record_outcome(s_test, {"invalid_metric": "True"})
                assert False, "FAILED: String boolean 'True' was accepted into ledger!"
            except ValueError:
                pass

        # Check Holm-Bonferroni adjustment
        holm = ledger.compute_holm_bonferroni(family_id)
        assert holm["m"] == 2, f"Expected 2 completed comparisons, got {holm['m']}"
        # Ranked p-values: 0.012, 0.045. Thresholds: 0.05 / 2 = 0.025, 0.05 / 1 = 0.05
        # 0.012 <= 0.025 -> Significant. 0.045 <= 0.05 -> Significant.
        res0 = holm["results"][0]
        assert res0["statistically_significant"] is True
    print("     [OK] Stateful selection ledger, crash preservation and Holm-Bonferroni verified.")

    # 3. Discovery100 Lineage Deduplication
    print("  -> Testing Discovery100 Lineage Engine (Fork/Mirror Dedup)...")
    engine = Discovery100LineageEngine(max_lineages=5)

    c1 = LineageCandidate(
        candidate_id="c1_upstream_repo",
        canonical_repo="https://github.com/astral-sh/uv",
        canonical_upstream="astral-sh/uv",
        release_or_commit="v0.4.0",
        capability_family="package_management",
        license_spdx="MIT",
        is_fork_or_mirror=False,
        relevance_gap=35.0,
        relevance_fit=28.0,
        relevance_impact=18.0,
        relevance_modularity=9.0,  # Relevance: 90.0 (Priority review >=80)
        readiness_compatibility=28.0,
        readiness_maturity=19.0,
        readiness_low_friction=19.0,
        readiness_proven_gain=18.0,
        readiness_reversibility=9.0,  # Readiness: 93.0
    )
    res_c1 = engine.ingest_candidate(c1)
    assert res_c1["admitted"] is True
    assert res_c1["priority_review"] is True

    # Ingest a fork/mirror of the exact same upstream with equal or worse scores
    c2_mirror = LineageCandidate(
        candidate_id="c2_forked_repo",
        canonical_repo="https://github.com/random_fork/uv",
        canonical_upstream="astral-sh/uv",  # Same canonical upstream
        release_or_commit="v0.3.9",
        capability_family="package_management",
        license_spdx="MIT",
        is_fork_or_mirror=True,
        relevance_gap=20.0,
        relevance_fit=15.0,
        relevance_impact=10.0,
        relevance_modularity=5.0,
        readiness_compatibility=15.0,
        readiness_maturity=10.0,
        readiness_low_friction=10.0,
        readiness_proven_gain=10.0,
        readiness_reversibility=5.0,
    )
    res_c2 = engine.ingest_candidate(c2_mirror)
    assert res_c2["admitted"] is False, "FAILED: Fork/mirror of existing upstream was falsely admitted as new lineage!"
    assert "DEDUPLICATED" in res_c2["reason"]

    # Verify false negative rate estimation
    fn_rate = engine.sample_discarded_false_negative_rate(ground_truth_useful={"c2_forked_repo"})
    assert fn_rate == 1.0
    print("     [OK] Discovery-100 lineage deduplication and upstream frontier verified.")

    # 4. Cluster-Aware Rollout Manager
    print("  -> Testing ClusterAwareRolloutManager (Anti-Pseudoreplication)...")
    cluster_mgr = ClusterAwareRolloutManager()
    # Cluster A: 3 rollouts
    cluster_mgr.record_rollout(ClusterRolloutMetrics("cluster_web_scraping", 0, 0.90, 0, 0.02, 120.0, 1, 400))
    cluster_mgr.record_rollout(ClusterRolloutMetrics("cluster_web_scraping", 1, 0.92, 0, 0.02, 130.0, 1, 420))
    cluster_mgr.record_rollout(ClusterRolloutMetrics("cluster_web_scraping", 2, 0.88, 0, 0.02, 110.0, 1, 380))

    # Cluster B: 2 rollouts
    cluster_mgr.record_rollout(ClusterRolloutMetrics("cluster_code_refactor", 0, 0.96, 0, 0.05, 200.0, 2, 800))
    cluster_mgr.record_rollout(ClusterRolloutMetrics("cluster_code_refactor", 1, 0.94, 0, 0.05, 210.0, 2, 820))

    agg = cluster_mgr.aggregate_cluster_level()
    assert agg["total_rollouts"] == 5
    assert agg["cluster_count"] == 2
    # Mean Q of Cluster A = 0.90, Mean Q of Cluster B = 0.95 -> Cluster-level mean = 0.925
    assert abs(agg["mean_q"] - 0.925) < 1e-4, f"Cluster-level mean failed: {agg['mean_q']}"
    print("     [OK] Cluster-level aggregation cleanly prevents pseudoreplication.")

    # 5. AntiGoodhartPromoter Multi-Objective
    print("  -> Testing AntiGoodhartPromoter (Pareto Frontier, Margins, Gate Floors)...")
    promoter = AntiGoodhartPromoter(
        epsilon_q=0.02,
        min_quality_gain=0.05,
        min_resource_gain=0.10,
        max_resource_regression=0.25,
    )

    base = {"mean_q": 0.80, "mean_cost": 0.10, "mean_latency": 100.0, "total_f": 0}

    # Case A: Gate failure -> REJECTED
    res_a = promoter.evaluate_promotion(base, {"mean_q": 0.95, "mean_cost": 0.10, "mean_latency": 100.0, "total_f": 0}, gates_passed=False)
    assert res_a["verdict"] == PromotionVerdict.REJECTED

    # Case B: Critical failure increased -> REJECTED
    res_b = promoter.evaluate_promotion(base, {"mean_q": 0.95, "mean_cost": 0.10, "mean_latency": 100.0, "total_f": 1}, gates_passed=True)
    assert res_b["verdict"] == PromotionVerdict.REJECTED
    assert "SAFETY_REGRESSION" in res_b["reason"]

    # Case C: Candidate more expensive (+20% cost) but quality gain is tiny (+0.02 < 0.05) -> REJECTED
    res_c = promoter.evaluate_promotion(base, {"mean_q": 0.82, "mean_cost": 0.12, "mean_latency": 100.0, "total_f": 0}, gates_passed=True)
    assert res_c["verdict"] == PromotionVerdict.REJECTED
    assert "INSUFFICIENT_QUALITY_GAIN" in res_c["reason"]

    # Case D: Candidate more expensive (+20% cost) with strong quality gain (+0.08) within resource tolerance -> PROMOTED
    res_d = promoter.evaluate_promotion(base, {"mean_q": 0.88, "mean_cost": 0.12, "mean_latency": 100.0, "total_f": 0}, gates_passed=True)
    assert res_d["verdict"] == PromotionVerdict.PROMOTED

    # Case E: Candidate with huge quality gain (+0.15) but massive latency regression (+60% > 25%) -> RESOURCE_TRADEOFF_REVIEW
    res_e = promoter.evaluate_promotion(base, {"mean_q": 0.95, "mean_cost": 0.10, "mean_latency": 160.0, "total_f": 0}, gates_passed=True)
    assert res_e["verdict"] == PromotionVerdict.RESOURCE_TRADEOFF_REVIEW

    # Case F: Cheaper candidate (-30% cost) with quality preserved within epsilon_q (0.79 >= 0.80 - 0.02) -> PROMOTED
    res_f = promoter.evaluate_promotion(base, {"mean_q": 0.79, "mean_cost": 0.07, "mean_latency": 90.0, "total_f": 0}, gates_passed=True)
    assert res_f["verdict"] == PromotionVerdict.PROMOTED
    print("     [OK] Anti-Goodhart promotion gates successfully protect quality, safety, and resources.")

    # 6. BenchmarkSanityOracle
    print("  -> Testing BenchmarkSanityOracle (Known-Good vs Mutants)...")
    def benchmark_eval(impl):
        # Target: function must compute x * 2 + 1
        test_inputs = [(1, 3), (2, 5), (5, 11), (-1, -1)]
        return all(impl(x) == expected for x, expected in test_inputs)

    good_impl = lambda x: x * 2 + 1
    mutant_1 = lambda x: x * 2      # Missing + 1
    mutant_2 = lambda x: x * 2 - 1  # Inverted sign

    sanity = BenchmarkSanityOracle.verify_benchmark(benchmark_eval, good_impl, [mutant_1, mutant_2])
    assert sanity["sanity_valid"] is True
    assert sanity["mutants_rejected_count"] == 2

    # Test broken benchmark that always returns True (blind eval)
    blind_eval = lambda impl: True
    try:
        BenchmarkSanityOracle.verify_benchmark(blind_eval, good_impl, [mutant_1])
        assert False, "FAILED: Blind benchmark that accepts mutants was not caught!"
    except InvalidEvalError:
        pass
    print("     [OK] Benchmark sanity oracle successfully refutes blind evaluation harnesses.")

    # 7. AGI/ASI Divergence
    print("  -> Testing AGIASIDivergenceEngine...")
    analysis = AGIASIDivergenceEngine.analyze_change(
        change_description="Integrate persistent SQLite WAL ledger for multi-turn state",
        pragmatic_thesis="Immediate crash recovery and zero memory loss across CLI executions.",
        systemic_thesis="Risk of schema drift, SQLite disk locks under concurrent threads, and I/O footprint.",
    )
    assert analysis["empirical_experiment"]["falsification_metric"] is not None
    assert "EXP_" in analysis["experiment_id"]
    print("     [OK] AGI/ASI divergence synthesis produces actionable falsification experiment.")

    print("\n[VERIFICATION COMPLETE] All 7 chambers of MASTER PROMPT ALPHA-C13 PASSED with 100% adherence to invariants.")
    return True


if __name__ == "__main__":
    success = run_all_tests()
    if not success:
        sys.exit(1)
    sys.exit(0)
