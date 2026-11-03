"""Phase 1 Verification Tests — Contracts, Calibration, DPAPI & Durable Engine."""

from __future__ import annotations

from pathlib import Path
import pytest

from am_ua.contracts import (
    CalibrationLedger,
    CognitiveEnvelope,
    EpistemicTag,
    HypothesisRecord,
    MissionContract,
    ProblemFramingError,
    ProblemFramingGate,
    TrustLevel,
    WorkforcePlan,
)
from am_ua.execution import (
    DurableExecutionEngine,
    EffectClass,
    FairDispatchScheduler,
    LastMileSecurityError,
    OutcomeUnknownError,
    ReconcileObservation,
    StaleLeaseFenceError,
    StepStatus,
    ToolContract,
)
from am_ua.security import (
    AuthenticatedEnvelopeManager,
    EnvelopeTamperedError,
    ReplayAttackError,
    WindowsDPAPIProvider,
)


def test_p1_1_problem_framing_contradictions_and_hypotheses() -> None:
    gate = ProblemFramingGate()
    bad_mission = MissionContract(
        mission_id="m_bad",
        objective="Deploy live API client",
        domain="backend",
        functional_requirements=["Call cloud endpoint"],
        allow_network=False,
        constraints={"require_live_external_api": True},
    )
    verdict = gate.evaluate(bad_mission)
    assert verdict.approved_for_execution is False
    assert verdict.counter_proposal is not None
    assert any("allow_network=False" in c for c in verdict.contradictions)

    # Disjoint write-scope check (/dag-ulw law)
    bad_plan = WorkforcePlan(
        mission_id="m1",
        lanes=[{"id": "l1"}, {"id": "l2"}],
        write_scopes={"l1": ["src/core.py"], "l2": ["src/core.py"]},
        verification_lane_id="verify_1",
    )
    with pytest.raises(ProblemFramingError, match="Write-scope collision"):
        gate.validate_workforce_disjoint_scopes(bad_plan)

    # R04 Hypothesis requires pre-registered falsification criterion
    with pytest.raises(ValueError, match="R04"):
        HypothesisRecord(
            hypothesis_id="h0",
            statement="Cache fixes latency",
            predicted_observation="p99 < 10ms",
            falsification_criterion="",
            experiment_command="pytest",
        )
    hyp = HypothesisRecord(
        hypothesis_id="h1",
        statement="Pool size 8 eliminates timeout",
        predicted_observation="0 timeouts in 100 reqs",
        falsification_criterion=">= 1 timeout in 100 reqs",
        experiment_command="pytest -k pool",
    )
    assert hyp.evaluate_outcome(observed_output="3 timeouts", falsified=True) == "FALSIFIED"


def test_p1_2_calibration_ledger_penalizes_overconfidence(tmp_path: Path) -> None:
    ledger = CalibrationLedger(tmp_path / "cal.db")
    for i in range(5):
        ledger.record(domain="sql_migration", task_id=f"t{i}", predicted_conf=0.95, actual_pass=False)
    stats = ledger.domain_stats("sql_migration")
    assert stats.autonomy_tier == "REQUIRE_DOUBLE_CHECK"
    adj = ledger.calibrated_confidence("sql_migration", 0.95)
    assert adj["calibrated_confidence"] < 0.60


def test_p1_3_windows_dpapi_and_replay_protection(tmp_path: Path) -> None:
    secret = b"super-secret-cognitive-token-2026"
    ct = WindowsDPAPIProvider.protect(secret)
    assert ct != secret
    assert WindowsDPAPIProvider.unprotect(ct) == secret

    mgr = AuthenticatedEnvelopeManager(
        key_file=tmp_path / "master.bin",
        nonce_db_path=tmp_path / "nonces.db",
    )
    env = CognitiveEnvelope(
        source="planner",
        target="executor",
        task_id="task_42",
        payload={"cmd": "build"},
        confidence=0.92,
        epistemic_tag=EpistemicTag.PROVADO,
    )
    packet = mgr.sign(env)
    recovered = mgr.verify_and_consume(packet)
    assert recovered.event_id == env.event_id

    # Replaying identical packet must fail closed!
    with pytest.raises(ReplayAttackError):
        mgr.verify_and_consume(packet)

    # Tampering payload invalidates HMAC
    tampered = mgr.sign(env)
    tampered["envelope"]["payload"]["cmd"] = "rm -rf"
    with pytest.raises(EnvelopeTamperedError):
        mgr.verify_and_consume(tampered)


def test_p1_4_durable_engine_outcome_unknown_fencing_and_last_mile_sieve(tmp_path: Path) -> None:
    # 1. FairDispatchScheduler prevents starvation
    sched = FairDispatchScheduler(aging_interval=2)
    sched.observe(["low_task", "high_task"])
    sched.advance(10)  # low_task gains +5 boost
    sel = sched.select([{"task_id": "low_task", "priority": 1}, {"task_id": "new_task", "priority": 4}])
    assert sel["selected"] == ["low_task"]

    # 2. Durable engine + R08 OUTCOME_UNKNOWN reconciliation without duplicate write
    engine = DurableExecutionEngine(tmp_path / "durable.db")
    target_file = Path(r"F:\AetherMind_Temp\r08_reconcile_proof.txt")
    target_file.unlink(missing_ok=True)
    call_count = {"n": 0}

    def flaky_writer(args: dict) -> dict:
        call_count["n"] += 1
        Path(args["file"]).write_text("COMMITTED_ONCE", encoding="utf-8")
        # Simulate network/IPC timeout AFTER side effect already happened!
        raise TimeoutError("Confirmation lost over IPC")

    def reconcile_writer(args: dict) -> ReconcileObservation:
        p = Path(args["file"])
        if p.is_file() and p.read_text(encoding="utf-8") == "COMMITTED_ONCE":
            return ReconcileObservation(True, {"written": True}, "File verified on disk")
        return ReconcileObservation(False, None, "File absent")

    engine.register_tool(
        ToolContract(
            name="write_invoice",
            effect_class=EffectClass.COMPENSATABLE_MUTATION,
            execute_fn=flaky_writer,
            required_args={"file"},
            reconcile_fn=reconcile_writer,
        )
    )

    epoch1 = engine.fencer.acquire_lease("run_r08", "worker_A")
    with pytest.raises(OutcomeUnknownError):
        engine.execute_step(
            run_id="run_r08",
            step_id="s1",
            step_index=0,
            tool_name="write_invoice",
            args={"file": str(target_file)},
            state={},
            lease_epoch=epoch1,
        )

    # Blind retry MUST be blocked!
    with pytest.raises(OutcomeUnknownError, match="Call reconcile_step"):
        engine.execute_step(
            run_id="run_r08",
            step_id="s1",
            step_index=0,
            tool_name="write_invoice",
            args={"file": str(target_file)},
            state={},
            lease_epoch=epoch1,
        )
    assert call_count["n"] == 1

    # Reconcile discovers side effect succeeded -> marks COMPLETED with 0 extra executions!
    rec_cp = engine.reconcile_step("run_r08", "s1", lease_epoch=epoch1)
    assert rec_cp["status"] == StepStatus.COMPLETED.value
    assert call_count["n"] == 1
    target_file.unlink(missing_ok=True)

    # 3. Zombie worker with old epoch is blocked by FencedEffectWriter
    epoch2 = engine.fencer.acquire_lease("run_r08", "worker_B")
    assert epoch2 == epoch1 + 1
    with pytest.raises(StaleLeaseFenceError):
        engine.fencer.assert_fence_valid("run_r08", epoch1)

    # 4. Last-Mile Security Gate blocks UNTRUSTED_DATA & invalid URE CFG expressions
    tainted_env = CognitiveEnvelope(
        source="web_scraper",
        target="executor",
        task_id="t_inj",
        payload={},
        trust_level=TrustLevel.UNTRUSTED_DATA,
    )
    with pytest.raises(LastMileSecurityError, match="R16 violation"):
        engine.execute_step(
            run_id="run_r08",
            step_id="s_taint",
            step_index=1,
            tool_name="write_invoice",
            args={"file": str(target_file)},
            state={},
            lease_epoch=epoch2,
            envelope=tainted_env,
        )

    with pytest.raises(LastMileSecurityError, match="CFGGrammarSieve"):
        engine.execute_step(
            run_id="run_r08",
            step_id="s_cfg",
            step_index=2,
            tool_name="write_invoice",
            args={
                "file": str(target_file),
                "formal_guard_expr": "__import__('os').system('calc')",
                "allowed_vars": ["x"],
            },
            state={},
            lease_epoch=epoch2,
        )
