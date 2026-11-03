"""Empirical Verification Suite for Phase 6.1 & 6.2: Kernel, OTel, Triggers, CLI & Cold-Team Handoff."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from am_ua import PROJECT_ROOT
from am_ua.agent_kernel import (
    AetherMindUniversalAgent,
    AutonomousTriggerScheduler,
    SplitBrainStateError,
    TelemetrySpanLedger,
)
from am_ua.contracts.contracts import HypothesisRecord, MissionContract
from am_ua.lifecycle import HandoffPackExporter


def test_p6_1_kernel_single_owner_otel_fastpath_and_triggers(tmp_path: Path) -> None:
    agent = AetherMindUniversalAgent(data_dir=tmp_path / "ua_data")

    # 1. Single-State-Owner guard blocks unauthorized mutators (Sonnet Anti-Split-Brain Law)
    with pytest.raises(SplitBrainStateError):
        agent.assert_single_state_owner("external_rogue_framework")

    # 2. Doctor health check
    doc = agent.doctor()
    assert doc["homeostasis_healthy"] is True
    assert doc["topology_v2_ok"] is True
    assert doc["codex_exe_available"] is True
    assert doc["omh_browser_seam_unlocked"] is True

    # 3. End-to-end mission execution + Fast-Path + Independent Judge + OTel Spans
    sample_dir = tmp_path / "sample_proj"
    sample_dir.mkdir()
    (sample_dir / "main.py").write_text("print('ok')\n", encoding="utf-8")

    hyp = HypothesisRecord(
        hypothesis_id="hyp_ucip_01",
        statement="UCIP scan succeeds on valid directory",
        predicted_observation="total_files == 1",
        falsification_criterion="total_files != 1 or exception raised",
        experiment_command="ucip_radar_scan",
    )
    mission = MissionContract(
        mission_id="m_verify_p6",
        objective="Scan sample directory via sovereign kernel",
        domain="software_engineering",
        functional_requirements=["Scan sample_proj"],
        acceptance_criteria=["Step completes and independent judge signs receipt"],
        max_tokens_budget=10_000,
    )
    res = agent.execute_mission(
        mission,
        steps=[
            {
                "step_id": "s0",
                "tool_name": "ucip_radar_scan",
                "args": {"target_dir": str(sample_dir), "invoke_binary": False},
            }
        ],
        hypothesis=hyp,
    )
    assert res["status"] == "VERIFIED"
    assert res["fast_path_used"] is True
    assert res["actor_route"] != res["judge_route"]
    spans = agent.telemetry.read_spans(trace_id=res["trace_id"])
    assert len(spans) >= 2

    # 4. Contradictory mission halted at R01 framing gate BEFORE execution
    bad_mission = MissionContract(
        mission_id="m_contradictory",
        objective="Call external live API offline",
        domain="software_engineering",
        functional_requirements=["Fetch remote API"],
        constraints={"require_live_external_api": True},
        allow_network=False,
    )
    halted = agent.execute_mission(bad_mission)
    assert halted["status"] == "HALTED_AT_FRAMING"

    # 5. AutonomousTriggerScheduler (Sonnet S5)
    sched = AutonomousTriggerScheduler(tmp_path / "triggers.db")
    fired_box: list[str] = []
    sched.register_handler("heartbeat_audit", lambda p: fired_box.append(p["tag"]) or "ALIVE")
    sched.schedule_recurring(
        "trig_01",
        "heartbeat_audit",
        interval_seconds=60.0,
        payload={"tag": "tick_ok"},
        start_immediately=True,
    )
    due_out = sched.tick()
    assert due_out[0]["status"] == "OK"
    assert fired_box == ["tick_ok"]


def test_p6_1_cli_shortcut_end_to_end_and_p6_2_handoff_pack(tmp_path: Path) -> None:
    cmd_path = Path(PROJECT_ROOT) / "aether-ua.cmd"
    assert cmd_path.is_file()

    proc = subprocess.run(
        ["cmd.exe", "/c", str(cmd_path), "doctor"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, f"aether-ua.cmd doctor failed: {proc.stdout}\n{proc.stderr}"
    parsed = json.loads(proc.stdout)
    assert parsed["topology_v2_ok"] is True

    # P6.2 Cold-Team Handoff Exporter (Astra R18)
    exporter = HandoffPackExporter(PROJECT_ROOT)
    out = exporter.export(tmp_path / "HANDOFF_TEST")
    for fpath in out["files"]:
        p = Path(fpath)
        assert p.is_file() and p.stat().st_size > 50
    assert len(out["receipt"]["artifacts_sha256"]) >= 8
