"""v5.4 Verification Suite: HyperFleet 1,000+ Agents In-Process, Zero-Copy <50 KB/agent, SingleFlight, Deterministic Offload & Generation Chaining."""

from __future__ import annotations

import json
from pathlib import Path


def test_v54_hyperfleet_1000_concurrent_agents_memory_and_cost_supremacy(tmp_path: Path) -> None:
    """Empirically verify 1,000 concurrent agents run in-process with <50 KB/agent (beating OpenHuman's 1.77 MiB) and $0.00 deterministic offload."""
    from am_ua.execution.subagent_bus import SubAgentSessionBus

    ws = tmp_path / "fleet_ws"
    ws.mkdir()
    (ws / "mod.py").write_text("def square(x: int) -> int:\n    return x * x\n", encoding="utf-8")

    bus = SubAgentSessionBus(db_path=tmp_path / "hyperfleet.db")

    # Mix 800 deterministic agents (syntax sweep / git forensics) + 200 S1 micro-workers
    tasks = []
    for i in range(1000):
        if i < 800:
            tasks.append({"id": f"ag-{i:04d}", "role": "worker", "objective": f"syntax check python files #{i % 20}"})
        else:
            tasks.append({"id": f"ag-{i:04d}", "role": "coder", "objective": f"micro synthesis variant {i % 25}"})

    res = bus.run_hyper_fleet(
        tasks,
        workspace=ws,
        max_concurrency=128,
        max_budget_usd=10.0,
        prefer_deterministic=True,
    )
    assert res["ok"] is True
    assert res["agents_executed"] == 1000
    assert res["completed_count"] == 1000
    assert res["deterministic_offloaded_count"] == 800
    assert res["coalesced_saved_calls"] >= 900  # 1,000 tasks collapsed to 45 unique executions via SingleFlight!
    assert res["kb_per_agent"] < 50.0  # >35x lighter than OpenHuman's 1,812 KB/agent!
    assert res["memory_efficiency_vs_openhuman_x"] > 35.0
    assert res["total_cost_usd"] < 0.05  # <5 cents total for 1,000 agents!


def test_v54_zero_erasure_generation_chaining_hard_budget_and_cli_fleet(tmp_path: Path, capsys) -> None:
    """Verify `begin_generation` parent->child SHA-256 chain, hard USD budget cutoff, and `cli fleet`."""
    from am_ua.cli import main as cli_main
    from am_ua.execution.subagent_bus import SubAgentSessionBus

    bus = SubAgentSessionBus(db_path=tmp_path / "gen.db")

    # 1. Zero-Erasure Generation Chaining (`begin_generation`)
    g1 = bus.begin_generation("sess-1", "Gen 1 summary head", archived_transcript="full turn 1..5 log")
    g2 = bus.begin_generation(
        "sess-1",
        "Gen 2 summary head",
        parent_generation_id=g1["generation_id"],
        archived_transcript="full turn 6..10 log",
    )
    chain = bus.get_generation_chain("sess-1")
    assert len(chain) == 2
    assert chain[1]["parent_generation_id"] == g1["generation_id"]
    assert len(chain[1]["sealed_sha256"]) == 64 and chain[0]["sealed_sha256"] != chain[1]["sealed_sha256"]

    # 2. Hard USD Budget Enforcer caps spend strictly at max_budget_usd
    expensive_tasks = [
        {"id": f"exp-{i}", "role": "architect", "objective": f"unique non-deterministic architectural query {i}"}
        for i in range(50)
    ]
    capped_res = bus.run_hyper_fleet(
        expensive_tasks,
        workspace=tmp_path,
        max_budget_usd=0.01,
        prefer_deterministic=False,
        llm_worker_fn=lambda slot: {"ok": True, "cost_usd": 0.004, "prompt_tokens": 1000, "completion_tokens": 500},
    )
    assert capped_res["ok"] is True
    assert capped_res["total_cost_usd"] <= 0.01
    assert capped_res["budget_capped_count"] >= 45

    # 3. CLI `fleet --count 600`
    rc = cli_main(["fleet", "--count", "600", "--max-usd", "10.0", "--workspace", str(tmp_path)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True and out["agents_executed"] == 600
