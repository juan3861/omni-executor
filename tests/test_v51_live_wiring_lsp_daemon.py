"""v5.1 Verification Suite: Live AgentLoop Wiring, Cross-Platform Temp, Persistent LSP & Durable Daemon Queue."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


class _StubLLM:
    """Deterministic stub LLM for testing live AgentLoop.run() wiring without external API calls."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.providers = []

    def chat(self, messages, **kwargs):
        idx = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        self.total_prompt_tokens += 50
        self.total_completion_tokens += 30
        return SimpleNamespace(
            text=self._responses[idx],
            provider="stub",
            model="stub-s1",
            prompt_tokens=50,
            completion_tokens=30,
            total_tokens=80,
        )


def test_v51_live_agent_loop_plan_mode_self_review_dlp_todo_events_and_skill_compile(tmp_path: Path) -> None:
    """Prove all v5.0 gears fire automatically inside live AgentLoop.run()."""
    from am_ua.execution.adaptive_skills import AdaptiveSkillForge
    from am_ua.execution.agent_loop import AgentLoop
    from am_ua.execution.durable_engine import DurableExecutionEngine
    from am_ua.governance.seal_guard import ConstitutionSealGuard

    ws = tmp_path / "live_ws"
    ws.mkdir()
    (ws / "app.py").write_text("def greet():\n    return 'hi'\n", encoding="utf-8")

    guard = ConstitutionSealGuard()
    guard.policy = dict(guard.policy)
    guard.policy["hardware_safety_locks"] = {**guard.policy.get("hardware_safety_locks", {}), "safe_temp_root": str(tmp_path)}

    # 1. PLAN mode physically blocks write_file inside live AgentLoop.run()
    plan_llm = _StubLLM([
        json.dumps({"thought": "try write in plan mode", "tool": "write_file", "args": {"file": "hack.py", "content": "x=1\n"}}),
        json.dumps({"thought": "blocked as expected", "tool": "finish", "args": {"summary": "Plan complete", "confidence": 0.9}}),
    ])
    eng_plan = DurableExecutionEngine(tmp_path / "plan.db")
    eng_plan.security_gate.seal_guard = guard
    loop_plan = AgentLoop(
        engine=eng_plan,
        seal_guard=guard,
        llm=plan_llm,
        trace_dir=tmp_path / "traces_plan",
    )
    res_plan = loop_plan.run(
        "Inspect app.py",
        ws,
        max_turns=4,
        use_judge=False,
        enable_zero_token_offload=False,
        execution_mode="plan",
    )
    assert not (ws / "hack.py").exists()
    assert any(tc["tool"] == "write_file" and tc["ok"] is False for tc in res_plan.tool_calls)

    # 2. ACT mode: Self-Review Diff Gate rejects broken syntax on finish -> agent fixes -> DLP redacts CPF -> todo + events + auto_compile_skill
    forge = AdaptiveSkillForge(skills_dir=tmp_path / "auto_skills")
    act_llm = _StubLLM([
        json.dumps({"thought": "write broken python", "tool": "write_file", "args": {"file": "calc.py", "content": "def add(a, b:\n    return a + b\n"}}),
        json.dumps({"thought": "try finish with broken syntax", "tool": "finish", "args": {"summary": "Done", "confidence": 0.8}}),
        json.dumps({"thought": "fix syntax error", "tool": "write_file", "args": {"file": "calc.py", "content": "def add(a, b):\n    return a + b\n"}}),
        json.dumps({"thought": "finish cleanly", "tool": "finish", "args": {"summary": "Fixed calc.py for user CPF 123.456.789-00", "confidence": 0.95}}),
    ])
    eng_act = DurableExecutionEngine(tmp_path / "act.db")
    eng_act.security_gate.seal_guard = guard
    loop_act = AgentLoop(
        engine=eng_act,
        seal_guard=guard,
        llm=act_llm,
        trace_dir=tmp_path / "traces_act",
        skill_forge=forge,
    )
    res_act = loop_act.run(
        "Implement add in calc.py",
        ws,
        mission_id="m_live_v51",
        max_turns=6,
        use_judge=False,
        enable_zero_token_offload=False,
        execution_mode="act",
        sync_todo_anchor=True,
        enable_self_review_gate=True,
        enable_dlp_supervisor=True,
        auto_compile_skill=True,
    )
    assert res_act.stop_reason == "finish"
    assert res_act.turns >= 3  # finish on turn 2 was rejected by Self-Review Diff Gate!
    assert "def add(a, b):" in (ws / "calc.py").read_text(encoding="utf-8")
    assert "123.456.789-00" not in res_act.final_summary
    assert "[REDACTED_BRAZILIAN_CPF]" in res_act.final_summary
    assert (ws / ".omni_todo.md").is_file()
    assert "- [x]" in (ws / ".omni_todo.md").read_text(encoding="utf-8")

    ev_path = tmp_path / "traces_act" / "m_live_v51_events.jsonl"
    assert ev_path.is_file()
    replayed = AgentLoop.replay_event_stream(ev_path)
    assert replayed["ok"] is True and replayed["action_count"] >= 2

    compiled_names = [s["name"] for s in forge.list_skills()]
    assert any(n.startswith("sop_m_live_v51") for n in compiled_names)


def test_v51_portable_temp_dir_lsp_client_and_durable_daemon_queue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove cross-platform temp resolution, PersistentLSPClient, and DurableDaemonQueue reboot resilience."""
    from am_ua.contracts.contracts import resolve_omni_temp_dir
    from am_ua.perception.lsp_client import PersistentLSPClient
    from am_ua.runtime.daemon_queue import DurableDaemonQueue

    # 1. Cross-platform temp dir via OMNI_TEMP_DIR
    custom_tmp = tmp_path / "custom_omni_tmp"
    monkeypatch.setenv("OMNI_TEMP_DIR", str(custom_tmp))
    assert resolve_omni_temp_dir("sub") == custom_tmp / "sub"

    # 2. PersistentLSPClient diagnostics & goto_definition
    ws = tmp_path / "lsp_ws"
    ws.mkdir()
    (ws / "service.py").write_text("class OrderService:\n    def charge(self, amount: int) -> int:\n        return amount\n", encoding="utf-8")
    (ws / "broken.py").write_text("def oops(:\n    pass\n", encoding="utf-8")

    lsp = PersistentLSPClient(ws, language="python")
    st = lsp.start(prefer_external=False)
    assert st["ok"] is True
    assert lsp.get_diagnostics("service.py")["ok"] is True
    bad_diag = lsp.get_diagnostics("broken.py")
    assert bad_diag["ok"] is False and bad_diag["diagnostics"][0]["code"] == "SyntaxError"
    defs = lsp.goto_definition("OrderService")
    assert defs["ok"] is True and defs["locations"][0]["file"] == "service.py" and defs["locations"][0]["line"] == 1
    lsp.shutdown()

    # 3. DurableDaemonQueue persistence across simulated reboot + webhook ingestion
    db_file = tmp_path / "daemon.db"
    q1 = DurableDaemonQueue(db_file)
    t_low = q1.enqueue("Low priority cleanup", str(ws), priority=10)
    wh = q1.ingest_webhook("github", "pull_request.opened", {"title": "Fix race condition"}, workspace=str(ws), priority=90)
    assert wh["ok"] is True

    # Simulate process reboot by creating a fresh instance on the same SQLite WAL db
    q2 = DurableDaemonQueue(db_file)
    claimed_1 = q2.claim_next("worker-1")
    assert claimed_1 is not None and claimed_1["task_id"] == wh["task_id"]
    q2.complete(claimed_1["task_id"], {"status": "VERIFIED"})

    claimed_2 = q2.claim_next("worker-1")
    assert claimed_2 is not None and claimed_2["task_id"] == t_low
    q2.fail(t_low, "transient error", retry_delay_s=0.0)
    assert q2.stats()["queued"] == 1 and q2.stats()["completed"] == 1
