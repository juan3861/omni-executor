"""Empirical verification suite for OmniExecutor v11.0 (Global AGI & Deterministic Supremacy):
  1. Compiler-grade Code Property Graph (AST/CFG/Dataflow taint slicing + SCIP JSON index + WorkspaceTools CPG & post-edit diagnostics).
  2. Temporal/Restate-style Deterministic Record-and-Replay (`RecorderSession` / `ReplaySession` / `NonDeterminismDriftError`).
  3. Zero-'unknown' categorization of all 220 rails + Turn-0 Playbook Router (0 LLM calls) + Trace-to-Playbook Compiler + SelfHealingSelectorCache.
  4. AgentLoop Best-of-N Worktree Arbitration + Hardened Kernel Docker Flags + PublicBenchmarkSuiteAdapter (SWE-bench/Terminal-Bench/OSWorld/WebArena) + Zero Orphans & Doctor v11.0.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.execution.agent_loop import AgentLoop, WorkspaceTools
from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.playbook_compiler import (
    SelfHealingSelectorCache,
    TraceToPlaybookCompiler,
    TurnZeroPlaybookRouter,
)
from am_ua.execution.record_replay import NonDeterminismDriftError
from am_ua.execution.swebench_harness import PublicBenchmarkSuiteAdapter, SWEBenchHarness
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.gui.cdp_browser import CDPIndexedBrowser, IndexedDOMElement
from am_ua.perception.code_property_graph import CodePropertyGraphBuilder, SCIPIndexStore
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate


def test_v110_cpg_taint_scip_and_post_edit_diagnostics(tmp_path: Path) -> None:
    ws = tmp_path / "cpg_ws"
    ws.mkdir()
    (ws / "auth.py").write_text(
        "def sanitize_token(raw_input):\n"
        "    cleaned = raw_input.strip()\n"
        "    return cleaned\n",
        encoding="utf-8",
        newline="\n",
    )
    (ws / "app.py").write_text(
        "from auth import sanitize_token\n"
        "def handle_request(user_tok):\n"
        "    safe = sanitize_token(user_tok)\n"
        "    if safe:\n"
        "        return safe\n"
        "    return 'guest'\n",
        encoding="utf-8",
        newline="\n",
    )

    cpg = CodePropertyGraphBuilder(ws).build()
    summary = cpg.to_summary()
    assert summary["edge_kinds"].get("CALLS", 0) >= 1
    assert summary["edge_kinds"].get("FLOWS_TO", 0) >= 2
    assert summary["edge_kinds"].get("BRANCHES", 0) >= 1

    impact = cpg.impact_analysis("sanitize_token")
    assert "handle_request" in impact["transitive_callers"]
    assert "app.py" in impact["affected_files"] and "auth.py" in impact["affected_files"]

    taint = cpg.trace_taint_slice("user_tok", direction="forward")
    assert "sanitize_token" in taint["reachable_nodes"] or "safe" in taint["reachable_nodes"]

    scip_out = SCIPIndexStore(ws).build_and_save(ws / "index.scip.json")
    assert (ws / "index.scip.json").is_file()
    assert "sanitize_token" in scip_out["symbols"]

    wt = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))
    bad = wt.write_file({"path": str(ws / "broken.py"), "content": "def bad(:\n  pass\n"})
    assert bad["post_edit_diagnostics"]["ok"] is False
    cpg_tool = wt.cpg_impact({"action": "impact", "symbol": "sanitize_token"})
    assert cpg_tool["ok"] is True and "app.py" in cpg_tool["affected_files"]


def test_v110_temporal_record_replay_and_drift_detection(tmp_path: Path) -> None:
    engine = DurableExecutionEngine(tmp_path / "durable.db")
    rr = engine.create_replay_engine()

    side_calls = {"n": 0}

    def run_workflow(session, arg_val: str) -> dict:
        t0 = session.now_timestamp()
        r0 = session.random_float("jitter")
        act = session.activity("fetch_item", {"id": arg_val}, lambda: side_calls.__setitem__("n", side_calls["n"] + 1) or {"v": arg_val.upper()})
        llm = session.llm_call("plan", {"id": arg_val}, lambda: {"plan": f"use:{act['v']}"})
        return session.finish({"ts": t0, "rng": r0, "act": act, "llm": llm})

    rec = rr.start_recording("wf-1", "demo_wf", seed=123)
    out1 = run_workflow(rec, "alpha")
    assert side_calls["n"] == 1

    rep = rr.start_replay("wf-1")
    out2 = run_workflow(rep, "alpha")
    assert out1 == out2
    assert side_calls["n"] == 1  # ZERO re-executions of external activity during replay!
    assert rep.replayed_events >= 5

    # Control-flow / argument drift MUST fail closed
    rep_drift = rr.start_replay("wf-1")
    with pytest.raises(NonDeterminismDriftError):
        run_workflow(rep_drift, "beta")


def test_v110_turn0_router_compiler_rails_categories_and_selector_heal(tmp_path: Path) -> None:
    # 1. Zero 'unknown' rails across all 220 rails
    rails = DeterministicTaskOffloader.list_rails()
    assert len(rails) >= 220
    assert all(r["category"] != "unknown" for r in rails)
    assert len(DeterministicTaskOffloader.list_rails(category="windows")) >= 5

    # 2. Turn-0 Router executes Code rename playbook WITHOUT waking LLM (`llm_calls == 0`)
    ws = tmp_path / "turn0_ws"
    ws.mkdir()
    (ws / "calc.py").write_text("def old_fn(v):\n    return v + 1\n", encoding="utf-8", newline="\n")
    (ws / "test_calc.py").write_text("from calc import new_fn\ndef test_x(): assert new_fn(4) == 5\n", encoding="utf-8", newline="\n")

    engine = DurableExecutionEngine(tmp_path / "loop_durable.db")
    loop = AgentLoop(engine=engine, seal_guard=ConstitutionSealGuard(ROOT))
    res = loop.run(
        "Rename function old_fn to new_fn in calc.py",
        ws,
        verify_cmd=f'"{sys.executable}" -B -m pytest -q test_calc.py',
    )
    assert res.status == "VERIFIED" and res.llm_calls == 0 and res.turns == 0
    assert "def new_fn" in (ws / "calc.py").read_text(encoding="utf-8")

    # 3. Trace-to-Playbook Compiler compiles trace and persists reusable playbook
    compiler = TraceToPlaybookCompiler(tmp_path / "compiled.json")
    comp = compiler.compile_trace(
        name="custom_smoke_fetch",
        objective="fetch local smoke page summary",
        tool_calls=[{"tool": "deterministic_preflight", "args": {"max_chars": 1500}, "ok": True}],
        domain="code",
        verification={"passed": True},
    )
    assert comp["ok"] is True and comp["steps_compiled"] == 1
    matched = TurnZeroPlaybookRouter.match_intent("fetch local smoke page summary", compiler=compiler)
    assert matched is not None and matched["playbook"] == "custom_smoke_fetch"

    # 4. Self-Healing Selector Cache + CDPIndexedBrowser integration
    br = CDPIndexedBrowser(artifact_dir=tmp_path / "cdp_heal")
    br.last_elements[1] = IndexedDOMElement(
        idx=1, tag="button", type="submit", role="button", name="submit-order", text="Save Profile", placeholder="", href="", bbox=[0, 0, 20, 10]
    )
    br.selector_cache.record_anchor("profile_page", "save button", selector="#old-save-btn", role="button", text="Save Profile")
    healed = br.heal_selector_from_elements("profile_page", "save button", primary_selector="#old-save-btn")
    assert healed["ok"] is True and healed["healed"] is True
    assert healed["selector"] == '[data-am-idx="1"]'


def test_v110_best_of_n_hardened_docker_public_bench_and_doctor(tmp_path: Path) -> None:
    # 1. AgentLoop BestOfN + ExperimentalArbitrator over temporary workspace
    ws = tmp_path / "bo_ws"
    ws.mkdir()
    (ws / "app.py").write_text("X = 1\n", encoding="utf-8")
    loop = AgentLoop(engine=DurableExecutionEngine(tmp_path / "bo.db"), seal_guard=ConstitutionSealGuard(ROOT))
    bo = loop.resolve_via_best_of_n_worktrees(
        ws,
        candidates=[
            {"candidate_id": "bad", "files": {"app.py": "X = 0\n"}},
            {"candidate_id": "good", "files": {"app.py": "X = 42\n"}},
        ],
        verify_fn=lambda cand_ws: ("X = 42" in (cand_ws / "app.py").read_text(encoding="utf-8"), "check 42"),
        apply_winner=True,
    )
    assert bo["ok"] is True and (ws / "app.py").read_text(encoding="utf-8").strip() == "X = 42"

    # 2. Hardened Docker command + PublicBenchmarkSuiteAdapter (SWE-bench/Terminal-Bench/OSWorld/WebArena)
    cmd = SWEBenchHarness.build_docker_command(ws, ["test_a.py"], hardened=True, read_only_root=True)
    for flag in ("--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=256", "--read-only"):
        assert flag in cmd

    raw_tasks = [
        {"suite": "swebench", "raw": {"instance_id": "sw-1", "problem_statement": "Fix off by one"}},
        {"suite": "terminal_bench", "raw": {"task_id": "tb-1", "instruction": "Inspect logs"}},
        {"suite": "osworld", "raw": {"id": "os-1", "instruction": "Open settings window"}},
        {"suite": "webarena", "raw": {"task_id": "wa-1", "intent": "Extract checkout total"}},
    ]
    norm = [PublicBenchmarkSuiteAdapter.normalize_task(x["raw"], suite=x["suite"]) for x in raw_tasks]
    suite_rep = PublicBenchmarkSuiteAdapter.evaluate_suite(
        norm, runner_fn=lambda t: {"ok": True, "llm_calls": 0 if t["suite"] == "terminal_bench" else 2, "cost_usd": 0.0}
    )
    assert suite_rep["ok"] is True and suite_rep["evaluated"] == 4 and suite_rep["zero_token_rate"] == 0.25

    # 3. Packaging, Topology V2, Orphan check, and v11.0 Doctor readiness
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert int(pyproject["project"]["version"].split(".")[0]) >= 11 and pyproject["project"]["dependencies"] == []
    topo = InterRepoTopologyGate().audit_package_imports(ROOT / "src" / "am_ua")
    assert topo["ok"] is True, topo.get("violations")

    doc = AetherMindUniversalAgent(ROOT).doctor()
    assert doc["seal_valid"] is True
    assert doc["record_replay_ready"] is True
    assert doc["cpg_scip_ready"] is True
    assert doc["zero_turn_playbook_router_ready"] is True
    assert "unknown" not in doc["rails_by_category"]


def test_v110_multikey_pool_rotation_and_env_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.error
    from am_ua.cognition.llm_client import LLMClient, ProviderSpec, load_local_env

    env_f = tmp_path / "vault.env"
    env_f.write_text("GROQ_API_KEYS=keyA,keyB,keyC\n", encoding="utf-8")
    monkeypatch.delenv("GROQ_API_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert load_local_env(env_f) >= 1

    spec = ProviderSpec("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", "openai/gpt-oss-120b")
    assert spec.api_keys() == ["keyA", "keyB", "keyC"]

    client = LLMClient(providers=[spec])
    seen_keys: list[str] = []

    def _fake_post(s, body, *, enable_prompt_cache=True, api_key_override=None):  # noqa: ARG001
        seen_keys.append(str(api_key_override))
        if api_key_override == "keyA":
            raise urllib.error.HTTPError("https://api.groq.com", 429, "rate limit", {}, io.BytesIO(b"rate_limit"))
        return {
            "model": s.model,
            "choices": [{"message": {"content": "ROTATED_OK"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "_post", _fake_post)
    resp = client.chat([{"role": "user", "content": "hi"}], max_tokens=16)
    assert resp.text == "ROTATED_OK"
    assert seen_keys == ["keyA", "keyB"]


def test_v110_workspace_tools_search_supports_single_file_target(tmp_path: Path) -> None:
    from am_ua.execution.workspace_tools import WorkspaceTools

    ws = tmp_path / "ws_search"
    ws.mkdir()
    target = ws / "mod.py"
    target.write_text("class Foo:\n    def clear(self):\n        return 1\n", encoding="utf-8")

    tools = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))
    res = tools.search({"path": "mod.py", "pattern": "def clear", "prefer_native": False})
    assert res["hits"] == ["mod.py:2: def clear(self):"]
    assert res["truncated"] is False
