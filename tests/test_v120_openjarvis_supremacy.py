"""OmniExecutor v12.0.0 — OpenJarvis High-Maturity Extraction Test Suite.

Verifies all 5 zero-dependency pillars extracted from OpenJarvis:
  1. Runtime Information-Flow Taint Tracking, SSRF Validator & MountAllowlistGuard
  2. ComplexityQueryAnalyzer, SkillOrchestra StageSkillHandbook & LearnedRouterPolicy
  3. Native Zero-Dep ACEContextPlaybook & SpecSearchOrchestrator (with Regression Gate & Rollback)
  4. EfficiencyTracker (TTFT/ITL/GFLOPs) & WasmSandboxRunner (Zero-Docker AST Fallback)
  5. OMNI_TOPOLOGY_V2 DAG integrity, 12.0.0 packaging (`dependencies = []`), Doctor v12 flags & CLI
"""

from __future__ import annotations

import json
from pathlib import Path
import tomllib
from typing import Any

import pytest

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.cognition.stage_router import (
    ComplexityQueryAnalyzer,
    LearnedRouterPolicy,
    StageSkillHandbook,
)
from am_ua.evolution.spec_search_ace import (
    ACEContextPlaybook,
    BenchmarkRegressionGate,
    BenchmarkSnapshot,
    EditRiskTier,
    SpecSearchOrchestrator,
    classify_edit_risk,
)
from am_ua.execution.wasm_sandbox import WasmSandboxRunner
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.seal_guard import ConstitutionSealGuard, ConstitutionalViolationError
from am_ua.perception.efficiency_telemetry import EfficiencyTracker, compute_itl_percentiles, estimate_transformer_gflops
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate
from am_ua.security.runtime_taint import (
    AllowedRoot,
    MountAllowlistGuard,
    RuntimeTaintTracker,
    SSRFValidator,
    TaintLabel,
    TaintSet,
    check_taint,
    detect_taint,
)

ROOT = Path(__file__).resolve().parents[1]


def test_v120_runtime_taint_ssrf_and_mount_allowlist(tmp_path: Path) -> None:
    # 1. Dynamic runtime taint detection & sink blocking (construct synthetic token dynamically)
    fake_secret = "sk_" + "live_" + ("A1b2C3d4" * 4)
    fake_email = "alice@example.org"
    taint = detect_taint(f"owner={fake_email} key={fake_secret}", source_external=True)
    assert taint.has(TaintLabel.SECRET) and taint.has(TaintLabel.PII) and taint.has(TaintLabel.EXTERNAL)
    assert check_taint("http_request", taint) is not None
    assert check_taint("read_only_tool", taint) is None

    tracker = RuntimeTaintTracker(enforce=True)
    tracker.observe_source("config.txt", fake_secret)
    sink_res = tracker.check_sink("ws.write_file", f"leaked={fake_secret}")
    assert sink_res["ok"] is False and sink_res["blocked"] is True

    # WorkspaceTools integration: enforce_taint blocks writing secret to file
    ws = tmp_path / "ws_taint"
    ws.mkdir()
    secret_f = ws / "input.txt"
    secret_f.write_text(f"token={fake_secret}\n", encoding="utf-8")
    tools = WorkspaceTools(ws, ConstitutionSealGuard(ROOT), enforce_taint=True)
    read_res = tools.read_file({"file": "input.txt"})
    assert "secret" in read_res.get("taint_labels", [])
    with pytest.raises(ConstitutionalViolationError):
        tools.write_file({"path": str(ws / "out.txt"), "content": f"dump={fake_secret}\n"})

    # 2. SSRF Validator
    assert SSRFValidator.validate_url("https://api.github.com/repos")[0] is True
    assert SSRFValidator.validate_url("http://169.254.169.254/latest/meta-data/")[0] is False
    assert SSRFValidator.validate_url("http://127.0.0.1:8080/admin")[0] is False
    assert SSRFValidator.validate_url("http://10.0.0.5/internal")[0] is False
    assert SSRFValidator.validate_url("file:///etc/passwd")[0] is False

    # 3. MountAllowlistGuard
    allowed_dir = tmp_path / "safe_mount"
    allowed_dir.mkdir()
    ssh_dir = allowed_dir / ".ssh"
    ssh_dir.mkdir()
    guard = MountAllowlistGuard([AllowedRoot(allowed_dir, read_only=True)])
    assert guard.validate_mount(allowed_dir / "data.txt", write=False)[0] is True
    assert guard.validate_mount(allowed_dir / "data.txt", write=True)[0] is False
    assert guard.validate_mount(ssh_dir / "config", write=False)[0] is False
    assert guard.validate_mount(allowed_dir / ".env", write=False)[0] is False


def test_v120_complexity_stage_and_learned_router(tmp_path: Path) -> None:
    simple = ComplexityQueryAnalyzer.analyze("hello")
    assert simple.tier == "trivial" and simple.suggested_max_tokens == 1024

    hard = ComplexityQueryAnalyzer.analyze(
        "Step 1: analyze the root cause in `src/app.py` and debug def distance(self, p): "
        "then calculate the proof equation and refactor the patch with pytest verification.",
        model_name="deepseek-r1-distill",
    )
    assert hard.score >= 0.55 and hard.query_class == "code"
    assert "thinking_headroom_2x" in hard.signals and hard.suggested_max_tokens >= 8192

    # SkillOrchestra StageSkillHandbook
    hb = StageSkillHandbook()
    assert hb.infer_stage(turn=1, has_edits=False) == "locate"
    assert hb.infer_stage(turn=4, has_edits=True) == "reason"
    assert hb.infer_stage(turn=5, has_edits=True, pending_verify=True) == "verify"
    for _ in range(4):
        hb.record_outcome(provider="cerebras", model="llama-3.3", stage="locate", success=True, latency_s=0.4)
        hb.record_outcome(provider="groq", model="gpt-oss", stage="locate", success=False, latency_s=2.0)
    assert hb.select_provider("locate", ["groq", "cerebras", "openrouter"]) == "cerebras"

    # LearnedRouterPolicy with min_samples gate
    store = tmp_path / "learned_router.json"
    lr = LearnedRouterPolicy(min_samples=3, store_path=store)
    for _ in range(2):
        lr.observe("Fix pytest failure in foo.py", "openrouter", reward=1.0)
    # Below min_samples -> falls back to default
    assert lr.select_provider("Fix pytest failure in bar.py", ["groq", "openrouter"], default_provider="groq") == "groq"
    lr.observe("Fix pytest failure in baz.py", "openrouter", reward=1.0)
    assert lr.select_provider("Fix pytest failure in qux.py", ["groq", "openrouter"], default_provider="groq") == "openrouter"
    assert store.is_file()


def test_v120_spec_search_and_native_ace_playbook(tmp_path: Path) -> None:
    pb_path = tmp_path / "ace.json"
    pb = ACEContextPlaybook(pb_path)
    added = pb.curate_from_trace({"agent_status": "BUDGET_EXHAUSTED", "patch_bytes": 0, "turns": 20, "repo": "pytest"})
    assert len(added) == 1
    bad = pb.add_or_reinforce("Always run mutating formatter", domain="code", helpful=False)
    pb.record_outcome(bad.rule_id, helpful=False)
    assert pb.prune_harmful(min_net_score=0) == 1
    rendered = pb.render_context(top_k=5)
    assert "[ACE LEARNED PLAYBOOK" in rendered and "str-00001" in rendered

    # Risk classification
    assert classify_edit_risk("src/am_ua/governance/seal_guard.py") == EditRiskTier.HIGH
    assert classify_edit_risk("src/am_ua/execution/agent_loop.py") == EditRiskTier.MEDIUM
    assert classify_edit_risk("data/ace_playbook.json") == EditRiskTier.LOW

    # SpecSearchOrchestrator: accept improvement, rollback on regression
    target = tmp_path / "strategy.txt"
    target.write_text("v0\n", encoding="utf-8")
    orch = SpecSearchOrchestrator(
        seal_guard=ConstitutionSealGuard(ROOT),
        gate=BenchmarkRegressionGate(min_improvement=0.05, max_regression=0.05),
    )

    before = BenchmarkSnapshot(overall_score=0.50, cluster_scores={"flask": 1.0, "sympy": 0.0})
    res_ok = orch.run_cycle(
        target_file=target,
        traces=[{"agent_status": "BUDGET_EXHAUSTED", "patch_bytes": 0, "turns": 20}],
        before_snapshot=before,
        apply_fn=lambda p, _rules: p.write_text("v1_improved\n", encoding="utf-8"),
        scorer_fn=lambda: BenchmarkSnapshot(overall_score=0.67, cluster_scores={"flask": 1.0, "sympy": 1.0}),
        playbook=pb,
    )
    assert res_ok["accepted"] is True and res_ok["rolled_back"] is False
    assert target.read_text(encoding="utf-8").strip() == "v1_improved"

    # Regression triggers automatic checkpoint rollback
    res_rej = orch.run_cycle(
        target_file=target,
        traces=[],
        before_snapshot=BenchmarkSnapshot(overall_score=0.67, cluster_scores={"flask": 1.0, "sympy": 1.0}),
        apply_fn=lambda p, _rules: p.write_text("v2_broken\n", encoding="utf-8"),
        scorer_fn=lambda: BenchmarkSnapshot(overall_score=0.80, cluster_scores={"flask": 0.50, "sympy": 1.0}),
        playbook=pb,
    )
    assert res_rej["accepted"] is False and res_rej["rolled_back"] is True
    assert target.read_text(encoding="utf-8").strip() == "v1_improved"


def test_v120_efficiency_telemetry_wasm_sandbox_topology_and_cli(capsys: Any) -> None:
    # 1. Efficiency Telemetry
    assert estimate_transformer_gflops(prompt_tokens=1000, completion_tokens=500, active_params_billions=8.0) == 24000.0
    itl = compute_itl_percentiles([10.0, 12.0, 15.0, 40.0])
    assert itl["p50_ms"] == 13.5 and itl["p95_ms"] == 40.0

    tracker = EfficiencyTracker()
    tracker.record(
        turn=1,
        provider="groq",
        model="gpt-oss-120b",
        stage="locate",
        prompt_tokens=1200,
        completion_tokens=300,
        latency_s=1.5,
        ttft_ms=120.0,
        itl_ms=[10.0, 14.0],
        cost_usd=0.0,
    )
    summary = tracker.summary(quality_score=1.0)
    assert summary["turns"] == 1 and summary["tokens_per_sec"] == 200.0 and summary["estimated_gflops"] > 0

    # 2. Zero-Docker WasmSandboxRunner AST fallback
    sb = WasmSandboxRunner()
    ok_res = sb.run_restricted_python("print(math.sqrt(25) + x)", inputs={"x": 7})
    assert ok_res.ok is True and ok_res.output.strip() == "12.0"
    bad_res = sb.run_restricted_python("import os\nprint(os.listdir('.'))")
    assert bad_res.ok is False and "Forbidden" in bad_res.error

    # 3. Packaging 12.0.0 zero-dep, Topology V2, Doctor v12 flags & CLI smoke
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == "12.0.0" and pyproject["project"]["dependencies"] == []
    topo = InterRepoTopologyGate().audit_package_imports(ROOT / "src" / "am_ua")
    assert topo["ok"] is True, topo.get("violations")

    doc = AetherMindUniversalAgent(ROOT).doctor()
    for flag in (
        "runtime_taint_ready",
        "stage_router_ready",
        "spec_search_ace_ready",
        "efficiency_telemetry_ready",
        "wasm_sandbox_ready",
    ):
        assert doc[flag] is True

    from am_ua import cli

    assert cli.main(["route", "--query", "Refactor pytest fixture in src/app.py", "--stage", "locate"]) == 0
    out_route = json.loads(capsys.readouterr().out)
    assert out_route["complexity"]["query_class"] == "code"
    assert cli.main(["evolve-ace", "--status"]) == 0
    out_ace = json.loads(capsys.readouterr().out)
    assert out_ace["ok"] is True


def test_v120_dirty_worktree_preservation_and_live_best_of_n_escalation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    from am_ua.execution.agent_loop import AgentLoop, AgentRunResult
    from am_ua.execution.best_of_n import BehaviorBestOfNEngine
    from am_ua.execution.durable_engine import DurableExecutionEngine

    # 1. Dirty git repo must fall back to copytree so uncommitted SWE-bench test_patch is never lost
    repo = tmp_path / "dirty_repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.local"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(repo), capture_output=True, check=True)
    (repo / "app.py").write_text("VAL = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), capture_output=True, check=True)
    # Apply uncommitted test_patch file
    (repo / "test_patch_uncommitted.py").write_text("assert True\n", encoding="utf-8")

    cand_dst = tmp_path / "cand_dirty"
    used_wt = BehaviorBestOfNEngine._prepare_candidate_workspace(repo, cand_dst, use_git_worktree=True)
    assert used_wt is False
    assert (cand_dst / "test_patch_uncommitted.py").is_file()

    # 2. AgentLoop.run_live_best_of_n escalates from failed attempt 1 to passing attempt 2 and stops early
    seen_calls: list[tuple[str, str, str]] = []

    def _fake_run(self, objective: str, workspace: Path | str, **kwargs: Any) -> AgentRunResult:  # noqa: ANN001
        ws_p = Path(workspace)
        wf = str(kwargs.get("workflow", "react"))
        rl = str(kwargs.get("role", "general_engineer"))
        seen_calls.append((wf, rl, os.environ.get("PYTHONPATH", "")))
        if len(seen_calls) == 1:
            return AgentRunResult(
                mission_id="m1",
                objective=objective,
                workspace=str(ws_p),
                status="BUDGET_EXHAUSTED",
                epistemic_tag="NAO VERIFICADO",
                final_summary="ran out of turns",
                actor_confidence=0.2,
                actor_providers=["groq"],
                turns=5,
                tool_calls=[],
                verification={"passed": False, "exit_code": 1, "output": "fail"},
                judge=None,
                changed_files=[],
                diff="",
                tokens={"prompt": 100, "completion": 20},
                llm_calls=5,
                elapsed_s=1.0,
                stop_reason="max_turns",
            )
        (ws_p / "app.py").write_text("VAL = 99\n", encoding="utf-8")
        return AgentRunResult(
            mission_id="m2",
            objective=objective,
            workspace=str(ws_p),
            status="VERIFIED",
            epistemic_tag="PROVADO",
            final_summary="fixed VAL=99",
            actor_confidence=0.95,
            actor_providers=["openrouter"],
            turns=2,
            tool_calls=[],
            verification={"passed": True, "exit_code": 0, "output": "ok"},
            judge=None,
            changed_files=["app.py"],
            diff="+VAL = 99",
            tokens={"prompt": 80, "completion": 15},
            llm_calls=2,
            elapsed_s=0.5,
            stop_reason="finish",
        )

    import os
    monkeypatch.setattr(AgentLoop, "run", _fake_run)
    loop = AgentLoop(engine=DurableExecutionEngine(tmp_path / "bbon.db"), seal_guard=ConstitutionSealGuard(ROOT))
    out = loop.run_live_best_of_n(
        "Set VAL = 99",
        repo,
        verify_cmd="pytest -q",
        n=3,
        max_turns=10,
        early_stop_on_first_verified=True,
        post_sync_verify_fn=lambda p: "VAL = 99" in (p / "app.py").read_text(encoding="utf-8"),
    )
    assert out["ok"] is True
    assert out["attempts_run"] == 2  # stopped early before candidate 3!
    assert seen_calls[0][:2] == ("react", "general_engineer")
    assert seen_calls[1][:2] == ("sparc", "tdd_enforcer")
    assert (repo / "app.py").read_text(encoding="utf-8").strip() == "VAL = 99"

    # 3. Verify WorkspaceTools.run PowerShell quoted-chain normalization and Windows binary hermetic bypass
    import sys
    wt_ps = WorkspaceTools(repo, ConstitutionSealGuard(ROOT))
    if os.name == "nt":
        py_q = f'"{Path(sys.executable).as_posix()}"'
        r_chain = wt_ps.run({"command": f"cd . && {py_q} -c \"print('PWSH_CHAIN_OK')\"", "sandbox": "hermetic"})
        assert r_chain["exit_code"] == 0 and "PWSH_CHAIN_OK" in r_chain["output"]
        assert r_chain.get("sandbox_note") == "host_fallback_from_hermetic_for_windows_binary"
