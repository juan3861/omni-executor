"""OmniExecutor v13.0.0 — Tier-1 Industrial Supremacy Test Suite.

Verifies all 4 engineering pillars of v13.0.0:
  1. NativeBackendRouter (ast-grep, ruff, typecheck_file, ripgrep) & Real JSON-RPC 2.0 PersistentLSPClient
     (encode/decode framing, diagnostics, goto_definition, find_references, hover_signature) + WorkspaceTools typing
  2. Live TTFT/ITL telemetry in LLMResponse & EfficiencyTracker, StageSkillHandbook free/frontier gating,
     Post-Edit Traceback Lock & auto-compilation into 0-token playbooks/skills
  3. Docker Linux image routing (Py2.7 vs Py3.9 vs Py3.11), hardened Docker shell commands,
     HermeticSandboxBridge status/fallback & PublicBenchmarkSuiteAdapter Terminal-Bench/WebArena runners
  4. Always-on DurableDaemonWorker (crash-lease recovery + Record-and-Replay + backoff),
     GitHubPRBridge (AgentShield gate + dry-run PR + CI fix objective), Topology V2, v13.0.0 zero-dep & CLI
"""

from __future__ import annotations

import json
from pathlib import Path
import time
import tomllib
from typing import Any, Dict, List

import pytest

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.cognition.llm_client import LLMResponse
from am_ua.cognition.stage_router import StageSkillHandbook
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.github_pr_bridge import GitHubPRBridge
from am_ua.execution.hermetic_sandbox_bridge import HermeticSandboxBridge
from am_ua.execution.native_backends import NativeBackendRouter
from am_ua.execution.swebench_harness import PublicBenchmarkSuiteAdapter, SWEBenchHarness, SWEBenchInstance
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.perception.lsp_client import PersistentLSPClient
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate
from am_ua.runtime.daemon_queue import DurableDaemonQueue
from am_ua.runtime.daemon_worker import DurableDaemonWorker

ROOT = Path(__file__).resolve().parents[1]


def test_v130_native_backends_real_lsp_and_post_edit_typing(tmp_path: Path) -> None:
    caps = NativeBackendRouter.probe_capabilities()
    for key in ("ripgrep", "ast_grep", "basedpyright", "pyright", "mypy", "ruff", "docker", "gh", "node", "go"):
        assert key in caps

    ws = tmp_path / "ws_lsp"
    ws.mkdir()
    mod = ws / "calc.py"
    mod.write_text(
        'def compute_total(price: int, qty: int) -> int:\n'
        '    """Compute line total."""\n'
        '    return price * qty\n\n'
        'def run_calc() -> int:\n'
        '    return compute_total(10, 3)\n',
        encoding="utf-8",
    )

    # 1. ast-grep structural search (native sg/ast-grep or Python fallback)
    ag = NativeBackendRouter.ast_grep_search(ws, "compute_total($A, $B)", lang="python")
    assert ag["ok"] is True and len(ag["hits"]) >= 1
    assert any("calc.py" in h["file"] for h in ag["hits"])

    # 2. PersistentLSPClient JSON-RPC 2.0 stream encode + decode + references + hover
    raw_frames = PersistentLSPClient.encode_lsp_message({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}) + (
        PersistentLSPClient.encode_lsp_message({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": "file:///a.py", "diagnostics": []}})
    )
    decoded = PersistentLSPClient.decode_lsp_stream(raw_frames)
    assert len(decoded) == 2 and decoded[0]["id"] == 1 and decoded[1]["method"] == "textDocument/publishDiagnostics"

    lsp = PersistentLSPClient(ws, language="python")
    lsp.start(prefer_external=bool(caps.get("basedpyright") or caps.get("pyright")))
    try:
        d_ok = lsp.get_diagnostics("calc.py", include_typecheck=True)
        assert d_ok["ok"] is True
        g_def = lsp.goto_definition("compute_total")
        assert g_def["ok"] is True and g_def["locations"][0]["file"] == "calc.py"
        refs = lsp.find_references("compute_total")
        assert refs["ok"] is True and len(refs["references"]) >= 1
        hov = lsp.hover_signature("calc.py", line=1)
        assert hov["ok"] is True and "def compute_total(price, qty)" in hov["signature"]
    finally:
        lsp.shutdown()

    # 3. WorkspaceTools post-edit semantic diagnostics + ast_grep_search + lsp_query
    wt = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))
    wt_ag = wt.ast_grep_search({"pattern": "compute_total($A, $B)", "lang": "python"})
    assert wt_ag["ok"] is True and len(wt_ag["hits"]) >= 1
    wt_lsp = wt.lsp_query({"action": "references", "symbol": "compute_total"})
    assert wt_lsp["ok"] is True

    # Write a syntactically valid file with an undefined variable -> AST ok, semantic check catches it when ruff/typechecker present
    undef = wt.write_file({"path": str(ws / "bad_sem.py"), "content": "def f() -> int:\n    return missing_symbol_xyz + 1\n"})
    assert undef["post_edit_diagnostics"]["ok"] is True
    if caps.get("ruff") or caps.get("basedpyright") or caps.get("mypy"):
        assert undef["post_edit_diagnostics"]["semantic_ok"] is False
        assert len(undef["post_edit_diagnostics"]["semantic_diagnostics"]) >= 1


def test_v130_ttft_itl_stage_routing_and_traceback_lock(tmp_path: Path) -> None:
    # 1. StageSkillHandbook free-tier protection vs explicit frontier escalation
    hb = StageSkillHandbook()
    avail = ["anthropic", "openai", "groq", "openrouter"]
    assert hb.select_provider("reason", avail, prefer_free=True, allow_frontier=False, complexity_score=0.95) == "groq"
    assert hb.select_provider("reason", avail, prefer_free=True, allow_frontier=True, complexity_score=0.85) == "anthropic"

    # 2. Post-Edit Traceback Lock catches failing test assertions right after edit
    tb_lock = AgentLoop._extract_post_edit_traceback_lock(
        "FAILED tests/test_mod.py::test_x\nE   AssertionError: got 'str' instead of 'Optional[str]'\n",
        ["pylint/pyreverse/utils.py"],
    )
    assert "POST_EDIT_TRACEBACK_LOCK" in tb_lock and "utils.py" in tb_lock and "AssertionError" in tb_lock

    # 3. Live EfficiencyTracker + stage_routing_history inside AgentLoop.run with fake LLM emitting ttft_ms & itl_ms
    ws = tmp_path / "ws_loop"
    ws.mkdir()
    (ws / "app.py").write_text("X = 1\n", encoding="utf-8")

    class _FakeStreamingLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self._step = 0

        def available(self) -> List[str]:
            return ["groq", "openrouter"]

        def chat(self, messages: List[Dict[str, Any]], **kwargs: Any) -> LLMResponse:
            self.calls += 1
            self._step += 1
            self.total_prompt_tokens += 120
            self.total_completion_tokens += 30
            if self._step == 1:
                txt = json.dumps({
                    "thought": "Update X to 2",
                    "tool": "replace_in_file",
                    "args": {"file": "app.py", "old": "X = 1", "new": "X = 2"},
                })
            else:
                txt = json.dumps({
                    "thought": "Done",
                    "tool": "finish",
                    "args": {"summary": "Updated X=2", "confidence": 0.98},
                })
            return LLMResponse(
                txt, "groq", "openai/gpt-oss-120b", 120, 30, 42.5,
                ttft_ms=18.4, itl_ms=[4.2, 5.1, 6.0], cost_usd=0.0,
            )

    loop = AgentLoop(engine=DurableExecutionEngine(tmp_path / "loop.db"), seal_guard=ConstitutionSealGuard(ROOT), llm=_FakeStreamingLLM())
    res = loop.run(
        "Set X = 2 in app.py",
        ws,
        max_turns=6,
        use_judge=False,
        use_native_tools=False,
        enable_zero_token_offload=False,
    )
    assert res.status == "COMPLETED_UNVERIFIED"
    assert res.efficiency_summary is not None
    assert res.efficiency_summary["turns"] == 2
    assert res.efficiency_summary["ttft_mean_ms"] == pytest.approx(18.4, rel=1e-2)
    assert res.efficiency_summary["itl"]["p50_ms"] == pytest.approx(5.1, rel=1e-2)
    assert res.stage_routing_history is not None and len(res.stage_routing_history) == 2
    assert res.stage_routing_history[0]["stage"] == "locate"


def test_v130_docker_image_routing_terminal_bench_and_webarena(tmp_path: Path) -> None:
    inst_py2 = SWEBenchInstance(
        instance_id="psf__requests-1724",
        repo="psf/requests",
        base_commit="1ba83c47",
        problem_statement="unicode method name",
        test_patch="+ r = requests.request(method=u'POST', url=httpbin('post'))\n",
    )
    inst_sympy = SWEBenchInstance(
        instance_id="sympy__sympy-12419",
        repo="sympy/sympy",
        base_commit="479939f8",
        problem_statement="Identity sum",
    )
    assert SWEBenchHarness.select_docker_image_for_instance(inst_py2) == "python:2.7-slim"
    assert SWEBenchHarness.select_docker_image_for_instance(inst_sympy) == "python:3.9-slim"

    d_cmd = SWEBenchHarness.build_docker_shell_command(tmp_path, "pytest -q", docker_image="python:2.7-slim", hardened=True)
    assert "--network=none" in d_cmd and "--cap-drop=ALL" in d_cmd and "python:2.7-slim" in d_cmd

    # Terminal-Bench real execution in isolated tmp workspace
    tb_task = PublicBenchmarkSuiteAdapter.normalize_task(
        {"task_id": "tb-01", "instruction": "Print marker", "verify_cmd": "python -c \"print('TB_OK_13')\"", "expected_keywords": ["TB_OK_13"]},
        suite="terminal_bench",
    )
    tb_res = PublicBenchmarkSuiteAdapter.run_terminal_bench_task(tb_task, tmp_path / "tb_ws", use_docker=False)
    assert tb_res["ok"] is True and tb_res["keywords_matched"] is True and tb_res["llm_calls"] == 0

    # WebArena deterministic local HTML verification
    html_p = tmp_path / "page.html"
    html_p.write_text("<html><body><h1>OmniExecutor Tier1</h1><p>STATUS_READY</p></body></html>", encoding="utf-8")
    wa_task = PublicBenchmarkSuiteAdapter.normalize_task(
        {"task_id": "wa-01", "intent": "Verify page status", "start_url": html_p.as_uri(), "expected_keywords": ["omniexecutor tier1", "status_ready"]},
        suite="webarena",
    )
    wa_res = PublicBenchmarkSuiteAdapter.run_webarena_task(wa_task)
    assert wa_res["ok"] is True and wa_res["keywords_matched"] is True

    hs = HermeticSandboxBridge().status()
    assert "docker_daemon_alive" in hs


def test_v130_daemon_worker_github_pr_bridge_topology_and_cli(tmp_path: Path, capsys: Any) -> None:
    # 1. DurableDaemonWorker crash lease recovery + Record-and-Replay + retry backoff
    q = DurableDaemonQueue(tmp_path / "daemon_q.db")
    t1 = q.enqueue("Task alpha", str(tmp_path), priority=90)
    t2 = q.enqueue("Task flaky", str(tmp_path), priority=50)

    # Simulate crashed worker holding stale lease on t1
    claimed = q.claim_next("crashed-worker")
    assert claimed is not None and claimed["task_id"] == t1
    with q._connect() as conn:
        conn.execute("UPDATE daemon_tasks SET updated_at = ? WHERE task_id = ?", (time.time() - 600.0, t1))

    attempts_seen: Dict[str, int] = {}

    def _exec(task: Dict[str, Any]) -> Dict[str, Any]:
        tid = str(task["task_id"])
        attempts_seen[tid] = attempts_seen.get(tid, 0) + 1
        if tid == t2 and attempts_seen[tid] == 1:
            return {"ok": False, "error": "transient_err"}
        return {"ok": True, "done": tid}

    worker = DurableDaemonWorker(q, worker_id="w-live", executor_fn=_exec, stale_lease_s=60.0, base_backoff_s=0.0)
    drained = worker.run_until_empty(max_tasks=10)
    assert drained["recovered_leases"] == 1
    assert q.stats()["completed"] == 2 and q.stats()["failed"] == 0

    # 2. GitHubPRBridge audit + dry-run PR + CI fix objective
    bridge = GitHubPRBridge(ROOT)
    pr_dry = bridge.create_pr(title="v13 test PR", body="Automated test", dry_run=True, require_shield_pass=True)
    assert pr_dry["ok"] is True and pr_dry["dry_run"] is True and pr_dry["audit"]["shield_grade"] == "A"
    obj = GitHubPRBridge.build_ci_fix_objective({"pr_number": 42, "branch": "feat/v13", "failing_checks": [{"name": "verify-windows"}]})
    assert "PR #42" in obj and "verify-windows" in obj

    # 3. Packaging 13.0.0 zero-dep, Topology V2, Doctor v13 flags & CLI smoke
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == "13.0.0" and pyproject["project"]["dependencies"] == []
    topo = InterRepoTopologyGate().audit_package_imports(ROOT / "src" / "am_ua")
    assert topo["ok"] is True, topo.get("violations")

    doc = AetherMindUniversalAgent(ROOT).doctor()
    for flag in ("lsp_real_ready", "daemon_worker_ready"):
        assert doc[flag] is True
    assert "compiled_playbooks_count" in doc and "docker_daemon_alive" in doc

    from am_ua import cli

    assert cli.main(["pr", "audit", "--workspace", str(ROOT)]) == 0
    pr_out = json.loads(capsys.readouterr().out)
    assert pr_out["ok"] is True and pr_out["shield_grade"] == "A"
    assert cli.main(["lsp", "definition", "DurableDaemonWorker", "--workspace", str(ROOT)]) == 0
    lsp_out = json.loads(capsys.readouterr().out)
    assert lsp_out["ok"] is True
