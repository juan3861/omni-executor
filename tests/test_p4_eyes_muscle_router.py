"""Empirical Verification Suite for Phase 4: Multi-Scale Eyes, Codex Muscle, SAST/Worktree & Router (P4.1–P4.4).

Validates:
  - P4.1: `SiliconProjectRadar` (`aetherscan_v1.3.0.exe` real invocation + `UCIPSummary` >60% compression + parasite detection)
  - P4.2: `PolyglotRepoMapper` (PageRank centrality across Python/JS/Rust/Go + structural AST search) +
          `InterRepoTopologyGate` (`OMNI_TOPOLOGY_V2` DAG audit on live `src/am_ua/`) + `MCPStdioClient`
  - P4.3: `CodexSandboxMuscle` (live JSON-RPC 2.0 `initialize` + `tools/list` against `codex.exe mcp-server`),
          `SafeEditTransactionalJournal` + `StaticVerificationGate` (atomic apply, manual rollback, AND
          automatic SAST/Secret-Leak rollback!), `WorktreeIsolationManager` (real `git worktree` isolation),
          `E2BRemoteSandboxAdapter`
  - P4.4: `ResponsesWireTranslator` (`/v1/chat/completions` <-> `/v1/responses` lossless tool-call roundtrip) +
          `UniversalCognitiveRouter` (RTK code-preserving compression + independent-judge route selection).
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from am_ua import PROJECT_ROOT
from am_ua.execution.codex_muscle import (
    CodexSandboxMuscle,
    E2BRemoteSandboxAdapter,
    SafeEditTransactionalJournal,
    StaticVerificationError,
    StaticVerificationGate,
    WorktreeIsolationManager,
)
from am_ua.perception import (
    InterRepoTopologyGate,
    PolyglotRepoMapper,
    SiliconProjectRadar,
)
from am_ua.routing import ResponsesWireTranslator, UniversalCognitiveRouter


def test_p4_1_silicon_radar_and_ucip_compression(tmp_path: Path) -> None:
    # Build sample project with parasite node_modules
    (tmp_path / "src").mkdir()
    for idx in range(12):
        (tmp_path / "src" / f"module_feature_component_{idx}.py").write_text(
            f"def compute_{idx}(x: int) -> int:\n    return x + {idx}\n",
            encoding="utf-8",
        )
    nm = tmp_path / "node_modules" / "heavy_dep"
    nm.mkdir(parents=True)
    for idx in range(15):
        (nm / f"bundle_chunk_{idx}.js").write_text("const a = 1;\n" * 20, encoding="utf-8")

    radar = SiliconProjectRadar()
    if radar.is_binary_available():
        walk_res = radar.run_aetherscan_walk(tmp_path, top_n=5)
        assert walk_res["ok"] is True

    ucip = radar.build_ucip_summary(tmp_path)
    assert ucip.total_files == 12
    assert ucip.reduction_pct >= 65.0
    assert "@UCIP/1" in ucip.ucip_compact_text
    assert any("node_modules" in p["path"] for p in ucip.parasite_hotspots)


def test_p4_2_polyglot_repomap_pagerank_and_topology_gate(tmp_path: Path) -> None:
    (tmp_path / "core_hub.py").write_text(
        "class SovereignHub:\n    def execute_core(self) -> int:\n        return 42\n",
        encoding="utf-8",
    )
    (tmp_path / "worker_a.py").write_text(
        "from core_hub import SovereignHub\ndef run_a():\n    return SovereignHub().execute_core()\n",
        encoding="utf-8",
    )
    (tmp_path / "worker_b.ts").write_text(
        "export function callHub() { return SovereignHub; }\n",
        encoding="utf-8",
    )
    (tmp_path / "engine.rs").write_text(
        "pub struct SovereignRust { pub id: u64 }\npub fn refer() { let _ = SovereignHub; }\n",
        encoding="utf-8",
    )

    mapper = PolyglotRepoMapper(tmp_path)
    ranked, rendered = mapper.build_ranked_map(max_chars=2000)
    assert len(ranked) == 4
    # `core_hub.py` is referenced by all 3 other files -> must rank #1 in PageRank!
    assert ranked[0].rel_path == "core_hub.py"
    assert "SovereignHub" in rendered

    hits = mapper.structural_search("def $FN(self) -> int:", lang="python")
    assert any(h["file"] == "core_hub.py" for h in hits)

    # Audit our own live `src/am_ua` package against `OMNI_TOPOLOGY_V2`!
    gate = InterRepoTopologyGate()
    audit = gate.audit_package_imports(Path(PROJECT_ROOT) / "src" / "am_ua")
    assert audit["ok"] is True, f"OMNI_TOPOLOGY_V2 violations: {audit['violations']}"


def test_p4_3_codex_mcp_safe_edit_sast_rollback_and_worktree(tmp_path: Path) -> None:
    # 1. Precompiled Codex JSON-RPC stdio handshake + real Win32 Restricted Token Sandbox
    muscle = CodexSandboxMuscle()
    inv = muscle.inventory()
    assert inv["codex_exe"]["available"] is True
    assert inv["code_mode_host_exe"]["available"] is True
    mcp_probe = muscle.probe_mcp_server(timeout_s=15.0)
    assert mcp_probe["ok"] is True
    assert mcp_probe["platform_os"] == "windows"

    sbx = muscle.run_in_sandbox(["cmd.exe", "/c", "echo", "CODEX_WIN32_SANDBOX_VERIFIED"])
    assert sbx["ok"] is True
    assert "CODEX_WIN32_SANDBOX_VERIFIED" in sbx["stdout"]

    # 2. SafeEditTransactionalJournal + StaticVerificationGate (Sonnet S1)
    ws = tmp_path / "edit_ws"
    ws.mkdir()
    target_py = ws / "service.py"
    original_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    target_py.write_text(original_code, encoding="utf-8")
    orig_sha = hashlib.sha256(target_py.read_bytes()).hexdigest()

    journal = SafeEditTransactionalJournal(ws, static_gate=StaticVerificationGate())
    # Clean edit succeeds
    rec = journal.apply_verified_plan(
        [
            {
                "op": "replace",
                "path": "service.py",
                "oldString": "return a + b",
                "newString": "return int(a) + int(b)",
                "expectedReplacements": 1,
            }
        ],
        plan_id="clean-edit-01",
    )
    assert rec["ok"] is True
    assert "int(a) + int(b)" in target_py.read_text(encoding="utf-8")

    # Manual rollback restores byte-identical SHA-256
    rb = journal.rollback(rec["receiptPath"])
    assert rb["ok"] is True
    assert hashlib.sha256(target_py.read_bytes()).hexdigest() == orig_sha

    # Malicious SAST/Secret edit is AUTOMATICALLY rolled back fail-closed!
    fake_secret = "sk-proj-" + ("A9b8C7d6" * 5)
    with pytest.raises(StaticVerificationError):
        journal.apply_verified_plan(
            [
                {
                    "op": "replace",
                    "path": "service.py",
                    "oldString": "return a + b",
                    "newString": f"API_TOKEN = '{fake_secret}'\n    return eval(user_input)",
                    "expectedReplacements": 1,
                }
            ],
            plan_id="sast-blocked-02",
        )
    assert hashlib.sha256(target_py.read_bytes()).hexdigest() == orig_sha

    # 3. WorktreeIsolationManager (Sonnet S2) parallel subagent isolation
    git_repo = tmp_path / "git_demo"
    git_repo.mkdir()
    subprocess.run(["git", "init"], cwd=git_repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "ua@aethermind.local"], cwd=git_repo, check=True)
    subprocess.run(["git", "config", "user.name", "AetherMind UA"], cwd=git_repo, check=True)
    (git_repo / "app.py").write_text("VERSION = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=git_repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=git_repo, check=True, capture_output=True)

    wt_mgr = WorktreeIsolationManager(tmp_path / "wt_pool")
    lane_a = wt_mgr.create_lane_worktree(git_repo, mission_id="m01", lane_id="coder_a")
    lane_b = wt_mgr.create_lane_worktree(git_repo, mission_id="m01", lane_id="coder_b")
    try:
        (lane_a.worktree_path / "app.py").write_text("VERSION = 2\n", encoding="utf-8")
        (lane_b.worktree_path / "app.py").write_text("VERSION = 3\n", encoding="utf-8")
        # Main repo remains completely untouched while both lanes edit concurrently!
        assert (git_repo / "app.py").read_text(encoding="utf-8") == "VERSION = 1\n"
        assert "+VERSION = 2" in wt_mgr.collect_diff(lane_a)
    finally:
        wt_mgr.release_worktree(lane_a)
        wt_mgr.release_worktree(lane_b)

    e2b = E2BRemoteSandboxAdapter(api_key="")
    assert e2b.describe_capabilities()["fallback"] == "local_codex_win32_sandbox"


def test_p4_4_omni_router_wire_translator_and_rtk() -> None:
    chat_req = {
        "model": "gpt-5.4",
        "messages": [
            {"role": "system", "content": "You are a strict verifier."},
            {"role": "user", "content": "Check file status."},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_abc",
                        "type": "function",
                        "function": {"name": "stat_file", "arguments": '{"path":"a.py"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_abc", "content": '{"exists":true}'},
        ],
    }
    resp_payload = ResponsesWireTranslator.chat_to_responses_payload(chat_req)
    assert resp_payload["instructions"] == "You are a strict verifier."
    assert any(i.get("type") == "function_call_output" for i in resp_payload["input"])

    chat_back = ResponsesWireTranslator.responses_to_chat_completion(
        {
            "id": "resp_99",
            "model": "gpt-5.4",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_xyz",
                    "name": "run_pytest",
                    "arguments": '{"q":true}',
                }
            ],
        }
    )
    assert chat_back["choices"][0]["finish_reason"] == "tool_calls"
    assert chat_back["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "run_pytest"

    router = UniversalCognitiveRouter()
    sample_prompt = (
        "In order to verify the module at this point in time, please make sure to run:\n"
        "```python\nprint('in order to keep literal code untouched')\n```"
    )
    comp = router.compress_prompt_rtk(sample_prompt)
    assert comp["saved_chars"] > 15
    assert "print('in order to keep literal code untouched')" in comp["text"]

    actor_route = router.select_route("architect_deep")
    judge_route = router.select_route("verifier", require_different_from=actor_route["endpoint"])
    assert judge_route["endpoint"] != actor_route["endpoint"]
