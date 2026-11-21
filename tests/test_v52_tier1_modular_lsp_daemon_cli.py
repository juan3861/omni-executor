"""v5.2 Top-Tier-1 Verification Suite: Modular loop_policies, Rail 28 (lsp_diagnostics), and CLI lsp/daemon/a2a."""

from __future__ import annotations

import json
from pathlib import Path


def test_v52_modular_loop_policies_and_rail28_lsp_diagnostics(tmp_path: Path) -> None:
    """Verify modular `loop_policies` extraction and Rail 28 (`lsp_diagnostics`) in DeterministicTaskOffloader."""
    from am_ua.execution import loop_policies
    from am_ua.execution.agent_loop import AgentLoop
    from am_ua.execution.deterministic_offloader import BUILTIN_DETERMINISTIC_RAILS, DeterministicTaskOffloader

    # 1. Modular extraction preserves 100% AgentLoop API parity
    assert AgentLoop.AGENT_STATE_TRANSITIONS is loop_policies.AGENT_STATE_TRANSITIONS
    assert AgentLoop.PLAN_MODE_FORBIDDEN_TOOLS is loop_policies.PLAN_MODE_FORBIDDEN_TOOLS
    assert AgentLoop.transition_state("PREFLIGHT", "ACT") == "ACT"
    assert loop_policies.validate_output_schema({"ok": True}, {"type": "object", "required": ["ok"]}) is None

    # 2. Rail 28 (lsp_diagnostics) registered & functional
    assert "lsp_diagnostics" in BUILTIN_DETERMINISTIC_RAILS
    assert len(BUILTIN_DETERMINISTIC_RAILS) >= 28

    ws = tmp_path / "lsp_rail_ws"
    ws.mkdir()
    (ws / "engine.py").write_text("class CoreEngine:\n    def run(self) -> int:\n        return 1\n", encoding="utf-8")
    (ws / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

    d_ok = DeterministicTaskOffloader.execute_rail("lsp_diagnostics", ws, params={"file_path": "engine.py"})
    assert d_ok["ok"] is True and d_ok["diagnostic_count"] == 0

    d_bad = DeterministicTaskOffloader.execute_rail("lsp_diagnostics", ws, params={"file_path": "bad.py"})
    assert d_bad["ok"] is False and d_bad["diagnostics"][0]["code"] == "SyntaxError"

    d_def = DeterministicTaskOffloader.execute_rail("lsp_diagnostics", ws, params={"symbol": "CoreEngine"})
    assert d_def["ok"] is True and d_def["locations"][0]["file"] == "engine.py"


def test_v52_cli_lsp_daemon_and_a2a_subcommands(tmp_path: Path, capsys) -> None:
    """Verify live CLI subcommands: `lsp`, `daemon`, and `a2a-serve --card-only`."""
    from am_ua.cli import main as cli_main

    ws = tmp_path / "cli_ws"
    ws.mkdir()
    (ws / "mod.py").write_text("def hello_tier1() -> str:\n    return 'tier1'\n", encoding="utf-8")

    # 1. CLI lsp definition
    rc = cli_main(["lsp", "definition", "hello_tier1", "--workspace", str(ws)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True and out["locations"][0]["file"] == "mod.py"

    # 2. CLI daemon enqueue -> stats -> claim
    db_path = tmp_path / "cli_daemon.db"
    rc_enq = cli_main(["daemon", "enqueue", "--objective", "Verify tier1", "--workspace", str(ws), "--db", str(db_path)])
    out_enq = json.loads(capsys.readouterr().out)
    assert rc_enq == 0 and out_enq["ok"] is True

    rc_st = cli_main(["daemon", "stats", "--db", str(db_path)])
    out_st = json.loads(capsys.readouterr().out)
    assert rc_st == 0 and out_st["stats"]["queued"] == 1

    rc_cl = cli_main(["daemon", "claim", "--worker-id", "w-ci", "--db", str(db_path)])
    out_cl = json.loads(capsys.readouterr().out)
    assert rc_cl == 0 and out_cl["ok"] is True and out_cl["task"]["task_id"] == out_enq["task_id"]

    # 3. CLI a2a-serve --card-only
    rc_a2a = cli_main(["a2a-serve", "--card-only"])
    out_a2a = json.loads(capsys.readouterr().out)
    assert rc_a2a == 0 and out_a2a["name"] == "omni-executor"
