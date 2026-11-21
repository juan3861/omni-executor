"""v5.3 Verification Suite: 31 Deterministic Rails (Windows, Browser, Patch), SWEBenchHarness, Daemon Worker & workspace_fs."""

from __future__ import annotations

import json
from pathlib import Path


def test_v53_three_pillars_deterministic_rails_windows_browser_and_patch(tmp_path: Path) -> None:
    """Verify Rails 29, 30, 31 (`windows_system_rail`, `browser_playbook_rail`, `patch_validate_and_apply`)."""
    from am_ua.execution.deterministic_offloader import BUILTIN_DETERMINISTIC_RAILS, DeterministicTaskOffloader

    assert len(BUILTIN_DETERMINISTIC_RAILS) >= 31
    assert {"windows_system_rail", "browser_playbook_rail", "patch_validate_and_apply"} <= set(BUILTIN_DETERMINISTIC_RAILS)

    # 1. Pillar 1: Windows Desktop & OS deterministic rail
    win_res = DeterministicTaskOffloader.execute_rail("windows_system_rail", tmp_path, params={"sub_action": "storage_health"})
    assert win_res["ok"] is True and "casimir" in win_res and "regime_state" in win_res["casimir"]

    # 2. Pillar 2: Browser & Web deterministic rail (HTML DOM extraction + domain check)
    (tmp_path / "portal.html").write_text(
        '<html><body><a id="nav1" href="/dashboard">Go</a>'
        '<input id="user_in" name="user" type="text"/>'
        '<button id="btn_ok" type="submit">Submit</button></body></html>',
        encoding="utf-8",
    )
    br_dom = DeterministicTaskOffloader.execute_rail(
        "browser_playbook_rail",
        tmp_path,
        params={"sub_action": "extract_links_forms", "file_path": "portal.html"},
    )
    assert br_dom["ok"] is True and br_dom["link_count"] == 1 and br_dom["input_count"] == 1 and br_dom["button_count"] == 1

    br_guard = DeterministicTaskOffloader.execute_rail(
        "browser_playbook_rail",
        tmp_path,
        params={"sub_action": "domain_check", "url": "https://10.0.0.1/admin", "allowed_domains": ["example.com"]},
    )
    assert br_guard["ok"] is False and br_guard["allowed"] is False

    # 3. Pillar 3: Atomic AST-verified patch rail (`patch_validate_and_apply`)
    py_f = tmp_path / "calc.py"
    py_f.write_text("def mul(a, b):\n    return a + b\n", encoding="utf-8")

    # Rejects broken syntax without touching disk
    bad_p = DeterministicTaskOffloader.execute_rail(
        "patch_validate_and_apply",
        tmp_path,
        params={"file_path": "calc.py", "old_text": "return a + b", "new_text": "return a * (", "apply": True},
    )
    assert bad_p["ok"] is False and bad_p["applied"] is False
    assert "return a + b" in py_f.read_text(encoding="utf-8")

    # Applies valid patch atomically
    good_p = DeterministicTaskOffloader.execute_rail(
        "patch_validate_and_apply",
        tmp_path,
        params={"file_path": "calc.py", "old_text": "return a + b", "new_text": "return a * b", "apply": True},
    )
    assert good_p["ok"] is True and good_p["applied"] is True
    assert "return a * b" in py_f.read_text(encoding="utf-8")


def test_v53_swebench_harness_daemon_worker_and_workspace_fs(tmp_path: Path, capsys) -> None:
    """Verify SWEBenchHarness (FAIL_TO_PASS + PASS_TO_PASS + predictions.json), DurableDaemonQueue worker, and workspace_fs."""
    from am_ua.cli import main as cli_main
    from am_ua.execution.swebench_harness import SWEBenchHarness, SWEBenchInstance
    from am_ua.execution.workspace_fs import apply_hunks_safely, strip_code_fences
    from am_ua.runtime.daemon_queue import DurableDaemonQueue

    # 1. SWEBenchHarness end-to-end
    ws = tmp_path / "swe_ws"
    ws.mkdir()
    (ws / "math_lib.py").write_text("def clamp_pos(x: int) -> int:\n    return x\n", encoding="utf-8")
    (ws / "test_math.py").write_text(
        "from math_lib import clamp_pos\n"
        "def test_positive():\n    assert clamp_pos(5) == 5\n"
        "def test_negative_clamped():\n    assert clamp_pos(-3) == 0\n",
        encoding="utf-8",
    )

    inst = SWEBenchInstance.from_dict({
        "instance_id": "omni__math-lib-001",
        "repo": "omni/math-lib",
        "base_commit": "abc1234",
        "problem_statement": "clamp_pos(x) must return 0 when x < 0.",
        "FAIL_TO_PASS": ["test_math.py::test_negative_clamped"],
        "PASS_TO_PASS": ["test_math.py::test_positive"],
    })
    harness = SWEBenchHarness(model_name="omni-executor-v5.3")

    def _solver(w: Path, _i: SWEBenchInstance) -> None:
        (w / "math_lib.py").write_text("def clamp_pos(x: int) -> int:\n    return max(0, x)\n", encoding="utf-8")

    rec = harness.evaluate_instance(inst, ws, _solver)
    assert rec["resolved"] is True and rec["fail_to_pass_ok"] is True and rec["pass_to_pass_ok"] is True
    assert "+    return max(0, x)" in rec["model_patch"]

    pred_file = tmp_path / "predictions.json"
    harness.export_predictions([rec], pred_file)
    rc_swe = cli_main(["swebench", "validate-predictions", str(pred_file)])
    out_swe = json.loads(capsys.readouterr().out)
    assert rc_swe == 0 and out_swe["ok"] is True and out_swe["count"] == 1

    # 2. DurableDaemonQueue recover_stale_leases & run_worker_once
    q = DurableDaemonQueue(tmp_path / "worker.db")
    t1 = q.enqueue("Stale task", str(ws), priority=90, scheduled_at=900.0)
    claimed = q.claim_next("dead-worker", now_ts=1000.0)
    assert claimed is not None and claimed["task_id"] == t1
    recovered = q.recover_stale_leases(stale_after_s=60.0, now_ts=1200.0)
    assert recovered == 1

    w_res = q.run_worker_once("live-worker", executor_fn=lambda t: {"ok": True, "handled": t["task_id"]})
    assert w_res["ok"] is True and w_res["status"] == "completed"
    assert q.stats()["completed"] == 1

    # 3. Modular workspace_fs
    assert strip_code_fences("```python\nx = 1\n```") == "x = 1\n"
    patched_txt, err = apply_hunks_safely("a = 1\n", [("a = 1", "a = 2\\nb = 3")], is_python=True)
    assert err is None and "a = 2\nb = 3" in patched_txt
