"""Phase 2 Verification Tests — Vendor Sync, Win32 Hermes PTC/JobObjects, DSH/OpenHands & OMH."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
import pytest

from am_ua import PROJECT_ROOT
from am_ua.runtime import (
    AmortizedContextCondenser,
    ExperimentalArbitrator,
    OMHMaestroBridge,
    PersistentPwshSession,
    RepeatToolLoopBreaker,
    RepeatToolLoopError,
    SpillToDiskMiddleware,
)


def _ensure_synced() -> Path:
    root = Path(PROJECT_ROOT)
    sync_mod_dir = str(root / "tools")
    if sync_mod_dir not in sys.path:
        sys.path.insert(0, sync_mod_dir)
    import vendor_sync  # type: ignore[import-not-found]

    if not vendor_sync.verify_vendor_provenance():
        vendor_sync.sync_vendor_trees()
    assert vendor_sync.verify_vendor_provenance() is True
    return root / "vendor" / "hermes_agent"


def test_p2_1_and_p2_2_win32_job_object_kills_grandchild_tree_and_posix_shims() -> None:
    hermes_dir = _ensure_synced()
    if str(hermes_dir) not in sys.path:
        sys.path.insert(0, str(hermes_dir))

    from tools.win32_compat import Win32JobObject, flock_exclusive, flock_unlock  # type: ignore[import-not-found]

    # 1. File lock works natively via msvcrt
    lock_file = Path(r"F:\AetherMind_Temp\win32_lock_test.lck")
    lock_file.write_bytes(b"X")
    with lock_file.open("r+b") as fh:
        flock_exclusive(fh)
        flock_unlock(fh)
    lock_file.unlink(missing_ok=True)

    # 2. Win32JobObject kills child AND spawned grandchild Python sleeper!
    pid_file = Path(r"F:\AetherMind_Temp\grandchild_pid.txt")
    pid_file.unlink(missing_ok=True)
    parent_code = (
        "import subprocess, sys, time, pathlib\n"
        "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"pathlib.Path(r'{pid_file}').write_text(str(gc.pid))\n"
        "time.sleep(60)\n"
    )
    job = Win32JobObject()
    proc = subprocess.Popen([sys.executable, "-c", parent_code])
    assert job.assign_pid(proc.pid) is True

    deadline = time.monotonic() + 5.0
    while not pid_file.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.is_file()
    grandchild_pid = int(pid_file.read_text().strip())

    # Terminate job -> both parent and grandchild MUST die immediately!
    job.terminate(exit_code=1, fallback_pid=proc.pid)
    proc.wait(timeout=5)
    time.sleep(0.15)
    check = subprocess.run(
        ["tasklist", "/FI", f"PID eq {grandchild_pid}", "/NH"],
        capture_output=True,
        text=True,
    )
    assert str(grandchild_pid) not in check.stdout
    pid_file.unlink(missing_ok=True)


def test_p2_2_hermes_execute_code_ptc_runs_over_authenticated_win32_loopback() -> None:
    hermes_dir = _ensure_synced()
    if str(hermes_dir) not in sys.path:
        sys.path.insert(0, str(hermes_dir))

    import types
    # Provide lightweight stub/router for `model_tools.handle_function_call` & `tools.terminal_tool._get_env_config`
    # so we test the actual patched `code_execution_tool.execute_code` TCP+HMAC loopback transport end-to-end!
    import tools.code_execution_tool as cet  # type: ignore[import-not-found]

    assert cet.SANDBOX_AVAILABLE is True

    fake_mt = types.ModuleType("model_tools")

    def _mock_dispatch(tool_name: str, tool_args: dict, task_id: str | None = None) -> str:
        if tool_name == "read_file":
            return json.dumps({"content": f"WIN32_RPC_OK:{tool_args['path']}", "total_lines": 1})
        return json.dumps({"status": "ok"})

    fake_mt.handle_function_call = _mock_dispatch  # type: ignore[attr-defined]
    old_mt = sys.modules.get("model_tools")
    sys.modules["model_tools"] = fake_mt
    try:
        script = (
            "from hermes_tools import read_file\n"
            "res = read_file('F:/AetherMind_Universal_Agent/AGENTS.md')\n"
            "print(res['content'])\n"
        )
        raw_out = cet.execute_code(script, task_id="test_win32_ptc", enabled_tools=["read_file"])
        parsed = json.loads(raw_out)
        assert parsed["status"] == "success", f"PTC failed: {parsed}"
        assert "WIN32_RPC_OK:F:/AetherMind_Universal_Agent/AGENTS.md" in parsed["output"]
        assert parsed["tool_calls_made"] == 1
    finally:
        if old_mt is not None:
            sys.modules["model_tools"] = old_mt
        else:
            sys.modules.pop("model_tools", None)


def test_p2_3_and_p2_4_enhancers_omh_maestro_and_r10_arbitrator() -> None:
    _ensure_synced()

    # 1. Persistent PowerShell preserves variable across calls
    pwsh = PersistentPwshSession()
    try:
        r1 = pwsh.execute("$global:AM_VAR = 777; Write-Output 'SET_OK'")
        assert r1["exit_code"] == 0 and "SET_OK" in r1["output"]
        r2 = pwsh.execute("Write-Output ($global:AM_VAR + 23)")
        assert r2["exit_code"] == 0 and "800" in r2["output"]
    finally:
        pwsh.close()

    # 2. SpillToDiskMiddleware + chunked readback
    spill = SpillToDiskMiddleware(max_inline_chars=200)
    big = "A" * 500 + "MIDDLE_SECRET" + "B" * 500
    sp_res = spill.process_output("search_files", big)
    assert sp_res["spilled"] is True
    assert "MIDDLE_SECRET" in spill.read_chunk(sp_res["spill_id"], offset=490, limit=50)

    # 3. RepeatToolLoopBreaker
    breaker = RepeatToolLoopBreaker(max_identical_calls=3)
    breaker.record_and_check("grep", {"q": "foo"})
    breaker.record_and_check("grep", {"q": "foo"})
    with pytest.raises(RepeatToolLoopError):
        breaker.record_and_check("grep", {"q": "foo"})

    # 4. AmortizedContextCondenser
    condenser = AmortizedContextCondenser(head_keep=1, tail_keep=2, max_total_chars=100)
    msgs = [{"role": "user", "content": f"Message {i} " + ("x" * 40)} for i in range(8)]
    condensed = condenser.condense(msgs)
    assert len(condensed) == 4
    assert condensed[1]["condensed_count"] == 5

    # 5. OMHMaestroBridge unlocks host_browser_capability == True!
    omh = OMHMaestroBridge()
    with omh.bind_request_browser_identity(session_id="sess_live_01") as cap:
        assert cap["supported"] is True, f"Browser capability still locked: {cap}"
    lane = omh.resolve_lane("ultrabrain")
    assert lane["category"] == "ultrabrain"

    # 6. Astra R10 ExperimentalArbitrator overrules wrong majority vote via empirical oracle!
    arb = ExperimentalArbitrator()
    decision = arb.arbitrate(
        [
            {"candidate_id": "popular_buggy", "votes": 4, "val": 2 + 3},  # 4 models hallucinated 5 == 4
            {"candidate_id": "minority_correct", "votes": 1, "val": 4},
        ],
        oracle_fn=lambda c: {"passed": c["val"] == 4, "score": 1.0 if c["val"] == 4 else 0.0, "evidence": str(c["val"])},
    )
    assert decision["winner_id"] == "minority_correct"
    assert decision["majority_overruled"] is True
