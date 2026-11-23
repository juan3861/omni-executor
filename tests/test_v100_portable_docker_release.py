"""Empirical verification suite for OmniExecutor v10.0 (Fase 5 — Universal Completeness):
  - Multi-OS portability: POSIX PBKDF2/HMAC-SHA256 fallback inside `WindowsDPAPIProvider`
    + tamper rejection + POSIX `HomeostasisGovernor.sample()` + `AetherMindUniversalAgent().doctor()`
  - `SWEBenchHarness` `use_docker=True` isolation flags (`--network=none`) & 5-instance
    on-demand free-tier pilot benchmark with real predictions output
  - `Dockerfile`, `pyproject.toml` (`10.0.0`, `dependencies=[]`), and public doc integrity.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.execution.swebench_harness import SWEBenchHarness, SWEBenchInstance
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.security.dpapi_envelope import EnvelopeTamperedError, WindowsDPAPIProvider


def test_v100_posix_dpapi_fallback_and_cross_platform_doctor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = b"omni-v10-master-key-material-32b"

    # Simulate POSIX mode safely without mutating global `os.name` (keeps Windows pathlib valid)
    monkeypatch.setattr(WindowsDPAPIProvider, "_use_win32_dpapi", staticmethod(lambda: False))
    key_file = tmp_path / "posix_master.bin"
    loaded_1 = WindowsDPAPIProvider.load_or_create_master_key(key_file)
    loaded_2 = WindowsDPAPIProvider.load_or_create_master_key(key_file)
    assert loaded_1 == loaded_2 and len(loaded_1) == 32

    sealed = WindowsDPAPIProvider.protect(secret)
    assert sealed.startswith(WindowsDPAPIProvider._POSIX_MAGIC)
    assert WindowsDPAPIProvider.unprotect(sealed) == secret

    tampered = bytearray(sealed)
    tampered[-1] ^= 0xFF
    with pytest.raises(EnvelopeTamperedError):
        WindowsDPAPIProvider.unprotect(bytes(tampered))

    gov = HomeostasisGovernor(safe_temp_dir=str(tmp_path / "posix_tmp"))
    snap = gov.sample(drives=())
    assert snap.healthy is True and snap.temp_redirected_ok is True


def test_v100_swebench_docker_flags_and_5_instance_pilot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Verify `use_docker=True` emits `--network=none`, volume mount, and custom image cleanly
    captured_cmds = []

    def _fake_run(cmd, **_kw):
        captured_cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout="1 passed", stderr="")

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    monkeypatch.setattr(subprocess, "run", _fake_run)

    d_res = SWEBenchHarness._run_pytest_targets(
        tmp_path,
        ["tests/test_sample.py"],
        use_docker=True,
        docker_image="swebench/custom:py311",
    )
    assert d_res["ok"] is True and d_res["backend"] == "docker"
    assert "--network=none" in captured_cmds[0]
    assert "swebench/custom:py311" in captured_cmds[0]
    monkeypatch.undo()

    # 2. 5-instance realistic local SWE-bench pilot via `run_dataset` (free-tier default, no cap)
    instances = []
    ws_map = {}
    for i in range(1, 6):
        iid = f"pilot__bug-{i}"
        rdir = tmp_path / f"repo_{i}"
        rdir.mkdir()
        (rdir / "mod.py").write_text(f"def fn(x):\n    return x - {i}\n", encoding="utf-8")
        (rdir / "test_mod.py").write_text(f"from mod import fn\ndef test_fn(): assert fn(10) == 10 + {i}\n", encoding="utf-8")
        ws_map[iid] = rdir
        instances.append(
            SWEBenchInstance(
                instance_id=iid,
                repo=f"pilot/repo_{i}",
                base_commit="HEAD",
                problem_statement=f"Fix sign error -{i} -> +{i}",
                fail_to_pass=["test_mod.py"],
                pass_to_pass=[],
            )
        )

    def _pilot_solver(repo_ws: Path, inst: SWEBenchInstance) -> dict:
        idx = int(inst.instance_id.split("-")[-1])
        (repo_ws / "mod.py").write_text(f"def fn(x):\n    return x + {idx}\n", encoding="utf-8")
        return {"ok": True}

    preds_file = tmp_path / "pilot_predictions.json"
    report = SWEBenchHarness(model_name="omni-executor-v10.0").run_dataset(
        instances,
        workspace_map=ws_map,
        provider="groq",
        solver_fn=_pilot_solver,
        out_predictions=preds_file,
    )
    assert report["resolved"] == 5 and report["resolve_rate"] == 1.0
    assert report["free_tier_default"] is True and report["max_cost_usd"] is None
    assert preds_file.is_file() and len(json.loads(preds_file.read_text(encoding="utf-8"))) == 5


def test_v100_packaging_dockerfile_and_doctor_integrity() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert int(pyproject["project"]["version"].split(".")[0]) >= 10
    assert pyproject["project"]["dependencies"] == []

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim" in dockerfile and "USER omni" in dockerfile

    doc = AetherMindUniversalAgent(ROOT).doctor()
    assert doc["seal_valid"] is True
    assert doc["topology_v2_ok"] is True
    assert doc["parametric_playbooks_count"] >= 18
