"""Phase 0 Verification Tests — Foundation, Compass, SealGuard & Homeostasis."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from am_ua import PROJECT_ROOT
from am_ua.governance import (
    ConstitutionSealGuard,
    ConstitutionalViolationError,
    HomeostasisGovernor,
    ResourceExhaustedError,
    casimir_collapse_force,
    compute_content_sha256,
)


def test_p0_1_workspace_and_beacons_exist() -> None:
    root = Path(PROJECT_ROOT)
    assert root.name == "AetherMind_Universal_Agent"
    for rel in ("pyproject.toml", "AGENTS.md", "CLAUDE.md", ".cursorrules", "START_HERE.md"):
        p = root / rel
        assert p.is_file() and p.stat().st_size > 0, f"Missing beacon {rel}"
    assert os.environ.get("TMP", "").upper().startswith("F:")


def test_p0_3_seal_guard_blocks_protected_and_untouchable_writes(tmp_path: Path) -> None:
    guard = ConstitutionSealGuard()
    # Agent cannot write to constitution/ or eval/
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_write_allowed("constitution/IMMUTABLE_CONSTITUTION.json", actor="agent")
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_write_allowed("eval/some_test.py", actor="evolver")
    # Agent cannot touch external untouchable repos
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_write_allowed(r"F:\rotor-llm\hack.txt", actor="agent")
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_write_allowed(r"D:\AetherRE_Megazord\hack.txt", actor="agent")
    # Hardware & remote push safety locks
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_command_safe("llama-server.exe -m model.gguf -ngl 99")
    with pytest.raises(ConstitutionalViolationError):
        guard.assert_command_safe("git push origin main")
    # Normal src/data writes inside project are allowed
    allowed = guard.assert_write_allowed("data/test_ok.json", actor="agent")
    assert str(allowed).startswith(str(guard.root))

    # Content SHA-256 changes even when file byte length & mtime match (fixes R2 P0 bug)
    f = Path( r"F:\AetherMind_Temp\canary_byte_check.txt" )
    f.write_bytes(b"AAAA")
    st = f.stat()
    h1 = compute_content_sha256(f)
    f.write_bytes(b"BBBB")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    h2 = compute_content_sha256(f)
    assert f.stat().st_size == st.st_size
    assert h1 != h2
    f.unlink(missing_ok=True)


def test_p0_4_homeostasis_casimir_and_economic_stop_loss() -> None:
    # Casimir attractive collapse force spikes when free ratio shrinks
    fc_safe = casimir_collapse_force(50, 100)     # d = 0.50
    fc_danger = casimir_collapse_force(5, 100)    # d = 0.05
    assert fc_danger < fc_safe < 0
    assert abs(fc_danger) > abs(fc_safe) * 1000

    gov = HomeostasisGovernor(max_tokens_budget=1000, max_stagnant_turns=3)
    snap = gov.assert_healthy()
    assert snap.healthy is True
    assert snap.temp_redirected_ok is True
    assert "F:" in snap.volumes
    assert snap.volumes["F:"].free_bytes > 1 * 1024**3

    # R09 Economic Stop-Loss halts stagnant loops
    gov.record_turn_cost(tokens=100, made_verified_progress=False)
    gov.record_turn_cost(tokens=100, made_verified_progress=False)
    with pytest.raises(ResourceExhaustedError, match="Stop-Loss"):
        gov.record_turn_cost(tokens=100, made_verified_progress=False)


def test_p0_2_master_phases_dag_is_valid_and_complete() -> None:
    master_file = Path(PROJECT_ROOT) / "project" / "MASTER_PHASES.json"
    data = json.loads(master_file.read_text(encoding="utf-8"))
    phases = data["phases"]
    assert len(phases) == 7
    seen_ids = set()
    for ph in phases:
        for sp in ph["subphases"]:
            for dep in sp["depends_on"]:
                assert dep in seen_ids, f"Dependency {dep} must precede {sp['id']}"
            seen_ids.add(sp["id"])
    assert len(seen_ids) == 27
