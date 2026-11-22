"""OmniExecutor v7.0 Full-Spectrum 220-Rail, Real Host Silicon Telemetry & AgentLoop Scope Tests."""

from __future__ import annotations

import hashlib
import hmac
import base64
import json
from pathlib import Path
import struct

import pytest

from am_ua.execution.agent_loop import (
    ROLE_TOOL_SCOPES,
    RepeatToolLoopBreaker,
    RepeatToolLoopError,
    SYSTEM_PROMPT,
    TOOL_FAMILIES,
    rank_tools_for_objective,
    scrubbed_env,
)
from am_ua.execution.cpu_cache_telemetry import CPUCacheTopologyProbe
from am_ua.execution.deterministic_matrix_v70 import V70_60_SPECS, match_v70_60_rail
from am_ua.execution.deterministic_offloader import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicTaskOffloader,
)


def test_v70_total_deterministic_rails_reaches_220() -> None:
    assert len(V70_60_SPECS) == 60
    assert len(BUILTIN_DETERMINISTIC_RAILS) == 220
    for name in V70_60_SPECS:
        assert name in BUILTIN_DETERMINISTIC_RAILS
        assert BUILTIN_DETERMINISTIC_RAILS[name].name == name


def test_v70_agent_loop_prompt_reexports_and_scope_ranking(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "deterministic_exec" in SYSTEM_PROMPT
    assert "deterministic_preflight" in SYSTEM_PROMPT
    assert "strict_auditor" in ROLE_TOOL_SCOPES
    assert "core_code" in TOOL_FAMILIES
    ranked = rank_tools_for_objective("fix python pytest bug and edit file")
    assert isinstance(ranked, dict) and len(ranked["selected_tools"]) >= 3
    monkeypatch.setenv("OPENAI_API_KEY", "secret-val")
    env = scrubbed_env()
    assert "OPENAI_API_KEY" not in env
    breaker = RepeatToolLoopBreaker(window_size=8, max_identical_calls=2)
    breaker.record_and_check("read_file", {"path": "a.py"})
    with pytest.raises(RepeatToolLoopError):
        breaker.record_and_check("read_file", {"path": "a.py"})


def test_v70_live_silicon_cache_and_memory_bandwidth_probe(tmp_path: Path) -> None:
    hw = CPUCacheTopologyProbe.probe_live_host_cache()
    assert hw["ok"] is True
    assert hw["probe_source"] in {
        "win32_cim_silicon_probe",
        "linux_sysfs_silicon_probe",
        "portable_defaults",
    }
    assert hw["physical_cores"] >= 1
    assert hw["logical_cores"] >= 1
    assert hw["l1d_kb"] >= 16
    assert hw["l2_kb"] >= 64
    assert hw["l3_kb"] >= 512
    assert hw["optimal_fp64_tile_block_dim"] >= 16

    bw = CPUCacheTopologyProbe.measure_memory_hierarchy_bandwidth()
    assert bw["ok"] is True
    tiers = bw["tiers"]
    assert tiers["l1_16kb"]["bandwidth_mbps"] > 0.0
    assert tiers["l2_256kb"]["bandwidth_mbps"] > 0.0
    assert tiers["dram_4mb"]["bandwidth_mbps"] > 0.0

    r1 = DeterministicTaskOffloader.execute_rail("live_silicon_cpu_cache_probe", tmp_path)
    assert r1["ok"] is True and r1["l1d_kb"] >= 16
    r2 = DeterministicTaskOffloader.execute_rail("memory_hierarchy_bandwidth_probe", tmp_path)
    assert r2["ok"] is True and r2["tiers"]["l1_16kb"]["bandwidth_mbps"] > 0.0


def test_v70_tier_l_polyglot_ast_clones_and_supply_chain(tmp_path: Path) -> None:
    ts_code = """
export class OrderRouter { async handle() {} }
export async function dispatchTask(id: string) { return id; }
const healthCheck = async () => true;
"""
    r_ts = DeterministicTaskOffloader.execute_rail(
        "polyglot_js_ts_symbol_map",
        tmp_path,
        params={"source_code": ts_code},
    )
    assert r_ts["ok"] is True
    assert "dispatchTask" in r_ts["functions"]
    assert "OrderRouter" in r_ts["classes"]
    assert "healthCheck" in r_ts["arrow_handlers"]

    dup_block = "\n".join(
        [
            "def compute_item(val):",
            "    base = val * 2 + 10",
            "    adj = base // 3 + 7",
            "    normalized = adj % 997",
            "    return normalized + 42",
        ]
    )
    (tmp_path / "mod_a.py").write_text(dup_block + "\n", encoding="utf-8")
    (tmp_path / "mod_b.py").write_text(dup_block + "\n", encoding="utf-8")
    r_clone = DeterministicTaskOffloader.execute_rail(
        "code_clone_shingle_detector",
        tmp_path,
        params={"target": "."},
    )
    assert r_clone["ok"] is True and r_clone["duplicate_clusters"] >= 1


def test_v70_tier_n_windows_apps_media_and_electron_asar(tmp_path: Path) -> None:
    r_apps = DeterministicTaskOffloader.execute_rail("win_installed_apps_discovery", tmp_path)
    assert r_apps["ok"] is True and r_apps["count"] >= 0

    r_wcag = DeterministicTaskOffloader.execute_rail(
        "font_ui_accessibility_contrast",
        tmp_path,
        params={"fg": "#FFFFFF", "bg": "#0F172A"},
    )
    assert r_wcag["ok"] is True and r_wcag["wcag_aa"] is True and r_wcag["wcag_aaa"] is True

    hdr_json = json.dumps({"files": {"app.js": {"size": 42}, "package.json": {"size": 88}}}).encode("utf-8")
    asar_blob = struct.pack("<IIII", 4, len(hdr_json) + 8, len(hdr_json) + 4, len(hdr_json)) + hdr_json
    r_asar = DeterministicTaskOffloader.execute_rail(
        "electron_asar_manifest_probe",
        tmp_path,
        params={"asar_bytes": asar_blob},
    )
    assert r_asar["ok"] is True and r_asar["top_entries"] == ["app.js", "package.json"]


def test_v70_tier_o_bm25_ddl_jwt_merkle_and_full_spectrum_gate(tmp_path: Path) -> None:
    (tmp_path / "orchestrator.py").write_text(
        "class QuantumOrchestrator:\n    def route_deterministic_rail(self): pass\n",
        encoding="utf-8",
    )
    r_bm25 = DeterministicTaskOffloader.execute_rail(
        "bm25_workspace_fulltext_search",
        tmp_path,
        params={"target": ".", "query": "QuantumOrchestrator route_deterministic_rail"},
    )
    assert r_bm25["ok"] is True and r_bm25["hits"][0]["file"] == "orchestrator.py"

    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode("ascii")
    payload = base64.urlsafe_b64encode(b'{"sub":"agent_01","exp":4102444800}').rstrip(b"=").decode("ascii")
    sig = base64.urlsafe_b64encode(
        hmac.new(b"test-secret", f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    r_jwt = DeterministicTaskOffloader.execute_rail(
        "jwt_hs256_verify_signature",
        tmp_path,
        params={"token": f"{header}.{payload}.{sig}", "secret": "test-secret"},
    )
    assert r_jwt["ok"] is True and r_jwt["signature_valid"] is True

    r_merkle = DeterministicTaskOffloader.execute_rail(
        "merkle_proof_verify",
        tmp_path,
        params={"leaves": ["a", "b", "c", "d"]},
    )
    assert r_merkle["ok"] is True and len(r_merkle["merkle_root"]) == 64

    assert match_v70_60_rail("run omega 220 full spectrum gate") == "v70_omega_220_full_spectrum_gate"
    r_gate = DeterministicTaskOffloader.execute_rail("v70_omega_220_full_spectrum_gate", tmp_path)
    assert r_gate["ok"] is True
    assert r_gate["version"] == "7.0.0"
    assert r_gate["total_deterministic_rails"] == 220
    assert r_gate["v62_parity_ok"] is True
