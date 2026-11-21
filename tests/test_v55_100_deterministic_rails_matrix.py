"""Verification tests for OmniExecutor v5.5 100-Rail Deterministic Matrix."""

from __future__ import annotations

from pathlib import Path

from am_ua.execution.deterministic_offloader import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicTaskOffloader,
)


def test_v55_exactly_100_deterministic_rails_registered(tmp_path: Path) -> None:
    assert len(BUILTIN_DETERMINISTIC_RAILS) >= 100
    rails_list = DeterministicTaskOffloader.list_rails()
    assert len(rails_list) >= 100

    # Test natural-language zero-token matching across new matrix domains
    assert DeterministicTaskOffloader.match_zero_token_rail("scan for dead code in project") == "dead_code_detector"
    assert DeterministicTaskOffloader.match_zero_token_rail("check cyclomatic complexity") == "cyclomatic_complexity_audit"
    assert DeterministicTaskOffloader.match_zero_token_rail("detect circular import cycles") == "circular_import_detector"
    assert DeterministicTaskOffloader.match_zero_token_rail("inspect pe header of binary") == "win_dll_pe_header_inspect"
    assert DeterministicTaskOffloader.match_zero_token_rail("calculate npv of cashflows") == "financial_irr_npv_calculator"


def test_v55_execute_matrix_rails_across_all_6_domains(tmp_path: Path) -> None:
    sample_py = tmp_path / "sample.py"
    sample_py.write_text(
        '"""Sample module."""\nimport math\nimport os\n\ndef used_fn(x: int) -> int:\n    if x > 0:\n        return x + 42\n    return 42\n\ndef unused_fn() -> int:\n    return used_fn(1)\n',
        encoding="utf-8",
    )

    # Domain A: Code Intelligence & AST
    r_cc = DeterministicTaskOffloader.execute_rail("cyclomatic_complexity_audit", tmp_path)
    assert r_cc["ok"] is True
    assert r_cc["functions_analyzed"] == 2

    r_dead = DeterministicTaskOffloader.execute_rail("dead_code_detector", tmp_path)
    assert r_dead["ok"] is True
    assert any(u["symbol"] == "unused_fn" for u in r_dead["unused"])

    r_fold = DeterministicTaskOffloader.execute_rail("constant_folding_optimizer", tmp_path, params={"expression": "10 * 20 + 5"})
    assert r_fold["ok"] is True and r_fold["folded_value"] == 205

    # Domain B: Git & DevOps
    r_sv = DeterministicTaskOffloader.execute_rail(
        "semver_bump_calculator",
        tmp_path,
        params={"current_version": "5.4.0", "commits": ["feat: expand to 100 deterministic rails"]},
    )
    assert r_sv["ok"] is True and r_sv["next_version"] == "5.5.0"

    # Domain C: DataFrames, Formats & Integrity
    r_csv = DeterministicTaskOffloader.execute_rail(
        "csv_schema_and_stats",
        tmp_path,
        params={"csv_text": "name,latency\nalpha,10.0\nbeta,20.0\ngamma,30.0\n"},
    )
    assert r_csv["ok"] is True
    assert r_csv["columns"]["latency"]["mean"] == 20.0

    # Domain D: Web, Browser & Document Intelligence
    r_html = DeterministicTaskOffloader.execute_rail(
        "html_table_to_json",
        tmp_path,
        params={"html": "<table><tr><th>Agent</th><th>Rails</th></tr><tr><td>OmniExecutor</td><td>100</td></tr></table>"},
    )
    assert r_html["ok"] is True
    assert r_html["rows"] == [["Agent", "Rails"], ["OmniExecutor", "100"]]

    r_url = DeterministicTaskOffloader.execute_rail(
        "url_normalizer_and_deparam",
        tmp_path,
        params={"url": "https://Example.com/docs?utm_source=x&id=7&fbclid=99"},
    )
    assert r_url["ok"] is True and r_url["normalized"] == "https://example.com/docs?id=7"

    # Domain E: Windows OS & Binary Inspection
    r_pe = DeterministicTaskOffloader.execute_rail(
        "win_dll_pe_header_inspect",
        tmp_path,
        params={"pe_bytes": b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00\x64\x86"},
    )
    assert r_pe["ok"] is True and r_pe["architecture"] == "x86_64"

    # Domain F: Security, Crypto, Math & Batch Pipeline
    r_pii = DeterministicTaskOffloader.execute_rail(
        "pii_redaction_rail",
        tmp_path,
        params={"text": "Contact user@example.com or CPF 123.456.789-00"},
    )
    assert r_pii["ok"] is True
    assert "[REDACTED_EMAIL]" in r_pii["redacted_text"]
    assert "[REDACTED_CPF]" in r_pii["redacted_text"]

    r_npv = DeterministicTaskOffloader.execute_rail(
        "financial_irr_npv_calculator",
        tmp_path,
        params={"discount_rate": "0.10", "cashflows": ["-100", "110"]},
    )
    assert r_npv["ok"] is True and r_npv["npv"] == "0.0000"

    r_pipe = DeterministicTaskOffloader.execute_rail(
        "deterministic_batch_pipeline",
        tmp_path,
        params={
            "steps": [
                {"rail": "ast_syntax_sweep"},
                {"rail": "docstring_coverage_audit"},
                {"rail": "checksum_manifest_generator"},
            ]
        },
    )
    assert r_pipe["ok"] is True and r_pipe["steps_executed"] == 3
