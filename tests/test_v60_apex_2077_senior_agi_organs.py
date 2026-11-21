"""Verification suite for OmniExecutor v6.0 Apex 2077 Senior AGI Deterministic Organs (135 Rails)."""

from __future__ import annotations

import ast
from pathlib import Path
import pytest

from am_ua.execution.apex_codeact_fuzzy import (
    AiderFuzzySearchReplaceEngine,
    CodeActASTSandbox,
    DirtyWorktreeSnapshotGuard,
    SeniorArchitectReadinessAuditor,
    analyze_import_layers,
    check_api_backward_compat,
    compute_pr_review_scorecard,
    parse_exception_traceback,
    strengthen_test_assertions,
)
from am_ua.execution.apex_fault_localizer import (
    AgentlessThreePhaseLocalizer,
    AutoCodeRoverASTGuardSynthesizer,
    OchiaiSBFLFaultLocalizer,
    SWEAgentWindowedACI,
)
from am_ua.execution.deterministic_offloader import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicTaskOffloader,
)


def test_v60_135_deterministic_rails_registered_and_nl_triggers() -> None:
    """Verify exactly 135 deterministic rails are registered and Domain I keyword triggers match."""
    assert len(BUILTIN_DETERMINISTIC_RAILS) == 135
    assert len(DeterministicTaskOffloader.list_rails()) == 135

    assert DeterministicTaskOffloader.match_zero_token_rail("run sbfl suspicious line ranking") == "sbfl_ochiai_fault_localize"
    assert DeterministicTaskOffloader.match_zero_token_rail("compute ochiai spectrum score") == "sbfl_ochiai_fault_localize"
    assert DeterministicTaskOffloader.match_zero_token_rail("run three phase localize on traceback") == "agentless_three_phase_localize"
    assert DeterministicTaskOffloader.match_zero_token_rail("run senior architect audit on repo") == "senior_architect_readiness_audit"
    assert DeterministicTaskOffloader.match_zero_token_rail("analyze traceback root cause") == "exception_root_cause_chain_parser"
    assert DeterministicTaskOffloader.match_zero_token_rail("run apex 2077 diagnostic sweep") == "apex_2077_full_diagnostic_sweep"


def test_v60_apex_fault_localizer_four_organs(tmp_path: Path) -> None:
    """Verify OchiaiSBFLFaultLocalizer, AgentlessThreePhaseLocalizer, AutoCodeRoverASTGuardSynthesizer, and SWEAgentWindowedACI."""
    # 1. OchiaiSBFLFaultLocalizer (Ochiai & Tarantula formulas + test-run format)
    sbfl = OchiaiSBFLFaultLocalizer()
    cov_specs = {
        "pkg/calc.py:10": {"ef": 4, "nf": 0, "ep": 0, "np": 6},
        "pkg/calc.py:20": {"ef": 2, "nf": 2, "ep": 3, "np": 3},
        "pkg/calc.py:30": {"ef": 0, "nf": 4, "ep": 5, "np": 1},
    }
    res_och = sbfl.rank_suspicious_lines(cov_specs, formula="ochiai")
    assert res_och["ok"] is True
    assert res_och["ranked"][0]["location"] == "pkg/calc.py:10"
    assert res_och["ranked"][0]["score"] == 1.0
    assert res_och["ranked"][-1]["score"] == 0.0

    res_tar = sbfl.rank_suspicious_lines(cov_specs, formula="tarantula")
    assert res_tar["ok"] is True
    assert res_tar["ranked"][0]["location"] == "pkg/calc.py:10"
    assert res_tar["ranked"][0]["score"] == 1.0

    test_runs = [
        {"passed": False, "lines": ["pkg/a.py:12", "pkg/a.py:15"]},
        {"passed": True, "lines": ["pkg/a.py:12", "pkg/a.py:40"]},
    ]
    res_runs = sbfl.rank_suspicious_lines(test_runs, formula="ochiai")
    assert res_runs["ok"] is True
    assert res_runs["ranked"][0]["location"] == "pkg/a.py:15"

    # 2. AgentlessThreePhaseLocalizer (Phase 1 ranking -> Phase 2 AST skeletons -> Phase 3 windows)
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    billing_py = pkg_dir / "billing_engine.py"
    billing_py.write_text(
        '"""Billing calculation module."""\n\n'
        "class InvoiceProcessor:\n"
        '    """Process customer invoices."""\n\n'
        "    def compute_unit_price(self, total_cents: int, quantity: int) -> float:\n"
        '        """Compute price per unit."""\n'
        "        return total_cents / quantity\n",
        encoding="utf-8",
    )
    (pkg_dir / "unrelated.py").write_text('"""Unrelated helper."""\ndef ping() -> str:\n    return "pong"\n', encoding="utf-8")

    tb_query = (
        'Traceback (most recent call last):\n'
        '  File "pkg/billing_engine.py", line 8, in compute_unit_price\n'
        '    return total_cents / quantity\n'
        'ZeroDivisionError: division by zero\n'
    )
    loc_res = AgentlessThreePhaseLocalizer().localize(tmp_path, query_or_traceback=tb_query, top_k_files=2, window=5)
    assert loc_res["ok"] is True
    assert loc_res["phase1_ranked_files"][0]["file"] == "pkg/billing_engine.py"
    assert "pkg/billing_engine.py" in loc_res["phase2_skeletons"]
    skel = loc_res["phase2_skeletons"]["pkg/billing_engine.py"]
    assert any(c["name"] == "InvoiceProcessor" for c in skel["classes"])
    assert any(w["file"] == "pkg/billing_engine.py" and "total_cents / quantity" in w["code"] for w in loc_res["phase3_windows"])

    # 3. AutoCodeRoverASTGuardSynthesizer (division, subscript, attribute guards)
    hazard_src = (
        "def process_record(payload: dict, divisor: int, client) -> float:\n"
        "    token = payload['token']\n"
        "    name = client.profile\n"
        "    return 100.0 / divisor\n"
    )
    guards = AutoCodeRoverASTGuardSynthesizer().synthesize_guards(hazard_src)
    assert guards["ok"] is True
    assert guards["candidates_count"] >= 3
    hazard_types = {c["hazard_type"] for c in guards["candidates"]}
    assert {"zero_division", "unsafe_subscript", "none_attribute"}.issubset(hazard_types)
    for cand in guards["candidates"]:
        assert cand["ast_valid"] is True
        ast.parse(cand["patched_source"])

    # 4. SWEAgentWindowedACI (open, goto_line, scroll_down, scroll_up, search_file, containment)
    long_file = tmp_path / "long_module.py"
    long_file.write_text("\n".join(f"line_{i} = {i}" for i in range(1, 61)) + "\n", encoding="utf-8")
    aci = SWEAgentWindowedACI()
    v1 = aci.open_file(tmp_path, "long_module.py", start_line=1, window=15)
    assert v1["ok"] is True
    assert "[File: long_module.py (60 lines total)]" in v1["header"]
    assert v1["start_line"] == 1 and v1["end_line"] == 15

    v2 = aci.scroll_down()
    assert v2["start_line"] == 16 and v2["end_line"] == 30

    v3 = aci.scroll_up()
    assert v3["start_line"] == 1 and v3["end_line"] == 15

    v4 = aci.goto_line(45)
    assert v4["start_line"] <= 45 <= v4["end_line"]

    s_res = aci.search_file("line_42")
    assert s_res["ok"] is True
    assert s_res["match_count"] == 1
    assert s_res["match_lines"] == [42]

    with pytest.raises(PermissionError):
        aci.open_file(tmp_path, "../outside_escape.py")


def test_v60_apex_codeact_fuzzy_snapshot_auditor_and_helpers(tmp_path: Path) -> None:
    """Verify Aider 4-level cascade, CodeAct AST sandbox safety, SnapshotGuard rollback, and Architect Auditor."""
    # 1. AiderFuzzySearchReplaceEngine across Levels 1, 2, 3, and 4
    target_py = tmp_path / "service.py"
    target_py.write_text(
        '"""Service module."""\n\n'
        "def alpha(x: int) -> int:   \n"
        "    return x + 1   \n\n"
        "class Worker:\n"
        "    def compute_value(self, item_count: int) -> int:\n"
        "        base_offset = 10\n"
        "        return item_count * base_offset\n",
        encoding="utf-8",
    )

    # Level 2: Trailing-whitespace difference
    r_l2 = AiderFuzzySearchReplaceEngine.apply_search_replace(
        tmp_path,
        file_path="service.py",
        search_block="def alpha(x: int) -> int:\n    return x + 1",
        replace_block="def alpha(x: int) -> int:\n    return x + 2",
        apply=True,
    )
    assert r_l2["ok"] is True and r_l2["match_level"] == 2

    # Level 3: Relative indentation difference (unindented search block matching 4-space class method)
    r_l3 = AiderFuzzySearchReplaceEngine.apply_search_replace(
        tmp_path,
        file_path="service.py",
        search_block="def compute_value(self, item_count: int) -> int:\n    base_offset = 10\n    return item_count * base_offset",
        replace_block="def compute_value(self, item_count: int) -> int:\n    base_offset = 25\n    return item_count * base_offset",
        apply=True,
    )
    assert r_l3["ok"] is True and r_l3["match_level"] == 3
    assert "        base_offset = 25" in target_py.read_text(encoding="utf-8")

    # Level 4: Fuzzy SequenceMatcher >= 0.92 (1 character typo in search block comment/identifier)
    target_py.write_text(
        '"""Service module."""\n\n'
        "def calculate_quarterly_revenue_summary(gross_amount: float, tax_rate: float) -> float:\n"
        "    adjusted_gross_amount = gross_amount * (1.0 - tax_rate)\n"
        "    return round(adjusted_gross_amount, 2)\n",
        encoding="utf-8",
    )
    r_l4 = AiderFuzzySearchReplaceEngine.apply_search_replace(
        tmp_path,
        file_path="service.py",
        search_block=(
            "def calculate_quarterly_revenue_summary(gross_amount: float, tax_rate: float) -> float:\n"
            "    adjusted_gross_amnt = gross_amount * (1.0 - tax_rate)\n"
            "    return round(adjusted_gross_amount, 2)"
        ),
        replace_block=(
            "def calculate_quarterly_revenue_summary(gross_amount: float, tax_rate: float) -> float:\n"
            "    adjusted_gross_amount = gross_amount * (1.0 - tax_rate)\n"
            "    return round(adjusted_gross_amount, 4)"
        ),
        apply=True,
    )
    assert r_l4["ok"] is True and r_l4["match_level"] == 4
    assert "round(adjusted_gross_amount, 4)" in target_py.read_text(encoding="utf-8")

    # SyntaxError pre-write rejection leaves file intact
    bad_patch = AiderFuzzySearchReplaceEngine.apply_search_replace(
        tmp_path,
        file_path="service.py",
        search_block="    return round(adjusted_gross_amount, 4)",
        replace_block="    return round(adjusted_gross_amount, ",
        apply=True,
    )
    assert bad_patch["ok"] is False and "SyntaxError" in bad_patch["error"]

    with pytest.raises(PermissionError):
        AiderFuzzySearchReplaceEngine.apply_search_replace(
            tmp_path,
            file_path="../escape.py",
            search_block="a",
            replace_block="b",
        )

    # 2. CodeActASTSandbox multi-tool execution & strict security rejections
    sandbox = CodeActASTSandbox(
        tools={
            "fetch_metrics": lambda: {"latency_ms": 12, "tokens_saved": 4500},
            "scale_score": lambda x, factor=2: x * factor,
        }
    )
    ok_script = (
        "m = fetch_metrics()\n"
        "lat = m.get('latency_ms', 0)\n"
        "tok = m['tokens_saved']\n"
        "final = scale_score(lat, factor=3) + tok\n"
        "final"
    )
    s_res = sandbox.execute_script(ok_script)
    assert s_res["ok"] is True
    assert s_res["last_result"] == 4536
    assert s_res["variables"]["final"] == 4536

    # Reject imports, dunder access, lambda, and non-whitelisted calls
    assert sandbox.execute_script("import os")["ok"] is False
    assert sandbox.execute_script("x = ().__class__")["ok"] is False
    assert sandbox.execute_script("fn = lambda a: a + 1")["ok"] is False
    assert sandbox.execute_script("open('secret.txt')")["ok"] is False

    # 3. DirtyWorktreeSnapshotGuard capture, status, and atomic rollback_all
    guard = DirtyWorktreeSnapshotGuard()
    existing_f = tmp_path / "tracked.py"
    existing_f.write_text("x = 1\n", encoding="utf-8")
    cap = guard.capture(tmp_path, ["tracked.py", "newly_created.py"])
    assert cap["ok"] is True and cap["tracked_count"] == 2
    assert guard.status()["clean"] is True

    existing_f.write_text("x = 999\n", encoding="utf-8")
    new_f = tmp_path / "newly_created.py"
    new_f.write_text("y = 2\n", encoding="utf-8")
    st_dirty = guard.status()
    assert st_dirty["clean"] is False
    assert "tracked.py" in st_dirty["modified_paths"]
    assert "newly_created.py" in st_dirty["created_paths"]

    rb = guard.rollback_all()
    assert rb["ok"] is True
    assert existing_f.read_text(encoding="utf-8") == "x = 1\n"
    assert not new_f.exists()
    assert guard.status()["clean"] is True

    # 4. SeniorArchitectReadinessAuditor & helpers (130-134)
    clean_pkg = tmp_path / "clean_mod.py"
    clean_pkg.write_text(
        '"""Clean module with full typing and docstrings."""\n\n'
        "def add_numbers(a: int, b: int) -> int:\n"
        '    """Add two integers deterministically."""\n'
        "    return a + b\n",
        encoding="utf-8",
    )
    audit_res = SeniorArchitectReadinessAuditor.audit(tmp_path, target="clean_mod.py")
    assert audit_res["ok"] is True
    assert audit_res["score"] == 100.0 and audit_res["grade"] == "S"

    layers = analyze_import_layers(tmp_path, target="clean_mod.py")
    assert layers["ok"] is True and layers["violation_count"] == 0

    weak_test = "def test_sample():\n    assert True\n    assert x\n    assert a == 1\n"
    st_assert = strengthen_test_assertions(weak_test)
    assert st_assert["ok"] is True and st_assert["weak_count"] == 2 and st_assert["strong_count"] == 1

    tb_parsed = parse_exception_traceback(
        'Traceback (most recent call last):\n'
        '  File "app/main.py", line 14, in run\n'
        '    process(data)\n'
        '  File "app/core.py", line 88, in process\n'
        '    raise ValueError("invalid payload")\n'
        'ValueError: invalid payload\n'
    )
    assert tb_parsed["ok"] is True
    assert tb_parsed["exception_class"] == "ValueError"
    assert tb_parsed["root_frame"]["file"] == "app/core.py" and tb_parsed["root_frame"]["line"] == 88

    compat_bad = check_api_backward_compat(
        "def connect(host: str, port: int = 80) -> bool:\n    return True\n",
        "def connect(host: str, port: int, tls: bool) -> bool:\n    return True\n",
    )
    assert compat_bad["ok"] is False and compat_bad["breaking_count"] >= 1

    scorecard = compute_pr_review_scorecard(
        tmp_path,
        old_source_map={"clean_mod.py": clean_pkg.read_text(encoding="utf-8")},
        new_source_map={"clean_mod.py": clean_pkg.read_text(encoding="utf-8")},
    )
    assert scorecard["ok"] is True and scorecard["approved"] is True and scorecard["score"] >= 90.0


def test_v60_execute_all_15_new_rails_via_offloader(tmp_path: Path) -> None:
    """Execute Rails 121 through 135 through DeterministicTaskOffloader.execute_rail."""
    mod_file = tmp_path / "engine.py"
    mod_file.write_text(
        '"""Engine module."""\n\n'
        "def divide_metric(numerator: float, denominator: float) -> float:\n"
        '    """Divide numerator by denominator."""\n'
        "    return numerator / denominator\n",
        encoding="utf-8",
    )

    # Rail 121: sbfl_ochiai_fault_localize
    r121 = DeterministicTaskOffloader.execute_rail(
        "sbfl_ochiai_fault_localize",
        tmp_path,
        params={"coverage_matrix": {"engine.py:5": {"ef": 3, "nf": 0, "ep": 0, "np": 5}}},
    )
    assert r121["ok"] is True and r121["ranked"][0]["location"] == "engine.py:5"

    # Rail 122: agentless_three_phase_localize
    r122 = DeterministicTaskOffloader.execute_rail(
        "agentless_three_phase_localize",
        tmp_path,
        params={"query_or_traceback": 'File "engine.py", line 5, in divide_metric\nZeroDivisionError'},
    )
    assert r122["ok"] is True and r122["phase1_ranked_files"][0]["file"] == "engine.py"

    # Rail 123: autocoderover_ast_guard_synth
    r123 = DeterministicTaskOffloader.execute_rail(
        "autocoderover_ast_guard_synth",
        tmp_path,
        params={"file_path": "engine.py", "target_line": 5},
    )
    assert r123["ok"] is True and r123["candidates_count"] >= 1

    # Rail 124: swe_agent_aci_window_view
    r124 = DeterministicTaskOffloader.execute_rail(
        "swe_agent_aci_window_view",
        tmp_path,
        params={"file_path": "engine.py", "goto_line": 3, "window": 10},
    )
    assert r124["ok"] is True and "divide_metric" in r124["content"]

    # Rail 125: swe_agent_aci_search_file
    r125 = DeterministicTaskOffloader.execute_rail(
        "swe_agent_aci_search_file",
        tmp_path,
        params={"file_path": "engine.py", "pattern": "divide_metric"},
    )
    assert r125["ok"] is True and r125["match_count"] == 1

    # Rail 128: dirty_worktree_snapshot_guard (capture before Rail 126 edit, then rollback)
    r128_cap = DeterministicTaskOffloader.execute_rail(
        "dirty_worktree_snapshot_guard",
        tmp_path,
        params={"action": "capture", "rel_paths": ["engine.py"], "reset": True},
    )
    assert r128_cap["ok"] is True and "engine.py" in r128_cap["captured"]

    # Rail 126: aider_fuzzy_search_replace
    r126 = DeterministicTaskOffloader.execute_rail(
        "aider_fuzzy_search_replace",
        tmp_path,
        params={
            "file_path": "engine.py",
            "search_block": "    return numerator / denominator",
            "replace_block": "    return 0.0 if denominator == 0 else (numerator / denominator)",
            "apply": True,
        },
    )
    assert r126["ok"] is True and r126["applied"] is True
    assert "0.0 if denominator == 0" in mod_file.read_text(encoding="utf-8")

    r128_st = DeterministicTaskOffloader.execute_rail(
        "dirty_worktree_snapshot_guard",
        tmp_path,
        params={"action": "status"},
    )
    assert r128_st["ok"] is True and r128_st["clean"] is False

    r128_rb = DeterministicTaskOffloader.execute_rail(
        "dirty_worktree_snapshot_guard",
        tmp_path,
        params={"action": "rollback_all"},
    )
    assert r128_rb["ok"] is True and r128_rb["rolled_back_count"] == 1

    # Rail 127: codeact_ast_multi_tool_run
    r127 = DeterministicTaskOffloader.execute_rail(
        "codeact_ast_multi_tool_run",
        tmp_path,
        params={
            "script_code": (
                "tb = parse_traceback('File \"engine.py\", line 5, in divide_metric\\nZeroDivisionError: div by 0')\n"
                "res = tb['exception_class']\n"
                "res"
            )
        },
    )
    assert r127["ok"] is True and r127["last_result"] == "ZeroDivisionError"

    # Rail 129: senior_architect_readiness_audit
    r129 = DeterministicTaskOffloader.execute_rail(
        "senior_architect_readiness_audit",
        tmp_path,
        params={"target": "engine.py"},
    )
    assert r129["ok"] is True and r129["score"] == 100.0

    # Rail 130: ast_import_dependency_layers
    r130 = DeterministicTaskOffloader.execute_rail(
        "ast_import_dependency_layers",
        tmp_path,
        params={"target": "."},
    )
    assert r130["ok"] is True and r130["violation_count"] == 0

    # Rail 131: deterministic_test_assertion_strengthener
    r131 = DeterministicTaskOffloader.execute_rail(
        "deterministic_test_assertion_strengthener",
        tmp_path,
        params={"source_code": "def test_x():\n    assert True\n"},
    )
    assert r131["ok"] is True and r131["weak_count"] == 1

    # Rail 132: exception_root_cause_chain_parser
    r132 = DeterministicTaskOffloader.execute_rail(
        "exception_root_cause_chain_parser",
        tmp_path,
        params={"traceback_text": 'File "engine.py", line 5, in divide_metric\nZeroDivisionError: zero'},
    )
    assert r132["ok"] is True and r132["exception_class"] == "ZeroDivisionError"

    # Rail 133: api_backward_compat_contract_gate
    r133 = DeterministicTaskOffloader.execute_rail(
        "api_backward_compat_contract_gate",
        tmp_path,
        params={
            "old_source": "def divide_metric(numerator: float, denominator: float) -> float: return 0.0\n",
            "new_source": "def divide_metric(numerator: float, denominator: float, scale: float = 1.0) -> float: return 0.0\n",
        },
    )
    assert r133["ok"] is True and r133["compatible"] is True

    # Rail 134: deterministic_pr_review_scorecard
    r134 = DeterministicTaskOffloader.execute_rail(
        "deterministic_pr_review_scorecard",
        tmp_path,
        params={
            "old_source_map": {"engine.py": mod_file.read_text(encoding="utf-8")},
            "new_source_map": {"engine.py": mod_file.read_text(encoding="utf-8")},
        },
    )
    assert r134["ok"] is True and r134["approved"] is True

    # Rail 135: apex_2077_full_diagnostic_sweep
    r135 = DeterministicTaskOffloader.execute_rail(
        "apex_2077_full_diagnostic_sweep",
        tmp_path,
        params={"target": "."},
    )
    assert r135["ok"] is True
    assert r135["total_deterministic_rails"] == 135
    assert r135["ast_syntax_sweep"]["ok"] is True
    assert r135["senior_architect_readiness_audit"]["score"] == 100.0
    assert r135["ast_import_dependency_layers"]["ok"] is True
    assert r135["gitleaks_precommit_gate"]["ok"] is True
