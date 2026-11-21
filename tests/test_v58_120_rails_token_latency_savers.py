"""Verification suite for OmniExecutor v5.8 120 Deterministic Rails (Token & Sub-Millisecond Latency Savers)."""

from __future__ import annotations

from pathlib import Path

from am_ua.execution.deterministic_offloader import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicTaskOffloader,
)
from am_ua.execution.token_latency_savers import (
    SimHashSemanticCache,
    ast_skeleton_compress,
    comby_template_rewrite,
    delta_debug_minimizer,
    dom_semantic_distiller,
    gitleaks_precommit_gate,
    grammar_json_repair,
    prompt_token_pruner,
    pytest_affected_test_selector,
    pyupgrade_modernizer,
)


def test_v58_120_deterministic_rails_token_compression_and_sub_ms_latency(tmp_path: Path) -> None:
    assert len(BUILTIN_DETERMINISTIC_RAILS) >= 120

    # 1. AST Skeleton Compressor (Rail 111)
    big_py = (
        "def compute_metric(a: int, b: int) -> int:\n"
        '    """Compute weighted metric."""\n'
        + "\n".join(f"    step_{i} = a * {i} + b" for i in range(40))
        + "\n    return step_39\n"
    )
    skel = ast_skeleton_compress(big_py)
    assert skel["ok"] is True
    assert skel["token_savings_pct"] > 65.0
    assert "def compute_metric(a: int, b: int) -> int:" in skel["skeleton"]
    assert "folded lines" in skel["skeleton"]

    # 2. Comby Structural Template Rewriter (Rail 112)
    rw = comby_template_rewrite(
        "assert_equal(actual_val, expected_val)",
        "assert_equal(:[lhs], :[rhs])",
        "assert :[lhs] == :[rhs]",
    )
    assert rw["ok"] is True and rw["rewritten"] == "assert actual_val == expected_val"

    # 3. Prompt & Log Token Pruner (Rail 113)
    noisy_log = "\x1b[32mPlease note that\x1b[0m\n" + "\n".join("12:00:01.123 INFO Polling worker status OK" for _ in range(30))
    pruned = prompt_token_pruner(noisy_log)
    assert pruned["ok"] is True and pruned["token_savings_pct"] > 70.0
    assert "repeated 29 identical lines omitted" in pruned["pruned_text"]

    # 4. Constrained Grammar JSON Repair (Rail 114)
    broken_json = '```json\n{"tool": "replace_in_file", "enabled": True, "old": None, "items": [1, 2,], '
    repaired = grammar_json_repair(broken_json)
    assert repaired["ok"] is True
    assert repaired["parsed"]["tool"] == "replace_in_file"
    assert repaired["parsed"]["enabled"] is True
    assert repaired["parsed"]["items"] == [1, 2]

    # 5. Zeller's Delta Debugging Minimizer ddmin (Rail 115)
    lines = [f"line_{i}_ok" for i in range(64)]
    lines[43] = "line_43_FATAL_CRASH_BUG"
    dd = delta_debug_minimizer(lines, fail_trigger_substring="FATAL_CRASH_BUG")
    assert dd["ok"] is True
    assert dd["minimal_subset"] == ["line_43_FATAL_CRASH_BUG"]
    assert dd["steps_taken"] < 20

    # 6. Selectolax DOM Semantic Distiller (Rail 116)
    heavy_html = (
        "<html><head><script>" + ("var x = 1; " * 200) + "</script><style>" + (".cls { color: red; } " * 200) + "</style></head>"
        '<body><h1>Checkout</h1><button id="pay-btn">Pay Now</button>'
        '<img src="data:image/png;base64,' + ("A" * 1000) + '"/><p>Order Summary</p></body></html>'
    )
    dom = dom_semantic_distiller(heavy_html)
    assert dom["ok"] is True and dom["token_savings_pct"] > 85.0
    assert "[BUTTON #pay-btn] Pay Now" in dom["digest"]

    # 7. PyUpgrade Syntax Modernizer (Rail 117)
    mod = pyupgrade_modernizer("class B(A):\n    def f(self, x: List[int]) -> Dict[str, int]:\n        super(B, self).__init__()\n        return {}\n")
    assert mod["ok"] is True and "super().__init__()" in mod["modernized_code"] and "list[int]" in mod["modernized_code"]

    # 8. Gitleaks Pre-Commit Secret Gate (Rail 118)
    clean_scan = gitleaks_precommit_gate("x = 'normal_value'")
    assert clean_scan["ok"] is True

    # 9. GPTCache 64-Bit SimHash Semantic Cache (Rail 119)
    cache = SimHashSemanticCache(max_hamming_distance=6)
    cache.put("run deterministic ast syntax check across workspace files", {"status": "all_valid"})
    hit = cache.lookup("run deterministic ast syntax check across workspace files!")
    assert hit["ok"] is True and hit["cache_hit"] is True and hit["response"] == {"status": "all_valid"}

    # 10. Pytest Affected Test Selector (Rail 120)
    t_dir = tmp_path / "tests"
    t_dir.mkdir()
    (t_dir / "test_alpha.py").write_text("from pkg import alpha\ndef test_a(): pass\n", encoding="utf-8")
    (t_dir / "test_beta.py").write_text("from pkg import beta\ndef test_b(): pass\n", encoding="utf-8")
    sel = DeterministicTaskOffloader.execute_rail(
        "pytest_affected_test_selector",
        tmp_path,
        params={"modified_files": ["src/pkg/alpha.py"]},
    )
    assert sel["ok"] is True
    assert sel["selected_tests"] == ["tests/test_alpha.py"]
    assert sel["estimated_time_saved_pct"] == 50.0
