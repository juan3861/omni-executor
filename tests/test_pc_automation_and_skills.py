"""Unit & Integration Tests for Complete PC Automation & Adaptive Skill Forge (Super-Union v3.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

from am_ua.cognition.llm_client import LLMResponse
from am_ua.execution.adaptive_skills import (
    AdaptiveSkillForge,
    SkillSecurityViolationError,
    audit_skill_ast,
)
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.execution.pc_automation import (
    DesktopProcessWindowOrgan,
    GroundedUIElement,
    PCAutomationEngine,
    RobocorpLocatorParser,
    SetOfMarkGrounder,
    TransactionalClipboard,
    compare_visual_signatures,
    compute_bbox_iou,
    compute_visual_dhash_2048,
    get_screen_resolution,
)


def test_robocorp_locator_parser_ast_and_or() -> None:
    query = 'name:"Salvar Arquivo" and type:ButtonControl or id:btn_save and depth:2'
    clauses = RobocorpLocatorParser.parse(query)
    assert len(clauses) == 2
    assert clauses[0].constraints == {"name": "Salvar Arquivo", "type": "ButtonControl"}
    assert clauses[1].constraints == {"id": "btn_save", "depth": 2}

    node_match_1 = {
        "name": "Salvar Arquivo",
        "control_type": "ButtonControl",
        "automation_id": "other",
        "depth": 5,
    }
    assert RobocorpLocatorParser.matches(node_match_1, clauses) is True

    node_match_2 = {
        "name": "Different",
        "control_type": "EditControl",
        "automation_id": "btn_save",
        "depth": 2,
    }
    assert RobocorpLocatorParser.matches(node_match_2, clauses) is True

    node_mismatch = {
        "name": "Different",
        "control_type": "EditControl",
        "automation_id": "btn_save",
        "depth": 3,
    }
    assert RobocorpLocatorParser.matches(node_mismatch, clauses) is False


def test_robocorp_locator_regex_and_path() -> None:
    clauses = RobocorpLocatorParser.parse('regex:"^Sci-Fi.*Antigravity" and path:1|0|2')
    node = {
        "name": "Sci-Fi Applications - Antigravity",
        "path": "1|0|2",
    }
    assert RobocorpLocatorParser.matches(node, clauses) is True

    with pytest.raises(ValueError, match="Unsupported locator field"):
        RobocorpLocatorParser.parse("invalid_field:123")


def test_som_grounder_iou_and_visual_dhash(tmp_path: Path) -> None:
    assert compute_bbox_iou((0, 0, 100, 100), (0, 0, 100, 100)) == 1.0
    assert compute_bbox_iou((0, 0, 50, 50), (100, 100, 150, 150)) == 0.0
    iou = compute_bbox_iou((0, 0, 100, 100), (50, 0, 150, 100))
    assert 0.33 <= iou <= 0.34

    grounder = SetOfMarkGrounder(tmp_path / "som")
    img, raw_path = grounder.capture_screen()
    assert raw_path.is_file()
    assert img.width > 0 and img.height > 0

    h1, vec1 = compute_visual_dhash_2048(img)
    assert len(h1) == 32
    assert len(vec1) == 2048
    cmp_same = compare_visual_signatures(vec1, vec1)
    assert cmp_same["cosine_similarity"] == 1.0
    assert cmp_same["change_magnitude"] == 0.0
    assert cmp_same["state_changed"] is False
    assert cmp_same["stalled"] is True

    # Test normalized [0, 1000] scaling (UI-TARS / Qwen2.5-VL standard)
    scr_w, scr_h = get_screen_resolution()
    px, py = grounder.scale_normalized_1000(500.0, 500.0)
    assert abs(px - scr_w // 2) <= 1
    assert abs(py - scr_h // 2) <= 1

    # Test Set-of-Mark fusion deduplicating overlapping OCR and UIA elements
    uia_list = [
        GroundedUIElement(
            tag_id=1,
            source="UIA",
            role="button",
            name="Confirmar",
            bbox=(100, 100, 220, 140),
            control_type="ButtonControl",
        )
    ]
    ocr_list = [
        # High overlap with UIA button -> should be deduplicated
        GroundedUIElement(
            tag_id=1,
            source="OCR",
            role="text",
            name="Confirmar",
            bbox=(102, 102, 218, 138),
        ),
        # Non-overlapping OCR text -> should be retained as tag [2]
        GroundedUIElement(
            tag_id=2,
            source="OCR",
            role="text",
            name="Status Online",
            bbox=(400, 300, 520, 330),
        ),
    ]
    fused, som_path = grounder.fuse_and_render_som(img, uia_list, ocr_list)
    assert len(fused) == 2
    assert fused[0].tag_id == 1 and fused[0].source == "UIA"
    assert fused[1].tag_id == 2 and fused[1].source == "OCR"
    assert som_path.is_file() and som_path.stat().st_size > 1000


def test_transactional_clipboard_unicode_and_preserve() -> None:
    cb = TransactionalClipboard()
    assert cb.set_text("Original_Clipboard_State_123") is True
    assert cb.get_text() == "Original_Clipboard_State_123"

    with cb.preserve():
        assert cb.set_text("Ação Crítica de Automação — Teto Ω") is True
        assert cb.get_text() == "Ação Crítica de Automação — Teto Ω"

    # Verify original clipboard was restored automatically upon exiting context
    assert cb.get_text() == "Original_Clipboard_State_123"


def test_desktop_window_and_process_organ_isolation_law() -> None:
    organ = DesktopProcessWindowOrgan()
    active = organ.get_active_window()
    assert isinstance(active, dict)
    assert "hwnd" in active

    wins = organ.list_windows(limit=20)
    assert isinstance(wins, list)
    assert len(wins) >= 1

    # Attempting to close an unowned window must be blocked by Isolation Law
    first_title = wins[0]["title"]
    res = organ.control_window(first_title, action="close")
    assert res["ok"] is False
    assert "Isolation Law" in res["error"]

    procs = organ.list_processes(name_filter="python", limit=10)
    assert len(procs) >= 1
    assert any("python" in p["name"].lower() for p in procs)

    port_info = organ.find_port_owner(65531)
    assert port_info["port"] == 65531
    assert isinstance(port_info["matches"], list)


def test_pc_automation_engine_safety_gate_and_paf_receipt(tmp_path: Path) -> None:
    engine = PCAutomationEngine(artifact_dir=tmp_path / "pc_auto")
    scr_w, scr_h = get_screen_resolution()

    # 1. Out of bounds blocked
    ok_oob, reason_oob = engine.verify_point_safety(-5, 200)
    assert ok_oob is False and "OUT_OF_BOUNDS" in reason_oob

    # 2. Protected zone (Start corner & Host close button) blocked
    ok_start, reason_start = engine.verify_point_safety(10, scr_h - 10)
    assert ok_start is False and "WINDOWS_START_SHUTDOWN_CORNER" in reason_start

    ok_close, reason_close = engine.verify_point_safety(scr_w - 10, 10)
    assert ok_close is False and "HOST_MAIN_WINDOW_CLOSE_BUTTON" in reason_close

    # 3. Safe center point allowed and generates DESKTOP_PAF_RECEIPT/v1
    res = engine.execute_gui_action(
        "click",
        norm_x=500.0,
        norm_y=500.0,
        dry_run=True,
    )
    assert res["ok"] is True
    rcpt = res["receipt"]
    assert rcpt["schema"] == "DESKTOP_PAF_RECEIPT/v1"
    assert rcpt["dry_run"] is True
    assert len(rcpt["receipt_digest"]) == 64

    # 4. Blocking Alt+F4 on unowned foreground window
    res_altf4 = engine.execute_gui_action("hotkey", keys=["alt", "f4"], dry_run=False)
    assert res_altf4["ok"] is False
    assert res_altf4.get("status") == "BLOCKED_BY_ISOLATION_LAW"


def test_adaptive_skill_forge_security_and_execution(tmp_path: Path) -> None:
    forge = AdaptiveSkillForge(tmp_path / "skills")

    # 1. AST Security Gate blocks eval / os.system / winreg
    bad_code_1 = "def evil_skill(x):\n    return eval(x)\n"
    with pytest.raises(SkillSecurityViolationError, match="eval"):
        forge.forge_skill("evil_skill", "Unsafe eval skill", bad_code_1)

    bad_code_2 = "import winreg\ndef reg_skill():\n    return 1\n"
    with pytest.raises(SkillSecurityViolationError, match="winreg"):
        forge.forge_skill("reg_skill", "Unsafe registry skill", bad_code_2)

    # 2. Forge a valid reusable skill with self-test
    valid_code = """
def compute_fibonacci_sum(n: int = 6) -> dict:
    a, b = 0, 1
    seq = []
    for _ in range(int(n)):
        seq.append(a)
        a, b = b, a + b
    return {"n": int(n), "sequence": seq, "sum": sum(seq)}
"""
    forged = forge.forge_skill(
        name="compute_fibonacci_sum",
        description="Compute the first N Fibonacci numbers and their sum",
        code=valid_code,
        tags=["math", "fibonacci", "automation"],
        test_kwargs={"n": 6},
    )
    assert forged["ok"] is True
    assert forged["test_executed"] is True
    assert forged["test_output"]["sum"] == 12  # 0+1+1+2+3+5 = 12

    # 3. Search and run skill
    matches = forge.search_skills("fibonacci numbers sum")
    assert len(matches) == 1
    assert matches[0]["name"] == "compute_fibonacci_sum"

    run_res = forge.run_skill("compute_fibonacci_sum", kwargs={"n": 8})
    assert run_res["ok"] is True
    assert run_res["result"]["sum"] == 33  # 0+1+1+2+3+5+8+13 = 33

    # 4. Tamper detection: modifying the .py file on disk invalidates SHA-256
    skill_path = Path(forged["skill"]["file_path"])
    skill_path.write_text(valid_code + "\n# tampered\n", encoding="utf-8")
    with pytest.raises(SkillSecurityViolationError, match="SHA-256 mismatch"):
        forge.run_skill("compute_fibonacci_sum", kwargs={"n": 5})


def test_agent_loop_pc_and_skill_tools_integration() -> None:
    import shutil
    ws = Path(r"F:\AetherMind_Temp\test_pc_skill_ws")
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir(parents=True, exist_ok=True)
    proof_file = ws / "pc_skill_proof.json"

    pc_engine = PCAutomationEngine(artifact_dir=ws / "pc_artifacts")
    skill_forge = AdaptiveSkillForge(ws / "adaptive_skills")
    engine = DurableExecutionEngine(ws / "durable.db")
    seal_guard = ConstitutionSealGuard()

    responses = [
        # Turn 1: Forge an adaptive skill
        json.dumps(
            {
                "thought": "Forge a reusable CSV stats skill",
                "tool": "skill_forge",
                "args": {
                    "name": "summarize_numbers",
                    "description": "Compute min, max, and total of a list of numbers",
                    "code": "def summarize_numbers(values: list) -> dict:\n    return {'count': len(values), 'total': sum(values), 'max': max(values)}\n",
                    "tags": ["stats", "math"],
                    "test_kwargs": {"values": [2, 4, 6]},
                },
            }
        ),
        # Turn 2: Run the forged skill
        json.dumps(
            {
                "thought": "Execute summarize_numbers on target dataset",
                "tool": "skill_run",
                "args": {
                    "name": "summarize_numbers",
                    "kwargs": {"values": [10, 20, 30, 40]},
                },
            }
        ),
        # Turn 3: Check active window via pc_window
        json.dumps(
            {
                "thought": "Inspect active desktop window",
                "tool": "pc_window",
                "args": {"action": "active"},
            }
        ),
        # Turn 4: Write verification artifact and finish
        json.dumps(
            {
                "thought": "Write output proof file",
                "tool": "write_file",
                "args": {"path": "pc_skill_proof.json", "content": "{\"total\": 100}"},
            }
        ),
        json.dumps(
            {
                "thought": "Mission complete",
                "tool": "finish",
                "args": {"summary": "Forged skill, inspected active window, and wrote proof."},
            }
        ),
        # Independent Judge turn
        json.dumps(
            {
                "verdict": "PASS",
                "confidence": 0.96,
                "rationale": "Skill forged, executed, and pc_skill_proof.json verified.",
            }
        ),
    ]
    idx = {"i": 0}

    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["mock_pc_actor", "mock_judge"]

        def chat(self, messages: List[Dict[str, str]], **_: Any) -> LLMResponse:
            out = responses[min(idx["i"], len(responses) - 1)]
            prov = "mock_judge" if idx["i"] == len(responses) - 1 else "mock_pc_actor"
            idx["i"] += 1
            self.calls += 1
            self.total_prompt_tokens += 50
            self.total_completion_tokens += 30
            return LLMResponse(
                text=out,
                provider=prov,
                model="mock-v1",
                prompt_tokens=50,
                completion_tokens=30,
                latency_ms=5.0,
            )

    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=FakeLLM(),  # type: ignore[arg-type]
        trace_dir=ws / "traces",
        agui_ledger_dir=ws / "agui",
        pc_engine=pc_engine,
        skill_forge=skill_forge,
    )
    res = loop.run(
        "Forge a number summary skill, inspect active window, and write pc_skill_proof.json",
        ws,
        verify_cmd="if (Test-Path pc_skill_proof.json) { exit 0 } else { exit 1 }",
        mission_id="test-pc-skill-loop",
    )
    assert res.status == "VERIFIED"
    assert res.verification is not None and res.verification["exit_code"] == 0
    assert proof_file.is_file()
    assert len(skill_forge.list_skills()) >= 1
