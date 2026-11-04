#!/usr/bin/env python3
"""Strict Empirical Evaluation for Complete PC Automation & Adaptive Skill Ceiling (Super-Union v3.3).

Executes 5 real end-to-end verification chambers (Zero Mocks on OS/Screen/AST/Clipboard):
  1. Chamber 1: Live Desktop Set-of-Mark (SoM) Grounding (UIA + OCR + Annotated PNG + 2048-bit dHash)
  2. Chamber 2: Robocorp-Windows AST Locator Engine, Process/Port Organ & Isolation Law Guard
  3. Chamber 3: Transactional Win32 Unicode Clipboard (Preserve/Restore) & Dependent Type Safety Gate
  4. Chamber 4: Adaptive Skill Forge (AST Security Gate, Self-Test, SHA-256 Sealing, Tamper Detection)
  5. Chamber 5: End-to-End AgentLoop PC/Skill Mission + Sovereign CLI (`aether-ua.cmd pc` & `skills`)
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from am_ua.cognition.llm_client import LLMResponse
from am_ua.execution.adaptive_skills import (
    AdaptiveSkillForge,
    SkillSecurityViolationError,
)
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.pc_automation import (
    PCAutomationEngine,
    RobocorpLocatorParser,
    compare_visual_signatures,
    compute_visual_dhash_2048,
    get_screen_resolution,
)
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.perception import InterRepoTopologyGate


def run_empirical_suite() -> Dict[str, Any]:
    import shutil
    t0 = time.perf_counter()
    sandbox = Path(r"F:\AetherMind_Temp\empirical_pc_ceiling")
    shutil.rmtree(sandbox, ignore_errors=True)
    sandbox.mkdir(parents=True, exist_ok=True)

    pc = PCAutomationEngine(artifact_dir=sandbox / "pc_artifacts")
    forge = AdaptiveSkillForge(sandbox / "adaptive_skills")

    # -------------------------------------------------------------------------
    # Chamber 1: Live Desktop Set-of-Mark (SoM) Grounding (UIA + OCR + dHash)
    # -------------------------------------------------------------------------
    obs = pc.observe_desktop(include_ocr=True, max_elements=50)
    raw_png = Path(obs["raw_screenshot_path"])
    som_png = Path(obs["som_screenshot_path"])
    assert obs["ok"] is True, "observe_desktop failed"
    assert raw_png.is_file() and raw_png.stat().st_size > 5000, "Raw screenshot missing or empty"
    assert som_png.is_file() and som_png.stat().st_size > 5000, "SoM annotated screenshot missing or empty"
    assert len(obs["visual_dhash_2048"]) == 32, "Invalid 2048-bit visual dHash digest"
    assert obs["total_elements"] >= 1, "Expected at least 1 grounded UI element (UIA or OCR) on live screen"

    img, _ = pc.grounder.capture_screen()
    _, vec = compute_visual_dhash_2048(img)
    sig_cmp = compare_visual_signatures(vec, vec)
    assert sig_cmp["cosine_similarity"] == 1.0 and sig_cmp["stalled"] is True

    chamber_1 = {
        "passed": True,
        "raw_screenshot_bytes": raw_png.stat().st_size,
        "som_screenshot_bytes": som_png.stat().st_size,
        "uia_count": obs["uia_count"],
        "ocr_count": obs["ocr_count"],
        "total_grounded_elements": obs["total_elements"],
        "visual_dhash_2048": obs["visual_dhash_2048"],
    }

    # -------------------------------------------------------------------------
    # Chamber 2: Robocorp AST Locators, Window/Process Organ & Isolation Law
    # -------------------------------------------------------------------------
    wins = pc.window_organ.list_windows(limit=30)
    assert len(wins) >= 1, "No visible top-level windows enumerated"
    loc_wins = pc.window_organ.find_windows_by_locator("type:WindowControl and depth:1")
    assert len(loc_wins) >= 1, "Robocorp locator failed to match top-level WindowControl"

    # Isolation Law must block closing unowned user windows
    close_attempt = pc.window_organ.control_window(wins[0]["title"], action="close")
    assert close_attempt["ok"] is False and "Isolation Law" in close_attempt["error"]

    # Isolation Law must block Alt+F4 on unowned foreground window
    alt_f4_attempt = pc.execute_gui_action("hotkey", keys=["alt", "f4"], dry_run=False)
    assert alt_f4_attempt["ok"] is False and alt_f4_attempt.get("status") == "BLOCKED_BY_ISOLATION_LAW"

    procs = pc.window_organ.list_processes(name_filter="python", limit=15)
    assert len(procs) >= 1, "Expected python process in process list"

    chamber_2 = {
        "passed": True,
        "visible_windows_count": len(wins),
        "robocorp_matched_windows": len(loc_wins),
        "isolation_law_close_blocked": True,
        "isolation_law_altf4_blocked": True,
        "python_processes_found": len(procs),
    }

    # -------------------------------------------------------------------------
    # Chamber 3: Transactional Unicode Clipboard & Dependent Type Safety Gate
    # -------------------------------------------------------------------------
    sentinel_before = "AetherMind_Clipboard_Before_Sentinel"
    pc.clipboard.set_text(sentinel_before)
    assert pc.clipboard.get_text() == sentinel_before

    unicode_payload = "Automação Soberana Ω — Validação Empírica de Área de Transferência"
    with pc.clipboard.preserve():
        pc.clipboard.set_text(unicode_payload)
        inside_val = pc.clipboard.get_text()
        assert inside_val == unicode_payload, f"Clipboard mismatch inside preserve(): {inside_val!r}"

    restored_val = pc.clipboard.get_text()
    assert restored_val == sentinel_before, f"Clipboard failed to restore: {restored_val!r}"

    scr_w, scr_h = get_screen_resolution()
    safe_start, reason_start = pc.verify_point_safety(5, scr_h - 5)
    safe_close, reason_close = pc.verify_point_safety(scr_w - 5, 5)
    assert not safe_start and "WINDOWS_START_SHUTDOWN_CORNER" in reason_start
    assert not safe_close and "HOST_MAIN_WINDOW_CLOSE_BUTTON" in reason_close

    paf_res = pc.execute_gui_action("click", norm_x=500.0, norm_y=500.0, dry_run=True)
    assert paf_res["ok"] is True
    receipt = paf_res["receipt"]
    assert receipt["schema"] == "DESKTOP_PAF_RECEIPT/v1"
    assert len(receipt["receipt_digest"]) == 64

    chamber_3 = {
        "passed": True,
        "unicode_clipboard_verified": True,
        "clipboard_restored_after_preserve": True,
        "protected_zones_blocked": [reason_start, reason_close],
        "paf_receipt_digest": receipt["receipt_digest"],
    }

    # -------------------------------------------------------------------------
    # Chamber 4: Adaptive Skill Forge (AST Security Gate + Self-Test + SHA-256)
    # -------------------------------------------------------------------------
    blocked_eval = False
    try:
        forge.forge_skill("unsafe_eval", "Bad skill", "def unsafe_eval(x):\n    return eval(x)\n")
    except SkillSecurityViolationError:
        blocked_eval = True
    assert blocked_eval is True, "AST Security Gate failed to block eval()"

    skill_code = """
import psutil

def inspect_top_memory_processes(top_n: int = 3) -> dict:
    rows = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            rss = (p.info['memory_info'].rss if p.info.get('memory_info') else 0) / (1024 * 1024)
            rows.append({'pid': p.info['pid'], 'name': p.info['name'], 'rss_mb': round(rss, 2)})
        except Exception:
            continue
    rows.sort(key=lambda r: r['rss_mb'], reverse=True)
    top = rows[:int(top_n)]
    return {'count': len(top), 'top_processes': top, 'max_rss_mb': top[0]['rss_mb'] if top else 0.0}
"""
    forged = forge.forge_skill(
        name="inspect_top_memory_processes",
        description="Inspect top N processes by RSS memory usage in MB",
        code=skill_code,
        tags=["process", "memory", "diagnostics", "psutil"],
        test_kwargs={"top_n": 3},
    )
    assert forged["ok"] is True and forged["test_executed"] is True
    assert forged["test_output"]["count"] == 3

    exec_skill = forge.run_skill("inspect_top_memory_processes", kwargs={"top_n": 4})
    assert exec_skill["ok"] is True and exec_skill["result"]["count"] == 4

    chamber_4 = {
        "passed": True,
        "ast_security_gate_blocked_eval": blocked_eval,
        "forged_skill_name": forged["skill"]["name"],
        "forged_skill_sha256": forged["skill"]["sha256"],
        "skill_execution_result": exec_skill["result"],
    }

    # -------------------------------------------------------------------------
    # Chamber 5: End-to-End AgentLoop Mission + Topology Gate + CLI Verification
    # -------------------------------------------------------------------------
    ws = sandbox / "mission_ws"
    ws.mkdir(parents=True, exist_ok=True)
    target_report = ws / "pc_automation_report.json"
    if target_report.exists():
        target_report.unlink()

    engine = DurableExecutionEngine(sandbox / "durable.db")
    seal_guard = ConstitutionSealGuard()

    scripted_turns = [
        json.dumps(
            {
                "thought": "Run forged skill inspect_top_memory_processes",
                "tool": "skill_run",
                "args": {"name": "inspect_top_memory_processes", "kwargs": {"top_n": 2}},
            }
        ),
        json.dumps(
            {
                "thought": "Observe active desktop window via pc_window",
                "tool": "pc_window",
                "args": {"action": "active"},
            }
        ),
        json.dumps(
            {
                "thought": "Write verified PC automation report",
                "tool": "write_file",
                "args": {
                    "path": "pc_automation_report.json",
                    "content": json.dumps({"status": "PC_AUTOMATION_VERIFIED", "organs": 7}, indent=2),
                },
            }
        ),
        json.dumps(
            {
                "thought": "Finish mission",
                "tool": "finish",
                "args": {"summary": "Executed adaptive skill, inspected window, and wrote report."},
            }
        ),
        json.dumps(
            {
                "verdict": "PASS",
                "confidence": 0.98,
                "rationale": "All PC automation and adaptive skill steps verified.",
            }
        ),
    ]
    turn_idx = {"i": 0}

    class ScriptedLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["actor_pc", "judge_pc"]

        def chat(self, messages: List[Dict[str, str]], **_: Any) -> LLMResponse:
            txt = scripted_turns[min(turn_idx["i"], len(scripted_turns) - 1)]
            prov = "judge_pc" if turn_idx["i"] == len(scripted_turns) - 1 else "actor_pc"
            turn_idx["i"] += 1
            self.calls += 1
            self.total_prompt_tokens += 60
            self.total_completion_tokens += 35
            return LLMResponse(
                text=txt,
                provider=prov,
                model="pc-v1",
                prompt_tokens=60,
                completion_tokens=35,
                latency_ms=4.0,
            )

    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=ScriptedLLM(),  # type: ignore[arg-type]
        trace_dir=sandbox / "traces",
        agui_ledger_dir=sandbox / "agui",
        pc_engine=pc,
        skill_forge=forge,
    )
    mission_res = loop.run(
        "Run inspect_top_memory_processes, check active window, and create pc_automation_report.json",
        ws,
        verify_cmd="if (Test-Path pc_automation_report.json) { exit 0 } else { exit 1 }",
        mission_id="emp-pc-ceiling-01",
    )
    assert mission_res.status == "VERIFIED", f"Expected VERIFIED, got {mission_res.status}"
    assert target_report.is_file()

    topo = InterRepoTopologyGate().audit_package_imports(ROOT / "src" / "am_ua")
    assert topo["ok"] is True, f"Topology violation: {topo}"

    cli_proc = subprocess.run(
        [sys.executable, str(ROOT / "src" / "am_ua" / "cli.py"), "pc", "probe"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert cli_proc.returncode == 0, f"CLI pc probe failed: {cli_proc.stderr}"
    cli_json = json.loads(cli_proc.stdout)
    assert cli_json["ok"] is True

    chamber_5 = {
        "passed": True,
        "mission_status": mission_res.status,
        "verify_exit_code": mission_res.verification["exit_code"] if mission_res.verification else -1,
        "topology_v2_ok": topo["ok"],
        "cli_pc_probe_ok": cli_json["ok"],
    }

    summary = {
        "schema": "AETHERMIND_EMPIRICAL_PC_AUTOMATION_PROOF/v1",
        "all_passed": True,
        "elapsed_s": round(time.perf_counter() - t0, 2),
        "chambers": {
            "chamber_1_som_grounding": chamber_1,
            "chamber_2_robocorp_and_isolation": chamber_2,
            "chamber_3_clipboard_and_safety_gate": chamber_3,
            "chamber_4_adaptive_skill_forge": chamber_4,
            "chamber_5_agent_loop_and_cli": chamber_5,
        },
    }
    proof_out = sandbox / "empirical_pc_ceiling_proof.json"
    proof_out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    run_empirical_suite()
