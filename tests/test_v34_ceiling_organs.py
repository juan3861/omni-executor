"""Unit & Integration Test Suite for Super-Union v3.4 Engineering Ceiling Organs."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
from PIL import Image, ImageDraw

from am_ua.cognition.hierarchical_planner import (
    HierarchicalPlan,
    ProactiveHierarchicalPlanner,
    Subgoal,
)
from am_ua.execution.adaptive_skills import AdaptiveSkillForge
from am_ua.execution.best_of_n import BehaviorBestOfNEngine
from am_ua.execution.mcp_federation import AetherMindMCPServer, MCPFederationHub
from am_ua.execution.modality_router import HybridModalityRouter, ModalityType
from am_ua.execution.pc_automation import (
    GroundedUIElement,
    PCAutomationEngine,
    SetOfMarkGrounder,
)
from am_ua.execution.subagent_bus import (
    SubAgentDepthExceededError,
    SubAgentSessionBus,
    acquire_gui_exclusive_lock,
)
from am_ua.gui.cdp_browser import CDPIndexedBrowser
from am_ua.perception import InterRepoTopologyGate


def test_proactive_hierarchical_planner_dag_and_replan(tmp_path: Path) -> None:
    planner = ProactiveHierarchicalPlanner(storage_dir=tmp_path / "plans")
    plan = planner.decompose(
        "Click the button in desktop window and verify output",
        mission_id="test-php-01",
        verify_cmd="pytest -q",
        use_llm=False,
    )
    assert len(plan.subgoals) == 3
    assert plan.subgoals[0].suggested_modality == "uia_locator"
    assert plan.subgoals[1].depends_on == [plan.subgoals[0].subgoal_id]
    assert not plan.has_blocked_cycle_or_deadlock()

    ready = plan.ready_subgoals()
    assert [s.subgoal_id for s in ready] == ["sg_1"]

    # Complete sg_1
    plan, replanned = planner.evaluate_and_replan(
        plan, "sg_1", passed=True, observation_summary="window inspected", use_llm=False
    )
    assert replanned is False
    ready2 = plan.ready_subgoals()
    assert [s.subgoal_id for s in ready2] == ["sg_2"]

    # Fail sg_2 -> triggers dynamic recovery subgoal replacement
    plan, replanned2 = planner.evaluate_and_replan(
        plan, "sg_2", passed=False, observation_summary="Button not visible via UIA", use_llm=False
    )
    assert replanned2 is True
    ready3 = plan.ready_subgoals()
    assert len(ready3) == 1
    assert ready3[0].subgoal_id == "sg_r1_1"
    assert ready3[0].suggested_modality == "visual_som"

    # Persistence check
    loaded = planner.load_plan(plan.plan_id)
    assert loaded.replan_count == 1
    assert len(loaded.subgoals) == 2


def test_hybrid_modality_router_code_first_and_mog(tmp_path: Path) -> None:
    forge = AdaptiveSkillForge(tmp_path / "skills")
    forge.forge_skill(
        name="parse_invoice_csv",
        description="Parse invoice CSV rows and compute tax totals",
        code="def parse_invoice_csv(rows):\n    return len(rows)\n",
        tags=["invoice", "csv", "tax"],
    )
    router = HybridModalityRouter(
        skill_forge=forge,
        telemetry_path=tmp_path / "modality_telemetry.json",
    )

    # 1. Adaptive skill match
    d_skill = router.select_modality("Parse invoice CSV rows and compute tax totals")
    assert d_skill.primary_modality == ModalityType.ADAPTIVE_SKILL.value
    assert d_skill.matched_skill == "parse_invoice_csv"

    # 2. Code-First law
    d_code = router.select_modality("Fix the bug in src/parser.py and run pytest")
    assert d_code.primary_modality == ModalityType.CODE_SHELL.value
    assert "replace_in_file" in d_code.recommended_tools

    # 3. Mixture-of-Grounding: Structural UIA vs Visual SoM
    d_uia = router.select_modality("Click the button in desktop window")
    assert d_uia.primary_modality == ModalityType.UIA_LOCATOR.value

    d_som = router.select_modality(
        "Click the button in desktop window",
        suggested_modality=ModalityType.VISUAL_SOM.value,
    )
    assert d_som.primary_modality == ModalityType.VISUAL_SOM.value

    router.record_outcome("general", ModalityType.CODE_SHELL.value, passed=True)
    assert router.empirical_pass_rate("general", ModalityType.CODE_SHELL.value) > 0.65


def test_behavior_best_of_n_code_and_gui(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")

    bbon = BehaviorBestOfNEngine(scratch_root=tmp_path / "bbon_temp")

    def fake_runner(cand_ws: Path, idx: int) -> Dict[str, Any]:
        if idx == 1:
            (cand_ws / "calc.py").write_text("def add(a, b):\n    return 0\n", encoding="utf-8")
            return {
                "status": "FAILED",
                "verification": {"passed": False, "exit_code": 1},
                "changed_files": ["calc.py"],
                "diff": "+    return 0",
                "turns": 4,
            }
        elif idx == 2:
            (cand_ws / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            return {
                "status": "VERIFIED",
                "verification": {"passed": True, "exit_code": 0},
                "changed_files": ["calc.py"],
                "diff": "+    return a + b",
                "turns": 2,
            }
        else:
            (cand_ws / "calc.py").write_text("def add(a, b):\n    # bloat\n    return a + b\n", encoding="utf-8")
            (cand_ws / "extra.py").write_text("x = 1\n" * 50, encoding="utf-8")
            return {
                "status": "VERIFIED",
                "verification": {"passed": True, "exit_code": 0},
                "changed_files": ["calc.py", "extra.py"],
                "diff": "+ extra\n" * 120,
                "turns": 8,
            }

    res = bbon.run_code_best_of_n(
        objective="Fix add", workspace=ws, runner_fn=fake_runner, n=3, use_llm_judge=False
    )
    assert res["winner_candidate_id"] == "cand_2"
    assert res["winner_passed_oracle"] is True
    assert "return a + b" in (ws / "calc.py").read_text(encoding="utf-8")
    assert not (ws / "extra.py").exists()

    # GUI plan-level Best-of-N
    p_slow = HierarchicalPlan(
        plan_id="p_slow",
        mission_id="m1",
        objective="gui",
        subgoals=[
            Subgoal("s1", "pixel click", "click", suggested_modality="visual_som", acceptance_criteria=""),
            Subgoal("s2", "pixel click 2", "click", suggested_modality="visual_som", acceptance_criteria=""),
        ],
    )
    p_fast = HierarchicalPlan(
        plan_id="p_fast",
        mission_id="m1",
        objective="gui",
        subgoals=[
            Subgoal("s1", "uia click", "click", suggested_modality="uia_locator", acceptance_criteria="window updated"),
        ],
    )
    gui_res = bbon.select_best_gui_plan([p_slow, p_fast])
    assert gui_res["winner_plan_id"] == "p_fast"


def test_subagent_session_bus_and_gui_lock(tmp_path: Path) -> None:
    bus = SubAgentSessionBus(tmp_path / "sessions.db")

    def worker_a(sid: str, obj: str, ws_path: Path) -> Dict[str, Any]:
        bus.send_message(sender_id=sid, recipient_id="parent", content="hello from A")
        return {"ok": True, "value": 42, "tokens_used": 100}

    s1 = bus.spawn_session("Task A", worker_a, parent_id="parent", current_depth=0, run_async=False)
    assert s1["ok"] is True
    rec = bus.get_session(s1["session_id"])
    assert rec is not None and rec["status"] == "COMPLETED"
    assert rec["result"]["value"] == 42

    inbox = bus.read_inbox("parent")
    assert len(inbox) == 1
    assert inbox[0]["content"] == "hello from A"

    # Depth limit enforcement (MAX_SPAWN_DEPTH = 2 -> current_depth=2 attempts depth 3)
    with pytest.raises(SubAgentDepthExceededError):
        bus.spawn_session("Too deep", worker_a, current_depth=2)

    with acquire_gui_exclusive_lock(timeout_s=2.0) as locked:
        assert locked is True


def test_som_ocr_reservation_and_vlm_grounding(tmp_path: Path) -> None:
    img = Image.new("RGB", (600, 400), color=(30, 30, 30))
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 200, 100], outline=(255, 255, 255))

    grounder = SetOfMarkGrounder(artifact_dir=tmp_path / "som_art")
    # Provide 60 UIA elements and 5 OCR elements with max_total=40 -> OCR must NOT be starved!
    uia_els = [
        GroundedUIElement(
            tag_id=i + 1,
            source="UIA",
            role="button",
            name=f"UIA_{i}",
            bbox=(10, 10 + i * 5, 60, 14 + i * 5),
            confidence=0.99,
        )
        for i in range(60)
    ]
    ocr_els = [
        GroundedUIElement(
            tag_id=i + 1,
            source="OCR",
            role="text",
            name=f"SECRET_{i}",
            bbox=(300, 50 + i * 30, 420, 75 + i * 30),
            confidence=0.95,
        )
        for i in range(5)
    ]
    fused, som_path = grounder.fuse_and_render_som(img, uia_els, ocr_els, max_total=40)
    assert som_path.is_file()
    ocr_grounded = [g for g in fused if g.source == "OCR"]
    assert len(ocr_grounded) == 5

    # Test VLM grounding with mock multimodal LLM
    pc = PCAutomationEngine(artifact_dir=tmp_path / "pc_art")
    pc.last_elements = {g.tag_id: g for g in fused}
    pc.last_observation = {
        "ok": True,
        "som_screenshot_path": str(som_path),
        "elements": [g.to_dict() for g in fused],
    }

    class DummyMultimodalLLM:
        def chat_multimodal(self, *args: Any, **kwargs: Any) -> Any:
            target_tag = ocr_grounded[0].tag_id

            class R:
                provider = "mock_vlm"
                model = "mock-vision-1"
                text = json.dumps({"tag_id": target_tag, "rationale": "Matched SECRET_0"})

            return R()

    vlm_res = pc.ground_with_vlm("SECRET_0", DummyMultimodalLLM(), refresh=False)
    assert vlm_res["ok"] is True
    assert vlm_res["tag_id"] == ocr_grounded[0].tag_id
    assert vlm_res["element"]["name"] == "SECRET_0"


def test_cdp_indexed_browser_observe_act_extract(tmp_path: Path) -> None:
    html_file = tmp_path / "test_page.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html>
<head><title>AM Browser Test</title></head>
<body>
  <h1 id="hdr">Initial Header</h1>
  <input id="name_input" type="text" placeholder="Enter code" />
  <button id="apply_btn" onclick="document.getElementById('hdr').innerText = 'CONFIRMED:' + document.getElementById('name_input').value">Apply Now</button>
</body>
</html>""",
        encoding="utf-8",
    )
    url = html_file.as_uri()
    browser = CDPIndexedBrowser(artifact_dir=tmp_path / "browser_art", headless=True)
    try:
        obs = browser.observe(url=url)
        assert obs["ok"] is True
        assert obs["element_count"] >= 2
        assert Path(obs["f12_dom_path"]).is_file()
        assert Path(obs["visual_screenshot_path"]).is_file()

        inp_el = next(e for e in obs["elements"] if e["tag"] == "input")
        btn_el = next(e for e in obs["elements"] if e["tag"] == "button")

        r_fill = browser.act("fill", idx=inp_el["idx"], text="OMEGA_34")
        assert r_fill["ok"] is True

        # Test self-healing selector recovery by passing button text instead of idx!
        r_click = browser.act("click", target="Apply Now")
        assert r_click["ok"] is True
        assert r_click["receipt"]["schema"] == "BROWSER_PAF_RECEIPT/v1"
        assert r_click["receipt"]["self_healed"] is True

        ext = browser.extract(selector="#hdr")
        assert ext["ok"] is True
        assert "CONFIRMED:OMEGA_34" in ext["text"]
    finally:
        browser.close()


def test_mcp_server_and_federation_hub_roundtrip(tmp_path: Path) -> None:
    pc = PCAutomationEngine(artifact_dir=tmp_path / "pc")
    forge = AdaptiveSkillForge(tmp_path / "skills")
    srv = AetherMindMCPServer(pc_engine=pc, skill_forge=forge)

    init_resp = srv.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "omni-executor-mcp"

    list_resp = srv.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert list_resp is not None
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert {"am_pc_probe", "am_pc_observe", "am_pc_windows", "am_skill_list", "am_skill_forge", "am_skill_run"}.issubset(tool_names)

    call_resp = srv.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "am_pc_probe", "arguments": {}}}
    )
    assert call_resp is not None
    assert call_resp["result"]["isError"] is False


def test_v34_topology_compliance() -> None:
    gate = InterRepoTopologyGate()
    res = gate.audit_package_imports("F:/AetherMind_Universal_Agent/src/am_ua")
    assert res["ok"] is True, f"Topology violations: {res}"


def test_agent_loop_prompt_test_protection_empty_tool_and_fast_path(tmp_path: Path) -> None:
    from am_ua.execution.agent_loop import AgentLoop, SYSTEM_PROMPT, SPARC_SYSTEM_PROMPT
    from am_ua.execution.durable_engine import DurableExecutionEngine
    from am_ua.governance.seal_guard import ConstitutionSealGuard

    assert "tests_visible/*" in SYSTEM_PROMPT
    assert "tests_visible/*" in SPARC_SYSTEM_PROMPT
    assert "edge cases beyond visible tests" in SYSTEM_PROMPT
    assert "edge cases beyond visible tests" in SPARC_SYSTEM_PROMPT

    class EmptyThenFinishLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
            self.calls += 1
            self.total_prompt_tokens += 5
            self.total_completion_tokens += 5

            class R:
                provider = "mock"
                model = "mock-1"
                prompt_tokens = 5
                completion_tokens = 5
                total_tokens = 10
                text = (
                    '{"thought": "oops", "tool": "", "args": {}}'
                    if self.calls == 1
                    else '{"thought": "done", "tool": "finish", "args": {"summary": "ok", "confidence": 0.9}}'
                )

            return R()

    llm = EmptyThenFinishLLM()
    engine = DurableExecutionEngine(tmp_path / "durable.db")
    seal_guard = ConstitutionSealGuard(r"F:\AetherMind_Universal_Agent")
    loop = AgentLoop(engine=engine, seal_guard=seal_guard, llm=llm)  # type: ignore[arg-type]
    res = loop.run("Fix bug in app.py", workspace=tmp_path, max_turns=4, workflow="hierarchical", use_judge=False)
    assert res.stop_reason == "finish"
    assert llm.calls == 2
    assert res.tool_calls == []


def test_finish_verification_gate_rejects_premature_finish(tmp_path: Path) -> None:
    from am_ua.execution.agent_loop import AgentLoop
    from am_ua.execution.durable_engine import DurableExecutionEngine
    from am_ua.governance.seal_guard import ConstitutionSealGuard

    (tmp_path / "val.py").write_text("X = 0\n", encoding="utf-8")

    class PrematureFinishLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
            self.calls += 1
            self.total_prompt_tokens += 5
            self.total_completion_tokens += 5

            class R:
                provider = "mock"
                model = "mock-1"
                prompt_tokens = 5
                completion_tokens = 5
                total_tokens = 10

            r = R()
            if self.calls == 1:
                r.text = '{"thought": "premature", "tool": "finish", "args": {"summary": "done", "confidence": 0.9}}'
            elif self.calls == 2:
                assert any("FINISH REJECTED" in m.get("content", "") for m in messages)
                r.text = '{"thought": "fix X", "tool": "write_file", "args": {"path": "val.py", "content": "X = 1\\n"}}'
            else:
                r.text = '{"thought": "now ok", "tool": "finish", "args": {"summary": "fixed", "confidence": 1.0}}'
            return r

    llm = PrematureFinishLLM()
    engine = DurableExecutionEngine(tmp_path / "durable.db")
    seal_guard = ConstitutionSealGuard(r"F:\AetherMind_Universal_Agent")
    loop = AgentLoop(engine=engine, seal_guard=seal_guard, llm=llm)  # type: ignore[arg-type]
    res = loop.run(
        "Set X = 1 in val.py",
        workspace=tmp_path,
        verify_cmd=f'"{sys.executable}" -c "import val; assert val.X == 1"',
        max_turns=5,
        workflow="hierarchical",
        use_judge=False,
    )
    assert res.status == "VERIFIED"
    assert res.stop_reason == "finish"
    assert llm.calls == 3


def test_agent_loop_browser_cdp_tools_end_to_end(tmp_path: Path) -> None:
    from am_ua.execution.agent_loop import AgentLoop
    from am_ua.execution.durable_engine import DurableExecutionEngine
    from am_ua.governance.seal_guard import ConstitutionSealGuard

    html_file = tmp_path / "form.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html><body>
  <h2 id="out">IDLE</h2>
  <input id="code_box" type="text" />
  <button id="go_btn" onclick="document.getElementById('out').innerText='OK:'+document.getElementById('code_box').value">Go</button>
</body></html>""",
        encoding="utf-8",
    )
    url = html_file.as_uri()

    class BrowserFlowLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
            self.calls += 1
            self.total_prompt_tokens += 5
            self.total_completion_tokens += 5

            class R:
                provider = "mock"
                model = "mock-1"
                prompt_tokens = 5
                completion_tokens = 5
                total_tokens = 10

            r = R()
            if self.calls == 1:
                r.text = json.dumps({"thought": "observe page", "tool": "browser_observe", "args": {"url": url, "headless": True}})
            elif self.calls == 2:
                r.text = json.dumps({"thought": "fill input", "tool": "browser_act", "args": {"action": "fill", "target": "#code_box", "text": "CDP_99"}})
            elif self.calls == 3:
                r.text = json.dumps({"thought": "click Go", "tool": "browser_act", "args": {"action": "click", "target": "#go_btn"}})
            elif self.calls == 4:
                r.text = json.dumps({"thought": "extract result", "tool": "browser_extract", "args": {"selector": "#out"}})
            else:
                assert any("OK:CDP_99" in m.get("content", "") for m in messages)
                r.text = json.dumps({"thought": "done", "tool": "finish", "args": {"summary": "OK:CDP_99", "confidence": 1.0}})
            return r

    llm = BrowserFlowLLM()
    engine = DurableExecutionEngine(tmp_path / "durable.db")
    seal_guard = ConstitutionSealGuard(r"F:\AetherMind_Universal_Agent")
    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=llm,  # type: ignore[arg-type]
        browser_factory=lambda headless=True: CDPIndexedBrowser(artifact_dir=tmp_path / "b_art", headless=headless),
    )
    res = loop.run(
        f"Open {url} in browser, enter CDP_99, click Go, and extract #out",
        workspace=tmp_path,
        max_turns=8,
        workflow="react",
        use_judge=False,
    )
    assert res.stop_reason == "finish"
    assert [tc["tool"] for tc in res.tool_calls] == [
        "browser_observe",
        "browser_act",
        "browser_act",
        "browser_extract",
    ]
    assert all(tc["ok"] for tc in res.tool_calls)


def test_am_bench_browser_tasks_registry() -> None:
    from eval.am_bench.tasks import ALL_TASKS, BROWSER_TASKS

    assert len(BROWSER_TASKS) == 5
    for t in BROWSER_TASKS:
        assert t.category == "browser"
        assert "{SITE_URI}" in t.objective
        assert "tests_hidden/test_h.py" in t.hidden
        assert t in ALL_TASKS


def test_repeat_tool_loop_breaker_consecutive_read_guard() -> None:
    from am_ua.execution.agent_loop import RepeatToolLoopBreaker, RepeatToolLoopError

    b = RepeatToolLoopBreaker(window_size=10, max_identical_calls=3, max_consecutive_read_calls=4)
    for sel in ("#a", "#b", "#c"):
        ok, _ = b.record_and_check("browser_extract", {"selector": sel})
        assert ok is True
    with pytest.raises(RepeatToolLoopError):
        b.record_and_check("browser_extract", {"selector": "#d"})


def test_list_dir_interleaved_loop_breaker_and_print_window_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from am_ua.execution.agent_loop import RepeatToolLoopBreaker, RepeatToolLoopError
    from am_ua.execution.pc_automation import SetOfMarkGrounder

    b = RepeatToolLoopBreaker(window_size=12, max_identical_calls=3)
    for i in range(3):
        b.record_and_check("list_dir", {"path": f"sub{i}"})
        b.record_and_check("run", {"command": f"echo {i}"})
    with pytest.raises(RepeatToolLoopError):
        b.record_and_check("list_dir", {"path": "sub9"})

    monkeypatch.setenv("AM_UA_KEEP_CURRENT_DESKTOP", "1")
    grounder = SetOfMarkGrounder(artifact_dir=tmp_path / "som")
    img, raw_path = grounder.capture_screen()
    assert raw_path.is_file()
    assert img.size[0] >= 40 and img.size[1] >= 40


def test_pc_automation_win32_input_shim_on_pyautogui_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins
    from am_ua.execution.pc_automation import PCAutomationEngine, _Win32InputShim, _get_gui_input_backend

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "pyautogui":
            raise AttributeError("_ARRAY_API not found")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    backend = _get_gui_input_backend()
    assert isinstance(backend, _Win32InputShim)
    pc = PCAutomationEngine(artifact_dir=tmp_path / "pc")
    res = pc.execute_gui_action("move", x=10, y=10, dry_run=True)
    assert res["ok"] is True


def test_repeat_tool_loop_breaker_window_caps_for_browser_extract_and_read_file() -> None:
    from am_ua.execution.agent_loop import RepeatToolLoopBreaker, RepeatToolLoopError

    b = RepeatToolLoopBreaker(window_size=12, max_identical_calls=3)
    for i in range(4):
        b.record_and_check("browser_extract", {"selector": f"#s{i}"})
        b.record_and_check("read_file", {"file": f"f{i}.py"})
    with pytest.raises(RepeatToolLoopError):
        b.record_and_check("browser_extract", {"selector": "#s9"})
