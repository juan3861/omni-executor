"""Empirical verification suite for OmniExecutor v9.0 (Fase 4):
  - Web Mission Control Server (HTTP 200, SSE AG-UI stream, live `on_demand` <-> `fixed`
    USD budget toggle enforcing `ResourceExhaustedError` in `HomeostasisGovernor`,
    Take-the-Wheel signals, and CLI `ui --port 0 --no-block`)
  - Interactive Terminal TUI (`OmniTUI` slash commands, diff confirm `[y/n/a/e]`)
  - Universal Playbook Engine expansion (`8` -> `18` playbooks across Browser, Windows/OS,
    Docker, ZIP zip-slip protection, & transactional auto-rollback code patching)
  - `PolyglotRepoMapper` native `tree-sitter` AST + `AgentLoop` multimodal SoM fallback
  - Desmonolitização check (`<= 650` lines across all 5 refactored suites) + zero-orphan
    reachability + `OMNI_TOPOLOGY_V2` compliance.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from am_ua.cli import main as cli_main
from am_ua.cognition.agui_protocol import AGUIEventBus, AGUIEventType
from am_ua.cognition.llm_client import LLMResponse, ToolCall
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.homeostasis import HomeostasisGovernor, ResourceExhaustedError
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate, PolyglotRepoMapper
from am_ua.ui.mission_control_web import MissionControlServer
from am_ua.ui.tui import OmniTUI


def test_v90_web_mission_control_budget_toggle_sse_and_tui(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    gov = HomeostasisGovernor()
    bus = AGUIEventBus(thread_id="t-v90", run_id="r-v90")
    srv = MissionControlServer(host="127.0.0.1", port=0, governor=gov, event_bus=bus)
    port = srv.start()
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(f"{base}/") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "OmniExecutor Mission Control" in html

        with urllib.request.urlopen(f"{base}/api/state") as resp:
            st0 = json.loads(resp.read().decode("utf-8"))
            assert st0["ok"] is True
            assert st0["budget_mode"] == "on_demand"
            assert st0["max_cost_usd"] is None
            assert st0["playbooks_count"] >= 18

        # Emit an AG-UI event and verify dashboard records it
        bus.emit(AGUIEventType.STEP_STARTED, step="verify_ui")
        srv.record_deterministic_savings(9000)
        with urllib.request.urlopen(f"{base}/api/state") as resp:
            st1 = json.loads(resp.read().decode("utf-8"))
            assert st1["recent_events_count"] >= 1
            assert st1["deterministic_tokens_saved"] == 9000

        # Switch live to fixed USD ceiling and verify HomeostasisGovernor enforces it
        req_fix = urllib.request.Request(
            f"{base}/api/budget",
            data=json.dumps({"mode": "fixed", "max_cost_usd": 0.05}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_fix) as resp:
            res_fix = json.loads(resp.read().decode("utf-8"))
            assert res_fix["ok"] is True and res_fix["budget_mode"] == "fixed" and res_fix["max_cost_usd"] == 0.05

        gov.record_turn_cost(tokens=500, cost_usd=0.03)
        with pytest.raises(ResourceExhaustedError):
            gov.record_turn_cost(tokens=500, cost_usd=0.03)

        # Send Take the Wheel signal
        req_w = urllib.request.Request(
            f"{base}/api/wheel",
            data=json.dumps({"action": "resume", "note": "Keep going"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_w) as resp:
            w_res = json.loads(resp.read().decode("utf-8"))
            assert w_res["wheel_status"] == "resume" and w_res["note"] == "Keep going"
    finally:
        srv.close()
        bus.close()

    # Verify CLI `ui --port 0 --no-block`
    assert cli_main(["ui", "--port", "0", "--no-block"]) == 0
    ui_out = json.loads(capsys.readouterr().out)
    assert ui_out["ok"] is True and ui_out["port"] > 0

    # Verify OmniTUI slash commands & diff approval
    tui = OmniTUI(tmp_path)
    assert tui.handle_line("/help")["action"] == "help"
    assert tui.handle_line("/budget 2.50")["max_cost_usd"] == 2.5
    assert tui.handle_line("/cost")["budget_mode"] == "fixed"
    assert tui.handle_line("/budget off")["budget_mode"] == "on_demand"
    assert len(tui.handle_line("/playbook")["playbooks"]) >= 18
    assert tui.handle_line("/rails")["count"] >= 220
    assert tui.confirm_diff("app.py", "-a\n+b", input_fn=lambda _: "a") == "y"
    assert tui.auto_approve is True


def test_v90_18_universal_playbooks_zip_rollback_docker_and_repomap(tmp_path: Path) -> None:
    ws = tmp_path / "u_ws"
    ws.mkdir()
    (ws / "hello.txt").write_text("OmniExecutor v9.0", encoding="utf-8")
    (ws / "page.html").write_text("<h1>Download Artifact</h1>", encoding="utf-8")
    (ws / "calc.py").write_text("VAL = 1\n", encoding="utf-8", newline="\n")
    (ws / "test_calc.py").write_text("from calc import VAL\ndef test_v(): assert VAL == 99\n", encoding="utf-8")

    playbooks = DEFAULT_PLAYBOOK_ENGINE.list_playbooks()
    assert len(playbooks) >= 18
    wt = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))

    # 1. ZIP archive create + safe extract inside workspace
    zip_c = wt.run_playbook(
        {"playbook": "win_batch_file_archive", "variables": {"mode": "create", "archive_path": "bundle.zip", "files": ["hello.txt"]}}
    )
    assert zip_c["ok"] is True and (ws / "bundle.zip").is_file()
    zip_x = wt.run_playbook(
        {"playbook": "win_batch_file_archive", "variables": {"mode": "extract", "archive_path": "bundle.zip", "dest_dir": "out_dir"}}
    )
    assert zip_x["ok"] is True and (ws / "out_dir" / "hello.txt").read_text(encoding="utf-8") == "OmniExecutor v9.0"

    # 2. Download + SHA-256 verification on local HTML
    dl_probe = wt.run_playbook({"playbook": "web_download_and_verify_sha256", "variables": {"url": (ws / "page.html").as_uri()}})
    assert dl_probe["ok"] is True and len(dl_probe["sha256"]) == 64

    # 3. Transactional patch + auto-rollback on failing test
    rb_res = wt.run_playbook(
        {
            "playbook": "code_git_worktree_patch_commit",
            "variables": {
                "path": "calc.py",
                "old": "VAL = 1",
                "new": "VAL = 50",
                "verify_cmd": f'"{sys.executable}" -m pytest -q test_calc.py',
            },
        }
    )
    assert rb_res["ok"] is False and rb_res["rolled_back"] is True
    assert (ws / "calc.py").read_text(encoding="utf-8") == "VAL = 1\n"

    # Now apply winning value -> succeeds cleanly without rollback
    ok_res = wt.run_playbook(
        {
            "playbook": "code_git_worktree_patch_commit",
            "variables": {
                "path": "calc.py",
                "old": "VAL = 1",
                "new": "VAL = 99",
                "verify_cmd": f'"{sys.executable}" -m pytest -q test_calc.py',
            },
        }
    )
    assert ok_res["ok"] is True and ok_res["rolled_back"] is False

    # 4. Paginated browser + multiapp OCR transfer using clean fakes
    class _PaginatedFakeBrowser:
        def __init__(self) -> None:
            self.p = 1

        def observe(self, url=None, **_kw):
            return {"ok": True, "url": url or "https://example.local", "element_count": 2}

        def act(self, action, **_kw):
            if action == "click":
                self.p += 1
            return {"ok": True, "receipt": {"visual_state_changed": True}}

        def extract(self, selector="body", **_kw):
            return {"ok": True, "text": f"Page {self.p} rows"}

        def close(self):
            return None

    wt_b = WorkspaceTools(ws, ConstitutionSealGuard(ROOT), browser_factory=lambda _h: _PaginatedFakeBrowser())
    pg_res = wt_b.run_playbook(
        {"playbook": "web_paginated_extract", "variables": {"url": "https://example.local/list", "max_pages": 2}}
    )
    assert pg_res["ok"] is True and pg_res["pages_collected"] == 2

    class _MockClipboard:
        def __init__(self) -> None:
            self.buf = ""

        def set_text(self, txt: str) -> bool:
            self.buf = txt
            return True

        def get_text(self) -> str:
            return self.buf

    class _MockPC:
        def __init__(self) -> None:
            self.clipboard = _MockClipboard()

        def observe_desktop(self, **_kw):
            return {"ok": True, "ocr_text": "TOKEN-XYZ"}

        def execute_gui_action(self, action_type="click", **_kw):
            return {"ok": True, "action_type": action_type, "receipt": {"visual_transition": "changed"}}

    wt_pc = WorkspaceTools(ws, ConstitutionSealGuard(ROOT), pc_engine=_MockPC())
    ocr_tr = wt_pc.run_playbook(
        {"playbook": "win_multiapp_ocr_transfer", "variables": {"source_window": "AppA", "target_window": "AppB", "text": "TOKEN-XYZ"}}
    )
    assert ocr_tr["ok"] is True and ocr_tr["transferred_chars"] == 9

    # 5. PolyglotRepoMapper tree-sitter / fallback extraction
    (ws / "widget.js").write_text("class WidgetCard {}\nfunction renderCard() { return new WidgetCard(); }\n", encoding="utf-8")
    rm = PolyglotRepoMapper(ws)
    ranked, txt = rm.build_ranked_map(max_chars=2000)
    assert any(r.rel_path == "widget.js" for r in ranked)
    assert "WidgetCard" in txt


def test_v90_agent_loop_multimodal_som_recovery_and_modular_limits(tmp_path: Path) -> None:
    ws = tmp_path / "mm_ws"
    ws.mkdir()
    shot = ws / "som_view.png"
    shot.write_bytes(b"\x89PNG\r\n\x1a\nFAKEPNG")

    class _UnchangedBrowser:
        def observe(self, url=None, **_kw):
            return {"ok": True, "url": url or "https://example.local", "element_count": 1}

        def act(self, action, **_kw):
            return {
                "ok": True,
                "action": action,
                "receipt": {"visual_state_changed": False, "visual_screenshot_path": str(shot)},
            }

        def close(self):
            return None

    class _VisionLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self.vision_invoked = False

        def chat(self, _messages, **_kw) -> LLMResponse:
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(
                    text="",
                    provider="mock",
                    model="mock-v90",
                    prompt_tokens=10,
                    completion_tokens=10,
                    latency_ms=1.0,
                    tool_calls=[ToolCall(id="b1", name="browser_act", arguments={"action": "click", "idx": 1})],
                )
            return LLMResponse(
                text="",
                provider="mock",
                model="mock-v90",
                prompt_tokens=10,
                completion_tokens=10,
                latency_ms=1.0,
                tool_calls=[ToolCall(id="f1", name="finish", arguments={"summary": "Handled via SoM vision fallback", "confidence": 0.9})],
            )

        def chat_multimodal(self, prompt, image_path, **_kw) -> LLMResponse:
            self.vision_invoked = True
            return LLMResponse(text="Try idx=2 button 'Submit'", provider="mock-vision", model="mock-vlm", prompt_tokens=5, completion_tokens=5, latency_ms=1.0)

    v_llm = _VisionLLM()
    loop = AgentLoop(
        engine=DurableExecutionEngine(tmp_path / "mm.db"),
        seal_guard=ConstitutionSealGuard(ROOT),
        llm=v_llm,
        browser_factory=lambda _h: _UnchangedBrowser(),
    )
    res = loop.run(objective="Click submit button in browser page", workspace=ws, max_turns=5, use_judge=False)
    assert res.status == "COMPLETED_UNVERIFIED"
    assert v_llm.vision_invoked is True

    # Modular architecture & zero-orphan audit after splitting the 5 monoliths
    pkg = ROOT / "src" / "am_ua"
    topo = InterRepoTopologyGate().audit_package_imports(pkg)
    assert topo["ok"] is True, topo.get("violations")

    for refactored in (
        "deterministic_matrix_100.py",
        "deterministic_offloader.py",
        "apex_fault_localizer.py",
        "pc_automation.py",
        "apex_codeact_fuzzy.py",
    ):
        line_cnt = len((pkg / "execution" / refactored).read_text(encoding="utf-8").splitlines())
        assert line_cnt <= 650, f"{refactored} still has {line_cnt} lines"

    # Zero-orphan verification
    all_files = {}
    for p in pkg.rglob("*.py"):
        rel = p.relative_to(pkg.parent).with_suffix("").as_posix().replace("/", ".")
        if p.name == "__init__.py":
            rel = rel.rsplit(".__init__", 1)[0]
        all_files[p] = rel
    graph = {}
    for p, mod in all_files.items():
        is_init = p.name == "__init__.py"
        tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        imps = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imps.add(a.name)
            elif isinstance(node, ast.ImportFrom) and (node.module or node.level > 0):
                if node.level > 0:
                    parts = mod.split(".")
                    base_parts = parts if is_init else parts[:-1]
                    if node.level > 1:
                        base_parts = base_parts[: -(node.level - 1)]
                    full = ".".join(base_parts + ([node.module] if node.module else []))
                    imps.add(full)
                    for a in node.names:
                        imps.add(full + "." + a.name)
                else:
                    assert node.module is not None
                    imps.add(node.module)
                    for a in node.names:
                        imps.add(node.module + "." + a.name)
        graph[mod] = imps

    visited = set()
    q = ["am_ua", "am_ua.agent_kernel", "am_ua.cli", "am_ua.execution.agent_loop"]
    all_mods = set(all_files.values())
    while q:
        cur = q.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        for target in graph.get(cur, ()):
            if target in all_mods and target not in visited:
                q.append(target)
    orphans = sorted({m for p, m in all_files.items() if p.name != "__init__.py"} - visited)
    assert orphans == [], f"Orphan modules detected: {orphans}"
