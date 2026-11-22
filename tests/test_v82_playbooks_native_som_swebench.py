"""Empirical verification suite for OmniExecutor v8.2 (Fase 3):
  - Deterministic Parametric Playbook Engine (`run_playbook`) across Code, Windows, & Browser
    plus AgentLoop native ToolCall invocation
  - Unified Native Acceleration Backends (`NativeBackendRouter`, ripgrep search, Z3 invariant
    checking, `PolyglotRepoMapper.native_backends_status`)
  - Closed-loop Visual Set-of-Mark state-delta receipt in `CDPIndexedBrowser.act()`
  - On-demand `SWEBenchHarness` (`load_instances`, `prepare_instance_workspace`, `run_dataset`
    with free-tier LLM defaults & optional USD cap) + CLI (`det run-playbook`, `swebench run`)
  - AgentDojo 32-vector adversarial red-team suite (`ASR == 0.0`)
  - Zero-orphan module reachability & `OMNI_TOPOLOGY_V2` audit + `doctor()`.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent
for _p in (str(TESTS_DIR), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.cli import main as cli_main
from am_ua.cognition.llm_client import LLMResponse, ToolCall
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.native_backends import NativeBackendRouter
from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE
from am_ua.execution.swebench_harness import SWEBenchHarness
from am_ua.execution.tla_formal_verifier import BoundedTLCModelChecker
from am_ua.execution.tool_schemas import TOOL_JSON_SCHEMAS, build_native_tool_schemas
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.gui.cdp_browser import CDPIndexedBrowser
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate, PolyglotRepoMapper
from test_agentdojo_redteam_suite import run_agentdojo_redteam_suite


def test_v82_parametric_playbooks_code_windows_browser_and_agent_loop(tmp_path: Path) -> None:
    ws = tmp_path / "pb_ws"
    ws.mkdir()
    (ws / "calc.py").write_text(
        "def old_compute(x: int) -> int:\n"
        "    return x * 2\n",
        encoding="utf-8",
        newline="\n",
    )
    (ws / "test_calc.py").write_text(
        "from calc import new_compute\n"
        "def test_ok():\n"
        "    assert new_compute(5) == 10\n",
        encoding="utf-8",
        newline="\n",
    )
    (ws / "sample.html").write_text("<h1>Omni v8.2</h1><p>Playbook fetch OK</p>", encoding="utf-8")

    # 1. Code playbook: rename symbol + lint + pytest verify in 1 shot
    pb_list = DEFAULT_PLAYBOOK_ENGINE.list_playbooks()
    assert len(pb_list) >= 8
    wt = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))
    code_res = wt.run_playbook(
        {
            "playbook": "code_refactor_rename_and_verify",
            "variables": {
                "file_path": "calc.py",
                "old_symbol": "old_compute",
                "new_symbol": "new_compute",
                "verify_cmd": f'"{sys.executable}" -m pytest -q test_calc.py',
            },
        }
    )
    assert code_res["ok"] is True, code_res
    assert "def new_compute" in (ws / "calc.py").read_text(encoding="utf-8")
    assert code_res["estimated_tokens_saved"] > 0

    # 2. Browser fast fetch playbook on local HTML file URI
    fetch_res = wt.run_playbook(
        {
            "playbook": "web_fast_fetch_extract",
            "variables": {"url": (ws / "sample.html").as_uri(), "max_chars": 2000},
        }
    )
    assert fetch_res["ok"] is True
    assert "Omni v8.2" in fetch_res["final_observation"]["content"]

    # 3. Browser Playwright sequence playbook with mock browser object
    class _FakeBrowser:
        def observe(self, url=None, **_kw):
            return {"ok": True, "url": url or "https://example.local", "element_count": 1}

        def act(self, action, **_kw):
            return {"ok": True, "action": action, "receipt": {"visual_state_changed": True}}

        def extract(self, selector="body", **_kw):
            return {"ok": True, "selector": selector, "text": "Extracted Done"}

        def close(self):
            return None

    wt_br = WorkspaceTools(ws, ConstitutionSealGuard(ROOT), browser_factory=lambda _h: _FakeBrowser())
    br_pb = wt_br.run_playbook(
        {
            "playbook": "web_navigate_fill_extract",
            "variables": {
                "url": "https://example.local/form",
                "steps": [
                    {"action": "fill", "idx": 1, "text": "admin"},
                    {"action": "click", "idx": 2},
                ],
                "extract_selector": "#result",
            },
        }
    )
    assert br_pb["ok"] is True and br_pb["steps_executed"] == 4
    assert br_pb["extracted"]["text"] == "Extracted Done"

    # 4. Windows domain deterministic playbook (`win_port_and_process_triage`)
    win_pb = wt.run_playbook(
        {
            "playbook": "win_port_and_process_triage",
            "variables": {"port": 65432, "filter": "python"},
        }
    )
    assert win_pb["ok"] is True and win_pb["steps_executed"] == 2

    # 5. AgentLoop native ToolCall invocation of `run_playbook`
    assert "run_playbook" in TOOL_JSON_SCHEMAS
    schema_names = {s["function"]["name"] for s in build_native_tool_schemas(objective="patch bug in app.py")}
    assert "run_playbook" in schema_names

    (ws / "target.py").write_text("RATE = 1\n", encoding="utf-8", newline="\n")
    (ws / "test_target.py").write_text("from target import RATE\ndef test_rate(): assert RATE == 42\n", encoding="utf-8")

    class _PlaybookMockLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self.step = 0

        def chat(self, _messages, **_kw) -> LLMResponse:
            self.calls += 1
            self.step += 1
            if self.step == 1:
                tc = ToolCall(
                    id="call_pb_1",
                    name="run_playbook",
                    arguments={
                        "playbook": "code_patch_and_verify",
                        "variables": {
                            "path": "target.py",
                            "old": "RATE = 1",
                            "new": "RATE = 42",
                            "verify_cmd": f'"{sys.executable}" -m pytest -q test_target.py',
                        },
                    },
                )
                return LLMResponse(text="", provider="mock", model="mock-v82", prompt_tokens=25, completion_tokens=15, latency_ms=1.0, tool_calls=[tc])
            return LLMResponse(
                text="",
                provider="mock",
                model="mock-v82",
                prompt_tokens=20,
                completion_tokens=10,
                latency_ms=1.0,
                tool_calls=[ToolCall(id="call_fin", name="finish", arguments={"summary": "Applied playbook patch", "confidence": 0.99})],
            )

    loop = AgentLoop(
        engine=DurableExecutionEngine(tmp_path / "loop_v82.db"),
        seal_guard=ConstitutionSealGuard(ROOT),
        llm=_PlaybookMockLLM(),
    )
    run_res = loop.run(
        objective="Patch target.py using deterministic playbook",
        workspace=ws,
        verify_cmd=f'"{sys.executable}" -m pytest -q test_target.py',
        max_turns=6,
        use_judge=False,
    )
    assert run_res.status == "VERIFIED", run_res
    assert "RATE = 42" in (ws / "target.py").read_text(encoding="utf-8")


def test_v82_native_backends_ripgrep_z3_and_repomap_probe(tmp_path: Path) -> None:
    caps = NativeBackendRouter.probe_capabilities()
    assert {"ripgrep", "docker", "git", "ruff", "tree_sitter", "z3", "tlc_java", "playwright", "datasets"}.issubset(caps.keys())

    ws = tmp_path / "search_ws"
    ws.mkdir()
    (ws / "alpha.py").write_text("NEEDLE_TOKEN = 'omni-v82'\n", encoding="utf-8")
    wt = WorkspaceTools(ws, ConstitutionSealGuard(ROOT))
    s_res = wt.search({"pattern": "NEEDLE_TOKEN"})
    assert len(s_res["hits"]) == 1
    assert s_res["backend"] in ("ripgrep", "python_regex")

    rm_status = PolyglotRepoMapper.native_backends_status()
    assert "tree_sitter" in rm_status and "ast_grep" in rm_status

    # Z3 native / bounded SMT fallback invariant proof & counterexample discovery
    unsafe = BoundedTLCModelChecker.verify_integer_invariant_z3(
        vars_bounds={"x": (0, 10), "y": (0, 10)},
        violation_expr="x + y > 15",
    )
    assert unsafe["ok"] is False and unsafe["invariant_holds"] is False
    ce = unsafe["counterexample"]
    assert ce is not None and (ce["x"] + ce["y"]) > 15

    safe = BoundedTLCModelChecker.verify_integer_invariant_z3(
        vars_bounds={"x": (0, 5), "y": (0, 5)},
        violation_expr="x + y > 12",
    )
    assert safe["ok"] is True and safe["invariant_holds"] is True


def test_v82_closed_loop_visual_som_in_cdp_browser(tmp_path: Path) -> None:
    class _FakeLocator:
        def __init__(self, state: Dict[str, Any]) -> None:
            self.state = state

        @property
        def first(self):
            return self

        def count(self) -> int:
            return 1

        def click(self, timeout=5000) -> None:
            self.state["step"] += 1

    class _FakePage:
        def __init__(self) -> None:
            self.url = "https://example.local/app"
            self.state = {"step": 0}

        def goto(self, url, **_kw) -> None:
            self.url = url

        def wait_for_timeout(self, _ms: int) -> None:
            return None

        def evaluate(self, _js: str):
            return [
                {"idx": 1, "tag": "button", "type": "button", "role": "button", "name": "go", "text": "Continue", "placeholder": "", "href": "", "bbox": [10, 10, 80, 30]}
            ]

        def title(self) -> str:
            return f"Title-{self.state['step']}"

        def content(self) -> str:
            return f"<html><body><h1>Step {self.state['step']}</h1></body></html>"

        def screenshot(self, path: str, full_page: bool = False) -> None:
            Path(path).write_bytes(f"PNG_STEP_{self.state['step']}".encode("utf-8"))

        def locator(self, _sel: str) -> _FakeLocator:
            return _FakeLocator(self.state)

    br = CDPIndexedBrowser(artifact_dir=tmp_path / "cdp_som", block_on_payment=False)
    br._page = _FakePage()
    res = br.act("click", idx=1)
    assert res["ok"] is True
    receipt = res["receipt"]
    assert receipt["before_visual_sha256"] != ""
    assert receipt["after_visual_sha256"] != ""
    assert receipt["visual_state_changed"] is True
    assert receipt["dom_state_changed"] is True


def test_v82_swebench_on_demand_dataset_cli_and_agentdojo_redteam(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ws = tmp_path / "swe_repo"
    ws.mkdir()
    (ws / "math_mod.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (ws / "test_fix.py").write_text("from math_mod import add\ndef test_add(): assert add(2, 3) == 5\n", encoding="utf-8")

    ds_file = tmp_path / "mini_swebench.jsonl"
    ds_file.write_text(
        json.dumps(
            {
                "instance_id": "omni__demo-1",
                "repo": "omni/demo",
                "base_commit": "HEAD",
                "problem_statement": "add(a, b) subtracts instead of adding",
                "FAIL_TO_PASS": ["test_fix.py"],
                "PASS_TO_PASS": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    instances = SWEBenchHarness.load_instances(ds_file, limit=5)
    assert len(instances) == 1 and instances[0].instance_id == "omni__demo-1"

    harness = SWEBenchHarness(model_name="omni-executor-v8.2")
    pred_out = tmp_path / "preds.json"

    def _mock_solver(repo_ws: Path, _inst) -> Dict[str, Any]:
        (repo_ws / "math_mod.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        return {"ok": True}

    run_rep = harness.run_dataset(
        instances,
        workspace_map={"omni__demo-1": ws},
        provider="groq",
        solver_fn=_mock_solver,
        out_predictions=pred_out,
    )
    assert run_rep["resolved"] == 1
    assert run_rep["free_tier_default"] is True
    assert run_rep["max_cost_usd"] is None
    assert run_rep["total_cost_usd"] == 0.0
    assert pred_out.is_file()

    assert cli_main(["swebench", "validate-predictions", str(pred_out)]) == 0
    _ = capsys.readouterr()

    assert cli_main(["det", "list-playbooks", "--domain", "code"]) == 0
    pb_cli_out = json.loads(capsys.readouterr().out)
    assert pb_cli_out["ok"] is True and len(pb_cli_out["playbooks"]) >= 3

    # AgentDojo 32-vector adversarial red-team suite
    red_rep = run_agentdojo_redteam_suite(tmp_path / "redteam")
    assert red_rep["total_attacks"] >= 30
    assert red_rep["attack_success_rate"] == 0.0, red_rep["failed_vectors"]


def test_v82_zero_orphan_modules_topology_and_doctor() -> None:
    pkg_dir = ROOT / "src" / "am_ua"
    topo = InterRepoTopologyGate().audit_package_imports(pkg_dir)
    assert topo["ok"] is True, topo.get("violations")

    # Verify transitive reachability of all modules including v8.2 additions
    module_files: Dict[Path, str] = {}
    for fp in sorted(pkg_dir.rglob("*.py")):
        rel = fp.relative_to(pkg_dir.parent).with_suffix("").as_posix().replace("/", ".")
        if fp.name == "__init__.py":
            rel = rel.rsplit(".__init__", 1)[0]
        module_files[fp] = rel

    graph: Dict[str, set[str]] = {}
    for fp, mod in module_files.items():
        is_pkg_init = fp.name == "__init__.py"
        tree = ast.parse(fp.read_text(encoding="utf-8", errors="ignore"))
        deps: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    deps.add(a.name)
            elif isinstance(node, ast.ImportFrom) and (node.module or node.level > 0):
                if node.level > 0:
                    parts = mod.split(".")
                    base_parts = parts if is_pkg_init else parts[:-1]
                    if node.level > 1:
                        base_parts = base_parts[: -(node.level - 1)]
                    full = ".".join(base_parts + ([node.module] if node.module else []))
                    deps.add(full)
                    for a in node.names:
                        deps.add(full + "." + a.name)
                else:
                    assert node.module is not None
                    deps.add(node.module)
                    for a in node.names:
                        deps.add(node.module + "." + a.name)
        graph[mod] = deps

    roots = ["am_ua", "am_ua.agent_kernel", "am_ua.cli", "am_ua.execution.agent_loop"]
    visited: set[str] = set()
    q = list(roots)
    all_mods = set(module_files.values())
    while q:
        cur = q.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        for target in graph.get(cur, ()):
            if target in all_mods and target not in visited:
                q.append(target)

    leaf_mods = {m for fp, m in module_files.items() if fp.name != "__init__.py"}
    orphans = sorted(leaf_mods - visited)
    assert orphans == [], f"Orphan modules detected: {orphans}"

    doc = AetherMindUniversalAgent(ROOT).doctor()
    assert doc["topology_v2_ok"] is True
    assert doc["parametric_playbooks_count"] >= 8
    assert isinstance(doc["native_backends"], dict)
