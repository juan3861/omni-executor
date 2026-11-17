#!/usr/bin/env python3
"""AM-Bench runner: real-LLM, zero-mock benchmark for the AetherMind agent.

Pass criterion per task (decided by the runner, never by the agent or an LLM judge):
  code    -> hidden tests exit 0 AND visible test files untouched (SHA-256)
  desktop -> GUI fixture state / workspace answer matches the secret that only exists on screen
Results: .proof/am_bench_<label>_<ts>.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tasks import ALL_TASKS, PY, PYTEST_VISIBLE, BenchTask  # noqa: E402

from am_ua.cognition.llm_client import LLMClient  # noqa: E402
from am_ua.execution.adaptive_skills import AdaptiveSkillForge  # noqa: E402
from am_ua.execution.agent_loop import AgentLoop  # noqa: E402
from am_ua.execution.durable_engine import DurableExecutionEngine  # noqa: E402
from am_ua.execution.pc_automation import PCAutomationEngine  # noqa: E402
from am_ua.governance.seal_guard import ConstitutionSealGuard  # noqa: E402

BENCH_ROOT = Path(r"F:\AetherMind_Temp\am_bench")
FIXTURE = Path(__file__).resolve().parent / "gui_fixture.py"
PYW = str(Path(PY).with_name("pythonw.exe"))


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _write(base: Path, files: Dict[str, str]) -> None:
    for rel, content in files.items():
        f = base / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8", newline="\n")


class GuiFixture:
    def __init__(self, mode: str, state_path: Path) -> None:
        self.mode, self.state_path = mode, state_path
        rnd = random.SystemRandom()
        if mode == "secret":
            self.payload = "".join(rnd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
            self.expected = self.payload
        elif mode == "numbers":
            nums = [rnd.randint(10, 99) for _ in range(5)]
            self.payload, self.expected = ",".join(map(str, nums)), str(sum(nums))
        elif mode == "button":
            self.payload = "".join(rnd.choice(string.ascii_lowercase) for _ in range(12))
            self.expected = self.payload
        else:  # form
            self.payload, self.expected = "-", "Ação Ω 2026"
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "GuiFixture":
        self.state_path.unlink(missing_ok=True)
        self.proc = subprocess.Popen(
            [PY, str(FIXTURE), self.mode, str(self.state_path), self.payload],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.time() + 15
        while time.time() < deadline and not self.state_path.exists():
            time.sleep(0.2)
        time.sleep(0.8)
        return self

    def state(self) -> Dict[str, Any]:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def __exit__(self, *exc: Any) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def judge_desktop(task: BenchTask, ws: Path, fx: GuiFixture) -> Dict[str, Any]:
    st = fx.state()
    read = lambda name: (ws / name).read_text(encoding="utf-8").strip() if (ws / name).is_file() else None  # noqa: E731
    if task.gui_mode in ("secret", "numbers"):
        got = read("answer.txt")
        return {"passed": got == fx.expected, "expected": fx.expected, "got": got}
    if task.gui_mode == "button":
        ok = bool(st.get("confirm_clicked")) and not st.get("cancel_clicked") and read("done.txt") == "DONE"
        return {"passed": ok, "state": st, "done": read("done.txt")}
    ok = st.get("saved_text") == fx.expected and read("done.txt") == "DONE"
    return {"passed": ok, "expected": fx.expected, "got": st.get("saved_text"), "done": read("done.txt")}


def judge_code(task: BenchTask, ws: Path, visible_hashes: Dict[str, str]) -> Dict[str, Any]:
    tampered = [rel for rel, h in visible_hashes.items() if not (ws / rel).is_file() or _sha(ws / rel) != h]
    _write(ws, task.hidden)
    proc = subprocess.run(
        [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests_hidden"],
        cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
    )
    return {
        "passed": proc.returncode == 0 and not tampered,
        "hidden_exit_code": proc.returncode,
        "visible_tampered": tampered,
        "hidden_output_tail": (proc.stdout + proc.stderr)[-1200:],
    }


def run_task(task: BenchTask, run_dir: Path, *, workflow: str, max_wall_s: float, llm: LLMClient, adaptive_bon: int = 1) -> Dict[str, Any]:
    ws = run_dir / task.task_id
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir(parents=True)
    _write(ws, task.files)
    _write(ws, task.visible)
    visible_hashes = {rel: _sha(ws / rel) for rel in task.visible}
    side = run_dir / "_side" / task.task_id
    side.mkdir(parents=True, exist_ok=True)
    snap_ws = side / "_clean_snap"
    if adaptive_bon > 1 and task.category != "desktop":
        shutil.copytree(ws, snap_ws)

    loop = AgentLoop(
        engine=DurableExecutionEngine(side / "durable.db"),
        seal_guard=ConstitutionSealGuard(ROOT),
        llm=llm,
        trace_dir=side / "traces",
        agui_ledger_dir=side / "agui",
        pc_engine=PCAutomationEngine(artifact_dir=side / "pc"),
        skill_forge=AdaptiveSkillForge(side / "skills"),
        browser_factory=lambda headless=True: __import__("am_ua.gui.cdp_browser", fromlist=["CDPIndexedBrowser"]).CDPIndexedBrowser(
            artifact_dir=side / "browser", headless=headless
        ),
    )
    raw_obj = task.objective.replace("{SITE_URI}", (ws / "site").resolve().as_uri())
    objective = raw_obj + f"\nPython interpreter: {PY} (python is NOT on PATH; call it by full path with '&')."
    calls0, pt0, ct0 = llm.calls, llm.total_prompt_tokens, llm.total_completion_tokens
    t0 = time.perf_counter()
    rec: Dict[str, Any] = {"task_id": task.task_id, "category": task.category}

    def _go() -> Any:
        return loop.run(
            objective, ws,
            verify_cmd=PYTEST_VISIBLE if task.category == "code" else None,
            mission_id=f"bench-{task.task_id}-{int(time.time())}",
            max_turns=task.max_turns, max_wall_s=max_wall_s, use_judge=False, workflow=workflow,
        )

    try:
        if task.category == "desktop":
            with GuiFixture(task.gui_mode or "secret", side / "gui_state.json") as fx:
                res = _go()
                verdict = judge_desktop(task, ws, fx)
        else:
            def _eval_ws(run_res: Any) -> Dict[str, Any]:
                v = judge_code(task, ws, visible_hashes)
                if task.category == "browser":
                    used_b = any(c["tool"].startswith("browser_") and c.get("ok") for c in run_res.tool_calls)
                    v["browser_tool_used"] = used_b
                    if not used_b:
                        v["passed"] = False
                return v

            res = _go()
            verdict = _eval_ws(res)
            if adaptive_bon > 1 and not verdict.get("passed") and snap_ws.exists():
                for alt_wf, alt_role in (("sparc", "tdd_enforcer"), ("react", "build_error_resolver"))[: adaptive_bon - 1]:
                    if str(res.stop_reason).startswith("llm_unavailable"):
                        time.sleep(10.0)
                    shutil.rmtree(ws, ignore_errors=True)
                    shutil.copytree(snap_ws, ws)
                    postmortem = (
                        f"\nFAILURE POSTMORTEM FROM PREVIOUS ATTEMPT (DO NOT REPEAT): "
                        f"status={res.status}, stop_reason={res.stop_reason}, "
                        f"tools={[c['tool'] for c in res.tool_calls[-8:]]}."
                    )
                    res2 = loop.run(
                        objective + postmortem, ws,
                        verify_cmd=PYTEST_VISIBLE if task.category == "code" else None,
                        mission_id=f"bench-{task.task_id}-esc-{int(time.time())}",
                        max_turns=task.max_turns, max_wall_s=max_wall_s, use_judge=False,
                        workflow=alt_wf, role=alt_role,
                    )
                    v2 = _eval_ws(res2)
                    res, verdict = res2, v2
                    verdict["adaptive_escalated"] = True
                    if verdict.get("passed"):
                        break
        rec.update(
            agent_status=res.status, stop_reason=res.stop_reason, turns=res.turns,
            providers=res.actor_providers, tools=[c["tool"] for c in res.tool_calls],
        )
    except Exception as exc:  # infrastructure failure is a FAIL, never silently skipped
        verdict = {"passed": False, "infra_error": f"{type(exc).__name__}: {str(exc)[:400]}"}
    rec.update(verdict)
    rec.update(
        elapsed_s=round(time.perf_counter() - t0, 1),
        llm_calls=llm.calls - calls0,
        prompt_tokens=llm.total_prompt_tokens - pt0,
        completion_tokens=llm.total_completion_tokens - ct0,
    )
    return rec


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    def agg(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(rows)
        p = sum(1 for r in rows if r.get("passed"))
        return {
            "n": n, "passed": p, "pass_rate": round(p / n, 3) if n else None,
            "tokens": sum(r.get("prompt_tokens", 0) + r.get("completion_tokens", 0) for r in rows),
            "llm_calls": sum(r.get("llm_calls", 0) for r in rows),
            "elapsed_s": round(sum(r.get("elapsed_s", 0) for r in rows), 1),
        }
    cats = sorted({r["category"] for r in results})
    return {"overall": agg(results), **{c: agg([r for r in results if r["category"] == c]) for c in cats}}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="am-bench")
    ap.add_argument("--label", default="baseline")
    ap.add_argument("--only", default="", help="comma-separated task ids or a category (code|desktop|browser)")
    ap.add_argument("--workflow", default="react")
    ap.add_argument("--max-wall", type=float, default=600.0)
    ap.add_argument("--pause", type=float, default=3.0, help="seconds between tasks (provider rate limits)")
    ap.add_argument("--adaptive-bon", type=int, default=1, help="Escalate failed tasks up to N diverse attempts with failure postmortem")
    a = ap.parse_args(argv)

    sel = [t for t in ALL_TASKS]
    if a.only:
        keys = {k.strip() for k in a.only.split(",") if k.strip()}
        sel = [t for t in ALL_TASKS if t.task_id in keys or t.category in keys]
    ts = time.strftime("%Y%m%d_%H%M%S")
    run_dir = BENCH_ROOT / f"{a.label}_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    llm = LLMClient()
    out_path = ROOT / ".proof" / f"am_bench_{a.label}_{ts}.json"
    results: List[Dict[str, Any]] = []
    for i, task in enumerate(sel, 1):
        print(f"[{i}/{len(sel)}] {task.task_id} ...", flush=True)
        r = run_task(task, run_dir, workflow=a.workflow, max_wall_s=a.max_wall, llm=llm, adaptive_bon=a.adaptive_bon)
        results.append(r)
        print(f"    -> {'PASS' if r.get('passed') else 'FAIL'} status={r.get('agent_status')} turns={r.get('turns')} "
              f"tok={r.get('prompt_tokens', 0) + r.get('completion_tokens', 0)} {r.get('infra_error', '')}", flush=True)
        report = {
            "schema": "AM_BENCH_RESULT/v1", "label": a.label, "workflow": a.workflow, "run_dir": str(run_dir),
            "providers_configured": [(p.name, p.model) for p in llm.providers],
            "completed": i, "selected": len(sel), "summary": summarize(results), "results": results,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        if i < len(sel):
            time.sleep(a.pause)
    print(json.dumps(summarize(results), indent=2))
    print(f"report: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
