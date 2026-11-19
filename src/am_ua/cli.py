#!/usr/bin/env python3
"""CLI Entrypoint for AetherMind Universal Agent (`aether-ua.cmd`) (P6.1)."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from am_ua.agent_kernel import AetherMindUniversalAgent
from am_ua.contracts.contracts import MissionContract
from am_ua.lifecycle.handoff_exporter import HandoffPackExporter


def fix_mangled_string(s: str) -> str:
    """Restore UTF-8 strings mangled by Windows PowerShell cp1252/cp850 codepages."""
    for enc in ("cp1252", "cp850", "cp437", "iso-8859-1"):
        try:
            return s.encode(enc).decode("utf-8")
        except UnicodeError:
            continue
    return s


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aether-ua",
        description="OmniExecutor Agent CLI: autonomous coding, browser and desktop automation harness",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Run full multi-organ & constitutional readiness check")

    p_radar = sub.add_parser("radar", help="Run AetherScan + UCIP topological compression")
    p_radar.add_argument("target", nargs="?", default=str(ROOT / "src"))

    p_map = sub.add_parser("repomap", help="Build polyglot PageRank RepoMap")
    p_map.add_argument("target", nargs="?", default=str(ROOT / "src"))
    p_map.add_argument("--max-chars", type=int, default=3000)

    p_mission = sub.add_parser(
        "mission",
        help="REAL agent: LLM plans and edits/runs code in a workspace; VERIFIED only if --verify exits 0 (or multi-organ diagnostic pipeline if --scan-dir is set)",
    )
    p_mission.add_argument("objective", help="Mission objective statement")
    p_mission.add_argument("--workspace", default=None, help="Workspace dir (default: current dir; must be inside the project or F:\\AetherMind_Temp)")
    p_mission.add_argument("--verify", default=None, help="Acceptance command (PowerShell) run in the workspace; exit 0 = PASS")
    p_mission.add_argument("--max-turns", type=int, default=30)
    p_mission.add_argument("--provider", default=None, help="Preferred actor provider (groq|openrouter|openai|omniroute)")
    p_mission.add_argument("--mission-id", default=None, help="Explicit mission ID")
    p_mission.add_argument("--full-json", action="store_true", help="Print the full result including diff")
    # Pipeline & diagnostic compatibility flags
    p_mission.add_argument("--role", default="general_engineer", help="Specialized persona contract (general_engineer|systems_architect|strict_auditor|security_reverse_engineer|performance_sre)")
    p_mission.add_argument("--workflow", default="react", choices=["react", "sparc", "hierarchical"], help="Execution workflow methodology (react|sparc|hierarchical)")
    p_mission.add_argument("--best-of-n", type=int, default=1, help="Behavior Best-of-N parallel candidate rollouts (Agent-S3 bBoN)")
    p_mission.add_argument("--wheel-timeout", type=float, default=0.0, help="Human intervention timeout in seconds (0 = disabled/autonomous)")
    p_mission.add_argument("--agui-port", type=int, default=None, help="Local loopback port to serve live AG-UI SSE stream (127.0.0.1)")
    p_mission.add_argument("--domain", default="software_engineering")
    p_mission.add_argument("--scan-dir", default=None)
    p_mission.add_argument("--repomap-dir", default=None)
    p_mission.add_argument("--ingest-doc", default=None)
    p_mission.add_argument("--force-dag", action="store_true")

    p_pipe = sub.add_parser("pipeline", help="LEGACY deterministic tool pipeline (no LLM; diagnostics only)")
    p_pipe.add_argument("objective", help="Mission objective statement")
    p_pipe.add_argument("--mission-id", default=None, help="Explicit mission ID (for resume/replay)")
    p_pipe.add_argument("--domain", default="software_engineering")
    p_pipe.add_argument("--scan-dir", default=None)
    p_pipe.add_argument("--repomap-dir", default=None)
    p_pipe.add_argument("--ingest-doc", default=None)
    p_pipe.add_argument("--force-dag", action="store_true")

    p_doc = sub.add_parser("ingest-doc", help="Ingest document (.docx/.xlsx/.csv/.pdf/.md) with R16 tainting")
    p_doc.add_argument("file_path")

    p_handoff = sub.add_parser("handoff", help="Export Cold-Team R18 HANDOFF_PACK")
    p_handoff.add_argument("--out", default=str(ROOT / "HANDOFF_PACK"))

    p_wheel = sub.add_parser("wheel", help="Take the Wheel: inspect or control human-in-the-loop intervention")
    p_wheel.add_argument("action", choices=["status", "resume", "abort"], help="Wheel action")
    p_wheel.add_argument("mission_id", nargs="?", default=None, help="Target mission ID for resume/abort")
    p_wheel.add_argument("--note", default="Operator intervention acknowledged", help="Message or instructions for the agent upon resumption/abort")

    p_pc = sub.add_parser("pc", help="Complete PC Desktop/OS Automation (SoM Grounding, Robocorp Locators, Window/Process/Clipboard)")
    p_pc.add_argument("action", choices=["probe", "windows", "observe", "find", "clipboard", "processes", "port"], help="PC automation sub-action")
    p_pc.add_argument("--locator", default=None, help="Robocorp locator query (e.g. 'name:\"Edit\" and type:EditControl')")
    p_pc.add_argument("--filter", default=None, help="Text filter for windows or processes")
    p_pc.add_argument("--text", default=None, help="Text to write to clipboard")
    p_pc.add_argument("--port", type=int, default=None, help="Port number to inspect")
    p_pc.add_argument("--no-ocr", action="store_true", help="Disable OCR fallback during observe")

    p_skills = sub.add_parser("skills", help="Adaptive Skill Forge (Voyager/Open-Interpreter self-extending Python skills)")
    p_skills.add_argument("action", choices=["list", "search", "run"], help="Skills action")
    p_skills.add_argument("--query", default="", help="Search query for skills")
    p_skills.add_argument("--name", default=None, help="Skill name to run")
    p_skills.add_argument("--kwargs", default="{}", help="JSON kwargs for skill execution")

    sub.add_parser("mcp-serve", help="Start the OmniExecutor MCP server over stdio (JSON-RPC 2.0)")
    sub.add_parser("acp-serve", help="Start the OmniExecutor ACP server over stdio (JSON-RPC 2.0)")

    p_bench = sub.add_parser("bench", help="Real-LLM Benchmark (AM-Bench) runner & comparison")
    p_bench.add_argument("action", choices=["run", "report"], help="Benchmark action")
    p_bench.add_argument("--suite", default="quick", choices=["code", "desktop", "all", "quick"], help="Benchmark suite")
    p_bench.add_argument("--label", default="v3.4", help="Label for benchmark report")
    p_bench.add_argument("--workflow", default="react", choices=["react", "sparc", "hierarchical"])
    p_bench.add_argument("--max-turns", type=int, default=12)

    p_browser = sub.add_parser("browser", help="CDP Interactive DOM-Indexed Browser (browser-use / Stagehand observe/act/extract)")
    p_browser.add_argument("action", choices=["observe", "act", "extract"], help="Browser action")
    p_browser.add_argument("--url", required=True, help="Target URL to open in isolated browser context")
    p_browser.add_argument("--index", type=int, default=None, help="DOM index [1..N] for 'act'")
    p_browser.add_argument("--selector", default=None, help="CSS selector for 'act' or 'extract'")
    p_browser.add_argument("--act-type", default="click", choices=["click", "fill", "press"], help="Interaction type for 'act'")
    p_browser.add_argument("--value", default="", help="Text or key value for 'act'")

    p_shield = sub.add_parser("shield", help="Run AgentShield static security audit over a directory")
    p_shield.add_argument("target", nargs="?", default=str(ROOT))

    args = parser.parse_args(argv)
    if args.cmd == "mcp-serve":
        from am_ua.execution.mcp_federation import AetherMindMCPServer
        from am_ua.security.agent_shield import AgentShieldAuditor
        agent = AetherMindUniversalAgent()
        srv = AetherMindMCPServer(
            pc_engine=agent.pc_automation,
            skill_forge=agent.skill_forge,
            security_auditor=AgentShieldAuditor(),
        )
        srv.serve_stdio()
        return 0

    if args.cmd == "acp-serve":
        from am_ua.execution.acp_adapter import OmniACPServer
        agent = AetherMindUniversalAgent()
        acp = OmniACPServer(agent=agent, default_workspace=str(ROOT))
        acp.serve_stdio()
        return 0

    agent = AetherMindUniversalAgent()

    if args.cmd == "doctor":
        rep = agent.doctor()
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep["homeostasis_healthy"] and rep["topology_v2_ok"] else 1

    if args.cmd == "shield":
        from am_ua.security.agent_shield import AgentShieldAuditor
        rep = AgentShieldAuditor().scan_directory(args.target)
        print(json.dumps(rep.to_dict(), indent=2, ensure_ascii=False))
        return 0 if rep.passed else 1

    if args.cmd == "radar":
        ucip = agent.radar.build_ucip_summary(args.target)
        print(json.dumps(asdict(ucip), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "repomap":
        res = agent.map_repository(args.target, max_chars=args.max_chars)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    def _execute_pipeline(args) -> int:
        obj = fix_mangled_string(args.objective)
        steps = []
        default_src = str(ROOT / "src" / "am_ua")
        scan_target = args.scan_dir or default_src
        steps.append(
            {
                "step_id": "scan_01",
                "tool_name": "ucip_radar_scan",
                "args": {"target_dir": scan_target, "invoke_binary": False},
            }
        )
        if getattr(args, "repomap_dir", None):
            steps.append(
                {
                    "step_id": "repomap_02",
                    "tool_name": "repomap_pagerank",
                    "args": {"repo_root": args.repomap_dir, "max_chars": 2500},
                }
            )
        if getattr(args, "ingest_doc", None):
            steps.append(
                {
                    "step_id": "doc_03",
                    "tool_name": "ingest_document_tainted",
                    "args": {"file_path": args.ingest_doc},
                }
            )
        steps.append(
            {
                "step_id": "mem_recall_04",
                "tool_name": "triad_memory_recall",
                "args": {"query": obj[:120]},
            }
        )
        steps.append(
            {
                "step_id": "topo_audit_05",
                "tool_name": "constitutional_topology_audit",
                "args": {"package_dir": default_src},
            }
        )
        mid = args.mission_id or f"cli-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
        reqs = [obj]
        if getattr(args, "force_dag", False) or getattr(args, "repomap_dir", None) or getattr(args, "ingest_doc", None):
            reqs.append("Multi-organ topological & epistemic verification")
        contract = MissionContract(
            mission_id=mid,
            objective=obj,
            domain=getattr(args, "domain", "software_engineering"),
            functional_requirements=reqs,
            acceptance_criteria=["All steps complete with independent verification receipt"],
            constraints={"force_multi_agent_dag": bool(getattr(args, "force_dag", False))},
        )
        out = agent.execute_mission(contract, steps=steps)
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0 if out["status"] == "VERIFIED" else 1

    if args.cmd == "mission":
        if args.scan_dir or args.repomap_dir or args.ingest_doc or args.force_dag:
            return _execute_pipeline(args)
        obj = fix_mangled_string(args.objective)
        ws = Path(args.workspace or Path.cwd()).resolve()

        def progress(ev: dict) -> None:
            print(f"[turn {ev.get('turn')}] {ev.get('provider')} -> {ev.get('tool')}: {ev.get('thought', '')}", file=sys.stderr, flush=True)

        try:
            out = agent.run_agent_mission(
                obj, ws, verify_cmd=args.verify, mission_id=args.mission_id,
                max_turns=args.max_turns, actor_provider=args.provider, on_event=progress,
                role=getattr(args, "role", "general_engineer"),
                workflow=getattr(args, "workflow", "react"),
                wheel_timeout_s=getattr(args, "wheel_timeout", 0.0),
                agui_port=getattr(args, "agui_port", None),
                best_of_n=getattr(args, "best_of_n", 1),
            )
        except PermissionError as exc:
            print(json.dumps({"status": "BLOCKED", "error": str(exc)}, ensure_ascii=False))
            return 2
        if not args.full_json:
            out = {k: v for k, v in out.items() if k not in ("diff", "tool_calls")}
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0 if str(out.get("status", "")).startswith("VERIFIED") else 1

    if args.cmd == "wheel":
        from am_ua.execution.human_wheel import HumanWheelGate
        if args.action == "status":
            active = HumanWheelGate.list_active_requests()
            print(json.dumps({"active_requests": active, "count": len(active)}, indent=2, ensure_ascii=False))
            return 0
        if not args.mission_id:
            print(json.dumps({"ok": False, "error": "mission_id is required for resume/abort"}, ensure_ascii=False))
            return 1
        if args.action == "resume":
            res = HumanWheelGate.resume(args.mission_id, note=args.note)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0 if res.get("ok") else 1
        if args.action == "abort":
            res = HumanWheelGate.abort(args.mission_id, note=args.note)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0 if res.get("ok") else 1

    if args.cmd == "pipeline":
        return _execute_pipeline(args)

    if args.cmd == "ingest-doc":
        ing = agent.documents.ingest_document(args.file_path)
        print(json.dumps(ing, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "handoff":
        exporter = HandoffPackExporter(ROOT)
        res = exporter.export(args.out)
        print(json.dumps({"ok": True, "output_dir": res["output_dir"], "files": res["files"]}, indent=2))
        return 0

    if args.cmd == "pc":
        pc = agent.pc_automation
        if args.action == "probe":
            res = pc.probe_capabilities()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
        if args.action == "windows":
            wins = pc.window_organ.list_windows(title_filter=args.filter or "")
            print(json.dumps({"ok": True, "count": len(wins), "windows": wins[:50]}, indent=2, ensure_ascii=False))
            return 0
        if args.action == "observe":
            res = pc.observe_desktop(include_ocr=not args.no_ocr)
            if args.locator:
                loc = fix_mangled_string(args.locator)
                res["matched_elements"] = pc.find_elements(loc, refresh=False)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0 if res.get("ok") else 1
        if args.action == "find":
            if not args.locator:
                print(json.dumps({"ok": False, "error": "--locator is required for 'pc find'"}, ensure_ascii=False))
                return 1
            loc = fix_mangled_string(args.locator)
            wins = pc.window_organ.find_windows_by_locator(loc)
            els = pc.find_elements(loc, refresh=True)
            print(json.dumps({
                "ok": True,
                "locator": loc,
                "matching_windows": wins,
                "matching_elements": els,
                "som_screenshot_path": pc.last_observation.get("som_screenshot_path") if pc.last_observation else None,
            }, indent=2, ensure_ascii=False))
            return 0
        if args.action == "clipboard":
            if args.text is not None:
                txt = fix_mangled_string(args.text)
                ok = pc.clipboard.set_text(txt)
                print(json.dumps({"ok": ok, "action": "set", "length": len(txt)}, indent=2, ensure_ascii=False))
                return 0 if ok else 1
            val = pc.clipboard.get_text()
            print(json.dumps({"ok": True, "action": "get", "text": val}, indent=2, ensure_ascii=False))
            return 0
        if args.action == "processes":
            procs = pc.window_organ.list_processes(name_filter=args.filter)
            print(json.dumps({"ok": True, "count": len(procs), "processes": procs}, indent=2, ensure_ascii=False))
            return 0
        if args.action == "port":
            if not args.port:
                print(json.dumps({"ok": False, "error": "--port is required for 'pc port'"}, ensure_ascii=False))
                return 1
            res = pc.window_organ.find_port_owner(args.port)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

    if args.cmd == "skills":
        forge = agent.skill_forge
        if args.action == "list":
            skills = forge.list_skills()
            print(json.dumps({"ok": True, "count": len(skills), "skills": skills}, indent=2, ensure_ascii=False))
            return 0
        if args.action == "search":
            skills = forge.search_skills(fix_mangled_string(args.query))
            print(json.dumps({"ok": True, "query": args.query, "matches": skills}, indent=2, ensure_ascii=False))
            return 0
        if args.action == "run":
            if not args.name:
                print(json.dumps({"ok": False, "error": "--name is required for 'skills run'"}, ensure_ascii=False))
                return 1
            kw = json.loads(args.kwargs or "{}")
            res = forge.run_skill(args.name, kwargs=kw)
            print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
            return 0 if res.get("ok") else 1

    if args.cmd == "bench":
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from eval.am_bench.runner import run_benchmark
        if args.action == "report":
            proof_dir = ROOT / ".proof"
            reports = sorted(proof_dir.glob("am_bench_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not reports:
                print(json.dumps({"ok": False, "error": "No AM-Bench reports found in .proof/"}))
                return 1
            data = json.loads(reports[0].read_text(encoding="utf-8"))
            print(json.dumps({"latest_report": str(reports[0]), "summary": {k: v for k, v in data.items() if k != "results"}}, indent=2))
            return 0
        rep = run_benchmark(suite=args.suite, label=args.label, workflow=args.workflow, max_turns=args.max_turns)
        print(json.dumps({k: v for k, v in rep.items() if k != "results"}, indent=2))
        return 0

    if args.cmd == "browser":
        br = agent.cdp_browser
        try:
            obs = br.observe(url=args.url)
            if args.action == "observe":
                print(json.dumps(obs, indent=2, ensure_ascii=False))
                return 0 if obs.get("ok") else 1
            if args.action == "act":
                res = br.act(args.act_type, idx=args.index, target=args.selector, text=args.value)
                print(json.dumps(res, indent=2, ensure_ascii=False))
                return 0 if res.get("ok") else 1
            if args.action == "extract":
                res = br.extract(selector=args.selector or "body")
                print(json.dumps(res, indent=2, ensure_ascii=False))
                return 0 if res.get("ok") else 1
        finally:
            br.close()

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
