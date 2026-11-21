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
    p_mission.add_argument("--output-schema", default=None, help="JSON Schema string or .json file path for typed structured output")
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

    p_mcp = sub.add_parser("mcp-serve", help="Start the OmniExecutor MCP server over stdio or Streamable HTTP (JSON-RPC 2.0)")
    p_mcp.add_argument("--http-port", type=int, default=None, help="Serve Streamable HTTP/SSE on 127.0.0.1:<port> instead of stdio")
    p_mcp.add_argument("--auth-token", default=None, help="Bearer token for Streamable HTTP mode (or OMNI_RPC_TOKEN env)")
    p_acp = sub.add_parser("acp-serve", help="Start the OmniExecutor ACP server over stdio or Streamable HTTP (JSON-RPC 2.0)")
    p_acp.add_argument("--http-port", type=int, default=None, help="Serve Streamable HTTP/SSE on 127.0.0.1:<port> instead of stdio")
    p_acp.add_argument("--auth-token", default=None, help="Bearer token for Streamable HTTP mode (or OMNI_RPC_TOKEN env)")

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

    p_det = sub.add_parser("det", help="Programmable Deterministic Command Hub (list or run 0-token deterministic rails)")
    p_det.add_argument("action", choices=["list", "run"], help="List available rails or run a deterministic rail")
    p_det.add_argument("rail", nargs="?", default="list_capabilities", help="Deterministic rail name for 'run'")
    p_det.add_argument("--workspace", default=str(ROOT), help="Target workspace directory")
    p_det.add_argument("--params", default="{}", help="JSON params object for the deterministic rail")

    p_a2a = sub.add_parser("a2a-serve", help="Run Agent2Agent (A2A) interoperability server or emit AgentCard JSON")
    p_a2a.add_argument("--host", default="127.0.0.1")
    p_a2a.add_argument("--port", type=int, default=8788)
    p_a2a.add_argument("--auth-token", default=None)
    p_a2a.add_argument("--card-only", action="store_true", help="Print /.well-known/agent.json AgentCard and exit")

    p_lsp = sub.add_parser("lsp", help="Persistent LSP diagnostics & go-to-definition (with instant AST fallback)")
    p_lsp.add_argument("action", choices=["diagnostics", "definition"], help="LSP action")
    p_lsp.add_argument("target", help="File path (for diagnostics) or symbol name (for definition)")
    p_lsp.add_argument("--workspace", default=str(ROOT), help="Target workspace directory")
    p_lsp.add_argument("--language", default="python")

    p_daemon = sub.add_parser("daemon", help="Always-on durable SQLite WAL task & webhook queue")
    p_daemon.add_argument("action", choices=["enqueue", "stats", "claim", "run-once", "recover"], help="Daemon queue action")
    p_daemon.add_argument("--objective", default="", help="Objective for enqueue")
    p_daemon.add_argument("--workspace", default=str(ROOT), help="Workspace path")
    p_daemon.add_argument("--priority", type=int, default=50)
    p_daemon.add_argument("--worker-id", default="cli-worker")
    p_daemon.add_argument("--db", default="", help="Optional custom SQLite DB path")

    p_swe = sub.add_parser("swebench", help="SWE-bench compatibility harness & predictions validator")
    p_swe.add_argument("action", choices=["validate-predictions"], help="SWE-bench action")
    p_swe.add_argument("predictions_path", help="Path to predictions.json")

    p_fleet = sub.add_parser("fleet", help="Run v5.4 HyperFleet (500 to 1,000+ concurrent in-process agents under a hard USD budget)")
    p_fleet.add_argument("--count", type=int, default=500, help="Number of concurrent agents to run (default 500)")
    p_fleet.add_argument("--max-usd", type=float, default=10.0, help="Hard USD budget cap (default $10.0)")
    p_fleet.add_argument("--concurrency", type=int, default=128, help="In-process worker concurrency")
    p_fleet.add_argument("--objective", default="syntax check python files", help="Base objective or deterministic rail task")
    p_fleet.add_argument("--workspace", default=str(ROOT), help="Target workspace directory")

    args = parser.parse_args(argv)
    if args.cmd == "fleet":
        from am_ua.execution.subagent_bus import SubAgentSessionBus
        bus = SubAgentSessionBus()
        tasks = [
            {"id": f"fleet-{i + 1:04d}", "role": "worker", "objective": args.objective}
            for i in range(max(1, int(args.count)))
        ]
        res = bus.run_hyper_fleet(
            tasks,
            workspace=args.workspace,
            max_concurrency=args.concurrency,
            max_budget_usd=args.max_usd,
            prefer_deterministic=True,
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    if args.cmd == "swebench":
        p_file = Path(args.predictions_path).resolve()
        data = json.loads(p_file.read_text(encoding="utf-8"))
        valid = isinstance(data, list) and all(
            isinstance(x, dict) and "instance_id" in x and "model_patch" in x and "model_name_or_path" in x
            for x in data
        )
        print(json.dumps({"ok": valid, "count": len(data) if isinstance(data, list) else 0, "path": str(p_file)}, indent=2))
        return 0 if valid else 1

    if args.cmd == "lsp":
        from am_ua.perception.lsp_client import PersistentLSPClient
        lsp = PersistentLSPClient(args.workspace, language=args.language)
        lsp.start(prefer_external=False)
        try:
            res = lsp.get_diagnostics(args.target) if args.action == "diagnostics" else lsp.goto_definition(args.target)
        finally:
            lsp.shutdown()
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("ok") else 1

    if args.cmd == "daemon":
        from am_ua.contracts.contracts import resolve_omni_temp_dir
        from am_ua.runtime.daemon_queue import DurableDaemonQueue
        db_p = Path(args.db) if args.db else (resolve_omni_temp_dir("daemon") / "queue.db")
        q = DurableDaemonQueue(db_p)
        if args.action == "enqueue":
            tid = q.enqueue(args.objective or "Scheduled check", args.workspace, priority=args.priority)
            print(json.dumps({"ok": True, "task_id": tid, "db": str(db_p)}, indent=2))
            return 0
        if args.action == "claim":
            task = q.claim_next(args.worker_id)
            print(json.dumps({"ok": task is not None, "task": task}, indent=2, default=str))
            return 0
        if args.action == "run-once":
            res = q.run_worker_once(args.worker_id)
            print(json.dumps(res, indent=2, default=str))
            return 0 if res.get("ok") else 1
        if args.action == "recover":
            rec_cnt = q.recover_stale_leases(stale_after_s=300.0)
            print(json.dumps({"ok": True, "recovered_count": rec_cnt}, indent=2))
            return 0
        print(json.dumps({"ok": True, "db": str(db_p), "stats": q.stats()}, indent=2))
        return 0

    if args.cmd == "a2a-serve":
        from am_ua.execution.a2a_protocol import AgentCard, OmniA2AServer
        srv = OmniA2AServer(card=AgentCard(url=f"http://{args.host}:{args.port}"))
        if args.card_only:
            print(json.dumps(srv.get_agent_card(), indent=2, ensure_ascii=False))
            return 0
        tok = args.auth_token or os.environ.get("OMNI_RPC_TOKEN")
        srv.serve_http(host=args.host, port=args.port, auth_token=tok)
        return 0
    if args.cmd == "mcp-serve":
        from am_ua.execution.acp_adapter import StreamableHTTPJsonRpcServer
        from am_ua.execution.mcp_federation import AetherMindMCPServer
        from am_ua.security.agent_shield import AgentShieldAuditor
        agent = AetherMindUniversalAgent()
        srv = AetherMindMCPServer(
            pc_engine=agent.pc_automation,
            skill_forge=agent.skill_forge,
            security_auditor=AgentShieldAuditor(),
        )
        if getattr(args, "http_port", None):
            tok = getattr(args, "auth_token", None) or os.environ.get("OMNI_RPC_TOKEN")
            StreamableHTTPJsonRpcServer(srv.handle_jsonrpc_message, port=args.http_port, auth_token=tok, server_name="omni-mcp").start()
        else:
            srv.serve_stdio()
        return 0

    if args.cmd == "acp-serve":
        from am_ua.execution.acp_adapter import OmniACPServer, StreamableHTTPJsonRpcServer
        agent = AetherMindUniversalAgent()
        acp = OmniACPServer(agent=agent, default_workspace=str(ROOT))
        if getattr(args, "http_port", None):
            tok = getattr(args, "auth_token", None) or os.environ.get("OMNI_RPC_TOKEN")
            StreamableHTTPJsonRpcServer(acp.handle_request, port=args.http_port, auth_token=tok, server_name="omni-acp").start()
        else:
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

    if args.cmd == "det":
        from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader
        if args.action == "list":
            print(json.dumps(DeterministicTaskOffloader.probe_capabilities(), indent=2, ensure_ascii=False))
            return 0
        ws_det = Path(args.workspace).resolve()
        params_det = json.loads(args.params or "{}")
        res_det = DeterministicTaskOffloader.execute_rail(args.rail, ws_det, params=params_det)
        print(json.dumps(res_det, indent=2, ensure_ascii=False, default=str))
        return 0 if res_det.get("ok", True) else 1

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

        parsed_schema = None
        if getattr(args, "output_schema", None):
            raw_schema = str(args.output_schema).strip()
            schema_path = Path(raw_schema)
            if schema_path.is_file():
                parsed_schema = json.loads(schema_path.read_text(encoding="utf-8"))
            else:
                parsed_schema = json.loads(raw_schema)

        try:
            out = agent.run_agent_mission(
                obj, ws, verify_cmd=args.verify, mission_id=args.mission_id,
                max_turns=args.max_turns, actor_provider=args.provider, on_event=progress,
                role=getattr(args, "role", "general_engineer"),
                workflow=getattr(args, "workflow", "react"),
                wheel_timeout_s=getattr(args, "wheel_timeout", 0.0),
                agui_port=getattr(args, "agui_port", None),
                best_of_n=getattr(args, "best_of_n", 1),
                output_schema=parsed_schema,
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
        if args.action == "report":
            proof_dir = ROOT / ".proof"
            reports = sorted(proof_dir.glob("am_bench_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not reports:
                print(json.dumps({"ok": False, "error": "No AM-Bench reports found in .proof/"}))
                return 1
            data = json.loads(reports[0].read_text(encoding="utf-8"))
            print(json.dumps({"latest_report": str(reports[0]), "summary": {k: v for k, v in data.items() if k != "results"}}, indent=2))
            return 0
        from eval.am_bench.runner import main as bench_main
        bench_argv = ["--label", args.label, "--workflow", args.workflow]
        if args.suite == "quick":
            bench_argv.extend(["--only", "c01_off_by_one,c02_mutable_default,c04_money_rounding"])
        elif args.suite in ("code", "desktop", "browser"):
            bench_argv.extend(["--only", args.suite])
        return int(bench_main(bench_argv))

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
