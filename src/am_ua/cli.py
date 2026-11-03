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
        description="AetherMind Universal Agent (Super-Union v3.1) Sovereign CLI",
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

    args = parser.parse_args(argv)
    agent = AetherMindUniversalAgent()

    if args.cmd == "doctor":
        rep = agent.doctor()
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep["homeostasis_healthy"] and rep["topology_v2_ok"] else 1

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
            )
        except PermissionError as exc:
            print(json.dumps({"status": "BLOCKED", "error": str(exc)}, ensure_ascii=False))
            return 2
        if not args.full_json:
            out = {k: v for k, v in out.items() if k not in ("diff", "tool_calls")}
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0 if str(out.get("status", "")).startswith("VERIFIED") else 1

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

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
