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

    p_mission = sub.add_parser("mission", help="Execute a formalized engineering mission")
    p_mission.add_argument("objective", help="Mission objective statement")
    p_mission.add_argument("--mission-id", default=None, help="Explicit mission ID (for resume/replay)")
    p_mission.add_argument("--domain", default="software_engineering")
    p_mission.add_argument("--scan-dir", default=None)
    p_mission.add_argument("--repomap-dir", default=None)
    p_mission.add_argument("--ingest-doc", default=None)
    p_mission.add_argument("--force-dag", action="store_true")

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

    if args.cmd == "mission":
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
        if args.repomap_dir:
            steps.append(
                {
                    "step_id": "repomap_02",
                    "tool_name": "repomap_pagerank",
                    "args": {"repo_root": args.repomap_dir, "max_chars": 2500},
                }
            )
        if args.ingest_doc:
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
        if args.force_dag or args.repomap_dir or args.ingest_doc:
            reqs.append("Multi-organ topological & epistemic verification")
        contract = MissionContract(
            mission_id=mid,
            objective=obj,
            domain=args.domain,
            functional_requirements=reqs,
            acceptance_criteria=["All steps complete with independent verification receipt"],
            constraints={"force_multi_agent_dag": bool(args.force_dag)},
        )
        out = agent.execute_mission(contract, steps=steps)
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
        return 0 if out["status"] == "VERIFIED" else 1

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
