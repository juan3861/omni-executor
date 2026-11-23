from __future__ import annotations

import ast
import base64
import csv
from decimal import Decimal, InvalidOperation
import difflib
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import xml.etree.ElementTree as ET
import zipfile

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    "vendor",
    "HANDOFF_PACK",
}


from am_ua.execution.matrix_rails_helpers import _WORKSPACE_SNAPSHOT_GUARDS, _iter_py, _safe_path

def execute_nov26_v62(
    rail_name: str,
    ws: Path,
    target: str,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    # --- DOMAIN K: NOV 2026 TOP-100 x TOP-100 TOTAL EXTRACTION (151-160) ---
    if rail_name == "ponytail_reuse_before_write_gate":
        from am_ua.execution.apex_v62_extracts import PonytailReuseBeforeWriteGate

        return {
            "rail": rail_name,
            **PonytailReuseBeforeWriteGate.check_reuse_candidates(
                ws,
                proposed_name=str(args.get("proposed_name") or ""),
                keywords=list(args.get("keywords") or ()),
                proposed_lines=int(args.get("proposed_lines", 0)),
            ),
        }

    if rail_name == "rea_binary_app_triage":
        from am_ua.execution.apex_v62_extracts import REABinaryAppTriageEngine

        return {
            "rail": rail_name,
            **REABinaryAppTriageEngine.inspect_artifact(
                ws,
                file_path=args.get("file_path"),
                raw_bytes=args.get("raw_bytes"),
            ),
        }

    if rail_name == "http_vcr_record_replay":
        from am_ua.execution.apex_v62_extracts import HTTPVCRRecorderReplayer

        cassette = _safe_path(ws, str(args.get("cassette_path") or ".omni_http_vcr.json"))
        vcr = HTTPVCRRecorderReplayer(cassette)
        mode = str(args.get("mode") or "replay").strip().lower()
        if mode == "record":
            res = vcr.record(
                method=str(args.get("method") or "GET"),
                url=str(args.get("url") or "https://example.com"),
                status=int(args.get("status", 200)),
                response_body=args.get("response_body", {}),
                request_body=str(args.get("request_body") or ""),
                headers=args.get("headers"),
            )
        else:
            res = vcr.replay(
                method=str(args.get("method") or "GET"),
                url=str(args.get("url") or "https://example.com"),
                request_body=str(args.get("request_body") or ""),
            )
        return {"rail": rail_name, **res}

    if rail_name == "cordis_plugin_lifecycle":
        from am_ua.execution.apex_v62_extracts import ComposablePluginSpec, CordisPluginLifecycleHub

        hub = CordisPluginLifecycleHub()
        for item in list(args.get("plugins") or []):
            hub.register(
                ComposablePluginSpec(
                    name=str(item.get("name") or "plugin"),
                    provides=tuple(item.get("provides") or ()),
                    requires=tuple(item.get("requires") or ()),
                )
            )
        return {"rail": rail_name, **hub.boot_all()}

    if rail_name == "claw_behavioral_parity_harness":
        from am_ua.execution.apex_v62_extracts import CordisPluginLifecycleHub
        from am_ua.execution.deterministic_matrix_100 import execute_matrix_69_rail
        from am_ua.execution.matrix_rails_helpers import MATRIX_69_SPECS

        scenarios = list(args.get("scenarios") or [])
        res = CordisPluginLifecycleHub.run_parity_scenarios(
            scenarios,
            lambda t, p: execute_matrix_69_rail(t, ws, p, execute_rail_fn=execute_rail_fn)
            if t in MATRIX_69_SPECS
            else (execute_rail_fn(t, ws, params=p) if execute_rail_fn is not None else {"ok": False}),
        )
        return {"rail": rail_name, **res}

    if rail_name == "etl_sql_lineage_dag":
        from am_ua.execution.apex_v62_extracts import DataEngineeringDeterministicSuite

        return {"rail": rail_name, **DataEngineeringDeterministicSuite.extract_sql_lineage_dag(dict(args.get("models") or {}))}

    if rail_name == "data_quality_expectation_gate":
        from am_ua.execution.apex_v62_extracts import DataEngineeringDeterministicSuite

        return {
            "rail": rail_name,
            **DataEngineeringDeterministicSuite.evaluate_data_quality_expectations(
                list(args.get("rows") or []),
                list(args.get("expectations") or []),
            ),
        }

    if rail_name == "sqlite_query_plan_auditor":
        from am_ua.execution.apex_v62_extracts import DataEngineeringDeterministicSuite

        return {
            "rail": rail_name,
            **DataEngineeringDeterministicSuite.audit_sqlite_query_plan(
                ddl_sql=str(args.get("ddl_sql") or "CREATE TABLE items(id INT PRIMARY KEY, sku TEXT);"),
                query_sql=str(args.get("query_sql") or "SELECT * FROM items WHERE sku = 'A1'"),
            ),
        }

    if rail_name == "universal_app_command_router":
        from am_ua.execution.apex_v62_extracts import UniversalAppCommandRouter

        return {
            "rail": rail_name,
            **UniversalAppCommandRouter.route_intent(
                str(args.get("intent") or "python_version"),
                target=str(args.get("target") or ""),
                out=str(args.get("out") or ""),
                execute=bool(args.get("execute", False)),
                workspace=ws,
            ),
        }

    if rail_name == "v62_top100_cross_parity_audit":
        from am_ua.execution.deterministic_offloader import BUILTIN_DETERMINISTIC_RAILS

        al_file = ws / "src" / "am_ua" / "execution" / "agent_loop.py"
        wt_file = ws / "src" / "am_ua" / "execution" / "workspace_tools.py"
        dm_file = ws / "src" / "am_ua" / "execution" / "deterministic_matrix_100.py"
        live_wired_symbols: Dict[str, bool] = {}
        if al_file.is_file():
            al_txt = al_file.read_text(encoding="utf-8", errors="replace")
            if wt_file.is_file():
                al_txt += "\n" + wt_file.read_text(encoding="utf-8", errors="replace")
            for sym in (
                "OpenHandsStuckDetector",
                "AiderFuzzySearchReplaceEngine",
                "ShellSemanticPolicyRails",
                "grammar_json_repair",
                "prompt_token_pruner",
                "SimHashSemanticCache",
                "AgentlessThreePhaseLocalizer",
            ):
                live_wired_symbols[sym] = sym in al_txt
        zero_stubs = True
        if dm_file.is_file():
            dm_txt = dm_file.read_text(encoding="utf-8", errors="replace")
            zero_stubs = ("execute_real_win_os_rail" in dm_txt) and not re.search(
                r'return\s+\{[^}]*"status"\s*:\s*"ready"', dm_txt
            )
        all_wired = all(live_wired_symbols.values()) if live_wired_symbols else True
        return {
            "ok": zero_stubs and all_wired and len(BUILTIN_DETERMINISTIC_RAILS) >= 160,
            "rail": rail_name,
            "total_deterministic_rails": len(BUILTIN_DETERMINISTIC_RAILS),
            "zero_windows_stubs": zero_stubs,
            "agent_loop_live_wired": live_wired_symbols,
        }

    return None
