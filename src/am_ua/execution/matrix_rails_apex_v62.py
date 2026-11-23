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

def execute_apex_v62(
    rail_name: str,
    ws: Path,
    target: str,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    # --- DOMAIN I: 2077 APEX SENIOR AGI ENGINEERING ORGANS (121-135) ---
    if rail_name == "sbfl_ochiai_fault_localize":
        from am_ua.execution.apex_fault_localizer import OchiaiSBFLFaultLocalizer

        cov = args.get("coverage_matrix")
        if cov is None:
            for key in ("coverage", "runs", "test_runs", "specs", "locations"):
                if key in args:
                    cov = args[key]
                    break
        if cov is None:
            cov = {k: v for k, v in args.items() if k not in ("formula", "target", "file_path")}
        formula = str(args.get("formula") or "ochiai")
        return {"rail": rail_name, **OchiaiSBFLFaultLocalizer().rank_suspicious_lines(cov, formula=formula)}

    if rail_name == "agentless_three_phase_localize":
        from am_ua.execution.apex_fault_localizer import AgentlessThreePhaseLocalizer

        query = str(args.get("query_or_traceback") or args.get("query") or args.get("traceback") or "")
        top_k = int(args.get("top_k_files", 3))
        win = int(args.get("window", 15))
        return {
            "rail": rail_name,
            **AgentlessThreePhaseLocalizer().localize(ws, query_or_traceback=query, top_k_files=top_k, window=win),
        }

    if rail_name == "autocoderover_ast_guard_synth":
        from am_ua.execution.apex_fault_localizer import AutoCodeRoverASTGuardSynthesizer

        src = str(args.get("source_code") or args.get("code") or "")
        if not src and args.get("file_path"):
            fp = _safe_path(ws, str(args["file_path"]))
            if fp.is_file():
                src = fp.read_text(encoding="utf-8", errors="replace")
        t_line = int(args["target_line"]) if args.get("target_line") is not None else None
        return {
            "rail": rail_name,
            **AutoCodeRoverASTGuardSynthesizer().synthesize_guards(src, target_line=t_line),
        }

    if rail_name == "swe_agent_aci_window_view":
        from am_ua.execution.apex_fault_localizer import SWEAgentWindowedACI

        aci = SWEAgentWindowedACI()
        fp_arg = str(args.get("file_path") or args.get("target") or "")
        res = aci.open_file(ws, fp_arg, start_line=int(args.get("start_line", 1)), window=int(args.get("window", 100)))
        if res.get("ok"):
            if args.get("goto_line") is not None:
                res = aci.goto_line(int(args["goto_line"]))
            scroll_dir = str(args.get("scroll_direction") or args.get("scroll") or "").strip().lower()
            if scroll_dir in ("down", "scroll_down", "next"):
                res = aci.scroll_down()
            elif scroll_dir in ("up", "scroll_up", "prev"):
                res = aci.scroll_up()
        return {"rail": rail_name, **res}

    if rail_name == "swe_agent_aci_search_file":
        from am_ua.execution.apex_fault_localizer import SWEAgentWindowedACI

        aci = SWEAgentWindowedACI()
        fp_arg = str(args.get("file_path") or args.get("target") or "")
        open_res = aci.open_file(ws, fp_arg, start_line=int(args.get("start_line", 1)), window=int(args.get("window", 100)))
        if not open_res.get("ok"):
            return {"rail": rail_name, **open_res}
        res = aci.search_file(
            str(args.get("pattern") or args.get("query") or ""),
            use_regex=args.get("use_regex"),
            case_sensitive=bool(args.get("case_sensitive", True)),
            max_matches=int(args.get("max_matches", 100)),
        )
        return {"rail": rail_name, **res}

    if rail_name == "aider_fuzzy_search_replace":
        from am_ua.execution.apex_codeact_fuzzy import AiderFuzzySearchReplaceEngine

        res = AiderFuzzySearchReplaceEngine.apply_search_replace(
            ws,
            file_path=str(args.get("file_path") or args.get("target") or ""),
            search_block=str(args.get("search_block") or args.get("old_text") or ""),
            replace_block=str(args.get("replace_block") or args.get("new_text") or ""),
            apply=bool(args.get("apply", True)),
        )
        return {"rail": rail_name, **res}

    if rail_name == "codeact_ast_multi_tool_run":
        from am_ua.execution.apex_codeact_fuzzy import (
            CodeActASTSandbox,
            check_api_backward_compat,
            parse_exception_traceback,
            strengthen_test_assertions,
        )

        def _run_rail_tool(r_name: str, r_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            if execute_rail_fn is not None:
                return execute_rail_fn(r_name, ws, params=dict(r_params or {}))
            return execute_matrix_69_rail(r_name, ws, dict(r_params or {}))

        def _read_text_tool(rel_p: str) -> str:
            return _safe_path(ws, str(rel_p)).read_text(encoding="utf-8", errors="replace")

        default_tools: Dict[str, Callable[..., Any]] = {
            "run_rail": _run_rail_tool,
            "read_text": _read_text_tool,
            "parse_traceback": parse_exception_traceback,
            "check_compat": check_api_backward_compat,
            "strengthen_asserts": strengthen_test_assertions,
        }
        custom_tools = args.get("tools")
        if isinstance(custom_tools, dict):
            default_tools.update(custom_tools)
        sandbox = CodeActASTSandbox(tools=default_tools)
        script_code = str(args.get("script_code") or args.get("code") or args.get("script") or "result = 40 + 2")
        return {"rail": rail_name, **sandbox.execute_script(script_code, initial_vars=args.get("initial_vars"))}

    if rail_name == "dirty_worktree_snapshot_guard":
        from am_ua.execution.apex_codeact_fuzzy import DirtyWorktreeSnapshotGuard

        guard = args.get("guard")
        if not isinstance(guard, DirtyWorktreeSnapshotGuard):
            ws_key = str(ws)
            if ws_key not in _WORKSPACE_SNAPSHOT_GUARDS or bool(args.get("reset", False)):
                _WORKSPACE_SNAPSHOT_GUARDS[ws_key] = DirtyWorktreeSnapshotGuard()
            guard = _WORKSPACE_SNAPSHOT_GUARDS[ws_key]
        raw_paths = args.get("rel_paths") if "rel_paths" in args else args.get("paths")
        action = str(
            args.get("action")
            or args.get("sub_action")
            or ("capture" if raw_paths is not None else "status")
        ).strip().lower()
        if action == "capture":
            res = guard.capture(ws, list(raw_paths or []))
        elif action in ("rollback_all", "rollback"):
            res = guard.rollback_all()
        else:
            res = guard.status()
        return {"rail": rail_name, "action": action, **res}

    if rail_name == "senior_architect_readiness_audit":
        from am_ua.execution.apex_codeact_fuzzy import SeniorArchitectReadinessAuditor

        if isinstance(args.get("sources"), dict):
            res = SeniorArchitectReadinessAuditor.audit_sources(args["sources"], target=target)
        else:
            res = SeniorArchitectReadinessAuditor.audit(ws, target=target)
        return {"rail": rail_name, **res}

    if rail_name == "ast_import_dependency_layers":
        from am_ua.execution.apex_codeact_fuzzy import analyze_import_layers

        return {
            "rail": rail_name,
            **analyze_import_layers(ws, target=target, layer_rules=args.get("layer_rules")),
        }

    if rail_name == "deterministic_test_assertion_strengthener":
        from am_ua.execution.apex_codeact_fuzzy import strengthen_test_assertions

        src = str(args.get("source_code") or args.get("code") or "")
        if not src and args.get("file_path"):
            fp = _safe_path(ws, str(args["file_path"]))
            if fp.is_file():
                src = fp.read_text(encoding="utf-8", errors="replace")
        return {"rail": rail_name, **strengthen_test_assertions(src)}

    if rail_name == "exception_root_cause_chain_parser":
        from am_ua.execution.apex_codeact_fuzzy import parse_exception_traceback

        tb = str(args.get("traceback_text") or args.get("traceback") or args.get("text") or "")
        return {"rail": rail_name, **parse_exception_traceback(tb)}

    if rail_name == "api_backward_compat_contract_gate":
        from am_ua.execution.apex_codeact_fuzzy import check_api_backward_compat

        old_src = str(args.get("old_source") or "")
        new_src = str(args.get("new_source") or "")
        if not old_src and args.get("old_file"):
            old_src = _safe_path(ws, str(args["old_file"])).read_text(encoding="utf-8", errors="replace")
        if not new_src and args.get("new_file"):
            new_src = _safe_path(ws, str(args["new_file"])).read_text(encoding="utf-8", errors="replace")
        return {"rail": rail_name, **check_api_backward_compat(old_src, new_src)}

    if rail_name == "deterministic_pr_review_scorecard":
        from am_ua.execution.apex_codeact_fuzzy import compute_pr_review_scorecard

        return {
            "rail": rail_name,
            **compute_pr_review_scorecard(
                ws,
                old_source_map=args.get("old_source_map"),
                new_source_map=args.get("new_source_map"),
                command=str(args.get("command") or ""),
            ),
        }

    if rail_name == "apex_2077_full_diagnostic_sweep":
        from am_ua.execution.apex_codeact_fuzzy import (
            SeniorArchitectReadinessAuditor,
            analyze_import_layers,
        )
        from am_ua.execution.token_latency_savers import gitleaks_precommit_gate

        syntax_errors: List[Dict[str, Any]] = []
        py_files = _iter_py(ws, target)
        for py_p in py_files:
            try:
                ast.parse(py_p.read_text(encoding="utf-8", errors="replace"), filename=str(py_p))
            except SyntaxError as exc:
                syntax_errors.append(
                    {"file": py_p.relative_to(ws).as_posix(), "line": exc.lineno, "msg": exc.msg}
                )
        syntax_res = {
            "ok": len(syntax_errors) == 0,
            "files_checked": len(py_files),
            "syntax_errors": syntax_errors,
        }
        readiness_res = SeniorArchitectReadinessAuditor.audit(ws, target=target)
        layers_res = analyze_import_layers(ws, target=target)
        gitleaks_res = gitleaks_precommit_gate(str(args.get("text") or ""))
        overall_ok = bool(
            syntax_res["ok"]
            and readiness_res.get("ok", False)
            and layers_res.get("ok", False)
            and gitleaks_res.get("ok", False)
        )
        return {
            "ok": overall_ok,
            "rail": rail_name,
            "version": "6.0.0",
            "total_deterministic_rails": 135,
            "ast_syntax_sweep": syntax_res,
            "senior_architect_readiness_audit": {
                "ok": readiness_res.get("ok"),
                "files_scanned": readiness_res.get("files_scanned"),
                "score": readiness_res.get("score"),
                "grade": readiness_res.get("grade"),
                "breakdown": readiness_res.get("breakdown"),
            },
            "ast_import_dependency_layers": {
                "ok": layers_res.get("ok"),
                "files_scanned": layers_res.get("files_scanned"),
                "violation_count": layers_res.get("violation_count"),
                "cycle_count": layers_res.get("cycle_count"),
                "layer_graph": layers_res.get("layer_graph"),
            },
            "gitleaks_precommit_gate": gitleaks_res,
        }

    return None
