"""Deterministic Task Offloader & Programmable Command Hub (`am_ua.execution.deterministic_offloader`)."""

from __future__ import annotations

import ast
import csv
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional


from am_ua.execution.offloader_shared import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicRailSpec,
    _MUTATION_INTENT_RX,
    _SKIP_DIRS,
    _iter_py_files,
    _resolve_in_workspace,
)
from am_ua.execution.offloader_code_ops import off_ast_syntax_sweep, off_code_autofix_and_lint, off_data_sql_query, off_generate_pytest_skeleton, off_git_forensics, off_property_edge_fuzz, off_run_preflight_bundle, off_sbom_and_deps_audit, off_structural_diff, off_structural_search_replace, off_type_and_contract_check
from am_ua.execution.offloader_synth_ops import off__eval_constraint_ast, off_codegen_from_openapi, off_codegen_sql_to_python, off_extract_document_structured, off_hypothesis_property_test, off_libcst_safe_codemod, off_os_sql_query, off_parse_pytest_output, off_polyglot_outline, off_pytest_failure_diagnoser, off_replace_function_body, off_z3_constraint_solve
from am_ua.execution.offloader_radar_ops import off_browser_playbook_rail, off_fastmft_radar, off_ledger_audit, off_patch_validate_and_apply, off_windows_system_rail


class DeterministicTaskOffloader:
    """Matches pure-diagnostic objectives to 0-token rails and executes programmable deterministic actions."""

    ast_syntax_sweep = staticmethod(off_ast_syntax_sweep)
    run_preflight_bundle = classmethod(off_run_preflight_bundle)
    code_autofix_and_lint = classmethod(off_code_autofix_and_lint)
    structural_search_replace = classmethod(off_structural_search_replace)
    type_and_contract_check = classmethod(off_type_and_contract_check)
    property_edge_fuzz = classmethod(off_property_edge_fuzz)
    git_forensics = classmethod(off_git_forensics)
    data_sql_query = classmethod(off_data_sql_query)
    sbom_and_deps_audit = classmethod(off_sbom_and_deps_audit)
    structural_diff = classmethod(off_structural_diff)
    generate_pytest_skeleton = classmethod(off_generate_pytest_skeleton)
    extract_document_structured = classmethod(off_extract_document_structured)
    polyglot_outline = classmethod(off_polyglot_outline)
    libcst_safe_codemod = classmethod(off_libcst_safe_codemod)
    replace_function_body = classmethod(off_replace_function_body)
    parse_pytest_output = staticmethod(off_parse_pytest_output)
    pytest_failure_diagnoser = classmethod(off_pytest_failure_diagnoser)
    _eval_constraint_ast = staticmethod(off__eval_constraint_ast)
    z3_constraint_solve = classmethod(off_z3_constraint_solve)
    hypothesis_property_test = classmethod(off_hypothesis_property_test)
    codegen_from_openapi = classmethod(off_codegen_from_openapi)
    codegen_sql_to_python = classmethod(off_codegen_sql_to_python)
    os_sql_query = classmethod(off_os_sql_query)
    fastmft_radar = classmethod(off_fastmft_radar)
    windows_system_rail = classmethod(off_windows_system_rail)
    browser_playbook_rail = classmethod(off_browser_playbook_rail)
    patch_validate_and_apply = classmethod(off_patch_validate_and_apply)
    ledger_audit = classmethod(off_ledger_audit)

    @staticmethod
    def _find_ast_grep() -> Optional[str]:
        for name in ("ast-grep", "sg"):
            found = shutil.which(name)
            if found:
                return found
        scripts_dir = Path(sys.executable).parent / ("Scripts" if Path(sys.executable).suffix.lower() == ".exe" else "")
        for cand in (scripts_dir / "ast-grep.exe", scripts_dir / "ast-grep", scripts_dir / "sg.exe", scripts_dir / "sg"):
            if cand.is_file():
                return str(cand)
        return None

    @staticmethod
    def _find_fastmft() -> Optional[str]:
        for name in ("fastmft", "aetherscan", "aetherscan_v1.3.0"):
            found = shutil.which(name)
            if found:
                return found
        for cand in (
            Path(r"E:\Tools\maps\aetherscan\fastmft.exe"),
            Path(r"E:\Tools\maps\aetherscan\aetherscan_v1.3.0.exe"),
            Path(r"E:\Tools\maps\aetherscan\aetherscan.exe"),
        ):
            if cand.is_file():
                return str(cand)
        return None

    @staticmethod
    def probe_capabilities() -> Dict[str, Any]:
        """Report which external deterministic engines and builtin fallbacks are available on this host."""
        bins = {
            b: bool(shutil.which(b))
            for b in ("ruff", "sg", "ast-grep", "mypy", "pyright", "semgrep", "difft", "syft", "uv", "git", "fastmft")
        }
        if DeterministicTaskOffloader._find_ast_grep():
            bins["ast-grep"] = True
        if DeterministicTaskOffloader._find_fastmft():
            bins["fastmft"] = True
        mods = {
            m: bool(importlib.util.find_spec(m))
            for m in ("ruff", "mypy", "hypothesis", "z3", "duckdb", "polars", "libcst", "tree_sitter", "trafilatura", "ast_grep_py", "pydantic", "pytest")
        }
        return {
            "ok": True,
            "binaries": bins,
            "python_modules": mods,
            "rails": DeterministicTaskOffloader.list_rails(),
        }

    @staticmethod
    def list_rails() -> List[Dict[str, Any]]:
        return [
            {
                "name": s.name,
                "description": s.description,
                "estimated_tokens_saved": s.estimated_tokens_saved,
                "mutates_workspace": s.mutates_workspace,
            }
            for s in BUILTIN_DETERMINISTIC_RAILS.values()
        ]

    @staticmethod
    def match_zero_token_rail(objective: str, *, verify_cmd: Optional[str] = None) -> Optional[str]:
        """Return a deterministic rail name ONLY if the objective is purely diagnostic/read-only."""
        text = (objective or "").strip()
        if not text or _MUTATION_INTENT_RX.search(text):
            return None
        low = text.lower()
        if any(k in low for k in ("security audit", "sast scan", "agent shield", "auditoria de seguranca", "auditoria sast")):
            return "shield_audit"
        if any(k in low for k in ("repomap", "repo map", "symbol map", "mapa de simbolos", "pagerank map")):
            return "repo_topology_map"
        if any(k in low for k in ("syntax check", "ast sweep", "check python syntax", "verificar sintaxe")):
            return "ast_syntax_sweep"
        if any(k in low for k in ("sbom", "dependency audit", "auditoria de dependencias")):
            return "sbom_and_deps_audit"
        if any(k in low for k in ("git forensics", "git status summary", "historico git")):
            return "git_forensics"
        if any(k in low for k in ("fastmft", "aetherscan", "casimir", "parasites", "parasitas", "disk radar")):
            return "fastmft_radar"
        if verify_cmd and any(k in low for k in ("only run verify", "run tests only", "rodar testes apenas", "somente verificar")):
            return "verify_only_check"
        from am_ua.execution.deterministic_matrix_100 import match_matrix_69_rail

        matched_matrix = match_matrix_69_rail(low)
        if matched_matrix:
            return matched_matrix
        return None

    @classmethod
    def execute_rail(
        cls,
        rail_name: str,
        workspace: Path,
        *,
        params: Optional[Dict[str, Any]] = None,
        verify_cmd: Optional[str] = None,
        run_fn: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Execute any programmable deterministic rail and return structured verification data."""
        ws = Path(workspace).resolve()
        args = dict(params or {})
        spec = BUILTIN_DETERMINISTIC_RAILS.get(rail_name)
        if spec is None:
            return {"ok": False, "error": f"Unknown deterministic rail: {rail_name}", "available": sorted(BUILTIN_DETERMINISTIC_RAILS)}

        if rail_name == "list_capabilities":
            return cls.probe_capabilities()
        if rail_name == "shield_audit":
            from am_ua.security.agent_shield import AgentShieldAuditor

            rep = AgentShieldAuditor().scan_directory(ws, include_source_sast=True)
            return {
                "ok": rep.passed,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"AgentShield {rep.grade} ({len(rep.findings)} findings across {rep.files_scanned} files)",
                "details": rep.to_dict(),
            }
        if rail_name == "repo_topology_map":
            from am_ua.perception.polyglot_repomap import PolyglotRepoMapper

            ranked, txt = PolyglotRepoMapper(ws).build_ranked_map(max_chars=int(args.get("max_chars", 4000)))
            return {
                "ok": True,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"PageRank RepoMap generated ({len(ranked)} files)",
                "details": {"file_count": len(ranked), "repomap": txt},
            }
        if rail_name == "ast_syntax_sweep":
            syn = cls.ast_syntax_sweep(ws)
            return {
                "ok": syn["ok"],
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"AST syntax sweep: {syn['files_checked']} files checked, {len(syn['syntax_errors'])} errors",
                "details": syn,
            }
        if rail_name == "verify_only_check":
            cmd_to_run = str(args.get("command") or verify_cmd or "").strip()
            if not cmd_to_run or run_fn is None:
                return {"ok": False, "rail": rail_name, "error": "verify_cmd and run_fn required"}
            v = run_fn({"command": cmd_to_run, "timeout_s": 600})
            passed = int(v.get("exit_code", 1)) == 0
            return {
                "ok": passed,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"Verification command exited {v.get('exit_code')}",
                "details": v,
            }
        if rail_name == "code_autofix_and_lint":
            return cls.code_autofix_and_lint(ws, target=str(args.get("target", ".")), apply_fix=bool(args.get("apply_fix", True)))
        if rail_name == "structural_search_replace":
            return cls.structural_search_replace(
                ws,
                symbol_or_pattern=str(args.get("symbol_or_pattern") or args.get("pattern") or ""),
                replacement=args.get("replacement"),
                target=str(args.get("target", ".")),
                lang=args.get("lang"),
            )
        if rail_name == "type_and_contract_check":
            return cls.type_and_contract_check(ws, target=str(args.get("target", ".")))
        if rail_name == "property_edge_fuzz":
            return cls.property_edge_fuzz(
                ws,
                module_path=str(args.get("module_path", "")),
                func_name=str(args.get("func_name", "")),
            )
        if rail_name == "git_forensics":
            return cls.git_forensics(ws)
        if rail_name == "data_sql_query":
            return cls.data_sql_query(
                ws,
                file_path=str(args.get("file_path", "")),
                sql=str(args.get("sql", "SELECT * FROM data LIMIT 20")),
                table_name=str(args.get("table_name", "data")),
            )
        if rail_name == "sbom_and_deps_audit":
            return cls.sbom_and_deps_audit(ws)
        if rail_name == "structural_diff":
            return cls.structural_diff(
                ws,
                file_a=str(args.get("file_a", "")),
                file_b=str(args.get("file_b", "")),
            )
        if rail_name == "generate_pytest_skeleton":
            return cls.generate_pytest_skeleton(
                ws,
                module_path=str(args.get("module_path", "")),
                write_to=args.get("write_to"),
            )
        if rail_name == "extract_document_structured":
            return cls.extract_document_structured(
                ws,
                file_path=str(args.get("file_path", "")),
            )
        if rail_name == "polyglot_outline":
            return cls.polyglot_outline(
                ws,
                file_path=str(args.get("file_path", "")),
            )
        if rail_name == "libcst_safe_codemod":
            return cls.libcst_safe_codemod(
                ws,
                file_path=str(args.get("file_path", "")),
                symbol_old=str(args.get("symbol_old", "")),
                symbol_new=str(args.get("symbol_new", "")),
            )
        if rail_name == "replace_function_body":
            return cls.replace_function_body(
                ws,
                file_path=str(args.get("file_path", "")),
                func_name=str(args.get("func_name", "")),
                new_code=str(args.get("new_code", "")),
            )
        if rail_name == "pytest_failure_diagnoser":
            return cls.pytest_failure_diagnoser(
                ws,
                target=str(args.get("target", ".")),
                raw_output=args.get("raw_output"),
            )
        if rail_name == "z3_constraint_solve":
            return cls.z3_constraint_solve(
                ints=args.get("ints"),
                reals=args.get("reals"),
                bools=args.get("bools"),
                constraints=args.get("constraints"),
            )
        if rail_name == "hypothesis_property_test":
            return cls.hypothesis_property_test(
                ws,
                module_path=str(args.get("module_path", "")),
                func_name=str(args.get("func_name", "")),
                arg_types=args.get("arg_types"),
                invariant=args.get("invariant"),
                max_examples=int(args.get("max_examples", 50)),
            )
        if rail_name == "codegen_from_openapi":
            return cls.codegen_from_openapi(
                ws,
                spec_path=str(args.get("spec_path", "")),
                write_to=args.get("write_to"),
            )
        if rail_name == "codegen_sql_to_python":
            return cls.codegen_sql_to_python(
                ws,
                schema_path=str(args.get("schema_path", "")),
                write_to=args.get("write_to"),
            )
        if rail_name == "os_sql_query":
            return cls.os_sql_query(
                ws,
                sql=str(args.get("sql", "SELECT path, size_bytes FROM files ORDER BY size_bytes DESC LIMIT 20")),
            )
        if rail_name == "fastmft_radar":
            return cls.fastmft_radar(
                ws,
                mode=str(args.get("mode", "projects")),
                target=str(args.get("target", ".")),
                top=int(args.get("top", 20)),
                dry_run=bool(args.get("dry_run", True)),
            )
        if rail_name == "ledger_audit":
            return cls.ledger_audit(
                entries=args.get("entries"),
                file_path=args.get("file_path"),
                workspace=ws,
            )
        if rail_name == "lsp_diagnostics":
            from am_ua.perception.lsp_client import PersistentLSPClient

            lsp = PersistentLSPClient(ws, language=str(args.get("language", "python")))
            lsp.start(prefer_external=bool(args.get("prefer_external", False)))
            try:
                if args.get("symbol"):
                    return lsp.goto_definition(str(args["symbol"]), target_dir=str(args.get("target", ".")))
                return lsp.get_diagnostics(str(args.get("file_path") or args.get("target") or ""))
            finally:
                lsp.shutdown()
        if rail_name == "windows_system_rail":
            return cls.windows_system_rail(
                ws,
                sub_action=str(args.get("sub_action") or args.get("action") or "probe"),
                target=str(args.get("target", "")),
                port=args.get("port"),
            )
        if rail_name == "browser_playbook_rail":
            return cls.browser_playbook_rail(
                ws,
                sub_action=str(args.get("sub_action") or args.get("action") or "extract_links_forms"),
                file_path=args.get("file_path"),
                html=args.get("html"),
                url=args.get("url"),
                allowed_domains=args.get("allowed_domains"),
            )
        if rail_name == "patch_validate_and_apply":
            return cls.patch_validate_and_apply(
                ws,
                file_path=str(args.get("file_path", "")),
                old_text=str(args.get("old_text", "")),
                new_text=str(args.get("new_text", "")),
                apply=bool(args.get("apply", False)),
            )
        from am_ua.execution.deterministic_matrix_100 import MATRIX_69_SPECS, execute_matrix_69_rail

        if rail_name in MATRIX_69_SPECS:
            return execute_matrix_69_rail(rail_name, ws, args, execute_rail_fn=cls.execute_rail)
        return cls.run_preflight_bundle(ws, max_chars=int(args.get("max_chars", 3500)))

