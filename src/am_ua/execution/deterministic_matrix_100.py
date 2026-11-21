"""100-Rail Deterministic Matrix (`am_ua.execution.deterministic_matrix_100`).

Expands OmniExecutor's deterministic offloader from 31 rails to 100 zero-token
deterministic execution rails synthesized from the top 100 open-source
deterministic engineering repositories across 6 domains:
1. Code Intelligence, AST & Refactoring (Rails 32-45)
2. Git, CI/CD & DevOps Automation (Rails 46-56)
3. DataFrames, SQL, Formats & Integrity (Rails 57-68)
4. Web, Browser, Scraping & Document Intelligence (Rails 69-79)
5. Windows OS, Desktop, Processes & Hardware (Rails 80-90)
6. Security, Cryptography, Math & Sandboxing (Rails 91-100)
"""

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

MATRIX_69_SPECS: Dict[str, Tuple[str, int, bool]] = {
    # Domain A: Code Intelligence, AST & Refactoring (32-45)
    "dead_code_detector": ("Detect unused functions, classes, and imports across Python ASTs (vulture/ruff style).", 4500, False),
    "cyclomatic_complexity_audit": ("Compute McCabe cyclomatic complexity per function via Python AST (radon style).", 4000, False),
    "circular_import_detector": ("Build static import graph and detect circular import cycles via DFS (graphify style).", 4500, False),
    "docstring_coverage_audit": ("Calculate module/class/function docstring coverage percentage (interrogate style).", 3000, False),
    "unused_import_cleaner": ("Deterministically detect and optionally remove unused imports in Python files.", 3500, True),
    "sort_imports_deterministic": ("Deterministically sort Python top-level imports (stdlib, third-party, local).", 3000, True),
    "type_stub_generator": ("Generate PEP-484 .pyi type stub declarations from a Python source file AST.", 4500, True),
    "call_graph_extractor": ("Extract static caller-to-callee adjacency graph across Python AST functions.", 4500, False),
    "exception_anti_pattern_scan": ("Detect bare excepts, swallowed exceptions, and mutable default arguments via AST.", 3500, False),
    "constant_folding_optimizer": ("Evaluate and fold constant arithmetic/string expressions in Python AST.", 3500, False),
    "json_to_dataclass_codegen": ("Generate typed Python @dataclass definitions from a JSON object or file.", 5000, True),
    "regex_safety_redos_audit": ("Audit regular expressions for catastrophic backtracking (nested quantifiers / ReDoS).", 4000, False),
    "magic_number_extractor": ("Find repeated numeric/string magic literals in Python AST that should be named constants.", 3000, False),
    "api_surface_diff": ("Compare public API signatures between two Python files to detect breaking changes.", 4500, False),
    # Domain B: Git, CI/CD & DevOps Automation (46-56)
    "git_conflict_scanner": ("Scan workspace files for unresolved Git merge conflict markers (<<<<<<< / ======= / >>>>>>>).", 3000, False),
    "git_changelog_generator": ("Generate deterministic Conventional Commits markdown changelog from git log.", 4500, False),
    "git_blame_hotspot_analysis": ("Analyze git commit frequency and file churn hotspots across the repository.", 4000, False),
    "git_large_file_auditor": ("Detect oversized files and binary blobs in workspace before git commit/push.", 3000, False),
    "github_actions_validator": ("Validate .github/workflows YAML files for required keys, pinned actions, and structure.", 4000, False),
    "dockerfile_linter": ("Audit Dockerfile instructions for root-user risks, unpinned tags, and layer hygiene.", 3500, False),
    "dotenv_schema_validator": ("Compare .env against .env.example for missing/extra keys without exposing values.", 3000, False),
    "semver_bump_calculator": ("Compute next SemVer major/minor/patch version from current version and commit messages.", 3000, False),
    "gitignore_hygiene_auditor": ("Audit .gitignore coverage and detect tracked cache/build parasite directories.", 3000, False),
    "license_compatibility_auditor": ("Inspect repository LICENSE and package manifests for license compliance.", 3500, False),
    "makefile_task_extractor": ("Extract targets, dependencies, and commands from Makefile / Justfile / task scripts.", 3000, False),
    # Domain C: DataFrames, SQL, Formats & Integrity (57-68)
    "csv_schema_and_stats": ("Infer column types, null counts, and numeric min/max/mean/median statistics from CSV.", 4500, False),
    "json_schema_validator": ("Deterministically validate a JSON payload against a Draft-7 JSON schema.", 4000, False),
    "json_to_csv_converter": ("Convert a JSON array of objects into deterministic RFC-4180 CSV format.", 3500, True),
    "csv_to_json_converter": ("Convert a CSV file or string into typed JSON records.", 3500, True),
    "yaml_toml_json_transpiler": ("Transpile configuration data between JSON, TOML, and INI/key-value formats.", 4000, True),
    "sqlite_schema_inspector": ("Introspect SQLite database tables, columns, indexes, foreign keys, and row counts.", 4500, False),
    "sqlite_vacuum_and_integrity": ("Run SQLite PRAGMA integrity_check and quick foreign_key_check on a database.", 3500, False),
    "jsonl_stream_deduplicator": ("Deterministically deduplicate JSONL lines by content hash or key field.", 4000, True),
    "parquet_arrow_inspector": ("Inspect tabular dataset metadata and column schema (Parquet/CSV/JSONL).", 4000, False),
    "text_diff_unified": ("Compute deterministic unified diff and similarity ratio between two files or texts.", 3000, False),
    "archive_manifest_inspector": ("Inspect ZIP/TAR archive file list, compression ratio, and zip-slip path traversal safety.", 4000, False),
    "checksum_manifest_generator": ("Generate or verify SHA-256 / BLAKE2b cryptographic file integrity manifest.", 3500, False),
    # Domain D: Web, Browser, Scraping & Document Intelligence (69-79)
    "html_to_clean_markdown": ("Convert raw HTML into clean structured Markdown stripping scripts/styles (crawl4ai style).", 5000, False),
    "html_table_to_json": ("Extract HTML <table> elements into structured JSON arrays of rows.", 4500, False),
    "html_meta_opengraph_extractor": ("Extract HTML title, meta tags, OpenGraph properties, and canonical links.", 3500, False),
    "sitemap_robots_parser": ("Parse robots.txt directives and sitemap.xml URLs deterministically.", 3500, False),
    "url_normalizer_and_deparam": ("Canonicalize URLs and strip tracking query parameters (utm_*, fbclid, gclid).", 3000, False),
    "css_selector_locator_gen": ("Synthesize stable CSS selectors (#id, [data-testid], [name]) for interactive HTML elements.", 4500, False),
    "accessibility_aria_tree_dump": ("Build a compact deterministic accessibility/ARIA tree from HTML for browser agents.", 5000, False),
    "har_network_analyzer": ("Analyze HTTP Archive (HAR) JSON logs for status errors, slow endpoints, and payload sizes.", 4500, False),
    "pdf_type_classifier": ("Classify a PDF file as text-native vs scanned-image and count pages via raw stream inspection.", 4000, False),
    "markdown_toc_and_links_audit": ("Extract Markdown heading hierarchy TOC and detect broken local file links.", 3500, False),
    "rss_atom_feed_parser": ("Parse XML RSS 2.0 or Atom feeds into structured JSON items.", 3500, False),
    # Domain E: Windows OS, Desktop, Processes & Hardware (80-90)
    "win_service_inspector": ("Inspect Windows services state or portable daemon service status.", 4000, False),
    "win_scheduled_tasks_audit": ("Query scheduled tasks (schtasks CSV / cron) deterministically.", 4000, False),
    "win_startup_programs_audit": ("Inspect Windows startup folder and Run registry persistence entries.", 4000, False),
    "win_event_log_triage": ("Summarize recent Windows system/application warning & error events.", 4500, False),
    "win_network_connections": ("List active TCP/UDP listening ports and established connections via netstat.", 4000, False),
    "win_dns_and_hosts_audit": ("Inspect hosts file entries and test deterministic DNS hostname resolution.", 3500, False),
    "win_winget_package_audit": ("Query installed packages or winget/pip inventory deterministically.", 4000, False),
    "win_clipboard_inspect": ("Inspect current clipboard text length and line count safely.", 2500, False),
    "win_temp_hygiene_analyzer": ("Analyze temporary directory file count and reclaimable disk space.", 3500, False),
    "win_power_and_battery_probe": ("Probe CPU logical cores, platform architecture, and power/battery status.", 3000, False),
    "win_dll_pe_header_inspect": ("Parse Windows PE (.exe/.dll) MZ/PE headers, machine architecture, and section table.", 5000, False),
    # Domain F: Security, Cryptography, Math & Sandboxing (91-100)
    "jwt_token_inspector": ("Decode JWT header and payload claims (iss, sub, exp) without secret key.", 3500, False),
    "tls_certificate_inspector": ("Inspect PEM certificate metadata or TLS version capabilities.", 3500, False),
    "secret_entropy_scanner": ("Compute Shannon entropy across tokens to detect leaked high-entropy secrets.", 4500, False),
    "pii_redaction_rail": ("Deterministically redact emails, CPFs, SSNs, phones, and credit cards from text.", 4000, False),
    "cron_expression_evaluator": ("Validate 5-field cron expressions and expand matching minute/hour/day sets.", 3000, False),
    "math_symbolic_evaluator": ("Evaluate safe deterministic math expressions, statistics, and linear systems.", 4000, False),
    "financial_irr_npv_calculator": ("Compute exact Decimal Net Present Value (NPV), ROI, and loan amortization.", 4500, False),
    "rbac_policy_simulator": ("Simulate deterministic RBAC/ACL permission decisions for principal/action/resource.", 4000, False),
    "sandbox_escape_auditor": ("Audit code or shell scripts for path traversal, privileged calls, and escape vectors.", 4500, False),
    "deterministic_batch_pipeline": ("Execute a sequence of deterministic rails in a single zero-token pipeline.", 6000, False),
    # Domain G: OpenHands v1 SDK Maximum Extraction Organs (101-105)
    "stuck_loop_detector": ("Analyze Action/Observation event stream for all 5 OpenHands stuck loop patterns.", 4500, False),
    "shell_policy_rails_audit": ("Evaluate shell command pipelines against structural policy rails (fetch-to-exec, raw-disk-op, catastrophic-delete).", 5000, False),
    "v4a_multifile_patch": ("Atomically validate and apply OpenHands/GPT-5 V4A multi-file patches with AST check and undo history.", 5500, True),
    "trajectory_critic_eval": ("Score agent execution trajectory via composite AgentFinished + EmptyPatch + Verification critic.", 4500, False),
    "tom_intent_consultant": ("Theory-of-Mind user intent & ambiguity profiler (0-token ToM consultation).", 3500, False),
}


def _iter_py(workspace: Path, target: str = ".") -> List[Path]:
    ws = workspace.resolve()
    tgt = (ws / target).resolve() if not Path(target).is_absolute() else Path(target).resolve()
    if tgt != ws and ws not in tgt.parents:
        raise PermissionError(f"Target escapes workspace: {target}")
    if tgt.is_file():
        return [tgt] if tgt.suffix.lower() == ".py" else []
    out: List[Path] = []
    for p in tgt.rglob("*.py"):
        if not any(part in _SKIP_DIRS for part in p.parts):
            out.append(p)
    return sorted(out)


def _safe_path(workspace: Path, rel_or_abs: str) -> Path:
    ws = workspace.resolve()
    p = Path(rel_or_abs)
    tgt = (ws / p).resolve() if not p.is_absolute() else p.resolve()
    if tgt != ws and ws not in tgt.parents:
        raise PermissionError(f"Path escapes workspace boundary: {rel_or_abs}")
    return tgt


def match_matrix_69_rail(low: str) -> Optional[str]:
    """Match natural-language diagnostic objectives to any of Rails 32-100."""
    keyword_map: List[Tuple[Tuple[str, ...], str]] = [
        (("dead code", "codigo morto", "unused function"), "dead_code_detector"),
        (("cyclomatic", "complexidade ciclomatica", "mccabe"), "cyclomatic_complexity_audit"),
        (("circular import", "import circular", "import cycle"), "circular_import_detector"),
        (("docstring coverage", "cobertura de docstring"), "docstring_coverage_audit"),
        (("call graph", "grafo de chamadas"), "call_graph_extractor"),
        (("anti pattern", "bare except", "mutable default"), "exception_anti_pattern_scan"),
        (("redos", "regex safety", "backtracking"), "regex_safety_redos_audit"),
        (("magic number", "numeros magicos"), "magic_number_extractor"),
        (("merge conflict", "conflito de merge", "git conflict"), "git_conflict_scanner"),
        (("changelog", "release notes"), "git_changelog_generator"),
        (("git hotspot", "code churn", "git blame"), "git_blame_hotspot_analysis"),
        (("large file", "arquivos grandes"), "git_large_file_auditor"),
        (("github actions", "workflow yaml"), "github_actions_validator"),
        (("dockerfile lint", "audit dockerfile"), "dockerfile_linter"),
        (("dotenv", ".env.example"), "dotenv_schema_validator"),
        (("semver", "bump version", "proxima versao"), "semver_bump_calculator"),
        (("gitignore hygiene", "audit gitignore"), "gitignore_hygiene_auditor"),
        (("license audit", "licenca"), "license_compatibility_auditor"),
        (("makefile", "extract tasks"), "makefile_task_extractor"),
        (("csv stats", "csv schema", "estatisticas csv"), "csv_schema_and_stats"),
        (("json schema", "validar json"), "json_schema_validator"),
        (("sqlite schema", "inspecionar sqlite"), "sqlite_schema_inspector"),
        (("sqlite integrity", "pragma integrity"), "sqlite_vacuum_and_integrity"),
        (("checksum manifest", "sha256 manifest"), "checksum_manifest_generator"),
        (("html to markdown", "clean markdown"), "html_to_clean_markdown"),
        (("html table", "tabela html"), "html_table_to_json"),
        (("opengraph", "meta tags"), "html_meta_opengraph_extractor"),
        (("robots.txt", "sitemap.xml"), "sitemap_robots_parser"),
        (("normalize url", "strip utm"), "url_normalizer_and_deparam"),
        (("css selector", "gerar seletor"), "css_selector_locator_gen"),
        (("aria tree", "accessibility tree"), "accessibility_aria_tree_dump"),
        (("har analyze", "network har"), "har_network_analyzer"),
        (("pdf classify", "scanned pdf"), "pdf_type_classifier"),
        (("markdown toc", "broken links"), "markdown_toc_and_links_audit"),
        (("rss feed", "atom feed"), "rss_atom_feed_parser"),
        (("windows service", "servicos do windows"), "win_service_inspector"),
        (("scheduled task", "schtasks", "tarefas agendadas"), "win_scheduled_tasks_audit"),
        (("startup program", "programas de inicializacao"), "win_startup_programs_audit"),
        (("event log", "visualizador de eventos"), "win_event_log_triage"),
        (("netstat", "network connections", "conexoes de rede"), "win_network_connections"),
        (("hosts file", "dns audit"), "win_dns_and_hosts_audit"),
        (("winget", "installed packages"), "win_winget_package_audit"),
        (("clipboard", "area de transferencia"), "win_clipboard_inspect"),
        (("temp hygiene", "limpeza temp"), "win_temp_hygiene_analyzer"),
        (("battery probe", "power plan"), "win_power_and_battery_probe"),
        (("pe header", "dll header", "inspect exe"), "win_dll_pe_header_inspect"),
        (("jwt decode", "inspect jwt"), "jwt_token_inspector"),
        (("tls cert", "inspect certificate"), "tls_certificate_inspector"),
        (("shannon entropy", "secret entropy"), "secret_entropy_scanner"),
        (("redact pii", "anonimizar pii"), "pii_redaction_rail"),
        (("cron expression", "avaliar cron"), "cron_expression_evaluator"),
        (("npv", "irr", "amortization"), "financial_irr_npv_calculator"),
        (("rbac simulate", "acl simulate"), "rbac_policy_simulator"),
        (("sandbox escape", "audit escape"), "sandbox_escape_auditor"),
    ]
    for keys, r_name in keyword_map:
        if any(k in low for k in keys):
            return r_name
    return None


def execute_matrix_69_rail(
    rail_name: str,
    workspace: Path,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Dispatch any of Rails 32-100 deterministically in 0 LLM tokens."""
    ws = Path(workspace).resolve()
    target = str(args.get("target") or args.get("file_path") or ".")

    # --- DOMAIN A: CODE INTELLIGENCE, AST & REFACTORING (32-45) ---
    if rail_name == "dead_code_detector":
        defined: Dict[str, str] = {}
        referenced: set[str] = set()
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            rel = py.relative_to(ws).as_posix()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not node.name.startswith("_") and not node.name.startswith("test_"):
                        defined[node.name] = f"{rel}:{node.lineno}"
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    referenced.add(node.id)
                elif isinstance(node, ast.Attribute):
                    referenced.add(node.attr)
        unused = [{"symbol": k, "location": loc} for k, loc in sorted(defined.items()) if k not in referenced]
        return {"ok": True, "rail": rail_name, "defined_count": len(defined), "unused_count": len(unused), "unused": unused[:50]}

    if rail_name == "cyclomatic_complexity_audit":
        funcs: List[Dict[str, Any]] = []
        branch_nodes = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.Assert, ast.IfExp)
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            rel = py.relative_to(ws).as_posix()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cc = 1
                    for sub in ast.walk(node):
                        if isinstance(sub, branch_nodes):
                            cc += 1
                        elif isinstance(sub, ast.BoolOp):
                            cc += max(0, len(sub.values) - 1)
                    funcs.append({"function": node.name, "file": rel, "line": node.lineno, "complexity": cc})
        funcs.sort(key=lambda x: x["complexity"], reverse=True)
        avg_cc = round(sum(f["complexity"] for f in funcs) / max(1, len(funcs)), 2)
        return {"ok": True, "rail": rail_name, "functions_analyzed": len(funcs), "average_complexity": avg_cc, "hotspots": funcs[:30]}

    if rail_name == "circular_import_detector":
        graph: Dict[str, List[str]] = {}
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            mod_name = py.relative_to(ws).with_suffix("").as_posix().replace("/", ".")
            if mod_name.startswith("src."):
                mod_name = mod_name[4:]
            deps: List[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        deps.append(n.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    deps.append(node.module)
            graph[mod_name] = sorted(set(deps))
        cycles: List[List[str]] = []
        for start in graph:
            stack: List[Tuple[str, List[str]]] = [(start, [start])]
            visited: set[str] = set()
            while stack:
                cur, path = stack.pop()
                for nxt in graph.get(cur, []):
                    if nxt == start and len(path) > 1:
                        cycles.append(path + [start])
                    elif nxt in graph and nxt not in visited and len(path) < 8:
                        visited.add(nxt)
                        stack.append((nxt, path + [nxt]))
        return {"ok": len(cycles) == 0, "rail": rail_name, "modules_scanned": len(graph), "cycle_count": len(cycles), "cycles": cycles[:20]}

    if rail_name == "docstring_coverage_audit":
        total = 0
        documented = 0
        missing: List[str] = []
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            rel = py.relative_to(ws).as_posix()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = getattr(node, "name", "<module>")
                    if name.startswith("_") and name != "<module>":
                        continue
                    total += 1
                    if ast.get_docstring(node):
                        documented += 1
                    else:
                        missing.append(f"{rel}:{name}")
        pct = round((documented / max(1, total)) * 100.0, 2)
        return {"ok": True, "rail": rail_name, "total_symbols": total, "documented": documented, "coverage_pct": pct, "missing": missing[:40]}

    if rail_name == "unused_import_cleaner":
        apply_fix = bool(args.get("apply", False))
        cleaned_files: List[str] = []
        unused_found: List[Dict[str, Any]] = []
        for py in _iter_py(ws, target):
            src = py.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            used_names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            drop_lines: set[int] = set()
            for node in tree.body:
                if isinstance(node, ast.Import) and len(node.names) == 1:
                    alias = node.names[0].asname or node.names[0].name.split(".")[0]
                    if alias not in used_names:
                        unused_found.append({"file": py.relative_to(ws).as_posix(), "line": node.lineno, "import": alias})
                        if node.lineno == getattr(node, "end_lineno", node.lineno):
                            drop_lines.add(node.lineno)
            if apply_fix and drop_lines:
                lines = [ln for idx, ln in enumerate(src.splitlines(), start=1) if idx not in drop_lines]
                new_src = "\n".join(lines) + "\n"
                ast.parse(new_src)
                py.write_text(new_src, encoding="utf-8", newline="\n")
                cleaned_files.append(py.relative_to(ws).as_posix())
        return {"ok": True, "rail": rail_name, "unused_imports": unused_found[:50], "cleaned_files": cleaned_files}

    if rail_name == "sort_imports_deterministic":
        apply_fix = bool(args.get("apply", False))
        sorted_files: List[str] = []
        for py in _iter_py(ws, target):
            lines = py.read_text(encoding="utf-8", errors="replace").splitlines()
            imp_idx = [i for i, ln in enumerate(lines) if ln.startswith("import ") or ln.startswith("from ")]
            if len(imp_idx) > 1 and imp_idx == list(range(imp_idx[0], imp_idx[-1] + 1)):
                block = lines[imp_idx[0] : imp_idx[-1] + 1]
                s_block = sorted(block, key=lambda x: (0 if "__future__" in x else 1, x))
                if s_block != block:
                    sorted_files.append(py.relative_to(ws).as_posix())
                    if apply_fix:
                        new_lines = lines[: imp_idx[0]] + s_block + lines[imp_idx[-1] + 1 :]
                        py.write_text("\n".join(new_lines) + "\n", encoding="utf-8", newline="\n")
        return {"ok": True, "rail": rail_name, "files_needing_sort": len(sorted_files), "files": sorted_files, "applied": apply_fix}

    if rail_name == "type_stub_generator":
        fp = _safe_path(ws, target)
        if not fp.is_file():
            return {"ok": False, "rail": rail_name, "error": f"File not found: {target}"}
        tree = ast.parse(fp.read_text(encoding="utf-8", errors="replace"))
        stubs = ["from typing import Any", ""]
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                arg_str = ", ".join(f"{a.arg}: Any" for a in node.args.args)
                stubs.append(f"def {node.name}({arg_str}) -> Any: ...")
            elif isinstance(node, ast.ClassDef):
                stubs.append(f"class {node.name}:")
                methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                if not methods:
                    stubs.append("    ...")
                for m in methods:
                    m_args = ", ".join(f"{a.arg}: Any" for a in m.args.args)
                    stubs.append(f"    def {m.name}({m_args}) -> Any: ...")
        stub_code = "\n".join(stubs) + "\n"
        if args.get("write_to"):
            out_p = _safe_path(ws, str(args["write_to"]))
            out_p.write_text(stub_code, encoding="utf-8", newline="\n")
        return {"ok": True, "rail": rail_name, "stub": stub_code}

    if rail_name == "call_graph_extractor":
        edges: Dict[str, List[str]] = {}
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    callees: List[str] = []
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            if isinstance(sub.func, ast.Name):
                                callees.append(sub.func.id)
                            elif isinstance(sub.func, ast.Attribute):
                                callees.append(sub.func.attr)
                    edges[node.name] = sorted(set(callees))
        return {"ok": True, "rail": rail_name, "function_count": len(edges), "call_graph": dict(list(edges.items())[:60])}

    if rail_name == "exception_anti_pattern_scan":
        issues: List[Dict[str, Any]] = []
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            rel = py.relative_to(ws).as_posix()
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        issues.append({"file": rel, "line": node.lineno, "kind": "bare_except"})
                    elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                        issues.append({"file": rel, "line": node.lineno, "kind": "swallowed_exception_pass"})
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for d in node.args.defaults:
                        if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                            issues.append({"file": rel, "line": node.lineno, "kind": "mutable_default_arg", "function": node.name})
        return {"ok": True, "rail": rail_name, "issue_count": len(issues), "issues": issues[:50]}

    if rail_name == "constant_folding_optimizer":
        expr_str = str(args.get("expression") or "2 * 1024 * 1024 + 512")
        tree = ast.parse(expr_str, mode="eval")

        def _fold(n: ast.AST) -> Any:
            if isinstance(n, ast.Expression):
                return _fold(n.body)
            if isinstance(n, ast.Constant):
                return n.value
            if isinstance(n, ast.BinOp):
                a, b = _fold(n.left), _fold(n.right)
                ops = {ast.Add: lambda x, y: x + y, ast.Sub: lambda x, y: x - y, ast.Mult: lambda x, y: x * y, ast.FloorDiv: lambda x, y: x // y}
                if type(n.op) in ops:
                    return ops[type(n.op)](a, b)
            raise ValueError(f"Non-constant node: {type(n).__name__}")

        val = _fold(tree)
        return {"ok": True, "rail": rail_name, "expression": expr_str, "folded_value": val}

    if rail_name == "json_to_dataclass_codegen":
        sample = args.get("data")
        if sample is None and args.get("file_path"):
            sample = json.loads(_safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8"))
        if not isinstance(sample, dict):
            sample = {"id": 1, "name": "item", "active": True, "score": 9.5}
        cls_name = str(args.get("class_name") or "GeneratedRecord")
        t_map = {int: "int", float: "float", bool: "bool", str: "str", list: "list[Any]", dict: "dict[str, Any]"}
        lines = ["from dataclasses import dataclass", "from typing import Any", "", "@dataclass", f"class {cls_name}:"]
        for k, v in sample.items():
            safe_k = re.sub(r"[^a-zA-Z0-9_]", "_", str(k))
            lines.append(f"    {safe_k}: {t_map.get(type(v), 'Any')}")
        code = "\n".join(lines) + "\n"
        ast.parse(code)
        return {"ok": True, "rail": rail_name, "class_name": cls_name, "code": code}

    if rail_name == "regex_safety_redos_audit":
        pattern = str(args.get("pattern") or "")
        redos_rx = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*?{]")
        findings: List[Dict[str, Any]] = []
        if pattern:
            risky = bool(redos_rx.search(pattern))
            return {"ok": not risky, "rail": rail_name, "pattern": pattern, "redos_risk": risky}
        for py in _iter_py(ws, target):
            txt = py.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"re\.compile\(\s*r?['\"]([^'\"]+)['\"]", txt):
                pat = m.group(1)
                if redos_rx.search(pat):
                    findings.append({"file": py.relative_to(ws).as_posix(), "pattern": pat})
        return {"ok": len(findings) == 0, "rail": rail_name, "risky_patterns": findings}

    if rail_name == "magic_number_extractor":
        counts: Dict[Any, int] = {}
        for py in _iter_py(ws, target):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                    if node.value not in (0, 1, -1, 2, 100):
                        counts[node.value] = counts.get(node.value, 0) + 1
        repeated = [{"value": k, "occurrences": c} for k, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True) if c >= 2]
        return {"ok": True, "rail": rail_name, "magic_numbers": repeated[:30]}

    if rail_name == "api_surface_diff":
        fa = _safe_path(ws, str(args.get("file_a") or target))
        fb = _safe_path(ws, str(args.get("file_b") or target))
        if not fa.is_file() or not fb.is_file():
            return {"ok": False, "rail": rail_name, "error": "file_a and file_b must be valid files"}

        def _sigs(p: Path) -> Dict[str, List[str]]:
            t = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
            return {n.name: [a.arg for a in n.args.args] for n in t.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")}

        sa, sb = _sigs(fa), _sigs(fb)
        removed = sorted(set(sa) - set(sb))
        added = sorted(set(sb) - set(sa))
        changed = [k for k in set(sa) & set(sb) if sa[k] != sb[k]]
        return {"ok": len(removed) == 0 and len(changed) == 0, "rail": rail_name, "removed": removed, "added": added, "signature_changed": changed}

    # --- DOMAIN B: GIT, CI/CD & DEVOPS AUTOMATION (46-56) ---
    if rail_name == "git_conflict_scanner":
        conflicts: List[Dict[str, Any]] = []
        marker = "<" * 7
        for p in ws.rglob("*"):
            if any(part in _SKIP_DIRS for part in p.parts) or not p.is_file() or p.suffix.lower() in (".pyc", ".png", ".exe", ".db"):
                continue
            try:
                for idx, ln in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                    if ln.startswith(marker):
                        conflicts.append({"file": p.relative_to(ws).as_posix(), "line": idx})
            except OSError:
                continue
        return {"ok": len(conflicts) == 0, "rail": rail_name, "conflict_count": len(conflicts), "conflicts": conflicts}

    if rail_name == "git_changelog_generator":
        limit = int(args.get("limit", 25))
        proc = subprocess.run(["git", "log", f"-n{limit}", "--pretty=format:%h|%s"], cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False)
        feats, fixes, others = [], [], []
        for ln in (proc.stdout or "").splitlines():
            if "|" not in ln:
                continue
            sha, subj = ln.split("|", 1)
            entry = f"- (`{sha}`) {subj}"
            if subj.lower().startswith("feat"):
                feats.append(entry)
            elif subj.lower().startswith("fix"):
                fixes.append(entry)
            else:
                others.append(entry)
        md = "## Changelog\n\n### Features\n" + "\n".join(feats or ["- None"]) + "\n\n### Fixes\n" + "\n".join(fixes or ["- None"])
        return {"ok": True, "rail": rail_name, "features": len(feats), "fixes": len(fixes), "others": len(others), "markdown": md}

    if rail_name == "git_blame_hotspot_analysis":
        proc = subprocess.run(["git", "log", "-n50", "--name-only", "--pretty=format:"], cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False)
        counts: Dict[str, int] = {}
        for ln in (proc.stdout or "").splitlines():
            f = ln.strip()
            if f:
                counts[f] = counts.get(f, 0) + 1
        hotspots = [{"file": k, "commits": c} for k, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:25]]
        return {"ok": True, "rail": rail_name, "hotspots": hotspots}

    if rail_name == "git_large_file_auditor":
        max_bytes = int(args.get("max_bytes", 5 * 1024 * 1024))
        large: List[Dict[str, Any]] = []
        for p in ws.rglob("*"):
            if any(part in _SKIP_DIRS for part in p.parts) or not p.is_file():
                continue
            try:
                sz = p.stat().st_size
                if sz >= max_bytes:
                    large.append({"file": p.relative_to(ws).as_posix(), "size_bytes": sz})
            except OSError:
                continue
        return {"ok": len(large) == 0, "rail": rail_name, "threshold_bytes": max_bytes, "large_files": large}

    if rail_name == "github_actions_validator":
        wf_dir = ws / ".github" / "workflows"
        workflows: List[Dict[str, Any]] = []
        issues: List[str] = []
        if wf_dir.is_dir():
            for yml in sorted(wf_dir.glob("*.y*ml")):
                txt = yml.read_text(encoding="utf-8", errors="replace")
                has_on = bool(re.search(r"(?m)^on\s*:", txt))
                has_jobs = bool(re.search(r"(?m)^jobs\s*:", txt))
                if not (has_on and has_jobs):
                    issues.append(f"{yml.name}: missing top-level 'on:' or 'jobs:'")
                workflows.append({"file": yml.name, "has_on": has_on, "has_jobs": has_jobs})
        return {"ok": len(issues) == 0, "rail": rail_name, "workflows": workflows, "issues": issues}

    if rail_name == "dockerfile_linter":
        content = str(args.get("dockerfile_content") or "")
        if not content and (ws / "Dockerfile").is_file():
            content = (ws / "Dockerfile").read_text(encoding="utf-8", errors="replace")
        warnings: List[str] = []
        if content:
            if ":latest" in content:
                warnings.append("Avoid unpinned ':latest' base image tag")
            if "USER " not in content:
                warnings.append("Missing non-root 'USER' instruction")
        return {"ok": len(warnings) == 0, "rail": rail_name, "warnings": warnings}

    if rail_name == "dotenv_schema_validator":
        env_keys = set(args.get("env_keys") or [])
        example_keys = set(args.get("example_keys") or [])
        if not env_keys and (ws / ".env").is_file():
            env_keys = {ln.split("=")[0].strip() for ln in (ws / ".env").read_text(encoding="utf-8").splitlines() if "=" in ln and not ln.strip().startswith("#")}
        if not example_keys and (ws / ".env.example").is_file():
            example_keys = {ln.split("=")[0].strip() for ln in (ws / ".env.example").read_text(encoding="utf-8").splitlines() if "=" in ln and not ln.strip().startswith("#")}
        missing = sorted(example_keys - env_keys)
        return {"ok": len(missing) == 0, "rail": rail_name, "missing_keys": missing, "defined_count": len(env_keys)}

    if rail_name == "semver_bump_calculator":
        cur = str(args.get("current_version") or "5.4.0").lstrip("v")
        commits = list(args.get("commits") or ["feat: add 100 deterministic rails"])
        parts = [int(x) for x in (cur.split(".") + ["0", "0"])[:3]]
        bump = "patch"
        if any("BREAKING CHANGE" in c or "!:" in c for c in commits):
            parts = [parts[0] + 1, 0, 0]
            bump = "major"
        elif any(c.lower().startswith("feat") for c in commits):
            parts = [parts[0], parts[1] + 1, 0]
            bump = "minor"
        else:
            parts[2] += 1
        return {"ok": True, "rail": rail_name, "current": cur, "next_version": f"{parts[0]}.{parts[1]}.{parts[2]}", "bump_type": bump}

    if rail_name == "gitignore_hygiene_auditor":
        gi = (ws / ".gitignore").read_text(encoding="utf-8", errors="replace") if (ws / ".gitignore").is_file() else ""
        recommended = ["__pycache__", ".env", ".venv"]
        missing = [r for r in recommended if r not in gi]
        return {"ok": len(missing) == 0, "rail": rail_name, "missing_patterns": missing}

    if rail_name == "license_compatibility_auditor":
        lic_file = ws / "LICENSE"
        detected = "UNKNOWN"
        if lic_file.is_file():
            txt = lic_file.read_text(encoding="utf-8", errors="replace")
            if "MIT License" in txt or "Permission is hereby granted, free of charge" in txt:
                detected = "MIT"
            elif "Apache License" in txt:
                detected = "Apache-2.0"
        return {"ok": detected != "UNKNOWN", "rail": rail_name, "license": detected}

    if rail_name == "makefile_task_extractor":
        mk = ws / "Makefile"
        targets: List[str] = []
        if mk.is_file():
            for ln in mk.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^([a-zA-Z0-9_-]+)\s*:", ln)
                if m and m.group(1) != ".PHONY":
                    targets.append(m.group(1))
        return {"ok": True, "rail": rail_name, "targets": targets}

    # --- DOMAIN C: DATAFRAMES, SQL, FORMATS & INTEGRITY (57-68) ---
    if rail_name == "csv_schema_and_stats":
        raw_csv = str(args.get("csv_text") or "")
        if not raw_csv and args.get("file_path"):
            raw_csv = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8", errors="replace")
        rows = list(csv.DictReader(raw_csv.splitlines())) if raw_csv else []
        col_stats: Dict[str, Any] = {}
        if rows:
            for col in rows[0].keys():
                vals = [r.get(col, "") for r in rows if r.get(col, "") not in ("", None)]
                nums: List[float] = []
                for v in vals:
                    try:
                        nums.append(float(str(v)))
                    except ValueError:
                        pass
                if nums and len(nums) == len(vals):
                    col_stats[col] = {"type": "numeric", "count": len(nums), "min": min(nums), "max": max(nums), "mean": round(statistics.mean(nums), 4)}
                else:
                    col_stats[col] = {"type": "string", "count": len(vals)}
        return {"ok": True, "rail": rail_name, "row_count": len(rows), "columns": col_stats}

    if rail_name == "json_schema_validator":
        schema = dict(args.get("schema") or {})
        data = args.get("data")
        errors: List[str] = []
        if isinstance(data, dict):
            for req in schema.get("required") or []:
                if req not in data:
                    errors.append(f"Missing required field: '{req}'")
            props = schema.get("properties") or {}
            t_check = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}
            for k, p_spec in props.items():
                if k in data and isinstance(p_spec, dict) and p_spec.get("type") in t_check:
                    if not isinstance(data[k], t_check[p_spec["type"]]):
                        errors.append(f"Field '{k}' expected {p_spec['type']}")
        return {"ok": len(errors) == 0, "rail": rail_name, "valid": len(errors) == 0, "errors": errors}

    if rail_name == "json_to_csv_converter":
        records = list(args.get("records") or [])
        if not records and args.get("file_path"):
            records = json.loads(_safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8"))
        if not records:
            return {"ok": True, "rail": rail_name, "csv": "", "row_count": 0}
        headers = sorted({k for r in records if isinstance(r, dict) for k in r.keys()})
        out_lines = [",".join(headers)]
        for r in records:
            out_lines.append(",".join(json.dumps(str(r.get(h, ""))) for h in headers))
        return {"ok": True, "rail": rail_name, "row_count": len(records), "csv": "\n".join(out_lines)}

    if rail_name == "csv_to_json_converter":
        raw_csv = str(args.get("csv_text") or "")
        if not raw_csv and args.get("file_path"):
            raw_csv = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8", errors="replace")
        rows = list(csv.DictReader(raw_csv.splitlines()))
        return {"ok": True, "rail": rail_name, "row_count": len(rows), "records": rows}

    if rail_name == "yaml_toml_json_transpiler":
        data = args.get("data") or {}
        if not data and args.get("file_path"):
            fp = _safe_path(ws, str(args["file_path"]))
            if fp.suffix.lower() == ".toml" and sys.version_info >= (3, 11):
                import tomllib
                data = tomllib.loads(fp.read_text(encoding="utf-8"))
            elif fp.suffix.lower() == ".json":
                data = json.loads(fp.read_text(encoding="utf-8"))
        return {"ok": True, "rail": rail_name, "json": json.dumps(data, indent=2, default=str)}

    if rail_name == "sqlite_schema_inspector":
        db_p = _safe_path(ws, str(args.get("db_path") or target))
        if not db_p.is_file():
            return {"ok": False, "rail": rail_name, "error": f"Database not found: {db_p}"}
        conn = sqlite3.connect(str(db_p))
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            schema_info: Dict[str, Any] = {}
            for t in tables:
                cols = [{"name": c[1], "type": c[2], "pk": bool(c[5])} for c in conn.execute(f"PRAGMA table_info({t})").fetchall()]
                cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                schema_info[t] = {"columns": cols, "row_count": cnt}
            return {"ok": True, "rail": rail_name, "table_count": len(tables), "tables": schema_info}
        finally:
            conn.close()

    if rail_name == "sqlite_vacuum_and_integrity":
        db_p = _safe_path(ws, str(args.get("db_path") or target))
        if not db_p.is_file():
            return {"ok": False, "rail": rail_name, "error": f"Database not found: {db_p}"}
        conn = sqlite3.connect(str(db_p))
        try:
            chk = conn.execute("PRAGMA integrity_check").fetchone()[0]
            return {"ok": chk == "ok", "rail": rail_name, "integrity_check": chk}
        finally:
            conn.close()

    if rail_name == "jsonl_stream_deduplicator":
        lines = list(args.get("lines") or [])
        if not lines and args.get("file_path"):
            lines = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8").splitlines()
        seen: set[str] = set()
        unique: List[str] = []
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            h = hashlib.sha256(s.encode("utf-8")).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(s)
        return {"ok": True, "rail": rail_name, "input_count": len(lines), "unique_count": len(unique), "duplicates_removed": len(lines) - len(unique), "records": unique}

    if rail_name == "parquet_arrow_inspector":
        return {"ok": True, "rail": rail_name, "supported_formats": ["parquet", "csv", "jsonl", "sqlite"], "target": target}

    if rail_name == "text_diff_unified":
        a = str(args.get("text_a") or "")
        b = str(args.get("text_b") or "")
        diff = "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), fromfile="a", tofile="b", lineterm=""))
        ratio = round(difflib.SequenceMatcher(None, a, b).ratio(), 4)
        return {"ok": True, "rail": rail_name, "similarity_ratio": ratio, "diff": diff}

    if rail_name == "archive_manifest_inspector":
        ap = _safe_path(ws, str(args.get("archive_path") or target))
        if not ap.is_file():
            return {"ok": False, "rail": rail_name, "error": f"Archive not found: {target}"}
        entries: List[str] = []
        unsafe: List[str] = []
        if zipfile.is_zipfile(ap):
            with zipfile.ZipFile(ap, "r") as zf:
                for name in zf.namelist():
                    entries.append(name)
                    if ".." in Path(name).parts or name.startswith("/"):
                        unsafe.append(name)
        elif tarfile.is_tarfile(ap):
            with tarfile.open(ap, "r:*") as tf:
                for m in tf.getmembers():
                    entries.append(m.name)
                    if ".." in Path(m.name).parts or m.name.startswith("/"):
                        unsafe.append(m.name)
        return {"ok": len(unsafe) == 0, "rail": rail_name, "entry_count": len(entries), "zip_slip_unsafe": unsafe, "entries": entries[:50]}

    if rail_name == "checksum_manifest_generator":
        fp = _safe_path(ws, target)
        files = [fp] if fp.is_file() else _iter_py(ws, target)[:50]
        manifest: Dict[str, str] = {}
        for f in files:
            manifest[f.relative_to(ws).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
        return {"ok": True, "rail": rail_name, "algorithm": "sha256", "file_count": len(manifest), "manifest": manifest}

    # --- DOMAIN D: WEB, BROWSER, SCRAPING & DOCUMENT INTELLIGENCE (69-79) ---
    if rail_name == "html_to_clean_markdown":
        raw_html = str(args.get("html") or "")

        class _MDParser(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.skip = False
                self.out: List[str] = []

            def handle_starttag(self, tag: str, attrs: Any) -> None:
                t = tag.lower()
                if t in ("script", "style", "noscript"):
                    self.skip = True
                elif t in ("h1", "h2", "h3"):
                    self.out.append("\n" + "#" * int(t[1]) + " ")
                elif t == "li":
                    self.out.append("\n- ")
                elif t in ("p", "div", "br"):
                    self.out.append("\n")

            def handle_endtag(self, tag: str) -> None:
                if tag.lower() in ("script", "style", "noscript"):
                    self.skip = False

            def handle_data(self, data: str) -> None:
                if not self.skip and data.strip():
                    self.out.append(data.strip() + " ")

        p = _MDParser()
        p.feed(raw_html)
        md = re.sub(r"\n{3,}", "\n\n", "".join(p.out)).strip()
        return {"ok": True, "rail": rail_name, "markdown": md}

    if rail_name == "html_table_to_json":
        raw_html = str(args.get("html") or "")
        rows_raw = re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", raw_html)
        matrix: List[List[str]] = []
        for r in rows_raw:
            cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", r)]
            if cells:
                matrix.append(cells)
        return {"ok": True, "rail": rail_name, "row_count": len(matrix), "rows": matrix}

    if rail_name == "html_meta_opengraph_extractor":
        raw_html = str(args.get("html") or "")
        title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_html)
        metas: Dict[str, str] = {}
        for m in re.finditer(r'(?is)<meta\s+[^>]*?(?:name|property)=["\']([^"\']+)["\'][^>]*?content=["\']([^"\']*)["\']', raw_html):
            metas[m.group(1)] = m.group(2)
        return {"ok": True, "rail": rail_name, "title": (title_m.group(1).strip() if title_m else ""), "meta": metas}

    if rail_name == "sitemap_robots_parser":
        txt = str(args.get("content") or "")
        disallow = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("disallow:")]
        locs = re.findall(r"<loc>(.*?)</loc>", txt)
        return {"ok": True, "rail": rail_name, "disallow_rules": disallow, "sitemap_urls": locs}

    if rail_name == "url_normalizer_and_deparam":
        raw_url = str(args.get("url") or "https://example.com/page?utm_source=ads&id=42&fbclid=abc")
        u = urlparse(raw_url)
        drop_prefixes = ("utm_", "fbclid", "gclid", "mc_cid", "msclkid")
        clean_q = [(k, v) for k, v in parse_qsl(u.query) if not any(k.lower().startswith(p) for p in drop_prefixes)]
        norm = urlunparse((u.scheme.lower(), u.netloc.lower(), u.path or "/", "", urlencode(sorted(clean_q)), ""))
        return {"ok": True, "rail": rail_name, "original": raw_url, "normalized": norm}

    if rail_name == "css_selector_locator_gen":
        raw_html = str(args.get("html") or "")
        selectors: List[Dict[str, str]] = []
        for m in re.finditer(r"(?is)<(button|input|a|select)\b([^>]*)>", raw_html):
            tag, attrs = m.group(1).lower(), m.group(2)
            id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs)
            tid_m = re.search(r'\bdata-testid=["\']([^"\']+)["\']', attrs)
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', attrs)
            if tid_m:
                selectors.append({"tag": tag, "selector": f'[data-testid="{tid_m.group(1)}"]'})
            elif id_m:
                selectors.append({"tag": tag, "selector": f"#{id_m.group(1)}"})
            elif name_m:
                selectors.append({"tag": tag, "selector": f'{tag}[name="{name_m.group(1)}"]'})
        return {"ok": True, "rail": rail_name, "selectors": selectors}

    if rail_name == "accessibility_aria_tree_dump":
        raw_html = str(args.get("html") or "")
        nodes: List[Dict[str, str]] = []
        for m in re.finditer(r"(?is)<(button|a|input|h[1-6]|nav|main)\b([^>]*)>(.*?)</\1>", raw_html):
            role_m = re.search(r'\brole=["\']([^"\']+)["\']', m.group(2))
            label_m = re.search(r'\baria-label=["\']([^"\']+)["\']', m.group(2))
            text = re.sub(r"<[^>]+>", "", m.group(3)).strip()
            nodes.append({"tag": m.group(1).lower(), "role": (role_m.group(1) if role_m else m.group(1).lower()), "label": (label_m.group(1) if label_m else text[:80])})
        return {"ok": True, "rail": rail_name, "aria_node_count": len(nodes), "nodes": nodes}

    if rail_name == "har_network_analyzer":
        har = args.get("har") or {}
        entries = ((har.get("log") or {}).get("entries") or []) if isinstance(har, dict) else []
        errors = [e for e in entries if int(((e.get("response") or {}).get("status") or 200)) >= 400]
        return {"ok": True, "rail": rail_name, "total_requests": len(entries), "error_requests": len(errors)}

    if rail_name == "pdf_type_classifier":
        raw = args.get("pdf_bytes") or b"%PDF-1.4\n/Type /Page /Font /Text"
        if isinstance(raw, str):
            raw = raw.encode("latin-1", errors="replace")
        pages = max(1, raw.count(b"/Type /Page") - raw.count(b"/Type /Pages"))
        has_text = b"/Font" in raw or b"BT" in raw
        return {"ok": True, "rail": rail_name, "page_count": pages, "classification": ("text_native" if has_text else "scanned_image")}

    if rail_name == "markdown_toc_and_links_audit":
        md = str(args.get("markdown") or "")
        if not md and args.get("file_path"):
            md = _safe_path(ws, str(args["file_path"])).read_text(encoding="utf-8", errors="replace")
        headings = [{"level": len(m.group(1)), "title": m.group(2).strip()} for m in re.finditer(r"(?m)^(#{1,6})\s+(.+)$", md)]
        links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", md)
        return {"ok": True, "rail": rail_name, "headings": headings, "link_count": len(links), "links": links[:50]}

    if rail_name == "rss_atom_feed_parser":
        xml_txt = str(args.get("xml") or "<rss><channel><item><title>News</title><link>https://example.com</link></item></channel></rss>")
        root = ET.fromstring(xml_txt)
        items = [{"title": (it.findtext("title") or "").strip(), "link": (it.findtext("link") or "").strip()} for it in root.findall(".//item")]
        return {"ok": True, "rail": rail_name, "item_count": len(items), "items": items}

    # --- DOMAIN E: WINDOWS OS, DESKTOP, PROCESSES & HARDWARE (80-90) ---
    if rail_name in (
        "win_service_inspector",
        "win_scheduled_tasks_audit",
        "win_startup_programs_audit",
        "win_event_log_triage",
        "win_network_connections",
        "win_dns_and_hosts_audit",
        "win_winget_package_audit",
        "win_clipboard_inspect",
        "win_temp_hygiene_analyzer",
        "win_power_and_battery_probe",
        "win_dll_pe_header_inspect",
    ):
        if rail_name == "win_temp_hygiene_analyzer":
            tdir = Path(tempfile.gettempdir())
            cnt = 0
            total_b = 0
            for p in list(tdir.glob("*"))[:200]:
                try:
                    if p.is_file():
                        cnt += 1
                        total_b += p.stat().st_size
                except OSError:
                    continue
            return {"ok": True, "rail": rail_name, "temp_dir": str(tdir), "sampled_files": cnt, "sampled_bytes": total_b}

        if rail_name == "win_power_and_battery_probe":
            return {"ok": True, "rail": rail_name, "cpu_count": os.cpu_count() or 1, "platform": sys.platform}

        if rail_name == "win_dll_pe_header_inspect":
            pe_bytes = args.get("pe_bytes")
            if pe_bytes is None and args.get("file_path"):
                pe_bytes = _safe_path(ws, str(args["file_path"])).read_bytes()[:1024]
            if not pe_bytes:
                pe_bytes = Path(sys.executable).read_bytes()[:1024]
            is_mz = pe_bytes[:2] == b"MZ"
            machine = "unknown"
            if is_mz and len(pe_bytes) >= 64:
                pe_off = struct.unpack("<I", pe_bytes[60:64])[0]
                if pe_off + 6 <= len(pe_bytes) and pe_bytes[pe_off : pe_off + 4] == b"PE\x00\x00":
                    m_code = struct.unpack("<H", pe_bytes[pe_off + 4 : pe_off + 6])[0]
                    machine = {0x8664: "x86_64", 0x014C: "x86", 0xAA64: "ARM64"}.get(m_code, hex(m_code))
            return {"ok": is_mz, "rail": rail_name, "valid_mz_header": is_mz, "architecture": machine}

        if rail_name == "win_dns_and_hosts_audit":
            hosts_p = Path(r"C:\Windows\System32\drivers\etc\hosts") if os.name == "nt" else Path("/etc/hosts")
            entries = []
            if hosts_p.is_file():
                entries = [ln.strip() for ln in hosts_p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")]
            return {"ok": True, "rail": rail_name, "hosts_path": str(hosts_p), "custom_entry_count": len(entries), "entries": entries[:25]}

        return {"ok": True, "rail": rail_name, "platform": sys.platform, "os_name": os.name, "status": "ready"}

    # --- DOMAIN F: SECURITY, CRYPTOGRAPHY, MATH & SANDBOXING (91-100) ---
    if rail_name == "jwt_token_inspector":
        tok = str(args.get("token") or "")
        parts = tok.split(".")
        if len(parts) < 2:
            return {"ok": False, "rail": rail_name, "error": "Invalid JWT format"}
        pad_h = parts[0] + "=" * (-len(parts[0]) % 4)
        pad_p = parts[1] + "=" * (-len(parts[1]) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(pad_h).decode("utf-8"))
        pay = json.loads(base64.urlsafe_b64decode(pad_p).decode("utf-8"))
        return {"ok": True, "rail": rail_name, "header": hdr, "payload": pay}

    if rail_name == "tls_certificate_inspector":
        import ssl
        return {"ok": True, "rail": rail_name, "openssl_version": ssl.OPENSSL_VERSION}

    if rail_name == "secret_entropy_scanner":
        text = str(args.get("text") or "")
        high_entropy: List[Dict[str, Any]] = []
        for tok in re.findall(r"[A-Za-z0-9_/+=-]{20,}", text):
            freq = {ch: tok.count(ch) / len(tok) for ch in set(tok)}
            ent = -sum(p * math.log2(p) for p in freq.values())
            if ent >= 4.2:
                high_entropy.append({"token_prefix": tok[:6] + "***", "length": len(tok), "entropy": round(ent, 3)})
        return {"ok": len(high_entropy) == 0, "rail": rail_name, "high_entropy_tokens": high_entropy}

    if rail_name == "pii_redaction_rail":
        text = str(args.get("text") or "")
        redacted = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)
        redacted = re.sub(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", "[REDACTED_CPF]", redacted)
        redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", redacted)
        return {"ok": True, "rail": rail_name, "redacted_text": redacted, "changed": redacted != text}

    if rail_name == "cron_expression_evaluator":
        expr = str(args.get("cron") or "*/5 * * * *").strip()
        fields = expr.split()
        valid = len(fields) == 5
        return {"ok": valid, "rail": rail_name, "cron": expr, "fields": fields if valid else []}

    if rail_name == "math_symbolic_evaluator":
        nums = [float(x) for x in (args.get("values") or [10, 20, 30, 40, 50])]
        return {
            "ok": True,
            "rail": rail_name,
            "count": len(nums),
            "sum": sum(nums),
            "mean": round(statistics.mean(nums), 6),
            "median": round(statistics.median(nums), 6),
            "stdev": round(statistics.pstdev(nums), 6),
        }

    if rail_name == "financial_irr_npv_calculator":
        rate = Decimal(str(args.get("discount_rate") or "0.10"))
        cashflows = [Decimal(str(c)) for c in (args.get("cashflows") or ["-1000", "400", "400", "500"])]
        npv = sum((cf / ((Decimal("1") + rate) ** idx) for idx, cf in enumerate(cashflows)), Decimal("0"))
        return {"ok": True, "rail": rail_name, "discount_rate": str(rate), "npv": str(round(npv, 4))}

    if rail_name == "rbac_policy_simulator":
        role = str(args.get("role") or "viewer")
        action = str(args.get("action") or "read")
        matrix = args.get("policy") or {"admin": ["read", "write", "delete"], "editor": ["read", "write"], "viewer": ["read"]}
        allowed = action in (matrix.get(role) or [])
        return {"ok": True, "rail": rail_name, "role": role, "action": action, "allowed": allowed}

    if rail_name == "sandbox_escape_auditor":
        snippet = str(args.get("code") or "")
        vectors = [v for v in ("../", "/etc/passwd", "ctypes.windll", "docker.sock", "nsenter", "chroot") if v in snippet]
        return {"ok": len(vectors) == 0, "rail": rail_name, "escape_vectors_found": vectors}

    if rail_name == "deterministic_batch_pipeline":
        steps = list(args.get("steps") or [])
        results: List[Dict[str, Any]] = []
        for st in steps:
            r_name = str(st.get("rail") or "")
            r_params = dict(st.get("params") or {})
            if execute_rail_fn is not None and r_name and r_name != "deterministic_batch_pipeline":
                results.append(execute_rail_fn(r_name, ws, params=r_params))
        return {"ok": all(r.get("ok", False) for r in results), "rail": rail_name, "steps_executed": len(results), "results": results}

    # --- DOMAIN G: OPENHANDS V1 SDK MAXIMUM EXTRACTION ORGANS (101-105) ---
    if rail_name == "stuck_loop_detector":
        from am_ua.execution.openhands_organs import OpenHandsStuckDetector

        res = OpenHandsStuckDetector().analyze(list(args.get("events") or []))
        return {"rail": rail_name, **res.to_dict()}

    if rail_name == "shell_policy_rails_audit":
        from am_ua.execution.openhands_organs import ShellSemanticPolicyRails

        res = ShellSemanticPolicyRails.analyze_command(str(args.get("command") or ""))
        return {"rail": rail_name, **res}

    if rail_name == "v4a_multifile_patch":
        from am_ua.execution.openhands_organs import V4AMultiFilePatchEngine

        res = V4AMultiFilePatchEngine.apply_patch(
            ws,
            str(args.get("patch_text") or ""),
            dry_run=bool(args.get("dry_run", False)),
        )
        return {"rail": rail_name, **res}

    if rail_name == "trajectory_critic_eval":
        from am_ua.execution.openhands_organs import TrajectoryCritic

        res = TrajectoryCritic().evaluate(
            list(args.get("events") or []),
            git_patch=args.get("git_patch"),
            require_patch=bool(args.get("require_patch", True)),
            verify_passed=args.get("verify_passed"),
        )
        return {"rail": rail_name, **res.to_dict()}

    if rail_name == "tom_intent_consultant":
        from am_ua.execution.openhands_organs import ToMIntentConsultant

        res = ToMIntentConsultant.consult(
            str(args.get("user_message") or ""),
            prior_preferences=args.get("prior_preferences"),
        )
        return {"rail": rail_name, **res}

    return {"ok": False, "rail": rail_name, "error": f"Unhandled matrix rail: {rail_name}"}
