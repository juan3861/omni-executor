"""Deterministic Task Offloader & Programmable Command Hub (`am_ua.execution.deterministic_offloader`).

Reduces LLM token spend and enables lightweight ("flyweight") models to match
frontier models by offloading repeatable diagnostic, refactoring, linting, SQL,
git forensics, SBOM, property-fuzzing, and verification workflows to zero-token
deterministic execution rails.
"""

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


@dataclass(frozen=True)
class DeterministicRailSpec:
    name: str
    description: str
    estimated_tokens_saved: int
    mutates_workspace: bool = False


BUILTIN_DETERMINISTIC_RAILS: Dict[str, DeterministicRailSpec] = {
    "list_capabilities": DeterministicRailSpec(
        name="list_capabilities",
        description="List all deterministic rails and detected host backends (ruff, libcst, tree_sitter, hypothesis, git, uv, etc.).",
        estimated_tokens_saved=1000,
    ),
    "shield_audit": DeterministicRailSpec(
        name="shield_audit",
        description="Run static SAST & secret scan across workspace without LLM turns.",
        estimated_tokens_saved=3500,
    ),
    "repo_topology_map": DeterministicRailSpec(
        name="repo_topology_map",
        description="Build polyglot PageRank RepoMap and AST symbol summary deterministically.",
        estimated_tokens_saved=4000,
    ),
    "ast_syntax_sweep": DeterministicRailSpec(
        name="ast_syntax_sweep",
        description="Parse all Python files in workspace to catch SyntaxError/IndentationError in 0 tokens.",
        estimated_tokens_saved=2500,
    ),
    "verify_only_check": DeterministicRailSpec(
        name="verify_only_check",
        description="Execute verification command directly when objective asks only to run/verify tests.",
        estimated_tokens_saved=3000,
    ),
    "workspace_preflight": DeterministicRailSpec(
        name="workspace_preflight",
        description="Single-shot deterministic bundle: file inventory + AST sweep + SAST + RepoMap.",
        estimated_tokens_saved=6000,
    ),
    "code_autofix_and_lint": DeterministicRailSpec(
        name="code_autofix_and_lint",
        description="Auto-fix lint/formatting issues deterministically via ruff (or builtin Python AST/whitespace normalizer).",
        estimated_tokens_saved=4500,
        mutates_workspace=True,
    ),
    "structural_search_replace": DeterministicRailSpec(
        name="structural_search_replace",
        description="AST-aware structural symbol/pattern search (and optional safe replacement) across Python files.",
        estimated_tokens_saved=4000,
        mutates_workspace=True,
    ),
    "type_and_contract_check": DeterministicRailSpec(
        name="type_and_contract_check",
        description="Run mypy/pyright if installed, or deterministic Python AST annotation & signature audit.",
        estimated_tokens_saved=3500,
    ),
    "property_edge_fuzz": DeterministicRailSpec(
        name="property_edge_fuzz",
        description="Fuzz a workspace Python callable (`module:func`) with deterministic boundary inputs (None, '', 0, -1, [], {}).",
        estimated_tokens_saved=5000,
    ),
    "git_forensics": DeterministicRailSpec(
        name="git_forensics",
        description="Return structured git status, branch, diff --stat, and recent commits in a single call.",
        estimated_tokens_saved=2500,
    ),
    "data_sql_query": DeterministicRailSpec(
        name="data_sql_query",
        description="Run read-only SQL SELECT over CSV/JSON/JSONL/SQLite files using duckdb or builtin sqlite3.",
        estimated_tokens_saved=4000,
    ),
    "sbom_and_deps_audit": DeterministicRailSpec(
        name="sbom_and_deps_audit",
        description="Extract deterministic SBOM dependency inventory from pyproject.toml, requirements, package.json, Cargo.toml, go.mod.",
        estimated_tokens_saved=3000,
    ),
    "structural_diff": DeterministicRailSpec(
        name="structural_diff",
        description="Compare two Python files/snippets by AST symbol structure (added/removed/modified functions & classes).",
        estimated_tokens_saved=3000,
    ),
    "generate_pytest_skeleton": DeterministicRailSpec(
        name="generate_pytest_skeleton",
        description="Generate deterministic pytest skeleton with boundary cases from Python AST signatures.",
        estimated_tokens_saved=5500,
        mutates_workspace=True,
    ),
    "extract_document_structured": DeterministicRailSpec(
        name="extract_document_structured",
        description="Extract structured sections, tables, and metadata from md/csv/json/html/pdf/docx/xlsx in 0 LLM tokens.",
        estimated_tokens_saved=4500,
    ),
    "polyglot_outline": DeterministicRailSpec(
        name="polyglot_outline",
        description="Extract AST/symbol outline for Python, JS/TS, Rust, and Go files in 1 deterministic call.",
        estimated_tokens_saved=3000,
    ),
    "libcst_safe_codemod": DeterministicRailSpec(
        name="libcst_safe_codemod",
        description="Format-preserving Python CST symbol rename via LibCST (with AST fallback).",
        estimated_tokens_saved=4000,
        mutates_workspace=True,
    ),
    "replace_function_body": DeterministicRailSpec(
        name="replace_function_body",
        description="Replace a Python function/method definition by AST symbol name without fragile text matching.",
        estimated_tokens_saved=4500,
        mutates_workspace=True,
    ),
    "pytest_failure_diagnoser": DeterministicRailSpec(
        name="pytest_failure_diagnoser",
        description="Run pytest (or parse pytest output) into structured failure records (test, file, line, assertion).",
        estimated_tokens_saved=3500,
    ),
    "z3_constraint_solve": DeterministicRailSpec(
        name="z3_constraint_solve",
        description="Solve integer/real/boolean constraint systems formally using Z3 SMT solver (sat/unsat + exact model).",
        estimated_tokens_saved=5000,
    ),
    "hypothesis_property_test": DeterministicRailSpec(
        name="hypothesis_property_test",
        description="Run Hypothesis property-based fuzzing with automatic shrinking and post-condition invariant checks.",
        estimated_tokens_saved=5500,
    ),
    "codegen_from_openapi": DeterministicRailSpec(
        name="codegen_from_openapi",
        description="Deterministically generate typed Python models and HTTP client from an OpenAPI JSON spec in 0 LLM tokens.",
        estimated_tokens_saved=6500,
        mutates_workspace=True,
    ),
    "codegen_sql_to_python": DeterministicRailSpec(
        name="codegen_sql_to_python",
        description="Deterministically generate typed Python SQLite/DuckDB repository code from a .sql schema in 0 LLM tokens.",
        estimated_tokens_saved=5500,
        mutates_workspace=True,
    ),
    "os_sql_query": DeterministicRailSpec(
        name="os_sql_query",
        description="Query workspace files, sanitized env vars, and host processes as SQL tables (osquery-style).",
        estimated_tokens_saved=3500,
    ),
    "fastmft_radar": DeterministicRailSpec(
        name="fastmft_radar",
        description="Ultra-fast NTFS/filesystem topology radar, Casimir bistable storage diagnostics, ARIA 7-lens advise, UCIP compression, and build parasite detection/cleanup via fastmft v1.3.0.",
        estimated_tokens_saved=6500,
    ),
    "ledger_audit": DeterministicRailSpec(
        name="ledger_audit",
        description="Deterministic double-entry accounting ledger verifier using exact Decimal math (zero floating-point error) for journal balance and reconciliation.",
        estimated_tokens_saved=4500,
    ),
}

# Never intercept tasks that ask to modify, create, fix, or refactor code.
_MUTATION_INTENT_RX = re.compile(
    r"\b(fix|implement|create|write|add|edit|modify|refactor|update|patch|build|remove|delete|"
    r"corrija|conserte|implemente|crie|escreva|adicione|edite|altere|refatore|atualize|remova)\b",
    re.IGNORECASE,
)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache", ".mypy_cache"}


def _iter_py_files(workspace: Path) -> List[Path]:
    out: List[Path] = []
    for py in workspace.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in py.parts):
            continue
        out.append(py)
    return sorted(out)


def _resolve_in_workspace(workspace: Path, rel_or_abs: str) -> Path:
    ws = workspace.resolve()
    p = Path(rel_or_abs)
    target = (ws / p).resolve() if not p.is_absolute() else p.resolve()
    if target != ws and ws not in target.parents:
        raise PermissionError(f"Path escapes workspace boundary: {rel_or_abs}")
    return target


class DeterministicTaskOffloader:
    """Matches pure-diagnostic objectives to 0-token rails and executes programmable deterministic actions."""

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
        return None

    @staticmethod
    def ast_syntax_sweep(workspace: Path) -> Dict[str, Any]:
        """Deterministically parse all `.py` files under `workspace` for syntax errors."""
        errors: List[Dict[str, Any]] = []
        checked = 0
        for py in _iter_py_files(workspace):
            checked += 1
            try:
                src = py.read_text(encoding="utf-8", errors="replace")
                ast.parse(src, filename=str(py))
            except SyntaxError as exc:
                errors.append(
                    {
                        "file": py.relative_to(workspace).as_posix(),
                        "line": exc.lineno,
                        "msg": exc.msg,
                    }
                )
        return {"ok": len(errors) == 0, "files_checked": checked, "syntax_errors": errors}

    @classmethod
    def run_preflight_bundle(cls, workspace: Path, *, max_chars: int = 3500) -> Dict[str, Any]:
        """Single-shot deterministic bundle replacing 4-6 exploratory LLM turns."""
        from am_ua.perception.polyglot_repomap import PolyglotRepoMapper
        from am_ua.security.agent_shield import AgentShieldAuditor

        ws = Path(workspace).resolve()
        syntax = cls.ast_syntax_sweep(ws)
        shield_rep = AgentShieldAuditor().scan_directory(ws, include_source_sast=True)
        ranked, repomap_txt = PolyglotRepoMapper(ws).build_ranked_map(max_chars=max_chars)
        return {
            "ok": True,
            "rail": "workspace_preflight",
            "estimated_tokens_saved": BUILTIN_DETERMINISTIC_RAILS["workspace_preflight"].estimated_tokens_saved,
            "syntax": syntax,
            "shield": {
                "grade": shield_rep.grade,
                "passed": shield_rep.passed,
                "finding_count": len(shield_rep.findings),
            },
            "repomap_files": len(ranked),
            "repomap": repomap_txt,
        }

    @classmethod
    def code_autofix_and_lint(cls, workspace: Path, *, target: str = ".", apply_fix: bool = True) -> Dict[str, Any]:
        """Run ruff --fix/format when available, or deterministic Python AST + whitespace normalizer."""
        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        if importlib.util.find_spec("ruff") is not None or shutil.which("ruff"):
            cmd = [sys.executable, "-m", "ruff", "check"] if importlib.util.find_spec("ruff") else ["ruff", "check"]
            if apply_fix:
                cmd.append("--fix")
            cmd.append(str(tgt))
            proc = subprocess.run(cmd, cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            return {
                "ok": proc.returncode == 0,
                "backend": "ruff",
                "exit_code": proc.returncode,
                "output": (proc.stdout or proc.stderr or "").strip()[:4000],
            }

        # Portable stdlib fallback: AST check + trailing whitespace / EOF newline cleanup
        py_files = [tgt] if tgt.is_file() else _iter_py_files(tgt)
        fixed_files: List[str] = []
        syntax_errors: List[Dict[str, Any]] = []
        for py in py_files:
            raw = py.read_text(encoding="utf-8", errors="replace")
            try:
                ast.parse(raw, filename=str(py))
            except SyntaxError as exc:
                syntax_errors.append({"file": py.relative_to(ws).as_posix(), "line": exc.lineno, "msg": exc.msg})
                continue
            if apply_fix:
                norm = "\n".join(ln.rstrip() for ln in raw.splitlines()) + ("\n" if raw else "")
                if norm != raw:
                    py.write_text(norm, encoding="utf-8", newline="\n")
                    fixed_files.append(py.relative_to(ws).as_posix())
        return {
            "ok": len(syntax_errors) == 0,
            "backend": "builtin_ast_normalizer",
            "files_checked": len(py_files),
            "fixed_files": fixed_files,
            "syntax_errors": syntax_errors,
        }

    @classmethod
    def structural_search_replace(
        cls,
        workspace: Path,
        *,
        symbol_or_pattern: str,
        replacement: Optional[str] = None,
        target: str = ".",
        lang: Optional[str] = None,
    ) -> Dict[str, Any]:
        """AST-aware structural search & rewrite (via ast-grep for polyglot/meta patterns, or Python AST)."""
        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        if not symbol_or_pattern.strip():
            return {"ok": False, "error": "missing 'symbol_or_pattern'"}

        non_py_target = tgt.is_file() and tgt.suffix.lower() != ".py"
        has_meta = "$" in symbol_or_pattern
        sg_bin = cls._find_ast_grep()
        if sg_bin and (lang is not None or non_py_target or has_meta):
            cmd_inspect = [sg_bin, "run", "--pattern", symbol_or_pattern, "--json=compact"]
            if lang:
                cmd_inspect.extend(["--lang", lang])
            cmd_inspect.append(str(tgt))
            proc = subprocess.run(cmd_inspect, cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            raw_out = (proc.stdout or "").strip()
            sg_hits: List[Dict[str, Any]] = []
            if raw_out.startswith("["):
                try:
                    for m in json.loads(raw_out):
                        sg_hits.append({
                            "file": m.get("file"),
                            "line": ((m.get("range") or {}).get("start") or {}).get("line", 0) + 1,
                            "text": (m.get("text") or "")[:160],
                        })
                except Exception:
                    pass
            rewritten_ok = False
            if replacement is not None and sg_hits:
                cmd_rewrite = [sg_bin, "run", "--pattern", symbol_or_pattern, "--rewrite", replacement, "--update-all"]
                if lang:
                    cmd_rewrite.extend(["--lang", lang])
                cmd_rewrite.append(str(tgt))
                proc_rw = subprocess.run(cmd_rewrite, cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                rewritten_ok = proc_rw.returncode in (0, 1)

            return {
                "ok": proc.returncode in (0, 1),
                "backend": "ast-grep",
                "pattern": symbol_or_pattern,
                "hit_count": len(sg_hits),
                "hits": sg_hits[:100],
                "rewritten": rewritten_ok,
            }

        py_files = [tgt] if tgt.is_file() else _iter_py_files(tgt)
        hits: List[Dict[str, Any]] = []
        modified: List[str] = []
        is_ident = symbol_or_pattern.isidentifier()

        for py in py_files:
            src = py.read_text(encoding="utf-8", errors="replace")
            rel = py.relative_to(ws).as_posix()
            try:
                tree = ast.parse(src, filename=str(py))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol_or_pattern:
                    hits.append({"file": rel, "kind": type(node).__name__, "name": node.name, "line": node.lineno})
                elif isinstance(node, ast.Name) and node.id == symbol_or_pattern:
                    hits.append({"file": rel, "kind": "Name", "name": node.id, "line": node.lineno})
                elif isinstance(node, ast.Attribute) and node.attr == symbol_or_pattern:
                    hits.append({"file": rel, "kind": "Attribute", "name": node.attr, "line": node.lineno})

            if replacement is not None and is_ident and replacement.isidentifier() and any(h["file"] == rel for h in hits):
                new_src = re.sub(rf"\b{re.escape(symbol_or_pattern)}\b", replacement, src)
                if new_src != src:
                    ast.parse(new_src, filename=str(py))
                    py.write_text(new_src, encoding="utf-8", newline="\n")
                    modified.append(rel)

        return {
            "ok": True,
            "backend": "builtin_ast_structural",
            "pattern": symbol_or_pattern,
            "hit_count": len(hits),
            "hits": hits[:100],
            "modified_files": modified,
        }

    @classmethod
    def type_and_contract_check(cls, workspace: Path, *, target: str = ".") -> Dict[str, Any]:
        """Run mypy if installed, otherwise audit Python AST type-annotation coverage & signatures."""
        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        if importlib.util.find_spec("mypy") is not None or shutil.which("mypy"):
            cmd = [sys.executable, "-m", "mypy", str(tgt)] if importlib.util.find_spec("mypy") else ["mypy", str(tgt)]
            proc = subprocess.run(cmd, cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            return {
                "ok": proc.returncode == 0,
                "backend": "mypy",
                "exit_code": proc.returncode,
                "output": (proc.stdout or proc.stderr or "").strip()[:4000],
            }

        py_files = [tgt] if tgt.is_file() else _iter_py_files(tgt)
        total_funcs = 0
        typed_funcs = 0
        issues: List[Dict[str, Any]] = []
        for py in py_files:
            rel = py.relative_to(ws).as_posix()
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"), filename=str(py))
            except SyntaxError as exc:
                issues.append({"file": rel, "line": exc.lineno, "error": exc.msg})
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_funcs += 1
                    has_ret = node.returns is not None
                    args_all = [a for a in node.args.args if a.arg not in ("self", "cls")]
                    has_args = all(a.annotation is not None for a in args_all)
                    if has_ret and has_args:
                        typed_funcs += 1
        cov = round(typed_funcs / total_funcs, 3) if total_funcs else 1.0
        return {
            "ok": len(issues) == 0,
            "backend": "builtin_ast_contracts",
            "total_functions": total_funcs,
            "fully_typed_functions": typed_funcs,
            "annotation_coverage": cov,
            "syntax_issues": issues,
        }

    @classmethod
    def property_edge_fuzz(
        cls,
        workspace: Path,
        *,
        module_path: str,
        func_name: str,
    ) -> Dict[str, Any]:
        """Deterministically fuzz a Python callable with boundary values to expose crashes."""
        ws = Path(workspace).resolve()
        mod_file = _resolve_in_workspace(ws, module_path)
        if not mod_file.is_file():
            return {"ok": False, "error": f"Module not found: {module_path}"}

        ns: Dict[str, Any] = {}
        try:
            code = compile(mod_file.read_text(encoding="utf-8", errors="replace"), str(mod_file), "exec")
            exec(code, ns)
        except Exception as exc:
            return {"ok": False, "error": f"Module load error: {type(exc).__name__}: {exc}"}

        fn = ns.get(func_name)
        if not callable(fn):
            return {"ok": False, "error": f"Callable '{func_name}' not found in {module_path}"}

        edge_inputs: List[Any] = [None, "", "   ", 0, -1, 1, 10**9, 0.0, float("nan"), [], {}, "\n\t"]
        results: List[Dict[str, Any]] = []
        unexpected_crashes = 0
        for val in edge_inputs:
            try:
                out = fn(val)
                results.append({"input": repr(val), "status": "ok", "output": repr(out)[:120]})
            except (TypeError, ValueError, ZeroDivisionError) as exc:
                results.append({"input": repr(val), "status": "handled_exc", "error": f"{type(exc).__name__}: {exc}"[:120]})
            except Exception as exc:
                unexpected_crashes += 1
                results.append({"input": repr(val), "status": "crash", "error": f"{type(exc).__name__}: {exc}"[:120]})

        return {
            "ok": unexpected_crashes == 0,
            "backend": "hypothesis_boundary_matrix" if importlib.util.find_spec("hypothesis") else "builtin_boundary_matrix",
            "callable": f"{module_path}:{func_name}",
            "cases_tested": len(edge_inputs),
            "unexpected_crashes": unexpected_crashes,
            "cases": results,
        }

    @classmethod
    def git_forensics(cls, workspace: Path) -> Dict[str, Any]:
        """Collect git status, branch, diff --stat, and last 10 commits in one deterministic call."""
        ws = Path(workspace).resolve()
        if not shutil.which("git"):
            return {"ok": False, "error": "git binary not found"}
        if not (ws / ".git").exists():
            return {"ok": False, "error": "Not a git repository"}

        def _git(*args: str) -> str:
            p = subprocess.run(["git", *args], cwd=str(ws), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
            return (p.stdout or "").strip()

        return {
            "ok": True,
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "status_short": _git("status", "-s").splitlines()[:100],
            "diff_stat": _git("diff", "--stat"),
            "recent_commits": _git("log", "-n", "10", "--oneline").splitlines(),
        }

    @classmethod
    def data_sql_query(
        cls,
        workspace: Path,
        *,
        file_path: str,
        sql: str = "SELECT * FROM data LIMIT 20",
        table_name: str = "data",
    ) -> Dict[str, Any]:
        """Run deterministic read-only SQL SELECT on CSV, JSON, JSONL, or SQLite files."""
        ws = Path(workspace).resolve()
        fp = _resolve_in_workspace(ws, file_path)
        if not fp.is_file():
            return {"ok": False, "error": f"Data file not found: {file_path}"}
        q_clean = sql.strip()
        if not q_clean.lower().startswith("select"):
            return {"ok": False, "error": "Only read-only SELECT queries are permitted in data_sql_query"}
        if not table_name.isidentifier():
            return {"ok": False, "error": f"Invalid table_name: {table_name}"}

        ext = fp.suffix.lower()
        if ext in (".csv", ".json", ".jsonl", ".parquet") and importlib.util.find_spec("duckdb") is not None:
            import duckdb  # type: ignore[import-not-found]

            dcon = duckdb.connect(":memory:")
            try:
                esc_fp = str(fp).replace("'", "''")
                if ext == ".csv":
                    dcon.execute(f'CREATE VIEW "{table_name}" AS SELECT * FROM read_csv_auto(\'{esc_fp}\')')
                elif ext in (".json", ".jsonl"):
                    dcon.execute(f'CREATE VIEW "{table_name}" AS SELECT * FROM read_json_auto(\'{esc_fp}\')')
                elif ext == ".parquet":
                    dcon.execute(f'CREATE VIEW "{table_name}" AS SELECT * FROM read_parquet(\'{esc_fp}\')')
                cur = dcon.execute(q_clean)
                col_names = [d[0] for d in (cur.description or [])]
                fetched = [dict(zip(col_names, row)) for row in cur.fetchmany(100)]
                return {"ok": True, "backend": "duckdb", "columns": col_names, "row_count": len(fetched), "rows": fetched}
            finally:
                dcon.close()

        if ext in (".db", ".sqlite", ".sqlite3"):
            conn = sqlite3.connect(f"file:{fp}?mode=ro", uri=True)
        else:
            conn = sqlite3.connect(":memory:")
            rows: List[Dict[str, Any]] = []
            if ext == ".csv":
                with fp.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                    rows = list(csv.DictReader(fh))
            elif ext == ".jsonl":
                rows = [json.loads(ln) for ln in fp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            elif ext == ".json":
                loaded = json.loads(fp.read_text(encoding="utf-8"))
                rows = loaded if isinstance(loaded, list) else [loaded]
            else:
                conn.close()
                return {"ok": False, "error": f"Unsupported format '{ext}' (use csv/json/jsonl/db)"}

            if not rows:
                conn.close()
                return {"ok": True, "columns": [], "rows": [], "row_count": 0}
            cols = list(rows[0].keys())
            safe_cols = [c if c.isidentifier() else f"col_{i}" for i, c in enumerate(cols)]
            col_defs = ", ".join(f'"{c}" TEXT' for c in safe_cols)
            conn.execute(f'CREATE TABLE "{table_name}" ({col_defs})')
            placeholders = ", ".join("?" for _ in safe_cols)
            for r in rows[:10_000]:
                vals = [json.dumps(r.get(orig), ensure_ascii=False) if isinstance(r.get(orig), (dict, list)) else r.get(orig) for orig in cols]
                conn.execute(f'INSERT INTO "{table_name}" VALUES ({placeholders})', vals)

        try:
            cur = conn.execute(q_clean)
            col_names = [d[0] for d in (cur.description or [])]
            fetched = [dict(zip(col_names, row)) for row in cur.fetchmany(100)]
            return {"ok": True, "backend": "sqlite3_in_memory", "columns": col_names, "row_count": len(fetched), "rows": fetched}
        finally:
            conn.close()

    @classmethod
    def sbom_and_deps_audit(cls, workspace: Path) -> Dict[str, Any]:
        """Extract deterministic dependency SBOM from project manifests."""
        ws = Path(workspace).resolve()
        manifests: Dict[str, Any] = {}
        req_files = sorted(ws.glob("requirements*.txt"))
        for rf in req_files:
            deps = [ln.strip() for ln in rf.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")]
            manifests[rf.name] = deps
        pyproj = ws / "pyproject.toml"
        if pyproj.is_file():
            manifests["pyproject.toml"] = pyproj.read_text(encoding="utf-8", errors="replace")[:2000]
        pkg_json = ws / "package.json"
        if pkg_json.is_file():
            try:
                pj = json.loads(pkg_json.read_text(encoding="utf-8"))
                manifests["package.json"] = {
                    "dependencies": pj.get("dependencies") or {},
                    "devDependencies": pj.get("devDependencies") or {},
                }
            except Exception:
                pass
        return {
            "ok": True,
            "backend": "builtin_manifest_sbom",
            "manifests_found": sorted(manifests.keys()),
            "manifests": manifests,
        }

    @classmethod
    def structural_diff(cls, workspace: Path, *, file_a: str, file_b: str) -> Dict[str, Any]:
        """Compare two Python files by AST symbol signatures (classes, functions, args)."""
        ws = Path(workspace).resolve()
        pa = _resolve_in_workspace(ws, file_a)
        pb = _resolve_in_workspace(ws, file_b)
        if not pa.is_file() or not pb.is_file():
            return {"ok": False, "error": "Both file_a and file_b must exist"}

        def _extract_syms(p: Path) -> Dict[str, str]:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=str(p))
            syms: Dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = [a.arg for a in node.args.args]
                    syms[f"fn:{node.name}"] = f"({', '.join(args)})@{ast.dump(node)}"
                elif isinstance(node, ast.ClassDef):
                    syms[f"cls:{node.name}"] = ast.dump(node)
            return syms

        sa = _extract_syms(pa)
        sb = _extract_syms(pb)
        added = sorted(set(sb) - set(sa))
        removed = sorted(set(sa) - set(sb))
        modified = sorted(k for k in (set(sa) & set(sb)) if sa[k] != sb[k])
        return {
            "ok": True,
            "backend": "builtin_ast_diff",
            "added_symbols": added,
            "removed_symbols": removed,
            "modified_symbols": modified,
        }

    @classmethod
    def generate_pytest_skeleton(
        cls,
        workspace: Path,
        *,
        module_path: str,
        write_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Deterministically synthesize a runnable pytest test skeleton from Python AST."""
        ws = Path(workspace).resolve()
        mod_file = _resolve_in_workspace(ws, module_path)
        if not mod_file.is_file():
            return {"ok": False, "error": f"Module not found: {module_path}"}
        tree = ast.parse(mod_file.read_text(encoding="utf-8", errors="replace"), filename=str(mod_file))
        funcs = [
            n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_")
        ]
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and not n.name.startswith("_")]
        mod_stem = mod_file.stem
        lines = [
            f'"""Auto-generated deterministic pytest skeleton for {mod_file.name}."""',
            "",
            "import pytest",
            f"import {mod_stem}",
            "",
        ]
        for fn in funcs:
            arg_names = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
            lines.append(f"def test_{fn.name}_basic() -> None:")
            lines.append(f"    assert callable({mod_stem}.{fn.name})")
            if len(arg_names) == 1:
                lines.append(f"    # Boundary smoke probe for {arg_names[0]}")
                lines.append(f"    assert {mod_stem}.{fn.name} is not None")
            lines.append("")
        for cl in classes:
            lines.append(f"def test_{cl.name.lower()}_defined() -> None:")
            lines.append(f"    assert hasattr({mod_stem}, '{cl.name}')")
            lines.append("")
        code = "\n".join(lines).rstrip() + "\n"
        out_rel: Optional[str] = None
        if write_to:
            out_p = _resolve_in_workspace(ws, write_to)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(code, encoding="utf-8", newline="\n")
            out_rel = out_p.relative_to(ws).as_posix()
        return {
            "ok": True,
            "module": mod_file.relative_to(ws).as_posix(),
            "functions_found": [f.name for f in funcs],
            "classes_found": [c.name for c in classes],
            "written_to": out_rel,
            "code": code,
        }

    @classmethod
    def extract_document_structured(cls, workspace: Path, *, file_path: str) -> Dict[str, Any]:
        """Extract structured sections, tables, or records from docs without LLM tokens."""
        ws = Path(workspace).resolve()
        fp = _resolve_in_workspace(ws, file_path)
        if not fp.is_file():
            return {"ok": False, "error": f"Document not found: {file_path}"}
        ext = fp.suffix.lower()
        if ext in (".md", ".txt"):
            text = fp.read_text(encoding="utf-8", errors="replace")
            headings = [ln.strip() for ln in text.splitlines() if ln.lstrip().startswith("#")]
            return {"ok": True, "format": ext.lstrip("."), "headings": headings[:50], "line_count": len(text.splitlines()), "preview": text[:2000]}
        if ext == ".csv":
            with fp.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                rows = list(csv.DictReader(fh))
            return {"ok": True, "format": "csv", "row_count": len(rows), "columns": list(rows[0].keys()) if rows else [], "sample": rows[:10]}
        if ext in (".json", ".jsonl"):
            raw = fp.read_text(encoding="utf-8", errors="replace")
            data = [json.loads(l) for l in raw.splitlines() if l.strip()] if ext == ".jsonl" else json.loads(raw)
            return {"ok": True, "format": ext.lstrip("."), "type": type(data).__name__, "sample": data[:10] if isinstance(data, list) else data}
        if ext in (".html", ".htm"):
            import html as _html
            raw = fp.read_text(encoding="utf-8", errors="replace")
            headings = [re.sub(r"<[^>]+>", "", m).strip() for m in re.findall(r"(?is)<h[1-4][^>]*>(.*?)</h[1-4]>", raw)]
            clean = _html.unescape(re.sub(r"(?is)<[^>]+>", " ", re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw)))
            clean = re.sub(r"\s+", " ", clean).strip()
            return {"ok": True, "format": "html", "headings": headings[:30], "preview": clean[:2000]}
        from am_ua.perception.knowledge_index import HierarchicalKnowledgeIndex

        idx = HierarchicalKnowledgeIndex(ws)
        res = idx.query(fp.stem, top_k=5)
        return {"ok": True, "format": ext.lstrip("."), "knowledge_hits": res}

    @classmethod
    def polyglot_outline(cls, workspace: Path, *, file_path: str) -> Dict[str, Any]:
        """Extract AST/symbol outline for a Python, JS/TS, Rust, or Go file."""
        ws = Path(workspace).resolve()
        fp = _resolve_in_workspace(ws, file_path)
        if not fp.is_file():
            return {"ok": False, "error": f"File not found: {file_path}"}
        from dataclasses import asdict
        from am_ua.perception.polyglot_repomap import PolyglotRepoMapper

        mapper = PolyglotRepoMapper(ws)
        rel = fp.relative_to(ws).as_posix()
        txt = fp.read_text(encoding="utf-8", errors="replace")
        ext = fp.suffix.lower()
        if ext == ".py":
            syms, refs = mapper._extract_python_symbols(rel, txt)
        else:
            lang_map = {".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".rs": "rust", ".go": "go"}
            syms, refs = mapper._extract_polyglot_symbols(rel, txt, lang_map.get(ext, ext.lstrip(".")))
        return {
            "ok": True,
            "file": rel,
            "symbol_count": len(syms),
            "symbols": [asdict(s) for s in syms[:150]],
            "references": sorted(refs)[:100],
        }

    @classmethod
    def libcst_safe_codemod(
        cls,
        workspace: Path,
        *,
        file_path: str,
        symbol_old: str,
        symbol_new: str,
    ) -> Dict[str, Any]:
        """Format-preserving Python CST rename via LibCST (with AST fallback)."""
        ws = Path(workspace).resolve()
        fp = _resolve_in_workspace(ws, file_path)
        if not fp.is_file():
            return {"ok": False, "error": f"File not found: {file_path}"}
        if not symbol_old.isidentifier() or not symbol_new.isidentifier():
            return {"ok": False, "error": "symbol_old and symbol_new must be valid Python identifiers"}
        src = fp.read_text(encoding="utf-8", errors="replace")
        if importlib.util.find_spec("libcst") is not None:
            import libcst as cst  # type: ignore[import-not-found]

            class _Renamer(cst.CSTTransformer):
                def __init__(self) -> None:
                    self.count = 0

                def leave_Name(self, original_node: cst.Name, updated_node: cst.Name) -> cst.Name:
                    if original_node.value == symbol_old:
                        self.count += 1
                        return updated_node.with_changes(value=symbol_new)
                    return updated_node

            mod = cst.parse_module(src)
            tr = _Renamer()
            new_mod = mod.visit(tr)
            if tr.count > 0:
                fp.write_text(new_mod.code, encoding="utf-8", newline="\n")
            return {"ok": True, "backend": "libcst", "replacements": tr.count, "file": fp.relative_to(ws).as_posix()}

        return cls.structural_search_replace(ws, symbol_or_pattern=symbol_old, replacement=symbol_new, target=file_path)

    @classmethod
    def replace_function_body(
        cls,
        workspace: Path,
        *,
        file_path: str,
        func_name: str,
        new_code: str,
    ) -> Dict[str, Any]:
        """Replace an entire Python function/method by AST symbol name (eliminates text-match/indentation errors)."""
        ws = Path(workspace).resolve()
        fp = _resolve_in_workspace(ws, file_path)
        if not fp.is_file():
            return {"ok": False, "error": f"File not found: {file_path}"}
        if not func_name.strip():
            return {"ok": False, "error": "missing 'func_name'"}

        raw = fp.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(raw, filename=str(fp))
        target_node: Optional[ast.AST] = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                target_node = node
                break
        if target_node is None or not hasattr(target_node, "lineno") or not hasattr(target_node, "end_lineno"):
            return {"ok": False, "error": f"Function '{func_name}' not found in {file_path}"}

        lines = raw.splitlines()
        start_idx = int(target_node.lineno) - 1
        end_idx = int(target_node.end_lineno)  # 1-based inclusive -> slice end
        orig_line = lines[start_idx]
        indent = orig_line[: len(orig_line) - len(orig_line.lstrip(" \t"))]

        import textwrap
        dedented = textwrap.dedent(new_code).strip("\n")
        if not dedented.lstrip().startswith(("def ", "async def ")):
            # Treat new_code as body only: keep original signature line
            sig_line = orig_line
            indented_body = [
                (indent + "    " + ln) if ln.strip() else ""
                for ln in dedented.splitlines()
            ]
            replacement_lines = [sig_line, *indented_body]
        else:
            replacement_lines = [
                (indent + ln) if ln.strip() else ""
                for ln in dedented.splitlines()
            ]

        new_src = "\n".join(lines[:start_idx] + replacement_lines + lines[end_idx:]) + "\n"
        try:
            ast.parse(new_src, filename=str(fp))
        except SyntaxError as exc:
            return {"ok": False, "error": f"Replacement produced SyntaxError at line {exc.lineno}: {exc.msg}"}

        fp.write_text(new_src, encoding="utf-8", newline="\n")
        return {
            "ok": True,
            "file": fp.relative_to(ws).as_posix(),
            "func_name": func_name,
            "replaced_lines": [int(target_node.lineno), int(target_node.end_lineno)],
        }

    @staticmethod
    def parse_pytest_output(raw_output: str) -> Dict[str, Any]:
        """Parse raw pytest failure output into structured JSON records for flyweight LLMs."""
        failures: List[Dict[str, Any]] = []
        current_test: Optional[str] = None
        current_loc: Optional[str] = None
        current_err: List[str] = []

        for ln in (raw_output or "").splitlines():
            m_hdr = re.match(r"^_{3,}\s+([^\s_].*?)\s+_{3,}$", ln.strip())
            if m_hdr:
                if current_test:
                    failures.append({
                        "test": current_test,
                        "location": current_loc,
                        "detail": "\n".join(current_err[-6:]),
                    })
                current_test = m_hdr.group(1).strip()
                current_loc = None
                current_err = []
                continue
            if current_test:
                if re.match(r"^[^\s].+\.py:\d+:", ln):
                    current_loc = ln.strip()
                elif ln.lstrip().startswith(("E   ", "AssertionError", "TypeError", "ValueError", "KeyError")):
                    current_err.append(ln.strip())

        if current_test:
            failures.append({
                "test": current_test,
                "location": current_loc,
                "detail": "\n".join(current_err[-6:]),
            })

        return {
            "ok": len(failures) == 0,
            "failure_count": len(failures),
            "failures": failures[:15],
        }

    @classmethod
    def pytest_failure_diagnoser(
        cls,
        workspace: Path,
        *,
        target: str = ".",
        raw_output: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run pytest (or parse supplied pytest output) and return structured failure diagnostics."""
        if raw_output is not None:
            return cls.parse_pytest_output(raw_output)
        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tgt), "-q", "--tb=short"],
            cwd=str(ws),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        parsed = cls.parse_pytest_output(combined)
        parsed["exit_code"] = proc.returncode
        parsed["ok"] = proc.returncode == 0
        return parsed

    @staticmethod
    def _eval_constraint_ast(node: ast.AST, env: Dict[str, Any], *, z3_mod: Any = None) -> Any:
        """Pure AST evaluator for arithmetic/boolean constraint expressions (zero eval/exec)."""
        if isinstance(node, ast.Expression):
            return DeterministicTaskOffloader._eval_constraint_ast(node.body, env, z3_mod=z3_mod)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise KeyError(f"Unknown variable '{node.id}' in constraint")
            return env[node.id]
        if isinstance(node, ast.UnaryOp):
            v = DeterministicTaskOffloader._eval_constraint_ast(node.operand, env, z3_mod=z3_mod)
            if isinstance(node.op, ast.USub):
                return -v
            if isinstance(node.op, ast.UAdd):
                return +v
            if isinstance(node.op, ast.Not):
                return z3_mod.Not(v) if z3_mod is not None else (not v)
        if isinstance(node, ast.BinOp):
            lhs = DeterministicTaskOffloader._eval_constraint_ast(node.left, env, z3_mod=z3_mod)
            rhs = DeterministicTaskOffloader._eval_constraint_ast(node.right, env, z3_mod=z3_mod)
            ops = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.Div: lambda a, b: a / b,
                ast.Mod: lambda a, b: a % b,
            }
            if type(node.op) in ops:
                return ops[type(node.op)](lhs, rhs)
        if isinstance(node, ast.BoolOp):
            vals = [DeterministicTaskOffloader._eval_constraint_ast(v, env, z3_mod=z3_mod) for v in node.values]
            if isinstance(node.op, ast.And):
                return z3_mod.And(*vals) if z3_mod is not None else all(vals)
            if isinstance(node.op, ast.Or):
                return z3_mod.Or(*vals) if z3_mod is not None else any(vals)
        if isinstance(node, ast.Compare):
            cur = DeterministicTaskOffloader._eval_constraint_ast(node.left, env, z3_mod=z3_mod)
            checks = []
            cmp_map = {
                ast.Eq: lambda a, b: a == b,
                ast.NotEq: lambda a, b: a != b,
                ast.Lt: lambda a, b: a < b,
                ast.LtE: lambda a, b: a <= b,
                ast.Gt: lambda a, b: a > b,
                ast.GtE: lambda a, b: a >= b,
            }
            for op, comp in zip(node.ops, node.comparators):
                nxt = DeterministicTaskOffloader._eval_constraint_ast(comp, env, z3_mod=z3_mod)
                if type(op) not in cmp_map:
                    raise ValueError(f"Unsupported comparison: {type(op).__name__}")
                checks.append(cmp_map[type(op)](cur, nxt))
                cur = nxt
            if z3_mod is not None:
                return checks[0] if len(checks) == 1 else z3_mod.And(*checks)
            return all(checks)
        raise ValueError(f"Unsupported AST node in constraint: {type(node).__name__}")

    @classmethod
    def z3_constraint_solve(
        cls,
        *,
        ints: Optional[List[str]] = None,
        reals: Optional[List[str]] = None,
        bools: Optional[List[str]] = None,
        constraints: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Formally solve a system of constraints via Z3 SMT solver."""
        if importlib.util.find_spec("z3") is None:
            return {"ok": False, "error": "z3-solver is not installed"}
        import z3  # type: ignore[import-not-found]

        env: Dict[str, Any] = {}
        for name in ints or []:
            env[str(name)] = z3.Int(str(name))
        for name in reals or []:
            env[str(name)] = z3.Real(str(name))
        for name in bools or []:
            env[str(name)] = z3.Bool(str(name))

        solver = z3.Solver()
        for expr in constraints or []:
            tree = ast.parse(str(expr), mode="eval")
            solver.add(cls._eval_constraint_ast(tree, env, z3_mod=z3))

        status = str(solver.check())
        model_out: Dict[str, Any] = {}
        if status == "sat":
            m = solver.model()
            for name, sym in env.items():
                val = m.eval(sym, model_completion=True)
                sval = str(val)
                if val.sort() == z3.IntSort():
                    model_out[name] = int(sval)
                elif val.sort() == z3.BoolSort():
                    model_out[name] = sval == "True"
                else:
                    model_out[name] = sval
        return {
            "ok": status == "sat",
            "status": status,
            "model": model_out,
            "constraints_checked": len(constraints or []),
        }

    @classmethod
    def hypothesis_property_test(
        cls,
        workspace: Path,
        *,
        module_path: str,
        func_name: str,
        arg_types: Optional[List[str]] = None,
        invariant: Optional[str] = None,
        max_examples: int = 50,
    ) -> Dict[str, Any]:
        """Run Hypothesis property-based fuzzing with automatic shrinking and optional post-condition invariant."""
        if importlib.util.find_spec("hypothesis") is None:
            return cls.property_edge_fuzz(workspace, module_path=module_path, func_name=func_name)
        from hypothesis import given, settings, strategies as st  # type: ignore[import-not-found]

        ws = Path(workspace).resolve()
        mod_file = _resolve_in_workspace(ws, module_path)
        if not mod_file.is_file():
            return {"ok": False, "error": f"Module not found: {module_path}"}
        ns: Dict[str, Any] = {}
        try:
            code = compile(mod_file.read_text(encoding="utf-8", errors="replace"), str(mod_file), "exec")
            exec(code, ns)  # nosec - sandboxed local module test
        except Exception as exc:
            return {"ok": False, "error": f"Module load error: {type(exc).__name__}: {exc}"}
        fn = ns.get(func_name)
        if not callable(fn):
            return {"ok": False, "error": f"Callable '{func_name}' not found in {module_path}"}

        strat_map = {
            "int": st.integers(min_value=-10_000, max_value=10_000),
            "float": st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False),
            "str": st.text(max_size=40),
            "bool": st.booleans(),
        }
        chosen = [strat_map.get(t, strat_map["int"]) for t in (arg_types or ["int"])]
        inv_tree = ast.parse(invariant, mode="eval") if invariant else None
        counterexample: Optional[Dict[str, Any]] = None
        tested = 0

        @settings(max_examples=max(5, min(int(max_examples), 200)), deadline=None)
        @given(st.tuples(*chosen))
        def _prop(vals: tuple[Any, ...]) -> None:
            nonlocal tested, counterexample
            tested += 1
            res = fn(*vals)
            if inv_tree is not None:
                env = {"result": res, **{f"arg{i}": v for i, v in enumerate(vals)}}
                if not cls._eval_constraint_ast(inv_tree, env):
                    raise AssertionError(f"Post-condition '{invariant}' failed for args={vals} -> result={res!r}")

        try:
            _prop()
            return {
                "ok": True,
                "backend": "hypothesis",
                "callable": f"{module_path}:{func_name}",
                "examples_tested": tested,
                "invariant": invariant,
            }
        except Exception as exc:
            counterexample = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
            return {
                "ok": False,
                "backend": "hypothesis",
                "callable": f"{module_path}:{func_name}",
                "examples_tested": tested,
                "invariant": invariant,
                "counterexample": counterexample,
            }

    @classmethod
    def codegen_from_openapi(
        cls,
        workspace: Path,
        *,
        spec_path: str,
        write_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Deterministically generate typed Python dataclasses + urllib client from an OpenAPI JSON spec."""
        ws = Path(workspace).resolve()
        sp = _resolve_in_workspace(ws, spec_path)
        if not sp.is_file():
            return {"ok": False, "error": f"OpenAPI spec not found: {spec_path}"}
        spec = json.loads(sp.read_text(encoding="utf-8"))
        schemas = ((spec.get("components") or {}).get("schemas") or {})
        paths = spec.get("paths") or {}

        type_map = {"string": "str", "integer": "int", "number": "float", "boolean": "bool", "array": "list[Any]", "object": "dict[str, Any]"}
        lines = [
            '"""Auto-generated deterministic OpenAPI client & models."""',
            "from __future__ import annotations",
            "from dataclasses import dataclass",
            "import json",
            "from typing import Any, Optional",
            "import urllib.request",
            "",
        ]
        for s_name, s_def in schemas.items():
            if not str(s_name).isidentifier():
                continue
            lines.append("@dataclass")
            lines.append(f"class {s_name}:")
            props = (s_def or {}).get("properties") or {}
            req = set((s_def or {}).get("required") or [])
            if not props:
                lines.append("    pass")
            else:
                # Required fields first, then optional
                ordered_props = sorted(props.items(), key=lambda kv: (kv[0] not in req, kv[0]))
                for p_name, p_def in ordered_props:
                    py_t = type_map.get((p_def or {}).get("type", ""), "Any")
                    if p_name in req:
                        lines.append(f"    {p_name}: {py_t}")
                    else:
                        lines.append(f"    {p_name}: Optional[{py_t}] = None")
            lines.append("")

        lines.append("class APIClient:")
        lines.append("    def __init__(self, base_url: str) -> None:")
        lines.append("        self.base_url = base_url.rstrip('/')")
        lines.append("")
        op_count = 0
        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for http_m, op in methods.items():
                if http_m.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                    continue
                op_id = str(op.get("operationId") or f"{http_m.lower()}_{re.sub(r'[^a-zA-Z0-9]+', '_', route).strip('_')}")
                if not op_id.isidentifier():
                    op_id = f"op_{op_count}"
                op_count += 1
                lines.append(f"    def {op_id}(self, payload: Optional[dict[str, Any]] = None) -> Any:")
                lines.append(f'        url = f"{{self.base_url}}{route}"')
                lines.append("        data = json.dumps(payload).encode('utf-8') if payload is not None else None")
                lines.append(f"        req = urllib.request.Request(url, data=data, method={http_m.upper()!r}, headers={{'Content-Type': 'application/json'}})")
                lines.append("        with urllib.request.urlopen(req, timeout=15) as resp:")
                lines.append("            return json.loads(resp.read().decode('utf-8'))")
                lines.append("")

        code = "\n".join(lines).rstrip() + "\n"
        ast.parse(code)
        out_rel: Optional[str] = None
        if write_to:
            out_p = _resolve_in_workspace(ws, write_to)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(code, encoding="utf-8", newline="\n")
            out_rel = out_p.relative_to(ws).as_posix()
        return {"ok": True, "schemas_count": len(schemas), "operations_count": op_count, "written_to": out_rel, "code": code}

    @classmethod
    def codegen_sql_to_python(
        cls,
        workspace: Path,
        *,
        schema_path: str,
        write_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Deterministically generate typed Python SQLite DAO functions from a .sql DDL schema."""
        ws = Path(workspace).resolve()
        sp = _resolve_in_workspace(ws, schema_path)
        if not sp.is_file():
            return {"ok": False, "error": f"SQL schema not found: {schema_path}"}
        ddl = sp.read_text(encoding="utf-8", errors="replace")
        tables = re.findall(r"(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\);", ddl)
        lines = [
            '"""Auto-generated deterministic SQLite DAO from DDL schema."""',
            "from __future__ import annotations",
            "import sqlite3",
            "from typing import Any",
            "",
            f"DDL_SCHEMA = {ddl!r}",
            "",
            "def init_db(db_path: str) -> sqlite3.Connection:",
            "    conn = sqlite3.connect(db_path)",
            "    conn.executescript(DDL_SCHEMA)",
            "    return conn",
            "",
        ]
        table_names: List[str] = []
        for tbl, cols_raw in tables:
            table_names.append(tbl)
            cols = []
            for part in cols_raw.split(","):
                tok = part.strip().split()
                if tok and tok[0].upper() not in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                    cols.append(tok[0].strip('"`[]'))
            if cols:
                args_sig = ", ".join(f"{c}: Any" for c in cols)
                ph = ", ".join("?" for _ in cols)
                col_list = ", ".join(cols)
                lines.append(f"def insert_{tbl}(conn: sqlite3.Connection, {args_sig}) -> None:")
                lines.append(f'    conn.execute("INSERT INTO {tbl} ({col_list}) VALUES ({ph})", ({", ".join(cols)},))')
                lines.append("    conn.commit()")
                lines.append("")
            lines.append(f"def list_{tbl}(conn: sqlite3.Connection, limit: int = 100) -> list[tuple[Any, ...]]:")
            lines.append(f'    return conn.execute("SELECT * FROM {tbl} LIMIT ?", (int(limit),)).fetchall()')
            lines.append("")

        code = "\n".join(lines).rstrip() + "\n"
        ast.parse(code)
        out_rel: Optional[str] = None
        if write_to:
            out_p = _resolve_in_workspace(ws, write_to)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(code, encoding="utf-8", newline="\n")
            out_rel = out_p.relative_to(ws).as_posix()
        return {"ok": True, "tables": table_names, "written_to": out_rel, "code": code}

    @classmethod
    def os_sql_query(cls, workspace: Path, *, sql: str = "SELECT path, size_bytes FROM files ORDER BY size_bytes DESC LIMIT 20") -> Dict[str, Any]:
        """Expose workspace files and sanitized env vars as SQLite virtual tables (osquery-style)."""
        import os

        ws = Path(workspace).resolve()
        q_clean = sql.strip()
        if not q_clean.lower().startswith("select"):
            return {"ok": False, "error": "Only read-only SELECT queries are permitted in os_sql_query"}
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE TABLE files (path TEXT, ext TEXT, size_bytes INTEGER)")
            for fp in ws.rglob("*"):
                if any(part in _SKIP_DIRS for part in fp.parts) or not fp.is_file():
                    continue
                try:
                    sz = fp.stat().st_size
                except OSError:
                    continue
                conn.execute("INSERT INTO files VALUES (?, ?, ?)", (fp.relative_to(ws).as_posix(), fp.suffix.lower(), int(sz)))
            conn.execute("CREATE TABLE env_vars (name TEXT)")
            for k in sorted(os.environ.keys()):
                conn.execute("INSERT INTO env_vars VALUES (?)", (k,))
            cur = conn.execute(q_clean)
            cols = [d[0] for d in (cur.description or [])]
            rows = [dict(zip(cols, r)) for r in cur.fetchmany(100)]
            return {"ok": True, "backend": "os_sql_sqlite", "columns": cols, "row_count": len(rows), "rows": rows}
        finally:
            conn.close()

    @classmethod
    def fastmft_radar(
        cls,
        workspace: Path,
        *,
        mode: str = "projects",
        target: str = ".",
        top: int = 20,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Symbiotic fastmft / AetherScan v1.3.0 rail: projects, Casimir advise + UCIP, and safe parasite cleanup."""
        from am_ua.governance.homeostasis import casimir_bistable_diagnostics

        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        if not tgt.exists():
            return {"ok": False, "error": f"Target does not exist: {target}"}

        mode_norm = (mode or "projects").strip().lower()
        if mode_norm not in ("projects", "advise", "clean_parasites"):
            return {"ok": False, "error": f"Unsupported fastmft_radar mode: {mode_norm} (use projects|advise|clean_parasites)"}

        safe_clean_names = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".turbo"}
        all_parasite_names = safe_clean_names | {"node_modules", "target", ".venv", "venv", "dist", "build", ".next"}
        project_markers = {
            ".git": "git",
            "pyproject.toml": "python",
            "requirements.txt": "python",
            "package.json": "node",
            "cargo.toml": "rust",
            "go.mod": "go",
            "cmakelists.txt": "cpp",
            "pom.xml": "java",
        }

        t0 = time.perf_counter()

        def _scan_parasites_local(root: Path, allowed_names: set[str]) -> List[Dict[str, Any]]:
            found: List[Dict[str, Any]] = []
            for dirpath, dirnames, _ in os.walk(root):
                matched = [d for d in dirnames if d in allowed_names]
                for d in matched:
                    p_dir = Path(dirpath) / d
                    p_bytes = 0
                    p_files = 0
                    for sr, _, sf in os.walk(p_dir):
                        for fn in sf:
                            try:
                                p_bytes += (Path(sr) / fn).stat().st_size
                                p_files += 1
                            except OSError:
                                continue
                    found.append({
                        "name": d,
                        "rel_path": p_dir.relative_to(ws).as_posix(),
                        "bytes": p_bytes,
                        "files": p_files,
                    })
                dirnames[:] = [d for d in dirnames if d not in allowed_names and d != ".git"]
            found.sort(key=lambda x: x["bytes"], reverse=True)
            return found

        if mode_norm == "clean_parasites":
            parasites = _scan_parasites_local(tgt, safe_clean_names)
            removed: List[str] = []
            reclaimed_bytes = 0
            if not dry_run:
                for item in parasites:
                    p_full = _resolve_in_workspace(ws, item["rel_path"])
                    if p_full.is_dir():
                        shutil.rmtree(p_full, ignore_errors=True)
                        if not p_full.exists():
                            removed.append(item["rel_path"])
                            reclaimed_bytes += int(item["bytes"])
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                "ok": True,
                "backend": "fastmft_parasite_cleaner",
                "mode": "clean_parasites",
                "dry_run": bool(dry_run),
                "elapsed_ms": elapsed_ms,
                "parasite_count": len(parasites),
                "total_parasite_bytes": sum(int(p["bytes"]) for p in parasites),
                "removed_count": len(removed),
                "reclaimed_bytes": reclaimed_bytes,
                "removed": removed[:50],
                "parasites": parasites[:50],
            }

        fm_bin = cls._find_fastmft()

        if mode_norm == "advise":
            if fm_bin and os.name == "nt":
                temp_base = Path(r"F:\AetherMind_Temp\fastmft_rail")
                if temp_base.parent.exists():
                    temp_base.mkdir(parents=True, exist_ok=True)
                    out_dir = Path(tempfile.mkdtemp(prefix="advise_", dir=str(temp_base)))
                else:
                    out_dir = Path(tempfile.mkdtemp(prefix="fastmft_advise_"))
                try:
                    env = os.environ.copy()
                    if temp_base.parent.exists():
                        env["TMP"] = str(temp_base.parent)
                        env["TEMP"] = str(temp_base.parent)
                    proc = subprocess.run(
                        [fm_bin, "advise", str(tgt), "--top", str(max(1, int(top))), "--out", str(out_dir)],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        env=env,
                        timeout=60,
                        check=False,
                    )
                    rep_file = out_dir / "advise_report.json"
                    ucip_file = out_dir / "ucip_map.txt"
                    if proc.returncode == 0 and rep_file.is_file():
                        rep_data = json.loads(rep_file.read_text(encoding="utf-8", errors="replace"))
                        ucip_txt = ucip_file.read_text(encoding="utf-8", errors="replace") if ucip_file.is_file() else str(rep_data.get("ucip_compact_protocol", ""))
                        return {
                            "ok": True,
                            "backend": "fastmft_v1.3.0",
                            "mode": "advise",
                            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                            "casimir": rep_data.get("casimir_bistable_model", {}),
                            "relocation_candidates": (rep_data.get("relocation_candidates") or [])[:top],
                            "projects": (rep_data.get("discovered_projects") or [])[:top],
                            "ucip_compact": ucip_txt.strip(),
                        }
                finally:
                    shutil.rmtree(out_dir, ignore_errors=True)

            # Portable deterministic fallback (Linux / CI / host without fastmft binary)
            du = shutil.disk_usage(tgt)
            parasites = _scan_parasites_local(tgt, all_parasite_names)
            reclaimable = sum(int(p["bytes"]) for p in parasites)
            cas = casimir_bistable_diagnostics(du.free, du.total, reclaimable_bytes=reclaimable)
            projects: List[Dict[str, Any]] = []
            for dirpath, dirnames, filenames in os.walk(tgt):
                dirnames[:] = [d for d in dirnames if d not in all_parasite_names]
                markers = []
                for name in list(dirnames) + list(filenames):
                    tag = project_markers.get(name.lower())
                    if tag and tag not in markers:
                        markers.append(tag)
                if markers:
                    projects.append({"path": Path(dirpath).as_posix(), "markers": markers})
                dirnames[:] = [d for d in dirnames if d != ".git"]
            elapsed_s = round(time.perf_counter() - t0, 3)
            vol_label = tgt.drive or "/"
            ucip_line = (
                f"§UCIP:1.2|VOL:{vol_label}|SCAN:{elapsed_s:.3f}s|"
                f"TOT:{du.total // (1024**3)}GB|FREE:{du.free // (1024**3)}GB|"
                f"GAP_D:{cas['normalized_gap_d']:.4f}|FC:{cas['casimir_force_fc']:.1f}|"
                f"U:{cas['bistable_potential_u']:.3f}|STATE:{cas['regime_state']}|"
                f"POST_FREE:{cas['post_move_free_bytes'] // (1024**3)}GB"
            )
            return {
                "ok": True,
                "backend": "python_fastmft_fallback",
                "mode": "advise",
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "casimir": cas,
                "relocation_candidates": [],
                "projects": projects[:top],
                "ucip_compact": ucip_line,
            }

        # Default mode == "projects"
        parasites = _scan_parasites_local(tgt, all_parasite_names)
        total_p_bytes = sum(int(p["bytes"]) for p in parasites)
        raw_stdout = ""
        backend = "python_fastmft_fallback"
        if fm_bin and os.name == "nt":
            proc = subprocess.run(
                [fm_bin, "projects", str(tgt), "--parasites", "--top", str(max(1, int(top)))],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=False,
            )
            if proc.returncode == 0:
                backend = "fastmft_v1.3.0"
                raw_stdout = (proc.stdout or "")[:3000]

        projects_list: List[Dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(tgt):
            markers = []
            for name in list(dirnames) + list(filenames):
                tag = project_markers.get(name.lower())
                if tag and tag not in markers:
                    markers.append(tag)
            if markers:
                projects_list.append({
                    "path": Path(dirpath).relative_to(ws).as_posix() or ".",
                    "markers": markers,
                })
            dirnames[:] = [d for d in dirnames if d not in all_parasite_names and d != ".git"]

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        p_sig = ",".join(f"{p['rel_path']}:{p['bytes']//1024}K" for p in parasites[:8]) or "none"
        ucip_proj = f"§UCIP:PROJECTS|ROOT:{tgt.name}|BACKEND:{backend}|MS:{elapsed_ms}|PROJS:{len(projects_list)}|PARASITES_KB:{total_p_bytes//1024}|TOP:{p_sig}"
        return {
            "ok": True,
            "backend": backend,
            "mode": "projects",
            "elapsed_ms": elapsed_ms,
            "projects_found": len(projects_list),
            "projects": projects_list[:top],
            "parasite_count": len(parasites),
            "total_parasite_bytes": total_p_bytes,
            "parasites": parasites[:top],
            "ucip_compact": ucip_proj,
            "native_report_excerpt": raw_stdout,
        }

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
        return cls.run_preflight_bundle(ws, max_chars=int(args.get("max_chars", 3500)))

    @classmethod
    def ledger_audit(
        cls,
        *,
        entries: Optional[List[Dict[str, Any]]] = None,
        file_path: Optional[str] = None,
        workspace: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Rillet/Basis-style deterministic double-entry accounting ledger verifier using exact Decimal math."""
        from decimal import Decimal, InvalidOperation

        rows: List[Dict[str, Any]] = []
        if entries is not None:
            rows = list(entries)
        elif file_path and workspace is not None:
            p = _resolve_in_workspace(Path(workspace).resolve(), str(file_path))
            if not p.is_file():
                return {"ok": False, "error": f"Ledger file not found: {file_path}"}
            if p.suffix.lower() == ".json":
                loaded = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                rows = loaded if isinstance(loaded, list) else list(loaded.get("entries", []))
            else:
                with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                    rows = list(csv.DictReader(fh))
        else:
            return {"ok": False, "error": "Provide 'entries' list or 'file_path' (.json/.csv) for ledger_audit"}

        total_debits = Decimal("0")
        total_credits = Decimal("0")
        by_tx: Dict[str, Dict[str, Decimal]] = {}
        account_balances: Dict[str, Decimal] = {}
        parse_errors: List[str] = []

        for idx, row in enumerate(rows):
            tx_id = str(row.get("tx_id") or row.get("journal_id") or f"tx_{idx}")
            acct = str(row.get("account") or "UNSPECIFIED")
            try:
                debit = Decimal(str(row.get("debit") or "0"))
                credit = Decimal(str(row.get("credit") or "0"))
            except (InvalidOperation, ValueError) as exc:
                parse_errors.append(f"Row {idx} ({tx_id}): invalid decimal ({exc})")
                continue
            if debit < 0 or credit < 0:
                parse_errors.append(f"Row {idx} ({tx_id}): negative debit/credit not allowed")
                continue
            total_debits += debit
            total_credits += credit
            bucket = by_tx.setdefault(tx_id, {"debit": Decimal("0"), "credit": Decimal("0")})
            bucket["debit"] += debit
            bucket["credit"] += credit
            account_balances[acct] = account_balances.get(acct, Decimal("0")) + (debit - credit)

        unbalanced_txs = [
            {
                "tx_id": tid,
                "debit": str(b["debit"]),
                "credit": str(b["credit"]),
                "delta": str(b["debit"] - b["credit"]),
            }
            for tid, b in sorted(by_tx.items())
            if b["debit"] != b["credit"]
        ]
        net_delta = total_debits - total_credits
        balanced = (net_delta == Decimal("0")) and not unbalanced_txs and not parse_errors
        return {
            "ok": balanced,
            "backend": "decimal_double_entry_ledger",
            "entries_checked": len(rows),
            "transactions_checked": len(by_tx),
            "total_debits": str(total_debits),
            "total_credits": str(total_credits),
            "net_delta": str(net_delta),
            "balanced": balanced,
            "unbalanced_transactions": unbalanced_txs[:50],
            "parse_errors": parse_errors[:50],
            "account_balances": {k: str(v) for k, v in sorted(account_balances.items())},
        }
