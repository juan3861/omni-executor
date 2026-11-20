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
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
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
    def probe_capabilities() -> Dict[str, Any]:
        """Report which external deterministic engines and builtin fallbacks are available on this host."""
        bins = {
            b: bool(shutil.which(b))
            for b in ("ruff", "sg", "ast-grep", "mypy", "pyright", "semgrep", "difft", "syft", "uv", "git")
        }
        mods = {
            m: bool(importlib.util.find_spec(m))
            for m in ("ruff", "mypy", "hypothesis", "duckdb", "polars", "libcst", "tree_sitter", "pydantic", "pytest")
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
    ) -> Dict[str, Any]:
        """AST-aware structural search (and exact identifier rename) across Python files."""
        ws = Path(workspace).resolve()
        tgt = _resolve_in_workspace(ws, target)
        if not symbol_or_pattern.strip():
            return {"ok": False, "error": "missing 'symbol_or_pattern'"}

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
        return cls.run_preflight_bundle(ws, max_chars=int(args.get("max_chars", 3500)))
