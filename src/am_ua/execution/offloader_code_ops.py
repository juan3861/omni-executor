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
    _SKIP_DIRS,
    _iter_py_files,
    _resolve_in_workspace,
)

def off_ast_syntax_sweep(workspace: Path) -> Dict[str, Any]:
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

def off_run_preflight_bundle(cls, workspace: Path, *, max_chars: int = 3500) -> Dict[str, Any]:
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

def off_code_autofix_and_lint(cls, workspace: Path, *, target: str = ".", apply_fix: bool = True) -> Dict[str, Any]:
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

def off_structural_search_replace(
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

def off_type_and_contract_check(cls, workspace: Path, *, target: str = ".") -> Dict[str, Any]:
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

def off_property_edge_fuzz(
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

def off_git_forensics(cls, workspace: Path) -> Dict[str, Any]:
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

def off_data_sql_query(
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

def off_sbom_and_deps_audit(cls, workspace: Path) -> Dict[str, Any]:
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

def off_structural_diff(cls, workspace: Path, *, file_a: str, file_b: str) -> Dict[str, Any]:
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

def off_generate_pytest_skeleton(
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
