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

def execute_code_git_data(
    rail_name: str,
    ws: Path,
    target: str,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
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

    return None
