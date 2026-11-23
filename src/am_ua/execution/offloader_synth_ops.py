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

def off_extract_document_structured(cls, workspace: Path, *, file_path: str) -> Dict[str, Any]:
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

def off_polyglot_outline(cls, workspace: Path, *, file_path: str) -> Dict[str, Any]:
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

def off_libcst_safe_codemod(
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

def off_replace_function_body(
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

def off_parse_pytest_output(raw_output: str) -> Dict[str, Any]:
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

def off_pytest_failure_diagnoser(
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

def off__eval_constraint_ast(node: ast.AST, env: Dict[str, Any], *, z3_mod: Any = None) -> Any:
    """Pure AST evaluator for arithmetic/boolean constraint expressions (zero eval/exec)."""
    if isinstance(node, ast.Expression):
        return off__eval_constraint_ast(node.body, env, z3_mod=z3_mod)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise KeyError(f"Unknown variable '{node.id}' in constraint")
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        v = off__eval_constraint_ast(node.operand, env, z3_mod=z3_mod)
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return +v
        if isinstance(node.op, ast.Not):
            return z3_mod.Not(v) if z3_mod is not None else (not v)
    if isinstance(node, ast.BinOp):
        lhs = off__eval_constraint_ast(node.left, env, z3_mod=z3_mod)
        rhs = off__eval_constraint_ast(node.right, env, z3_mod=z3_mod)
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
        vals = [off__eval_constraint_ast(v, env, z3_mod=z3_mod) for v in node.values]
        if isinstance(node.op, ast.And):
            return z3_mod.And(*vals) if z3_mod is not None else all(vals)
        if isinstance(node.op, ast.Or):
            return z3_mod.Or(*vals) if z3_mod is not None else any(vals)
    if isinstance(node, ast.Compare):
        cur = off__eval_constraint_ast(node.left, env, z3_mod=z3_mod)
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
            nxt = off__eval_constraint_ast(comp, env, z3_mod=z3_mod)
            if type(op) not in cmp_map:
                raise ValueError(f"Unsupported comparison: {type(op).__name__}")
            checks.append(cmp_map[type(op)](cur, nxt))
            cur = nxt
        if z3_mod is not None:
            return checks[0] if len(checks) == 1 else z3_mod.And(*checks)
        return all(checks)
    raise ValueError(f"Unsupported AST node in constraint: {type(node).__name__}")

def off_z3_constraint_solve(
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

def off_hypothesis_property_test(
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

def off_codegen_from_openapi(
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

def off_codegen_sql_to_python(
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

def off_os_sql_query(cls, workspace: Path, *, sql: str = "SELECT path, size_bytes FROM files ORDER BY size_bytes DESC LIMIT 20") -> Dict[str, Any]:
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
