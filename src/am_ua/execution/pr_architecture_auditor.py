from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
import difflib
import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from am_ua.execution.fuzzy_replace_engine import (
    _CARET_LINE_RE, _DEFAULT_TOPOLOGY_DAG, _EXC_LINE_RE, _SKIP_DIRS,
    _TRACEBACK_FRAME_RE, AiderFuzzySearchReplaceEngine, _atomic_write_bytes,
    _common_indent, _dedent_lines, _iter_python_files,
    _join_lines_preserving_nl, _leading_ws, _reindent_lines, _resolve_contained_path,
)

def _compute_mccabe_complexity(func_node: ast.AST) -> int:
    """Compute McCabe cyclomatic complexity for one function, excluding nested defs."""
    complexity = 1
    branch_types = (
        ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith, ast.IfExp
    )
    stack: List[ast.AST] = list(ast.iter_child_nodes(func_node))
    while stack:
        child = stack.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, branch_types):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += max(0, len(child.values) - 1)
        elif isinstance(child, ast.comprehension):
            complexity += 1 + len(child.ifs)
        elif hasattr(ast, "Match") and isinstance(child, ast.Match):
            complexity += len(child.cases)
        stack.extend(ast.iter_child_nodes(child))
    return complexity


def _is_mutable_default(node: Optional[ast.expr]) -> bool:
    """Detect mutable default literals or list/dict/set constructors in function args."""
    if node is None:
        return False
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"list", "dict", "set"}


def _score_to_grade(score: float) -> str:
    """Map a numeric 0..100 score to an S/A/B/C readiness grade."""
    if score >= 95.0:
        return "S"
    if score >= 85.0:
        return "A"
    if score >= 70.0:
        return "B"
    return "C"


def _count_func_annotations(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Tuple[int, int]:
    """Count annotated vs total type-annotation slots for a function/method."""
    annotated = 0
    total = 0
    all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    for idx, arg in enumerate(all_args):
        if idx == 0 and arg.arg in ("self", "cls"):
            continue
        total += 1
        if arg.annotation is not None:
            annotated += 1
    for special in (node.args.vararg, node.args.kwarg):
        if special is not None:
            total += 1
            if special.annotation is not None:
                annotated += 1
    total += 1
    if node.returns is not None:
        annotated += 1
    return annotated, total


class SeniorArchitectReadinessAuditor:
    """Deterministic 5-metric senior-engineering auditor for Python files."""

    COMPLEXITY_CEILING: int = 15

    @classmethod
    def _audit_single_function(
        cls,
        rel_path: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        issues: List[Dict[str, Any]],
    ) -> Tuple[int, int, int, int, int, Optional[Dict[str, Any]], int]:
        ann, slots = _count_func_annotations(node)
        pub_doc = 0
        pub_total = 0
        if not node.name.startswith("_"):
            pub_total = 1
            if ast.get_docstring(node):
                pub_doc = 1
            else:
                issues.append({"file": rel_path, "line": node.lineno, "metric": "docstring", "detail": f"Missing docstring on {node.name}"})

        cc = _compute_mccabe_complexity(node)
        cc_ok = 1 if cc <= cls.COMPLEXITY_CEILING else 0
        cc_viol: Optional[Dict[str, Any]] = None
        if not cc_ok:
            cc_viol = {"file": rel_path, "func": node.name, "line": node.lineno, "complexity": cc}
            issues.append({"file": rel_path, "line": node.lineno, "metric": "complexity", "detail": f"{node.name} complexity {cc} > {cls.COMPLEXITY_CEILING}"})

        mut_defs = sum(1 for d in (list(node.args.defaults) + list(node.args.kw_defaults)) if _is_mutable_default(d))
        if mut_defs:
            issues.append({"file": rel_path, "line": node.lineno, "metric": "anti_pattern", "detail": f"Mutable default arg in {node.name}"})

        return ann, slots, pub_doc, pub_total, cc_ok, cc_viol, mut_defs

    @classmethod
    def _audit_ast_tree(
        cls, rel_path: str, tree: ast.Module, issues: List[Dict[str, Any]]
    ) -> Tuple[int, int, int, int, int, int, List[Dict[str, Any]], int, int]:
        ann = slots = cc_ok = cc_tot = bare = mut = 0
        pub_doc = 1 if ast.get_docstring(tree) else 0
        pub_tot = 1
        if not pub_doc:
            issues.append({"file": rel_path, "line": 1, "metric": "docstring", "detail": "Missing module docstring"})

        cc_viols: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                pub_tot += 1
                if ast.get_docstring(node):
                    pub_doc += 1
                else:
                    issues.append({"file": rel_path, "line": node.lineno, "metric": "docstring", "detail": f"Missing docstring on class {node.name}"})
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                res = cls._audit_single_function(rel_path, node, issues)
                ann += res[0]
                slots += res[1]
                pub_doc += res[2]
                pub_tot += res[3]
                cc_ok += res[4]
                cc_tot += 1
                if res[5] is not None:
                    cc_viols.append(res[5])
                mut += res[6]
            elif isinstance(node, ast.ExceptHandler) and node.type is None:
                bare += 1
                issues.append({"file": rel_path, "line": node.lineno, "metric": "anti_pattern", "detail": "Bare except clause"})

        return ann, slots, pub_doc, pub_tot, cc_ok, cc_tot, cc_viols, bare, mut

    @classmethod
    def audit_sources(cls, sources: Dict[str, str], *, target: str = ".") -> Dict[str, Any]:
        """Score an in-memory `{rel_path: source_text}` mapping across all 5 metrics."""
        if not sources:
            return {"ok": True, "target": target, "files_scanned": 0, "score": 0.0, "grade": "C", "breakdown": {}, "issues": []}

        valid_files = ann = slots = pub_doc = pub_tot = cc_ok = cc_tot = bare = mut = 0
        cc_viols: List[Dict[str, Any]] = []
        issues: List[Dict[str, Any]] = []

        for rel_path, text in sorted(sources.items()):
            try:
                tree = ast.parse(text)
            except SyntaxError as exc:
                issues.append({"file": rel_path, "line": exc.lineno or 0, "metric": "ast_validity", "detail": f"SyntaxError: {exc.msg}"})
                continue
            valid_files += 1
            st = cls._audit_ast_tree(rel_path, tree, issues)
            ann, slots = ann + st[0], slots + st[1]
            pub_doc, pub_tot = pub_doc + st[2], pub_tot + st[3]
            cc_ok, cc_tot = cc_ok + st[4], cc_tot + st[5]
            cc_viols.extend(st[6])
            bare, mut = bare + st[7], mut + st[8]

        total_files = len(sources)
        ast_ratio = valid_files / total_files
        type_ratio = (ann / slots) if slots > 0 else 1.0
        doc_ratio = (pub_doc / pub_tot) if pub_tot > 0 else 1.0
        cc_ratio = (cc_ok / cc_tot) if cc_tot > 0 else 1.0
        anti_count = bare + mut

        s_ast, s_type, s_doc, s_cc = round(ast_ratio * 20.0, 2), round(type_ratio * 20.0, 2), round(doc_ratio * 20.0, 2), round(cc_ratio * 20.0, 2)
        s_hygiene = round(max(0.0, 20.0 - (5.0 * anti_count)), 2)
        total_score = round(min(100.0, s_ast + s_type + s_doc + s_cc + s_hygiene), 2)

        return {
            "ok": True,
            "target": target,
            "files_scanned": total_files,
            "score": total_score,
            "grade": _score_to_grade(total_score),
            "breakdown": {
                "ast_validity": {"score": s_ast, "max": 20.0, "valid_files": valid_files, "total_files": total_files, "ratio": round(ast_ratio, 4)},
                "type_annotations": {"score": s_type, "max": 20.0, "annotated": ann, "total_slots": slots, "ratio": round(type_ratio, 4)},
                "docstring_coverage": {"score": s_doc, "max": 20.0, "documented": pub_doc, "total_public": pub_tot, "ratio": round(doc_ratio, 4)},
                "cyclomatic_complexity": {"score": s_cc, "max": 20.0, "compliant": cc_ok, "total_functions": cc_tot, "violations_over_15": cc_viols, "ratio": round(cc_ratio, 4)},
                "zero_anti_patterns": {"score": s_hygiene, "max": 20.0, "bare_excepts": bare, "mutable_defaults": mut, "total_violations": anti_count},
            },
            "issues": issues,
        }

    @classmethod
    def audit(cls, workspace: Path, *, target: str = ".") -> Dict[str, Any]:
        """Audit Python files under `workspace/target` and return readiness score + breakdown."""
        ws, py_files = _iter_python_files(workspace, target)
        sources = {f.relative_to(ws).as_posix(): f.read_text(encoding="utf-8", errors="replace") for f in py_files}
        return cls.audit_sources(sources, target=target)


# ============================================================================
# 5. RAILS 130-135 DETERMINISTIC AST & CODE ANALYSIS HELPERS
# ============================================================================


def _module_name_from_rel(rel: str) -> str:
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else rel[:-3]


def _resolve_import_module(rel_parts: List[str], node: ast.AST) -> List[Tuple[str, int]]:
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.Import):
        return [(alias.name, line) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        mod = node.module or ""
        if node.level > 0:
            pkg_parts = rel_parts[:-1]
            base = pkg_parts[: max(0, len(pkg_parts) - (node.level - 1))]
            if mod:
                return [(".".join(base + mod.split(".")), line)]
            return [(".".join(base + [alias.name]), line) for alias in node.names]
        if mod:
            return [(mod, line)]
    return []


def _find_graph_cycles(graph: Dict[str, Set[str]]) -> List[List[str]]:
    state: Dict[str, int] = {}
    stack: List[str] = []
    cycles: List[List[str]] = []
    seen_sigs: Set[Tuple[str, ...]] = set()

    def _dfs(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for nxt in sorted(graph.get(node, set())):
            nxt_state = state.get(nxt, 0)
            if nxt_state == 0:
                _dfs(nxt)
            elif nxt_state == 1 and nxt in stack:
                cyc = stack[stack.index(nxt) :] + [nxt]
                sig = tuple(sorted(set(cyc)))
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    cycles.append(cyc)
        stack.pop()
        state[node] = 2

    for root in sorted(graph):
        if state.get(root, 0) == 0:
            _dfs(root)
    return cycles


def _record_import_edge(
    rel: str,
    src_mod: str,
    src_layer: Optional[str],
    imp_mod: str,
    line: int,
    dag: Dict[str, Set[str]],
    file_modules: Set[str],
    module_graph: Dict[str, Set[str]],
    layer_graph: Dict[str, Set[str]],
    violations: List[Dict[str, Any]],
) -> None:
    if imp_mod in file_modules and imp_mod != src_mod:
        module_graph[src_mod].add(imp_mod)
    elif ("src." + imp_mod) in file_modules and ("src." + imp_mod) != src_mod:
        module_graph[src_mod].add("src." + imp_mod)

    tgt_layer = next((p for p in imp_mod.split(".") if p in dag), None)
    if src_layer and tgt_layer and tgt_layer != src_layer:
        layer_graph[src_layer].add(tgt_layer)
        if tgt_layer not in dag[src_layer]:
            violations.append(
                {"file": rel, "line": line, "source_layer": src_layer, "forbidden_target": tgt_layer, "import": imp_mod}
            )


def _collect_file_imports(
    rel: str,
    tree: ast.Module,
    dag: Dict[str, Set[str]],
    file_modules: Set[str],
    module_graph: Dict[str, Set[str]],
    layer_graph: Dict[str, Set[str]],
    violations: List[Dict[str, Any]],
) -> None:
    rel_parts = rel.split("/")
    src_mod = _module_name_from_rel(rel)
    module_graph.setdefault(src_mod, set())
    src_layer = next((p for p in rel_parts[:-1] if p in dag), None)
    if src_layer:
        layer_graph.setdefault(src_layer, set())

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for imp_mod, line in _resolve_import_module(rel_parts, node):
                _record_import_edge(
                    rel, src_mod, src_layer, imp_mod, line, dag, file_modules, module_graph, layer_graph, violations
                )


def analyze_import_layers(
    workspace: Path,
    target: str = ".",
    *,
    layer_rules: Optional[Dict[str, Sequence[str]]] = None,
) -> Dict[str, Any]:
    """Build a module/layer dependency graph and flag layer DAG violations or cycles."""
    ws, py_files = _iter_python_files(workspace, target)
    dag = {k: set(v) for k, v in layer_rules.items()} if layer_rules is not None else _DEFAULT_TOPOLOGY_DAG

    module_graph: Dict[str, Set[str]] = {}
    layer_graph: Dict[str, Set[str]] = {}
    violations: List[Dict[str, Any]] = []
    parsed: List[Tuple[str, ast.Module]] = []
    file_modules: Set[str] = set()

    for py_file in py_files:
        rel = py_file.relative_to(ws).as_posix()
        file_modules.add(_module_name_from_rel(rel))
        try:
            parsed.append((rel, ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))))
        except SyntaxError:
            continue

    for rel, tree in parsed:
        _collect_file_imports(rel, tree, dag, file_modules, module_graph, layer_graph, violations)

    layer_cycles = _find_graph_cycles(layer_graph)
    module_cycles = _find_graph_cycles(module_graph)
    active_cycles = layer_cycles if layer_graph else module_cycles
    ok = len(violations) == 0 and len(active_cycles) == 0
    return {
        "ok": ok,
        "files_scanned": len(py_files),
        "layer_graph": {k: sorted(v) for k, v in sorted(layer_graph.items())},
        "module_graph": {k: sorted(v) for k, v in sorted(module_graph.items())},
        "violations": violations,
        "cycles": active_cycles,
        "module_cycles": module_cycles,
        "violation_count": len(violations),
        "cycle_count": len(active_cycles),
    }


def _safe_unparse(node: ast.AST, fallback: str) -> str:
    return ast.unparse(node) if hasattr(ast, "unparse") else fallback


def _classify_weak_assertion(node: ast.Assert, lines: List[str], fn_name: str) -> Optional[Dict[str, Any]]:
    test_expr = node.test
    src_line = lines[node.lineno - 1].strip() if 1 <= node.lineno <= len(lines) else ""
    pair: Optional[Tuple[str, str]] = None

    if isinstance(test_expr, ast.Constant):
        kind = "trivial_constant_assert" if bool(test_expr.value) else "constant_false_assert"
        pair = (kind, "Replace constant assertion with explicit equality check (e.g. `assert actual == expected`).")
    elif isinstance(test_expr, ast.Name):
        pair = ("bare_truthiness_assert", f"Replace `assert {test_expr.id}` with explicit identity/type/value check (e.g. `assert {test_expr.id} is True`).")
    elif isinstance(test_expr, ast.Attribute):
        expr_txt = _safe_unparse(test_expr, test_expr.attr)
        pair = ("attribute_truthiness_assert", f"Assert exact value instead of truthiness (e.g. `assert {expr_txt} is True`).")
    elif isinstance(test_expr, ast.UnaryOp) and isinstance(test_expr.op, ast.Not) and isinstance(test_expr.operand, (ast.Name, ast.Attribute)):
        inner = _safe_unparse(test_expr.operand, "value")
        pair = ("bare_negated_truthiness", f"Replace `assert not {inner}` with explicit check (`assert {inner} is False` or `is None`).")
    elif isinstance(test_expr, ast.Call) and isinstance(test_expr.func, ast.Name) and test_expr.func.id == "len":
        inner = _safe_unparse(test_expr, "len(items)")
        pair = ("bare_len_assert", f"Compare length explicitly (`assert {inner} > 0` or `assert {inner} == expected_len`).")

    if pair is None:
        return None
    return {"line": node.lineno, "function": fn_name, "kind": pair[0], "source": src_line, "suggestion": pair[1]}


def _collect_assertions_recursive(
    body: Sequence[ast.stmt], fn_name: str, lines: List[str], findings: List[Dict[str, Any]]
) -> int:
    total = 0
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            total += _collect_assertions_recursive(stmt.body, stmt.name, lines, findings)
            continue
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assert):
                total += 1
                finding = _classify_weak_assertion(node, lines, fn_name)
                if finding is not None:
                    findings.append(finding)
    return total


def strengthen_test_assertions(source_code: str) -> Dict[str, Any]:
    """Detect weak assertions (`assert True`, bare `assert x`) and suggest stronger checks."""
    try:
        tree = ast.parse(source_code or "")
    except SyntaxError as exc:
        return {"ok": False, "error": f"SyntaxError at line {exc.lineno}: {exc.msg}"}

    lines = (source_code or "").splitlines()
    findings: List[Dict[str, Any]] = []
    total_asserts = _collect_assertions_recursive(tree.body, "<module>", lines, findings)
    strong_count = total_asserts - len(findings)
    strength_score = round((strong_count / total_asserts) * 100.0, 2) if total_asserts > 0 else 100.0
    return {
        "ok": True,
        "total_asserts": total_asserts,
        "strong_count": strong_count,
        "weak_count": len(findings),
        "strength_score": strength_score,
        "findings": findings,
        "suggestions": [item["suggestion"] for item in findings],
    }


