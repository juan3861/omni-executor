from __future__ import annotations

import ast
import difflib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from am_ua.execution.fault_localization_core import (
    _CAMEL_CASE_RE, _COLON_FILE_LINE_RE, _DEF_CLASS_RE, _IDENT_RE,
    _PY_PATH_RE, _SEQUENCE_TYPE_HINTS, _SKIP_DIRS, _SNAKE_CASE_RE,
    _STOP_IDENTIFIERS, _TRACEBACK_FILE_LINE_RE, _TYPING_CONTAINER_NAMES,
    OchiaiSBFLFaultLocalizer, _extract_run_lines, _is_test_passed,
    _normalize_line_item, _split_location,
)

class AutoCodeRoverASTGuardSynthesizer:
    """AST-verified deterministic guard patch synthesizer (zero-div, safe .get, None guards)."""

    def synthesize_guards(
        self,
        source_code: str,
        *,
        target_line: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Parse `source_code` and synthesize AST-verified guard candidates for hazards."""
        raw = source_code or ""
        try:
            tree = ast.parse(raw)
        except SyntaxError as exc:
            return {
                "ok": False,
                "error": f"SyntaxError at line {exc.lineno}: {exc.msg}",
                "candidates_count": 0,
                "candidates": [],
            }

        if not raw.strip():
            return {"ok": True, "target_line": target_line, "candidates_count": 0, "candidates": []}

        lines = raw.splitlines(keepends=True)
        ctx: Dict[str, Any] = {
            "raw": raw,
            "lines": lines,
            "line_offsets": self._compute_line_offsets(lines),
            "nl": "\r\n" if "\r\n" in raw else "\n",
            "parent_map": self._build_parent_map(tree),
            "annotation_nodes": self._collect_annotation_nodes(tree),
        }
        ctx["imported"], ctx["classes"], ctx["funcs"] = self._collect_module_symbols(tree)
        ctx["type_hints"] = self._collect_type_annotations(tree, ctx["parent_map"])

        candidates: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[int, str, str]] = set()
        for node in ast.walk(tree):
            cand = self._inspect_ast_node(node, target_line=target_line, ctx=ctx)
            if cand is None:
                continue
            dedup = (cand["line"], cand["hazard_type"], cand["expression"])
            if dedup not in seen_keys:
                seen_keys.add(dedup)
                candidates.append(cand)

        candidates.sort(key=lambda c: (c["line"], c["hazard_type"], c["expression"]))
        for idx, cand in enumerate(candidates, start=1):
            cand["candidate_id"] = f"guard-{idx}"

        return {
            "ok": True,
            "target_line": target_line,
            "candidates_count": len(candidates),
            "candidates": candidates,
        }

    def _inspect_ast_node(
        self,
        node: ast.AST,
        *,
        target_line: Optional[int],
        ctx: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if node in ctx["annotation_nodes"]:
            return None
        lineno = getattr(node, "lineno", None)
        end_lineno = getattr(node, "end_lineno", lineno)
        if lineno is None:
            return None
        if target_line is not None and not (lineno <= target_line <= (end_lineno or lineno)):
            return None

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            return self._synthesize_div_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                nl=ctx["nl"],
                node=node,
                parent_map=ctx["parent_map"],
            )
        if isinstance(node, ast.Subscript):
            return self._synthesize_subscript_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                node=node,
                parent_map=ctx["parent_map"],
                scoped_type_hints=ctx["type_hints"],
            )
        if isinstance(node, ast.Attribute):
            return self._synthesize_attribute_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                nl=ctx["nl"],
                node=node,
                parent_map=ctx["parent_map"],
                imported_names=ctx["imported"],
                defined_classes=ctx["classes"],
                defined_funcs=ctx["funcs"],
            )
        return None

    @staticmethod
    def _compute_line_offsets(lines: List[str]) -> List[int]:
        offsets: List[int] = []
        pos = 0
        for ln in lines:
            offsets.append(pos)
            pos += len(ln)
        return offsets

    @staticmethod
    def _utf8_col_to_char(line_text: str, byte_col: int) -> int:
        raw_bytes = line_text.encode("utf-8")
        clamped = max(0, min(byte_col, len(raw_bytes)))
        return len(raw_bytes[:clamped].decode("utf-8", errors="replace"))

    def _node_char_span(
        self,
        lines: List[str],
        line_offsets: List[int],
        node: ast.AST,
    ) -> Optional[Tuple[int, int]]:
        lineno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        end_lineno = getattr(node, "end_lineno", None)
        end_col = getattr(node, "end_col_offset", None)
        if None in (lineno, col, end_lineno, end_col):
            return None
        if lineno < 1 or end_lineno > len(lines):
            return None
        s_char = line_offsets[lineno - 1] + self._utf8_col_to_char(lines[lineno - 1], col)
        e_char = line_offsets[end_lineno - 1] + self._utf8_col_to_char(lines[end_lineno - 1], end_col)
        if e_char < s_char:
            return None
        return s_char, e_char

    @staticmethod
    def _build_parent_map(tree: ast.AST) -> Dict[int, ast.AST]:
        parents: Dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        return parents

    @staticmethod
    def _collect_annotation_nodes(tree: ast.AST) -> Set[ast.AST]:
        ann_roots: List[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.annotation is not None:
                ann_roots.append(node.annotation)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
                ann_roots.append(node.returns)
            elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
                ann_roots.append(node.annotation)
        ann_nodes: Set[ast.AST] = set()
        for root in ann_roots:
            for sub in ast.walk(root):
                ann_nodes.add(sub)
        return ann_nodes

    @staticmethod
    def _collect_type_annotations(
        tree: ast.AST,
        parent_map: Dict[int, ast.AST],
    ) -> Dict[Tuple[int, str], str]:
        hints: Dict[Tuple[int, str], str] = {}

        def _scope_id(n: ast.AST) -> int:
            curr: Optional[ast.AST] = n
            while curr is not None:
                if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                    return id(curr)
                curr = parent_map.get(id(curr))
            return id(tree)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sid = id(node)
                all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
                if node.args.vararg is not None:
                    all_args.append(node.args.vararg)
                if node.args.kwarg is not None:
                    all_args.append(node.args.kwarg)
                for arg in all_args:
                    if arg.annotation is not None:
                        hints[(sid, arg.arg)] = ast.unparse(arg.annotation)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.annotation is not None:
                hints[(_scope_id(node), node.target.id)] = ast.unparse(node.annotation)
        return hints

    @staticmethod
    def _in_inline_expr_scope(node: ast.AST, parent_map: Dict[int, ast.AST]) -> bool:
        curr: Optional[ast.AST] = parent_map.get(id(node))
        while curr is not None:
            if isinstance(curr, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return True
            if isinstance(curr, (ast.stmt, ast.Module)):
                return False
            curr = parent_map.get(id(curr))
        return False

    @staticmethod
    def _collect_module_symbols(tree: ast.AST) -> Tuple[Set[str], Set[str], Set[str]]:
        imported: Set[str] = set()
        classes: Set[str] = set()
        funcs: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)
            elif isinstance(node, ast.ClassDef):
                classes.add(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.add(node.name)
        return imported, classes, funcs

    @staticmethod
    def _enclosing_stmt_and_func(
        node: ast.AST,
        parent_map: Dict[int, ast.AST],
    ) -> Tuple[Optional[ast.stmt], Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]]]:
        curr: Optional[ast.AST] = node
        enclosing_stmt: Optional[ast.stmt] = None
        enclosing_func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]] = None
        while curr is not None:
            if enclosing_stmt is None and isinstance(curr, ast.stmt):
                enclosing_stmt = curr
            if enclosing_func is None and isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                enclosing_func = curr
            curr = parent_map.get(id(curr))
        return enclosing_stmt, enclosing_func

    @staticmethod
    def _test_guards_expr(test_src: str, target_expr: str, mode: str) -> bool:
        if mode == "none":
            return f"{target_expr} is not None" in test_src or test_src == target_expr
        return f"{target_expr} != 0" in test_src or test_src == target_expr

    @classmethod
    def _has_existing_guard(
        cls,
        node: ast.AST,
        target_expr: str,
        parent_map: Dict[int, ast.AST],
        mode: str,
    ) -> bool:
        curr: Optional[ast.AST] = node
        while curr is not None:
            parent = parent_map.get(id(curr))
            if isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.And):
                for val in parent.values:
                    if val is curr:
                        break
                    if cls._test_guards_expr(ast.unparse(val), target_expr, mode):
                        return True
            elif isinstance(parent, (ast.IfExp, ast.If)):
                if cls._test_guards_expr(ast.unparse(parent.test), target_expr, mode):
                    return True
            curr = parent
        return False

    def _insert_statement_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        stmt: ast.stmt,
        guard_lines: List[str],
    ) -> Optional[Tuple[str, str]]:
        lineno = stmt.lineno
        if lineno < 1 or lineno > len(lines):
            return None
        line_text = lines[lineno - 1]
        char_col = self._utf8_col_to_char(line_text, stmt.col_offset)
        prefix = line_text[:char_col]

        if prefix.lstrip().startswith("elif "):
            return None

        if prefix.strip():
            # Handle single-line suite such as `if cond: return a / b`
            if prefix.rstrip().endswith(":"):
                outer_indent = line_text[: len(line_text) - len(line_text.lstrip(" \t"))]
                inner_indent = outer_indent + "    "
                body_tail = line_text[char_col:].lstrip()
                guard_block = "".join(f"{inner_indent}{gl}{nl}" for gl in guard_lines)
                replacement = f"{prefix.rstrip()}{nl}{guard_block}{inner_indent}{body_tail}"
                s_idx = line_offsets[lineno - 1]
                e_idx = s_idx + len(line_text)
                patched = raw[:s_idx] + replacement + raw[e_idx:]
                return patched, "\n".join(guard_lines)
            return None

        indent = prefix
        guard_block = "".join(f"{indent}{gl}{nl}" for gl in guard_lines)
        insert_pos = line_offsets[lineno - 1]
        patched = raw[:insert_pos] + guard_block + raw[insert_pos:]
        return patched, "\n".join(f"{indent}{gl}" for gl in guard_lines)

    @staticmethod
    def _verify_and_diff(raw: str, patched: str, filename: str = "source.py") -> Optional[str]:
        try:
            ast.parse(patched)
        except SyntaxError:
            return None
        return "".join(
            difflib.unified_diff(
                raw.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )

    @staticmethod
    def _default_guard_action(
        func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]],
        *,
        kind: str,
        expr: str,
    ) -> str:
        if func is None:
            msg = f"Invalid zero divisor: {expr}" if kind == "zero" else f"Unexpected None for: {expr}"
            return f'raise ValueError("{msg}")'
        if kind == "zero":
            if func.returns is not None:
                ret_txt = ast.unparse(func.returns)
                if "None" in ret_txt or "Optional" in ret_txt:
                    return "return None"
                if ret_txt == "int":
                    return "return 0"
                if ret_txt == "float":
                    return "return 0.0"
            return "return 0.0"
        return "return None"

    def _synthesize_div_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.BinOp,
        parent_map: Dict[int, ast.AST],
    ) -> Optional[Dict[str, Any]]:
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float, complex)):
            if node.right.value != 0:
                return None

        divisor_expr = ast.unparse(node.right)
        if self._has_existing_guard(node, divisor_expr, parent_map, "zero"):
            return None

        stmt, func = self._enclosing_stmt_and_func(node, parent_map)
        if stmt is None:
            return None

        patched: Optional[str] = None
        guard_code = ""

        # If inside a conditional header (e.g., `elif` / `while`) where statement insertion doesn't apply,
        # use an inline safe conditional expression fallback.
        is_elif = isinstance(stmt, ast.If) and lines[stmt.lineno - 1].lstrip().startswith("elif ")
        in_loop_test = isinstance(stmt, ast.While) and node in ast.walk(stmt.test)
        in_inline_scope = self._in_inline_expr_scope(node, parent_map)

        if not is_elif and not in_loop_test and not in_inline_scope:
            action = self._default_guard_action(func, kind="zero", expr=divisor_expr)
            res = self._insert_statement_guard(
                raw=raw,
                lines=lines,
                line_offsets=line_offsets,
                nl=nl,
                stmt=stmt,
                guard_lines=[f"if {divisor_expr} == 0:", f"    {action}"],
            )
            if res is not None:
                patched, guard_code = res

        if patched is None:
            span = self._node_char_span(lines, line_offsets, node)
            if span is None:
                return None
            orig_expr = raw[span[0] : span[1]]
            inline_guard = f"(0.0 if {divisor_expr} == 0 else {orig_expr})"
            patched = raw[: span[0]] + inline_guard + raw[span[1] :]
            guard_code = inline_guard

        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "zero_division",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": ast.unparse(node),
            "guard_description": f"Guard division against zero divisor `{divisor_expr}`.",
            "guard_code": guard_code,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    def _synthesize_subscript_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        node: ast.Subscript,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> Optional[Dict[str, Any]]:
        if self._is_skippable_subscript(node, parent_map, scoped_type_hints):
            return None

        full_span = self._node_char_span(lines, line_offsets, node)
        val_span = self._node_char_span(lines, line_offsets, node.value)
        slice_span = self._node_char_span(lines, line_offsets, node.slice)
        if full_span is None or val_span is None or slice_span is None:
            return None

        obj_src = raw[val_span[0] : val_span[1]]
        key_src = raw[slice_span[0] : slice_span[1]]
        parent = parent_map.get(id(node))
        is_chained_base = isinstance(parent, ast.Subscript) and parent.value is node
        safe_call = f"{obj_src}.get({key_src}, {{}})" if is_chained_base else f"{obj_src}.get({key_src})"

        patched = raw[: full_span[0]] + safe_call + raw[full_span[1] :]
        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "unsafe_subscript",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": raw[full_span[0] : full_span[1]],
            "guard_description": f"Replace direct indexing on `{obj_src}` with safe `.get(...)`.",
            "guard_code": safe_call,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    def _is_skippable_subscript(
        self,
        node: ast.Subscript,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> bool:
        if not isinstance(node.ctx, ast.Load):
            return True
        if isinstance(node.slice, (ast.Slice, ast.Tuple)):
            return True
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Constant)):
            return True
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int) and not isinstance(node.slice.value, bool):
            return True
        if isinstance(node.value, ast.Name):
            if node.value.id in _TYPING_CONTAINER_NAMES:
                return True
            hint = self._resolve_var_type_hint(node, node.value.id, parent_map, scoped_type_hints)
            if any(hint.startswith(seq_t) for seq_t in _SEQUENCE_TYPE_HINTS):
                return True
        return False

    def _resolve_var_type_hint(
        self,
        node: ast.AST,
        var_name: str,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> str:
        _, enclosing_func = self._enclosing_stmt_and_func(node, parent_map)
        if enclosing_func is not None:
            hint = scoped_type_hints.get((id(enclosing_func), var_name), "")
            if hint:
                return hint
        curr: Optional[ast.AST] = node
        while curr is not None and not isinstance(curr, ast.Module):
            curr = parent_map.get(id(curr))
        return scoped_type_hints.get((id(curr), var_name), "") if curr is not None else ""

    def _synthesize_attribute_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.Attribute,
        parent_map: Dict[int, ast.AST],
        imported_names: Set[str],
        defined_classes: Set[str],
        defined_funcs: Set[str],
    ) -> Optional[Dict[str, Any]]:
        if self._is_skippable_attr_target(node, imported_names, defined_classes, defined_funcs):
            return None

        stmt, func = self._enclosing_stmt_and_func(node, parent_map)
        if stmt is None:
            return None
        if func is None and isinstance(node.value, ast.Name) and node.value.id.isupper():
            return None
        if isinstance(stmt, ast.If) and lines[stmt.lineno - 1].lstrip().startswith("elif "):
            return None

        obj_expr = ast.unparse(node.value)
        if self._has_existing_guard(node, obj_expr, parent_map, "none"):
            return None

        patch_res = self._build_attr_guard_patch(
            raw=raw,
            lines=lines,
            line_offsets=line_offsets,
            nl=nl,
            node=node,
            stmt=stmt,
            func=func,
            obj_expr=obj_expr,
            parent_map=parent_map,
        )
        if patch_res is None:
            return None
        patched, guard_code = patch_res
        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "none_attribute",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": ast.unparse(node),
            "guard_description": f"Guard attribute `.{node.attr}` against `{obj_expr} is None`.",
            "guard_code": guard_code,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    @staticmethod
    def _is_skippable_attr_target(
        node: ast.Attribute,
        imported_names: Set[str],
        defined_classes: Set[str],
        defined_funcs: Set[str],
    ) -> bool:
        if isinstance(node.value, (ast.Constant, ast.List, ast.Dict, ast.Set, ast.Tuple, ast.JoinedStr, ast.Call)):
            return True
        if isinstance(node.value, ast.Name):
            base_name = node.value.id
            if base_name in {"self", "cls", "super"}:
                return True
            if base_name in imported_names or base_name in defined_classes or base_name in defined_funcs:
                return True
        return False

    def _build_attr_guard_patch(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.Attribute,
        stmt: ast.stmt,
        func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]],
        obj_expr: str,
        parent_map: Dict[int, ast.AST],
    ) -> Optional[Tuple[str, str]]:
        if self._in_inline_expr_scope(node, parent_map):
            if not isinstance(node.ctx, ast.Load):
                return None
            span = self._node_char_span(lines, line_offsets, node)
            if span is None:
                return None
            inline_guard = f"(None if {obj_expr} is None else {raw[span[0] : span[1]]})"
            return raw[: span[0]] + inline_guard + raw[span[1] :], inline_guard

        root_expr = self._root_obj_expr(node.value)
        is_chained = isinstance(node.value, ast.Attribute) and root_expr not in {"self", "cls", obj_expr}
        guard_cond = f"{root_expr} is None or {obj_expr} is None" if is_chained else f"{obj_expr} is None"
        action = self._default_guard_action(func, kind="none", expr=obj_expr)
        return self._insert_statement_guard(
            raw=raw,
            lines=lines,
            line_offsets=line_offsets,
            nl=nl,
            stmt=stmt,
            guard_lines=[f"if {guard_cond}:", f"    {action}"],
        )

    @staticmethod
    def _root_obj_expr(expr: ast.AST) -> str:
        curr = expr
        while isinstance(curr, ast.Attribute):
            curr = curr.value
        return ast.unparse(curr)


