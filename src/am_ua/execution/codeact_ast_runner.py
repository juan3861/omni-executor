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
    _ALLOWED_NODE_TYPES, _CARET_LINE_RE, _DEFAULT_TOPOLOGY_DAG, _EXC_LINE_RE,
    _SAFE_BUILTIN_MAP, _SAFE_READ_METHODS, _SKIP_DIRS, _TRACEBACK_FRAME_RE,
    AiderFuzzySearchReplaceEngine, _atomic_write_bytes,
    _common_indent, _dedent_lines, _iter_python_files,
    _join_lines_preserving_nl, _leading_ws, _reindent_lines, _resolve_contained_path,
)

class CodeActASTSandbox:
    """Safe multi-step Python snippet interpreter enforced by a strict AST whitelist."""

    MAX_SEQ_REPEAT: int = 1_000_000

    def __init__(self, tools: Optional[Dict[str, Callable[..., Any]]] = None) -> None:
        """Initialize the sandbox with an optional map of callable tools."""
        self.tools: Dict[str, Callable[..., Any]] = dict(tools or {})

    def _validate_call_node(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            if node.func.id not in self.tools and node.func.id not in _SAFE_BUILTIN_MAP:
                return f"Non-whitelisted call: {node.func.id}"
            return None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr not in _SAFE_READ_METHODS or node.func.attr.startswith("__"):
                return f"Forbidden method call: {node.func.attr}"
            return None
        return f"Forbidden call target: {type(node.func).__name__}"

    @staticmethod
    def _validate_attr_node(node: ast.Attribute) -> Optional[str]:
        if node.attr.startswith("__"):
            return f"Forbidden dunder attribute: {node.attr}"
        if node.attr not in _SAFE_READ_METHODS:
            return f"Forbidden attribute access: {node.attr}"
        if not isinstance(node.ctx, ast.Load):
            return f"Attribute mutation is forbidden: {node.attr}"
        return None

    def _validate_ast(self, tree: ast.AST) -> Optional[str]:
        """Validate all AST nodes in `tree` against the strict whitelist before running."""
        for node in ast.walk(tree):
            if not isinstance(node, _ALLOWED_NODE_TYPES):
                return f"Forbidden AST node: {type(node).__name__}"
            if isinstance(node, ast.Name) and node.id.startswith("__"):
                return f"Forbidden dunder identifier: {node.id}"
            if isinstance(node, ast.keyword) and node.arg is None:
                return "Dictionary unpacking (**kwargs) is forbidden"
            if isinstance(node, ast.Attribute):
                err = self._validate_attr_node(node)
                if err:
                    return err
            if isinstance(node, ast.Call):
                err = self._validate_call_node(node)
                if err:
                    return err
        return None

    @staticmethod
    def _apply_bin_op(op: ast.operator, left: Any, right: Any) -> Any:
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            if (isinstance(left, (str, list, tuple)) and isinstance(right, int) and right > CodeActASTSandbox.MAX_SEQ_REPEAT) or (
                isinstance(right, (str, list, tuple)) and isinstance(left, int) and left > CodeActASTSandbox.MAX_SEQ_REPEAT
            ):
                raise ValueError("Sequence repetition limit exceeded")
            return left * right
        if isinstance(op, ast.Div):
            return left / right
        if isinstance(op, ast.FloorDiv):
            return left // right
        if isinstance(op, ast.Mod):
            return left % right
        raise ValueError(f"Unsupported binary operator: {type(op).__name__}")

    @staticmethod
    def _apply_cmp_op(op: ast.cmpop, left: Any, right: Any) -> bool:
        ops: Dict[type, Callable[[Any, Any], bool]] = {
            ast.Eq: lambda a, b: bool(a == b),
            ast.NotEq: lambda a, b: bool(a != b),
            ast.Lt: lambda a, b: bool(a < b),
            ast.LtE: lambda a, b: bool(a <= b),
            ast.Gt: lambda a, b: bool(a > b),
            ast.GtE: lambda a, b: bool(a >= b),
            ast.In: lambda a, b: bool(a in b),
            ast.NotIn: lambda a, b: bool(a not in b),
            ast.Is: lambda a, b: a is b,
            ast.IsNot: lambda a, b: a is not b,
        }
        fn = ops.get(type(op))
        if fn is None:
            raise ValueError(f"Unsupported comparison operator: {type(op).__name__}")
        return fn(left, right)

    def _interpret_slice(self, node: ast.AST, env: Dict[str, Any]) -> Any:
        if hasattr(ast, "Index") and isinstance(node, ast.Index):
            return self._interpret_expr(node.value, env)
        if isinstance(node, ast.Slice):
            lower = self._interpret_expr(node.lower, env) if node.lower is not None else None
            upper = self._interpret_expr(node.upper, env) if node.upper is not None else None
            step = self._interpret_expr(node.step, env) if node.step is not None else None
            return slice(lower, upper, step)
        return self._interpret_expr(node, env)

    def _interpret_call(self, node: ast.Call, env: Dict[str, Any]) -> Any:
        args = [self._interpret_expr(arg, env) for arg in node.args]
        kwargs = {kw.arg: self._interpret_expr(kw.value, env) for kw in node.keywords if kw.arg is not None}
        if isinstance(node.func, ast.Name):
            fn = self.tools.get(node.func.id) or _SAFE_BUILTIN_MAP.get(node.func.id)
            if fn is None:
                raise PermissionError(f"Call not permitted: {node.func.id}")
            return fn(*args, **kwargs)
        if isinstance(node.func, ast.Attribute):
            target = self._interpret_expr(node.func.value, env)
            method_name = node.func.attr
            if method_name not in _SAFE_READ_METHODS or method_name.startswith("__"):
                raise PermissionError(f"Method not permitted: {method_name}")
            if isinstance(target, (type, ModuleType)):
                raise PermissionError("Attribute call on type or module is forbidden")
            if not isinstance(target, (str, dict, Mapping)) and not callable(getattr(target, method_name, None)):
                raise PermissionError(f"Target does not support safe method: {method_name}")
            return getattr(target, method_name)(*args, **kwargs)
        raise PermissionError("Unsupported call target")

    def _interpret_bool_or_cmp(self, node: ast.AST, env: Dict[str, Any]) -> Any:
        if isinstance(node, ast.BoolOp):
            is_and = isinstance(node.op, ast.And)
            val: Any = True if is_and else False
            for item in node.values:
                val = self._interpret_expr(item, env)
                if (is_and and not val) or (not is_and and val):
                    return val
            return val
        if isinstance(node, ast.Compare):
            left = self._interpret_expr(node.left, env)
            for op, comp in zip(node.ops, node.comparators):
                right = self._interpret_expr(comp, env)
                if not self._apply_cmp_op(op, left, right):
                    return False
                left = right
            return True
        raise ValueError(f"Unsupported logical/comparison node: {type(node).__name__}")

    def _interpret_compound_expr(self, node: ast.AST, env: Dict[str, Any]) -> Any:
        if isinstance(node, ast.BinOp):
            return self._apply_bin_op(node.op, self._interpret_expr(node.left, env), self._interpret_expr(node.right, env))
        if isinstance(node, ast.UnaryOp):
            operand = self._interpret_expr(node.operand, env)
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            return (not operand) if isinstance(node.op, ast.Not) else (~operand)
        return self._interpret_bool_or_cmp(node, env)

    def _interpret_container_or_lookup(self, node: ast.AST, env: Dict[str, Any]) -> Any:
        if isinstance(node, ast.List):
            return [self._interpret_expr(el, env) for el in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._interpret_expr(el, env) for el in node.elts)
        if isinstance(node, ast.Dict):
            return {self._interpret_expr(k, env): self._interpret_expr(v, env) for k, v in zip(node.keys, node.values) if k is not None}
        if isinstance(node, ast.Subscript):
            return self._interpret_expr(node.value, env)[self._interpret_slice(node.slice, env)]
        if isinstance(node, ast.Attribute):
            if node.attr not in _SAFE_READ_METHODS or node.attr.startswith("__"):
                raise PermissionError(f"Forbidden attribute: {node.attr}")
            target = self._interpret_expr(node.value, env)
            if isinstance(target, (type, ModuleType)):
                raise PermissionError("Attribute access on type or module is forbidden")
            return getattr(target, node.attr)
        return self._interpret_compound_expr(node, env)

    def _interpret_expr(self, node: ast.AST, env: Dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self.tools:
                return self.tools[node.id]
            if node.id in _SAFE_BUILTIN_MAP:
                return _SAFE_BUILTIN_MAP[node.id]
            raise NameError(f"Name '{node.id}' is not defined")
        if isinstance(node, ast.Call):
            return self._interpret_call(node, env)
        return self._interpret_container_or_lookup(node, env)

    def _assign_target(self, target: ast.AST, value: Any, env: Dict[str, Any]) -> None:
        if isinstance(target, ast.Name):
            if target.id.startswith("__"):
                raise PermissionError(f"Forbidden assignment to dunder name: {target.id}")
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            seq = list(value)
            if len(seq) != len(target.elts):
                raise ValueError(f"Expected {len(target.elts)} values to unpack, got {len(seq)}")
            for sub_target, sub_val in zip(target.elts, seq):
                self._assign_target(sub_target, sub_val, env)
            return
        if isinstance(target, ast.Subscript):
            container = self._interpret_expr(target.value, env)
            container[self._interpret_slice(target.slice, env)] = value
            return
        raise PermissionError(f"Unsupported assignment target: {type(target).__name__}")

    def _interpret_stmt(self, stmt: ast.stmt, env: Dict[str, Any]) -> Any:
        if isinstance(stmt, ast.Expr):
            return self._interpret_expr(stmt.value, env)
        if isinstance(stmt, ast.Assign):
            val = self._interpret_expr(stmt.value, env)
            for tgt in stmt.targets:
                self._assign_target(tgt, val, env)
            return None
        if isinstance(stmt, ast.AugAssign):
            rhs = self._interpret_expr(stmt.value, env)
            if isinstance(stmt.target, ast.Name):
                if stmt.target.id not in env:
                    raise NameError(f"Name '{stmt.target.id}' is not defined")
                env[stmt.target.id] = self._apply_bin_op(stmt.op, env[stmt.target.id], rhs)
                return None
            if isinstance(stmt.target, ast.Subscript):
                container = self._interpret_expr(stmt.target.value, env)
                key = self._interpret_slice(stmt.target.slice, env)
                container[key] = self._apply_bin_op(stmt.op, container[key], rhs)
                return None
        raise PermissionError(f"Unsupported statement: {type(stmt).__name__}")

    def execute_script(
        self,
        script_code: str,
        initial_vars: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely interpret a multi-step Python snippet using AST walking only."""
        try:
            tree = ast.parse(script_code or "", mode="exec")
        except SyntaxError as exc:
            return {"ok": False, "error": f"SyntaxError at line {exc.lineno}: {exc.msg}"}

        violation = self._validate_ast(tree)
        if violation is not None:
            return {"ok": False, "error": f"AST policy violation: {violation}"}

        env: Dict[str, Any] = dict(initial_vars or {})
        last_result: Any = None
        steps_executed = 0

        try:
            for stmt in tree.body:
                last_result = self._interpret_stmt(stmt, env)
                steps_executed += 1
        except Exception as exc:
            return {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "variables": dict(env),
                "steps_executed": steps_executed,
            }

        return {
            "ok": True,
            "variables": dict(env),
            "last_result": last_result,
            "steps_executed": steps_executed,
        }


# ============================================================================
# 3. DIRTY WORKTREE SNAPSHOT GUARD
# ============================================================================


@dataclass(frozen=True)
class _SnapshotEntry:
    rel_path: str
    existed: bool
    sha256: Optional[str]
    content: Optional[bytes]


class DirtyWorktreeSnapshotGuard:
    """Pre-edit file snapshot guard with SHA-256 drift detection and atomic rollback."""

    def __init__(self) -> None:
        """Initialize an empty worktree snapshot guard."""
        self._workspace: Optional[Path] = None
        self._snapshots: Dict[str, _SnapshotEntry] = {}

    def capture(self, workspace: Path, rel_paths: Sequence[str]) -> Dict[str, Any]:
        """Capture pre-mutation SHA-256 and original bytes (or None if absent) for `rel_paths`."""
        ws = Path(workspace).resolve()
        if self._workspace is not None and self._workspace != ws:
            self._snapshots.clear()
        self._workspace = ws

        newly_captured: List[str] = []
        already_tracked: List[str] = []
        for raw_rel in rel_paths:
            _, target, rel = _resolve_contained_path(ws, raw_rel)
            if rel in self._snapshots:
                already_tracked.append(rel)
                continue
            if target.exists():
                if not target.is_file():
                    raise IsADirectoryError(f"Snapshot target is not a file: {rel}")
                raw = target.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                self._snapshots[rel] = _SnapshotEntry(rel, True, digest, raw)
            else:
                self._snapshots[rel] = _SnapshotEntry(rel, False, None, None)
            newly_captured.append(rel)

        return {
            "ok": True,
            "workspace": str(ws),
            "captured": newly_captured,
            "already_tracked": already_tracked,
            "tracked_count": len(self._snapshots),
        }

    @staticmethod
    def _inspect_snapshot_entry(workspace: Path, snap: _SnapshotEntry) -> Tuple[Dict[str, Any], Optional[str]]:
        target = (workspace / snap.rel_path).resolve()
        exists_now = target.exists() and target.is_file()
        cur_sha = hashlib.sha256(target.read_bytes()).hexdigest() if exists_now else None
        change_kind: Optional[str] = None
        if not snap.existed and exists_now:
            change_kind = "created"
        elif snap.existed and not exists_now:
            change_kind = "deleted"
        elif snap.existed and exists_now and cur_sha != snap.sha256:
            change_kind = "modified"
        entry = {
            "existed": snap.existed,
            "exists_now": exists_now,
            "original_sha256": snap.sha256,
            "current_sha256": cur_sha,
            "dirty": change_kind is not None,
        }
        return entry, change_kind

    def status(self) -> Dict[str, Any]:
        """Report clean/dirty status and modified, created, or deleted paths."""
        if self._workspace is None:
            return {
                "ok": True,
                "workspace": None,
                "tracked_count": 0,
                "clean": True,
                "modified_paths": [],
                "created_paths": [],
                "deleted_paths": [],
                "entries": {},
            }

        modified_paths: List[str] = []
        created_paths: List[str] = []
        deleted_paths: List[str] = []
        entries: Dict[str, Dict[str, Any]] = {}

        for rel, snap in sorted(self._snapshots.items()):
            entry, change_kind = self._inspect_snapshot_entry(self._workspace, snap)
            entries[rel] = entry
            if change_kind == "created":
                created_paths.append(rel)
            elif change_kind == "deleted":
                deleted_paths.append(rel)
            if change_kind is not None:
                modified_paths.append(rel)

        return {
            "ok": True,
            "workspace": str(self._workspace),
            "tracked_count": len(self._snapshots),
            "clean": not modified_paths,
            "modified_paths": modified_paths,
            "created_paths": created_paths,
            "deleted_paths": deleted_paths,
            "entries": entries,
        }

    def rollback_all(self) -> Dict[str, Any]:
        """Atomically restore all modified/deleted files and unlink newly created files."""
        if self._workspace is None:
            return {
                "ok": True,
                "restored_paths": [],
                "deleted_paths": [],
                "unchanged_paths": [],
                "rolled_back_count": 0,
            }

        restored_paths: List[str] = []
        deleted_paths: List[str] = []
        unchanged_paths: List[str] = []

        for rel, snap in sorted(self._snapshots.items()):
            target = (self._workspace / rel).resolve()
            if snap.existed:
                data = snap.content if snap.content is not None else b""
                if target.exists() and target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == snap.sha256:
                    unchanged_paths.append(rel)
                    continue
                _atomic_write_bytes(target, data)
                restored_paths.append(rel)
            elif target.exists() and target.is_file():
                target.unlink()
                deleted_paths.append(rel)
            else:
                unchanged_paths.append(rel)

        return {
            "ok": True,
            "restored_paths": restored_paths,
            "deleted_paths": deleted_paths,
            "unchanged_paths": unchanged_paths,
            "rolled_back_count": len(restored_paths) + len(deleted_paths),
        }


# ============================================================================
# 4. SENIOR ARCHITECT READINESS AUDITOR
# ============================================================================


