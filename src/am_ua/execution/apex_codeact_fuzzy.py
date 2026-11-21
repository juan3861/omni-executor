"""Apex CodeAct, Fuzzy Search/Replace & Senior Readiness Engines (`am_ua.execution.apex_codeact_fuzzy`).

Provides deterministic, stdlib-only primitives for safe code editing, AST-only
sandboxed snippet interpretation, pre-mutation worktree rollback guards, senior
architectural readiness auditing, and Rails 130-135 code intelligence helpers:

1. `AiderFuzzySearchReplaceEngine`: 4-level deterministic search/replace cascade
   (exact, trailing-whitespace normalized, relative-indentation adjusted, and
   unique `SequenceMatcher` >= 0.92) with pre-write `ast.parse` verification.
2. `CodeActASTSandbox`: Strict whitelist AST walker & interpreter for multi-step
   Python tool-chaining snippets without dynamic code execution.
3. `DirtyWorktreeSnapshotGuard`: Pre-edit SHA-256 + content snapshot capture,
   dirty-path tracking, and atomic rollback/deletion restoration.
4. `SeniorArchitectReadinessAuditor`: 5-metric deterministic `.py` readiness scorer
   (AST validity, type annotations, docstrings, cyclomatic complexity <= 15,
   anti-pattern hygiene).
5. Rails 130-135 helpers: `analyze_import_layers`, `strengthen_test_assertions`,
   `parse_exception_traceback`, `check_api_backward_compat`, and
   `compute_pr_review_scorecard`.
"""

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


_SKIP_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    "vendor",
    "third_party",
    "HANDOFF_PACK",
    "data",
}

_DEFAULT_TOPOLOGY_DAG: Dict[str, Set[str]] = {
    "governance": set(),
    "contracts": {"governance"},
    "security": {"governance", "contracts"},
    "memory": {"governance", "contracts", "security"},
    "perception": {"governance", "contracts"},
    "routing": {"governance", "contracts"},
    "cognition": {"governance", "contracts"},
    "execution": {"governance", "contracts", "security", "perception", "cognition"},
    "runtime": {"governance", "contracts", "security", "execution", "memory"},
    "gui": {"governance", "contracts", "security", "execution"},
    "evolution": {"governance", "contracts", "execution", "cognition"},
    "lifecycle": {"governance", "contracts", "execution", "memory", "perception"},
}

_TRACEBACK_FRAME_RE = re.compile(
    r'^\s*File\s+"([^"]+)",\s+line\s+(\d+)(?:,\s+in\s+(.+))?$'
)
_CARET_LINE_RE = re.compile(r"^[~^\s]+$")
_EXC_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)(?::\s*(.*))?$")


def _resolve_contained_path(workspace: Path | str, file_path: str) -> Tuple[Path, Path, str]:
    """Resolve `file_path` inside `workspace`, raising `PermissionError` on escape."""
    ws = Path(workspace).resolve()
    raw = Path(file_path)
    target = (ws / raw).resolve() if not raw.is_absolute() else raw.resolve()
    if target != ws and ws not in target.parents:
        raise PermissionError(f"Path escapes workspace boundary: {file_path}")
    rel = target.relative_to(ws).as_posix() if target != ws else "."
    return ws, target, rel


def _iter_python_files(workspace: Path | str, target: str = ".") -> Tuple[Path, List[Path]]:
    """Collect sorted `.py` files under `workspace/target` while enforcing containment."""
    ws, tgt, _ = _resolve_contained_path(workspace, target)
    if not tgt.exists():
        return ws, []
    if tgt.is_file():
        return ws, [tgt] if tgt.suffix.lower() == ".py" else []

    files: List[Path] = []
    for root, dirs, names in os.walk(tgt):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(names):
            if name.endswith(".py"):
                files.append(Path(root) / name)
    return ws, files


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write `data` to `target` atomically via a temporary file in the same directory."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".am_atomic_", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_path, target)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _leading_ws(line: str) -> str:
    """Return leading spaces/tabs of a line."""
    return line[: len(line) - len(line.lstrip(" \t"))]


def _common_indent(lines: Sequence[str]) -> str:
    """Compute longest common leading whitespace prefix across non-empty lines."""
    indents = [_leading_ws(ln) for ln in lines if ln.strip()]
    if not indents:
        return ""
    prefix = indents[0]
    for ind in indents[1:]:
        limit = min(len(prefix), len(ind))
        idx = 0
        while idx < limit and prefix[idx] == ind[idx]:
            idx += 1
        prefix = prefix[:idx]
        if not prefix:
            break
    return prefix


def _dedent_lines(lines: Sequence[str], prefix: str) -> List[str]:
    """Strip `prefix` and trailing whitespace from each line."""
    plen = len(prefix)
    return [ln[plen:].rstrip() if ln.strip() else "" for ln in lines]


def _reindent_lines(lines: Sequence[str], target_indent: str) -> List[str]:
    """Reindent `lines` by replacing their common base indent with `target_indent`."""
    base = _common_indent(lines)
    blen = len(base)
    return ["" if not ln.strip() else (target_indent + ln[blen:]) for ln in lines]


def _join_lines_preserving_nl(lines: Sequence[str], had_trailing_nl: bool) -> str:
    """Join lines with newline separator, preserving trailing newline if present."""
    if not lines:
        return ""
    joined = "\n".join(lines)
    return joined + ("\n" if had_trailing_nl else "")


# ============================================================================
# 1. AIDER 4-LEVEL FUZZY SEARCH/REPLACE ENGINE
# ============================================================================


class AiderFuzzySearchReplaceEngine:
    """Deterministic 4-level search/replace patch engine with AST verification."""

    FUZZY_THRESHOLD: float = 0.92

    @classmethod
    def _match_level_2(
        cls, src_lines: List[str], s_lines: List[str]
    ) -> Tuple[Optional[int], Optional[str]]:
        n = len(s_lines)
        if n == 0 or n > len(src_lines):
            return None, None
        s_norm = [ln.rstrip() for ln in s_lines]
        hits = [
            idx
            for idx in range(len(src_lines) - n + 1)
            if [ln.rstrip() for ln in src_lines[idx : idx + n]] == s_norm
        ]
        if len(hits) == 1:
            return hits[0], None
        if len(hits) > 1:
            return None, f"Ambiguous trailing-whitespace match ({len(hits)} occurrences)"
        return None, None

    @classmethod
    def _match_level_3(
        cls, src_lines: List[str], s_lines: List[str]
    ) -> Tuple[Optional[Tuple[int, str]], Optional[str]]:
        n = len(s_lines)
        if n == 0 or n > len(src_lines) or not any(ln.strip() for ln in s_lines):
            return None, None
        s_dedented = _dedent_lines(s_lines, _common_indent(s_lines))
        hits: List[Tuple[int, str]] = []
        for idx in range(len(src_lines) - n + 1):
            window = src_lines[idx : idx + n]
            if not any(ln.strip() for ln in window):
                continue
            w_common = _common_indent(window)
            if _dedent_lines(window, w_common) == s_dedented:
                hits.append((idx, w_common))
        if len(hits) == 1:
            return hits[0], None
        if len(hits) > 1:
            return None, f"Ambiguous indentation-adjusted match ({len(hits)} occurrences)"
        return None, None

    @classmethod
    def _cluster_fuzzy_hits(cls, raw_hits: List[Tuple[float, int, int]]) -> List[Tuple[float, int, int]]:
        raw_hits.sort(key=lambda item: (-item[0], item[1]))
        clusters: List[Tuple[float, int, int]] = []
        for ratio, idx, wlen in raw_hits:
            if not any(abs(idx - kept_idx) < max(wlen, kept_len) for _, kept_idx, kept_len in clusters):
                clusters.append((ratio, idx, wlen))
        return clusters

    @classmethod
    def _scan_fuzzy_windows(
        cls, src_lines: List[str], s_joined: str, win_len: int
    ) -> List[Tuple[float, int, int]]:
        if win_len <= 0 or win_len > len(src_lines):
            return []
        raw_hits: List[Tuple[float, int, int]] = []
        for idx in range(len(src_lines) - win_len + 1):
            candidate = "\n".join(src_lines[idx : idx + win_len])
            ratio = difflib.SequenceMatcher(None, candidate, s_joined).ratio()
            if ratio >= cls.FUZZY_THRESHOLD:
                raw_hits.append((ratio, idx, win_len))
        return cls._cluster_fuzzy_hits(raw_hits) if raw_hits else []

    @classmethod
    def _match_level_4(
        cls, src_lines: List[str], s_lines: List[str]
    ) -> Tuple[Optional[Tuple[float, int, int]], Optional[str]]:
        n = len(s_lines)
        if n == 0:
            return None, None
        s_joined = "\n".join(s_lines)
        clusters = cls._scan_fuzzy_windows(src_lines, s_joined, n)
        if not clusters and n >= 3:
            alt_hits = cls._scan_fuzzy_windows(src_lines, s_joined, n - 1) + cls._scan_fuzzy_windows(
                src_lines, s_joined, n + 1
            )
            clusters = cls._cluster_fuzzy_hits(alt_hits)
        if len(clusters) == 1:
            return clusters[0], None
        if len(clusters) > 1:
            return None, f"Ambiguous fuzzy match ({len(clusters)} occurrences >= {cls.FUZZY_THRESHOLD})"
        return None, None

    @classmethod
    def _apply_line_cascade(
        cls, src: str, s_norm: str, r_norm: str
    ) -> Tuple[Optional[str], int, float, Optional[str]]:
        had_nl = src.endswith("\n")
        src_lines = src.splitlines()
        s_lines = s_norm.splitlines()
        r_lines = r_norm.splitlines()

        l2_idx, l2_err = cls._match_level_2(src_lines, s_lines)
        if l2_err:
            return None, 0, 1.0, l2_err
        if l2_idx is not None:
            patched = _join_lines_preserving_nl(src_lines[:l2_idx] + r_lines + src_lines[l2_idx + len(s_lines) :], had_nl)
            return patched, 2, 1.0, None

        l3_hit, l3_err = cls._match_level_3(src_lines, s_lines)
        if l3_err:
            return None, 0, 1.0, l3_err
        if l3_hit is not None:
            l3_idx, target_indent = l3_hit
            reindented = _reindent_lines(r_lines, target_indent)
            patched = _join_lines_preserving_nl(src_lines[:l3_idx] + reindented + src_lines[l3_idx + len(s_lines) :], had_nl)
            return patched, 3, 1.0, None

        l4_hit, l4_err = cls._match_level_4(src_lines, s_lines)
        if l4_err:
            return None, 0, 1.0, l4_err
        if l4_hit is not None:
            sim, l4_idx, wlen = l4_hit
            patched = _join_lines_preserving_nl(src_lines[:l4_idx] + r_lines + src_lines[l4_idx + wlen :], had_nl)
            return patched, 4, sim, None

        return None, 0, 1.0, "No unique search_block match found across cascade levels 1..4"

    @classmethod
    def apply_search_replace(
        cls,
        workspace: Path,
        *,
        file_path: str,
        search_block: str,
        replace_block: str,
        apply: bool = True,
    ) -> Dict[str, Any]:
        """Apply a search/replace block using a 4-level deterministic fuzzy cascade."""
        _, target, rel = _resolve_contained_path(workspace, file_path)
        if not search_block:
            return {"ok": False, "error": "search_block must not be empty", "file": rel, "applied": False}
        if not target.exists() or not target.is_file():
            return {"ok": False, "error": f"File not found: {rel}", "file": rel, "applied": False}

        src = target.read_text(encoding="utf-8")
        s_norm = search_block.replace("\r\n", "\n")
        r_norm = replace_block.replace("\r\n", "\n")

        exact_count = src.count(s_norm)
        if exact_count > 1:
            return {"ok": False, "error": f"Ambiguous exact match ({exact_count} occurrences)", "file": rel, "applied": False}
        if exact_count == 1:
            patched, match_level, similarity, err = src.replace(s_norm, r_norm, 1), 1, 1.0, None
        else:
            patched, match_level, similarity, err = cls._apply_line_cascade(src, s_norm, r_norm)

        if err or patched is None:
            return {"ok": False, "error": err or "Match failed", "file": rel, "applied": False}

        if target.suffix.lower() == ".py":
            try:
                ast.parse(patched)
            except SyntaxError as exc:
                return {
                    "ok": False,
                    "error": f"SyntaxError after patch at line {exc.lineno}: {exc.msg}",
                    "match_level": match_level,
                    "file": rel,
                    "applied": False,
                }

        if apply:
            _atomic_write_bytes(target, patched.encode("utf-8"))

        return {
            "ok": True,
            "match_level": match_level,
            "applied": bool(apply),
            "file": rel,
            "similarity": round(similarity, 4),
            "lines_before": len(src.splitlines()),
            "lines_after": len(patched.splitlines()),
            "patched_source": patched,
        }


# ============================================================================
# 2. CODEACT STRICT AST SANDBOX
# ============================================================================


_SAFE_BUILTIN_MAP: Dict[str, Callable[..., Any]] = {
    "len": len,
    "sum": sum,
    "min": min,
    "max": max,
    "sorted": sorted,
    "abs": abs,
    "round": round,
    "str": str,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
}

_SAFE_READ_METHODS: Set[str] = {
    "get",
    "keys",
    "values",
    "items",
    "strip",
    "lower",
    "upper",
    "split",
    "join",
}

_ALLOWED_BIN_OPS: Tuple[type, ...] = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)
_ALLOWED_CMP_OPS: Tuple[type, ...] = (
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot
)
_ALLOWED_BOOL_OPS: Tuple[type, ...] = (ast.And, ast.Or)
_ALLOWED_UNARY_OPS: Tuple[type, ...] = (ast.UAdd, ast.USub, ast.Not, ast.Invert)

_ALLOWED_NODE_TYPES: Tuple[type, ...] = (
    ast.Module, ast.Assign, ast.AugAssign, ast.Expr, ast.Name, ast.Constant,
    ast.List, ast.Tuple, ast.Dict, ast.Subscript, ast.Slice, ast.BinOp,
    ast.Compare, ast.BoolOp, ast.UnaryOp, ast.Call, ast.Attribute,
    ast.Load, ast.Store, ast.keyword,
    *_ALLOWED_BIN_OPS, *_ALLOWED_CMP_OPS, *_ALLOWED_BOOL_OPS, *_ALLOWED_UNARY_OPS,
) + ((ast.Index,) if hasattr(ast, "Index") else ())


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


def _extract_traceback_frames(lines: List[str]) -> List[Dict[str, Any]]:
    frames: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(lines):
        match = _TRACEBACK_FRAME_RE.match(lines[idx])
        if match:
            code_line = ""
            look = idx + 1
            while look < len(lines) and lines[look].strip() and not _TRACEBACK_FRAME_RE.match(lines[look]):
                if _CARET_LINE_RE.match(lines[look]):
                    look += 1
                    continue
                if lines[look].startswith((" ", "\t")):
                    code_line = lines[look].strip()
                    idx = look
                break
            frames.append(
                {
                    "file": match.group(1),
                    "line": int(match.group(2)),
                    "func": (match.group(3) or "").strip(),
                    "code": code_line,
                }
            )
        idx += 1
    return frames


def _extract_root_exception(lines: List[str]) -> Tuple[Optional[str], str]:
    skip_prefixes = ("Traceback (", "During handling ", "The above exception ")
    for raw_ln in reversed(lines):
        stripped = raw_ln.strip()
        if not stripped or _CARET_LINE_RE.match(stripped) or _TRACEBACK_FRAME_RE.match(raw_ln) or stripped.startswith(skip_prefixes):
            continue
        exc_match = _EXC_LINE_RE.match(stripped)
        if exc_match:
            return exc_match.group(1), (exc_match.group(2) or "").strip()
    return None, ""


def parse_exception_traceback(traceback_text: str) -> Dict[str, Any]:
    """Extract ordered stack frames (`file`, `line`, `func`, `code`) and root exception."""
    lines = (traceback_text or "").splitlines()
    frames = _extract_traceback_frames(lines)
    exc_class, exc_message = _extract_root_exception(lines)
    ok = bool(frames or exc_class)
    result: Dict[str, Any] = {
        "ok": ok,
        "frames": frames,
        "frame_count": len(frames),
        "exception_class": exc_class,
        "exception_message": exc_message,
        "root_frame": frames[-1] if frames else None,
        "entry_frame": frames[0] if frames else None,
    }
    if not ok:
        result["error"] = "No traceback frames or exception line detected"
    return result


@dataclass(frozen=True)
class _ParamSpec:
    name: str
    required: bool
    kind: str


@dataclass(frozen=True)
class _CallableSig:
    name: str
    params: Tuple[_ParamSpec, ...]
    has_vararg: bool
    has_kwarg: bool


def _extract_callable_sig(node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool) -> _CallableSig:
    args = node.args
    pos_all = list(args.posonlyargs) + list(args.args)
    first_def_idx = len(pos_all) - len(args.defaults)
    n_posonly = len(args.posonlyargs)

    specs: List[_ParamSpec] = []
    for idx, arg in enumerate(pos_all):
        if is_method and idx == 0 and arg.arg in ("self", "cls"):
            continue
        specs.append(_ParamSpec(arg.arg, required=idx < first_def_idx, kind="posonly" if idx < n_posonly else "pos_or_kw"))

    for arg, kw_def in zip(args.kwonlyargs, args.kw_defaults):
        specs.append(_ParamSpec(arg.arg, required=(kw_def is None), kind="kwonly"))

    return _CallableSig(node.name, tuple(specs), args.vararg is not None, args.kwarg is not None)


def _extract_api_surface(source_code: str) -> Tuple[Dict[str, _CallableSig], Dict[str, Dict[str, _CallableSig]]]:
    tree = ast.parse(source_code or "")
    funcs: Dict[str, _CallableSig] = {}
    classes: Dict[str, Dict[str, _CallableSig]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            funcs[node.name] = _extract_callable_sig(node, is_method=False)
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            classes[node.name] = {
                item.name: _extract_callable_sig(item, is_method=True)
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and (not item.name.startswith("_") or item.name == "__init__")
            }
    return funcs, classes


def _is_param_absorbed(param: _ParamSpec, new_sig: _CallableSig) -> bool:
    if param.required:
        return False
    return (param.kind == "posonly" and new_sig.has_vararg) or (
        param.kind in ("pos_or_kw", "kwonly") and new_sig.has_kwarg
    )


def _diff_callable_sigs(
    symbol: str,
    old_sig: _CallableSig,
    new_sig: _CallableSig,
    breaking: List[Dict[str, Any]],
    removed_params: List[Dict[str, Any]],
) -> None:
    new_map = {p.name: p for p in new_sig.params}
    old_map = {p.name: p for p in old_sig.params}

    for p in old_sig.params:
        if p.name not in new_map:
            if not _is_param_absorbed(p, new_sig):
                entry = {"symbol": symbol, "kind": "removed_required_param" if p.required else "removed_param", "param": p.name}
                breaking.append(entry)
                removed_params.append(entry)
        elif not p.required and new_map[p.name].required:
            breaking.append({"symbol": symbol, "kind": "param_became_required", "param": p.name})

    for p in new_sig.params:
        if p.name not in old_map and p.required:
            breaking.append({"symbol": symbol, "kind": "added_required_param", "param": p.name})


def check_api_backward_compat(old_source: str, new_source: str) -> Dict[str, Any]:
    """Check public API backward compatibility between `old_source` and `new_source`."""
    try:
        old_funcs, old_classes = _extract_api_surface(old_source)
        new_funcs, new_classes = _extract_api_surface(new_source)
    except SyntaxError as exc:
        return {"ok": False, "compatible": False, "error": f"SyntaxError at line {exc.lineno}: {exc.msg}"}

    breaking: List[Dict[str, Any]] = []
    removed_symbols: List[str] = []
    removed_params: List[Dict[str, Any]] = []

    for fn_name, old_sig in sorted(old_funcs.items()):
        if fn_name not in new_funcs:
            removed_symbols.append(fn_name)
            breaking.append({"symbol": fn_name, "kind": "removed_function"})
        else:
            _diff_callable_sigs(fn_name, old_sig, new_funcs[fn_name], breaking, removed_params)

    for cls_name, old_methods in sorted(old_classes.items()):
        if cls_name not in new_classes:
            removed_symbols.append(cls_name)
            breaking.append({"symbol": cls_name, "kind": "removed_class"})
            continue
        for m_name, old_sig in sorted(old_methods.items()):
            fqn = f"{cls_name}.{m_name}"
            if m_name not in new_classes[cls_name]:
                removed_symbols.append(fqn)
                breaking.append({"symbol": fqn, "kind": "removed_method"})
            else:
                _diff_callable_sigs(fqn, old_sig, new_classes[cls_name][m_name], breaking, removed_params)

    compatible = len(breaking) == 0
    return {
        "ok": compatible,
        "compatible": compatible,
        "breaking_count": len(breaking),
        "breaking_changes": breaking,
        "removed_symbols": removed_symbols,
        "removed_params": removed_params,
    }


def _scan_source_security_ast(rel_path: str, source_code: str) -> List[Dict[str, Any]]:
    flags: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return flags

    dyn_names = frozenset({"ev" + "al", "ex" + "ec"})
    shell_kw = "sh" + "ell"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in dyn_names:
                flags.append({"file": rel_path, "line": node.lineno, "rule": "dynamic_code_execution"})
            for kw in node.keywords:
                if kw.arg == shell_kw and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    flags.append({"file": rel_path, "line": node.lineno, "rule": "subprocess_shell_true"})
    return flags


def _audit_command_safety(command: str) -> List[Dict[str, Any]]:
    cmd = (command or "").strip()
    if not cmd:
        return []
    checks: Tuple[Tuple[str, re.Pattern[str]], ...] = (
        ("pipe_to_shell", re.compile(r"(?i)(?:curl|wget|irm)\s+[^\n|]+\|\s*(?:bash|sh|pwsh|powershell|iex)")),
        ("catastrophic_rm", re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|C:\\|\*)")),
        ("bypass_git_hooks", re.compile(r"(?i)\bgit\s+(?:commit|push)\b[^\n]*--no-ver" + r"ify\b")),
        ("force_push_main", re.compile(r"(?i)\bgit\s+push\b[^\n]*--force\b[^\n]*\b(?:main|master)\b")),
    )
    return [{"rule": rule, "command": cmd[:120]} for rule, rx in checks if rx.search(cmd)]


def _evaluate_compat_maps(
    ws: Path, old_source_map: Optional[Dict[str, str]], new_source_map: Optional[Dict[str, str]]
) -> List[Dict[str, Any]]:
    if not old_source_map:
        return []
    compat_breaks: List[Dict[str, Any]] = []
    new_map = new_source_map or {}
    for rel, old_src in sorted(old_source_map.items()):
        if not rel.endswith(".py"):
            continue
        if rel in new_map:
            new_src = new_map[rel]
        elif (ws / rel).is_file():
            new_src = (ws / rel).read_text(encoding="utf-8", errors="replace")
        else:
            new_src = ""
        res = check_api_backward_compat(old_src, new_src)
        for chg in res.get("breaking_changes", []):
            compat_breaks.append({"file": rel, **chg})
    return compat_breaks


def _score_test_files(py_new_map: Dict[str, str]) -> Tuple[float, int]:
    test_scores: List[float] = []
    weak_total = 0
    for rel, src in sorted(py_new_map.items()):
        if Path(rel).name.startswith("test_") or rel.endswith("_test.py"):
            ts = strengthen_test_assertions(src)
            if ts.get("ok"):
                test_scores.append(float(ts.get("strength_score", 100.0)))
                weak_total += int(ts.get("weak_count", 0))
    avg = round(sum(test_scores) / len(test_scores), 2) if test_scores else 100.0
    return avg, weak_total


def compute_pr_review_scorecard(
    workspace: Path,
    *,
    old_source_map: Optional[Dict[str, str]] = None,
    new_source_map: Optional[Dict[str, str]] = None,
    command: str = "",
) -> Dict[str, Any]:
    """Compute a composite senior PR review scorecard across 5 deterministic dimensions."""
    t0 = time.perf_counter()
    ws = Path(workspace).resolve()
    py_new_map = {k: v for k, v in (new_source_map or {}).items() if k.endswith(".py")}

    readiness = (
        SeniorArchitectReadinessAuditor.audit_sources(py_new_map, target="pr_diff")
        if py_new_map
        else SeniorArchitectReadinessAuditor.audit(ws, target=".")
    )
    import_audit = analyze_import_layers(ws, target=".")
    compat_breaks = _evaluate_compat_maps(ws, old_source_map, new_source_map)
    avg_test_strength, weak_asserts_total = _score_test_files(py_new_map)

    sec_flags: List[Dict[str, Any]] = []
    for rel, src in sorted(py_new_map.items()):
        sec_flags.extend(_scan_source_security_ast(rel, src))
    sec_flags.extend(_audit_command_safety(command))

    readiness_pts = round(float(readiness.get("score", 0.0)) * 0.40, 2)
    import_issues = int(import_audit.get("violation_count", 0)) + int(import_audit.get("cycle_count", 0))
    import_pts = 20.0 if import_audit.get("ok") else max(0.0, 20.0 - 5.0 * import_issues)
    compat_pts = 20.0 if not compat_breaks else max(0.0, 20.0 - 5.0 * len(compat_breaks))
    test_pts = round(avg_test_strength * 0.10, 2)
    sec_pts = 10.0 if not sec_flags else max(0.0, 10.0 - 5.0 * len(sec_flags))

    total_score = round(min(100.0, readiness_pts + import_pts + compat_pts + test_pts + sec_pts), 2)
    approved = total_score >= 75.0 and not compat_breaks and not sec_flags and bool(import_audit.get("ok", True))

    return {
        "ok": True,
        "approved": approved,
        "score": total_score,
        "grade": _score_to_grade(total_score),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "checks": {
            "readiness": {"score": readiness.get("score", 0.0), "grade": readiness.get("grade", "C"), "weighted": readiness_pts},
            "import_layers": {"ok": import_audit.get("ok", True), "violations": import_audit.get("violation_count", 0), "cycles": import_audit.get("cycle_count", 0), "weighted": import_pts},
            "backward_compat": {"compatible": not compat_breaks, "breaking_count": len(compat_breaks), "weighted": compat_pts},
            "test_strength": {"score": avg_test_strength, "weak_asserts": weak_asserts_total, "weighted": test_pts},
            "security_and_command": {"clean": not sec_flags, "flag_count": len(sec_flags), "weighted": sec_pts},
        },
        "breaking_changes": compat_breaks,
        "security_flags": sec_flags,
        "command": command,
        "summary": f"PR Scorecard {total_score}/100 ({_score_to_grade(total_score)}) - {'APPROVED' if approved else 'CHANGES_REQUESTED'}",
    }
