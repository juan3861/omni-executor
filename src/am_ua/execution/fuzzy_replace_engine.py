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
            target_window = src_lines[l4_idx : l4_idx + wlen]
            w_indent = _common_indent(target_window)
            adj_r = _reindent_lines(r_lines, w_indent) if w_indent and not _common_indent(r_lines) else r_lines
            patched = _join_lines_preserving_nl(src_lines[:l4_idx] + adj_r + src_lines[l4_idx + wlen :], had_nl)
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


