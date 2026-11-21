"""Modular Workspace Filesystem, Fence Stripping & Safe Hunk Application (`am_ua.execution.workspace_fs`).

Extracted from `agent_loop.py` to keep filesystem mutation primitives modular, deterministic,
and independently testable.
"""

from __future__ import annotations

import ast
import difflib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def strip_code_fences(content: str) -> str:
    """Strip outer Markdown code fences if an LLM wrapped file contents in ```...```."""
    s = str(content).strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines) + "\n"
    return str(content)


def apply_hunks_safely(
    text: str,
    hunks: List[Tuple[str, str]],
    *,
    is_python: bool = False,
) -> Tuple[str, Optional[str]]:
    """Apply (old, new) replacement hunks with automatic double-escaped `\\n` healing for Python files."""
    working = text
    for idx, (old_s, new_s) in enumerate(hunks, 1):
        old = strip_code_fences(old_s) if (old_s not in working and old_s.strip().startswith("```")) else old_s
        new = strip_code_fences(new_s)
        unescaped = False
        if old not in working and "\\n" in old:
            cand_old = old.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
            if cand_old in working:
                old = cand_old
                unescaped = True
        count = working.count(old)
        if count != 1:
            raise ValueError(f"Hunk #{idx} 'old' must match exactly once, matched {count} times")
        if (unescaped or (is_python and "\n" not in old and "\\n" in new)) and "\\n" in new:
            cand_new = new.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
            if is_python:
                try:
                    ast.parse(working.replace(old, cand_new, 1))
                    new = cand_new
                except SyntaxError:
                    pass
            else:
                new = cand_new
        working = working.replace(old, new, 1)

    if is_python and "\\n" in working:
        try:
            ast.parse(working)
        except SyntaxError:
            healed = working.replace("\\r\\n", "\n").replace("\\n", "\n")
            try:
                ast.parse(healed)
                working = healed
            except SyntaxError:
                pass

    syntax_err: Optional[str] = None
    if is_python:
        try:
            ast.parse(working)
        except SyntaxError as exc:
            syntax_err = f"SyntaxError line {exc.lineno}: {exc.msg}"
    return working, syntax_err


def compute_unified_diff(
    before: Dict[str, Tuple[str, Optional[str]]],
    after: Dict[str, Tuple[str, Optional[str]]],
    changed: List[str],
) -> str:
    """Compute unified diff across changed workspace files."""
    chunks: List[str] = []
    for rel in changed[:40]:
        b_txt = (before.get(rel) or ("", ""))[1] or ""
        a_txt = (after.get(rel) or ("", ""))[1] or ""
        diff = difflib.unified_diff(
            b_txt.splitlines(keepends=True),
            a_txt.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
        chunks.append("".join(diff))
    return "\n".join(chunks)
