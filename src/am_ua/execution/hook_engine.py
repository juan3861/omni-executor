"""Deterministic Lifecycle Hook Engine (src/am_ua/execution/hook_engine.py).

Inspired by ECC Hooks and Ruflo Lifecycle Hooks; runs deterministically outside
the LLM prompt loop on PreToolUse and PostToolUse/PostEdit events.
"""

from __future__ import annotations

import ast
import builtins
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class HookDecision:
    allowed: bool = True
    reason: str = ""
    annotations: Dict[str, Any] = field(default_factory=dict)


PreHookFn = Callable[[str, Dict[str, Any], Path], HookDecision]
PostHookFn = Callable[[str, Dict[str, Any], Dict[str, Any], Path], Dict[str, Any]]

_SECRET_RX = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{25,})\b"
)


def pre_write_secret_guard(tool: str, args: Dict[str, Any], workspace: Path) -> HookDecision:
    """Block writing raw leaked API tokens into workspace files."""
    if tool not in ("write_file", "replace_in_file"):
        return HookDecision(allowed=True)
    text = str(args.get("content", "") or args.get("new", "") or args.get("new_str", ""))
    rel = str(args.get("path", "") or args.get("file", ""))
    # Allow explicit test files named test_*.py
    if Path(rel).name.lower().startswith("test_"):
        return HookDecision(allowed=True)
    m = _SECRET_RX.search(text)
    if m:
        return HookDecision(
            allowed=False,
            reason=f"PreWriteSecretGuard blocked hardcoded credential pattern ({m.group(0)[:8]}...) in {Path(rel).name}",
        )
    return HookDecision(allowed=True)


_BUILTINS: Set[str] = set(dir(builtins)) | {"__name__", "__file__", "__doc__", "__package__"}


def _find_undefined_names(tree: ast.AST) -> List[str]:
    """Fast LSP-lite AST check for obvious undefined global names in module scope."""
    defined: Set[str] = set(_BUILTINS)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    defined.add(a.arg)
                if node.args.vararg:
                    defined.add(node.args.vararg.arg)
                if node.args.kwarg:
                    defined.add(node.args.kwarg.arg)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                defined.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    defined.add(alias.asname or alias.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            defined.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
        elif isinstance(node, ast.Global):
            defined.update(node.names)

    undef: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in defined and node.id not in undef:
                undef.append(node.id)
    return undef[:15]


def post_python_syntax_check(tool: str, args: Dict[str, Any], obs: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    """Deterministically syntax- and scope-check Python files immediately after write/replace."""
    if tool not in ("write_file", "replace_in_file") or "error" in obs:
        return {}
    raw_path = str(args.get("path") or args.get("file") or "")
    if not raw_path.lower().endswith(".py"):
        return {}
    target = Path(raw_path)
    if not target.is_absolute():
        target = (workspace / target).resolve()
    if not target.is_file():
        return {}
    try:
        src = target.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=str(target))
        undef = _find_undefined_names(tree)
        out: Dict[str, Any] = {"python_syntax_ok": True}
        if undef:
            out["undefined_names_warning"] = undef
        return out
    except SyntaxError as exc:
        return {"python_syntax_ok": False, "python_syntax_error": f"Line {exc.lineno}: {exc.msg}"}


class DeterministicHookEngine:
    """Registry and runner for deterministic PreToolUse and PostToolUse hooks."""

    def __init__(self, *, enable_defaults: bool = True) -> None:
        self._pre_hooks: List[Tuple[str, PreHookFn]] = []
        self._post_hooks: List[Tuple[str, PostHookFn]] = []
        if enable_defaults:
            self.register_pre("pre_write_secret_guard", pre_write_secret_guard)
            self.register_post("post_python_syntax_check", post_python_syntax_check)

    def register_pre(self, name: str, fn: PreHookFn) -> None:
        self._pre_hooks.append((name, fn))

    def register_post(self, name: str, fn: PostHookFn) -> None:
        self._post_hooks.append((name, fn))

    def run_pre(self, tool: str, args: Dict[str, Any], workspace: Path) -> HookDecision:
        merged_notes: Dict[str, Any] = {}
        for name, fn in self._pre_hooks:
            dec = fn(tool, args, workspace)
            if dec.annotations:
                merged_notes[name] = dec.annotations
            if not dec.allowed:
                return HookDecision(allowed=False, reason=dec.reason or f"Blocked by hook '{name}'", annotations=merged_notes)
        return HookDecision(allowed=True, annotations=merged_notes)

    def run_post(self, tool: str, args: Dict[str, Any], obs: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
        annotations: Dict[str, Any] = {}
        for name, fn in self._post_hooks:
            try:
                res = fn(tool, args, obs, workspace)
                if res:
                    annotations[name] = res
            except Exception as exc:
                annotations[name] = {"hook_error": str(exc)[:200]}
        return annotations
