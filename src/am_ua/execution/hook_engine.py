"""Deterministic Lifecycle Hook Engine (src/am_ua/execution/hook_engine.py).

Inspired by ECC Hooks and Ruflo Lifecycle Hooks; runs deterministically outside
the LLM prompt loop on PreToolUse and PostToolUse/PostEdit events.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class CommandRiskClass(IntEnum):
    """Fail-closed shell command classification ordered by blast radius."""

    READ = 1
    WRITE = 2
    NETWORK = 3
    INSTALL = 4
    DESTRUCTIVE = 5


_QUOTED_HEREDOC_RX = re.compile(
    r"<<-?\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1[^\r\n]*\r?\n.*?\r?\n\2(?:\r?\n|$)",
    re.DOTALL,
)
_PS_SINGLE_HERE_STRING_RX = re.compile(r"@'\r?\n.*?\r?\n'@", re.DOTALL)

_DESTRUCTIVE_RX = re.compile(
    r"(?i)(?:"
    r"\bformat(?:\.com)?\s+[a-z]:"
    r"|\bdiskpart\b"
    r"|\bshutdown\b"
    r"|\bRestart-Computer\b"
    r"|\bStop-Computer\b"
    r"|\bbcdedit\b"
    r"|\breg\s+delete\b"
    r"|\bcipher\s+/w\b"
    r"|\brm\s+-[^\s]*r[^\s]*f[^\s]*\s+/(\s|$)"
    r"|\brm\s+-[^\s]*f[^\s]*r[^\s]*\s+/(\s|$)"
    r"|\bgit\s+push\s+(?:--force|-f)\b"
    r"|\bInvoke-Expression\b"
    r"|\biex\s*\("
    r"|\biex\s+\$"
    r")"
)

_INSTALL_RX = re.compile(
    r"(?i)(?:^|\s)(?:"
    r"pip3?\s+install\b"
    r"|python(?:3)?\s+-m\s+pip\s+install\b"
    r"|uv\s+pip\s+install\b"
    r"|npm\s+(?:install|i|ci)\b"
    r"|pnpm\s+(?:add|install)\b"
    r"|yarn\s+add\b"
    r"|cargo\s+install\b"
    r"|winget\s+install\b"
    r"|choco\s+install\b"
    r"|apt(?:-get)?\s+install\b"
    r"|brew\s+install\b"
    r"|apk\s+add\b"
    r")"
)

_NETWORK_RX = re.compile(
    r"(?i)^(?:&\s*)?(?:"
    r"curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod|"
    r"ssh|scp|sftp|nc|netcat|telnet|ftp"
    r")\b|^(?:&\s*)?git\s+(?:clone|fetch|pull|push)\b"
)

_SHELL_INTERPRETER_RX = re.compile(
    r"(?i)^(?:&\s*)?(?:bash|sh|zsh|pwsh|powershell(?:\.exe)?|cmd(?:\.exe)?|iex|Invoke-Expression)\b"
)

_READONLY_CMDS = frozenset({
    "dir", "ls", "cat", "head", "tail", "echo", "pwd", "whoami", "which", "where",
    "grep", "rg", "findstr", "sort", "uniq", "wc", "tree", "stat", "file", "diff",
    "get-content", "get-childitem", "select-string", "test-path", "get-location",
    "get-item", "measure-object", "select-object", "format-table", "write-output",
    "pytest", "ruff", "mypy",
})

_READONLY_COMPOUND_RX = re.compile(
    r"(?i)^(?:&\s*)?(?:"
    r"git\s+(?:status|diff|log|show|branch|rev-parse|describe|ls-files)\b"
    r"|python(?:3)?(?:\.exe)?\s+(?:--version|-V|-m\s+pytest\b)"
    r"|node(?:\.exe)?\s+(?:--version|-v)\b"
    r")"
)


def _strip_quoted_heredocs(command: str) -> str:
    """Remove quoted heredoc/here-string literal bodies while keeping unquoted ones scannable."""
    cleaned = _QUOTED_HEREDOC_RX.sub(" <<'HEREDOC' ", command or "")
    cleaned = _PS_SINGLE_HERE_STRING_RX.sub(" @'HERESTRING'@ ", cleaned)
    return cleaned


def _split_shell_segments(command: str) -> List[str]:
    """Split shell command across pipes and chain operators while respecting quotes."""
    segments: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if quote is not None:
            buf.append(ch)
            if ch == quote and (quote == "'" or (i == 0 or command[i - 1] != "\\")):
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "|" or ch == ";":
            seg = "".join(buf).strip()
            if seg:
                segments.append(seg)
            buf.clear()
            if ch == "|" and i + 1 < n and command[i + 1] == "|":
                i += 2
            else:
                i += 1
            continue
        if ch == "&" and i + 1 < n and command[i + 1] == "&":
            seg = "".join(buf).strip()
            if seg:
                segments.append(seg)
            buf.clear()
            i += 2
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)
    return segments


def _has_unquoted_file_redirect(segment: str) -> bool:
    """Detect mutating file redirection (`>` or `>>`) outside quotes (ignoring `2>&1` / null sinks)."""
    quote: Optional[str] = None
    i = 0
    n = len(segment)
    while i < n:
        ch = segment[i]
        if quote is not None:
            if ch == quote and (quote == "'" or (i == 0 or segment[i - 1] != "\\")):
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == ">":
            tail = segment[i + 1 :].lstrip(">").strip().lower()
            if tail.startswith("&1") or tail.startswith("/dev/null") or tail.startswith("$null"):
                i += 1
                continue
            return True
        i += 1
    return False


def _classify_segment(segment: str) -> Tuple[CommandRiskClass, bool, str]:
    """Classify a single pipeline segment into CommandRiskClass (fail-closed to WRITE)."""
    s = segment.strip()
    if not s:
        return CommandRiskClass.READ, False, "empty"
    if _DESTRUCTIVE_RX.search(s):
        return CommandRiskClass.DESTRUCTIVE, False, "destructive_sink"
    if _INSTALL_RX.search(s):
        return CommandRiskClass.INSTALL, False, "package_install"
    if _NETWORK_RX.search(s):
        return CommandRiskClass.NETWORK, False, "network_io"
    if not _has_unquoted_file_redirect(s):
        if _READONLY_COMPOUND_RX.match(s):
            return CommandRiskClass.READ, False, "allowlisted_readonly_compound"
        head = s.lstrip("& ").split(None, 1)[0].strip("\"'").lower() if s.lstrip("& ") else ""
        head_base = Path(head).stem.lower() if head else ""
        if head in _READONLY_CMDS or head_base in _READONLY_CMDS:
            return CommandRiskClass.READ, False, "allowlisted_readonly"
    return CommandRiskClass.WRITE, True, "fail_closed_default_write"


def classify_shell_command(command: str) -> Dict[str, Any]:
    """Pipe-aware fail-closed classifier returning highest CommandRiskClass across all segments."""
    sanitized = _strip_quoted_heredocs(command or "")
    segments = _split_shell_segments(sanitized)
    if not segments:
        return {
            "risk_class": CommandRiskClass.WRITE.name,
            "risk_level": int(CommandRiskClass.WRITE),
            "segments": [],
            "fail_closed_write": True,
        }

    seg_reports: List[Dict[str, Any]] = []
    max_cls = CommandRiskClass.READ
    any_fail_closed = False
    saw_network = False

    for seg in segments:
        cls, fail_closed, reason = _classify_segment(seg)
        if saw_network and _SHELL_INTERPRETER_RX.match(seg):
            cls = CommandRiskClass.DESTRUCTIVE
            fail_closed = False
            reason = "pipe_network_to_shell"
        if cls == CommandRiskClass.NETWORK:
            saw_network = True
        if cls > max_cls:
            max_cls = cls
        if fail_closed:
            any_fail_closed = True
        seg_reports.append({
            "segment": seg[:120],
            "risk_class": cls.name,
            "risk_level": int(cls),
            "reason": reason,
        })

    return {
        "risk_class": max_cls.name,
        "risk_level": int(max_cls),
        "segments": seg_reports,
        "fail_closed_write": any_fail_closed and max_cls == CommandRiskClass.WRITE,
    }


def evaluate_autonomy_gate(
    command: str,
    *,
    tier: str = "full",
    allowlist: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Evaluate ALLOW / PROMPT / BLOCK for a shell command under the configured autonomy tier."""
    norm_tier = (tier or "full").strip().lower()
    if norm_tier not in ("readonly", "supervised", "full"):
        raise ValueError(f"Unsupported autonomy tier: {tier!r}")

    classification = classify_shell_command(command)
    level = CommandRiskClass(classification["risk_level"])
    clean_cmd = (command or "").strip()
    is_allowlisted = bool(
        allowlist
        and any(clean_cmd == entry or clean_cmd.startswith(entry + " ") for entry in allowlist)
    )

    if level == CommandRiskClass.DESTRUCTIVE:
        decision = "BLOCK"
    elif norm_tier == "readonly":
        decision = "ALLOW" if level == CommandRiskClass.READ else "BLOCK"
    elif norm_tier == "supervised":
        decision = "ALLOW" if (level == CommandRiskClass.READ or is_allowlisted) else "PROMPT"
    else:  # full
        decision = "ALLOW" if (level <= CommandRiskClass.WRITE or is_allowlisted) else "PROMPT"

    return {
        "decision": decision,
        "tier": norm_tier,
        "allowlisted": is_allowlisted,
        "classification": classification,
    }


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


def pre_run_command_classifier(tool: str, args: Dict[str, Any], workspace: Path) -> HookDecision:
    """Classify shell commands fail-closed and block DESTRUCTIVE patterns before execution."""
    if tool != "run":
        return HookDecision(allowed=True)
    cmd = str(args.get("command", ""))
    report = classify_shell_command(cmd)
    notes = {"command_risk_class": report["risk_class"], "command_risk_level": report["risk_level"]}
    if report["risk_level"] >= int(CommandRiskClass.DESTRUCTIVE):
        return HookDecision(
            allowed=False,
            reason=f"PreRunCommandClassifier blocked DESTRUCTIVE command: {cmd[:120]}",
            annotations=notes,
        )
    return HookDecision(allowed=True, annotations=notes)


class DeterministicHookEngine:
    """Registry and runner for deterministic PreToolUse and PostToolUse hooks."""

    def __init__(self, *, enable_defaults: bool = True) -> None:
        self._pre_hooks: List[Tuple[str, PreHookFn]] = []
        self._post_hooks: List[Tuple[str, PostHookFn]] = []
        if enable_defaults:
            self.register_pre("pre_write_secret_guard", pre_write_secret_guard)
            self.register_pre("pre_run_command_classifier", pre_run_command_classifier)
            self.register_post("post_python_syntax_check", post_python_syntax_check)

    @staticmethod
    def classify_command(command: str) -> Dict[str, Any]:
        """Classify a shell command or pipeline across the 5 fail-closed risk classes."""
        return classify_shell_command(command)

    @staticmethod
    def evaluate_command_gate(
        command: str,
        *,
        tier: str = "full",
        allowlist: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Evaluate autonomy tier decision (ALLOW | PROMPT | BLOCK) for a shell command."""
        return evaluate_autonomy_gate(command, tier=tier, allowlist=allowlist)

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
