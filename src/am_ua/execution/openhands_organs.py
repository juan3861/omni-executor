"""OpenHands v1 SDK Maximum Extraction Organs (`am_ua.execution.openhands_organs`).

Synthesizes and upgrades the 7 high-leverage architectural organs from
`OpenHands/OpenHands` and `OpenHands/software-agent-sdk` (v1) into deterministic,
zero-dependency Python primitives natively wired into OmniExecutor:

1. `OpenHandsStuckDetector` (5-Pattern Anti-Loop Detector: repeating action-obs,
   repeating action-error, monologue, alternating A-B-A-B ping-pong, context saturation)
2. `FIFOLock` & `ResourceLockManager` (Deadlock-free lexicographically-sorted
   multi-resource locking for concurrent tool execution)
3. `ShellSemanticPolicyRails` (Defense-in-Depth composed pipeline security analyzer:
   `fetch-to-exec`, `raw-disk-op`, `catastrophic-delete`, wrapper unwrapping)
4. `V4AMultiFilePatchEngine` & `UndoEditHistory` (Atomic multi-file `*** Begin Patch`
   / `*** Update File:` / `*** Add File:` / `*** Delete File:` with AST verification
   and per-file `undo_edit` stack)
5. `TrajectoryCritic` & `IterativeRefinementConfig` (`AgentFinishedCritic` +
   `EmptyPatchCritic` + verification scoring & follow-up refinement prompt generator)
6. `SecretRegistry` (Thread-safe JIT secret vault with `<secret-hidden:NAME>` output
   masking and on-demand environment injection)
7. `TriggerMicroagentRegistry`, `RollingCondenser` & `ToMIntentConsultant`
   (Keyword/Path/Task microagent triggers, head+tail rolling condensation summary,
   and Theory-of-Mind user intent & ambiguity modeling)
"""

from __future__ import annotations

import ast
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path
import re
import shlex
import threading
import time
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Sequence, Tuple


# ============================================================================
# 1. OPENHANDS 5-PATTERN STUCK DETECTOR
# ============================================================================


@dataclass(frozen=True)
class StuckDetectionThresholds:
    action_observation: int = 4
    action_error: int = 3
    monologue: int = 3
    alternating_cycles: int = 3  # 3 cycles = 6 alternating events (A, B, A, B, A, B)
    context_window_errors: int = 2
    max_events_to_scan: int = 20


@dataclass(frozen=True)
class StuckAnalysisResult:
    is_stuck: bool
    loop_type: Optional[str]
    repeat_count: int
    recovery_nudge: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": not self.is_stuck,
            "is_stuck": self.is_stuck,
            "loop_type": self.loop_type,
            "repeat_count": self.repeat_count,
            "recovery_nudge": self.recovery_nudge,
        }


class OpenHandsStuckDetector:
    """Detects all 5 OpenHands stuck patterns over an Action/Observation event log."""

    def __init__(self, thresholds: Optional[StuckDetectionThresholds] = None) -> None:
        self.thresholds = thresholds or StuckDetectionThresholds()

    @staticmethod
    def _event_sig(ev: Dict[str, Any]) -> str:
        tool = str(ev.get("tool") or ev.get("action") or ev.get("kind") or "")
        args = ev.get("args") or ev.get("params") or {}
        obs = str(ev.get("observation") or ev.get("output") or ev.get("content") or "")[:400]
        raw = json.dumps({"t": tool, "a": args, "o": obs}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _action_only_sig(ev: Dict[str, Any]) -> str:
        tool = str(ev.get("tool") or ev.get("action") or "")
        args = ev.get("args") or ev.get("params") or {}
        raw = json.dumps({"t": tool, "a": args}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def analyze(self, events: Sequence[Dict[str, Any]]) -> StuckAnalysisResult:
        window = list(events)[-self.thresholds.max_events_to_scan :]
        if not window:
            return StuckAnalysisResult(False, None, 0, "")

        # Pattern 5: Context Window Saturation Errors
        ctx_errs = sum(
            1
            for ev in window
            if "context_window" in str(ev.get("error_type", "")).lower()
            or "context length exceeded" in str(ev.get("error", "")).lower()
            or "maximum context length" in str(ev.get("observation", "")).lower()
        )
        if ctx_errs >= self.thresholds.context_window_errors:
            return StuckAnalysisResult(
                True,
                "context_window_error",
                ctx_errs,
                "Context window saturated; trigger RollingCondenser and switch to targeted line-range reads.",
            )

        # Pattern 3: Agent Monologue (consecutive thought/message events without tool action)
        trailing_monologue = 0
        for ev in reversed(window):
            kind = str(ev.get("kind") or ev.get("type") or "").lower()
            has_tool = bool(ev.get("tool") or ev.get("action"))
            if kind in ("thought", "message", "monologue") and not has_tool:
                trailing_monologue += 1
            else:
                break
        if trailing_monologue >= self.thresholds.monologue:
            return StuckAnalysisResult(
                True,
                "agent_monologue",
                trailing_monologue,
                "Agent emitted consecutive monologue turns without invoking a tool; execute a concrete verification or edit action now.",
            )

        # Pattern 2: Repeating Action-Error Cycles
        err_sigs: List[str] = []
        for ev in reversed(window):
            is_err = bool(ev.get("is_error") or ev.get("error") or int(ev.get("exit_code", 0) or 0) != 0)
            if is_err:
                err_sigs.append(self._action_only_sig(ev))
            else:
                break
        if len(err_sigs) >= self.thresholds.action_error and len(set(err_sigs[: self.thresholds.action_error])) == 1:
            return StuckAnalysisResult(
                True,
                "repeating_action_error",
                len(err_sigs),
                "Identical action failed repeatedly with error; inspect error details and change arguments or tool strategy.",
            )

        # Pattern 1: Repeating Action-Observation Cycles
        full_sigs = [self._event_sig(ev) for ev in window]
        n_ao = self.thresholds.action_observation
        if len(full_sigs) >= n_ao and len(set(full_sigs[-n_ao:])) == 1:
            return StuckAnalysisResult(
                True,
                "repeating_action_observation",
                n_ao,
                "Identical action-observation cycle repeated without state change; stop polling and proceed to edit or finish.",
            )

        # Pattern 4: Alternating Ping-Pong Pattern (A, B, A, B, A, B)
        need_alt = self.thresholds.alternating_cycles * 2
        if len(full_sigs) >= need_alt:
            tail = full_sigs[-need_alt:]
            even_set = set(tail[0::2])
            odd_set = set(tail[1::2])
            if len(even_set) == 1 and len(odd_set) == 1 and even_set != odd_set:
                return StuckAnalysisResult(
                    True,
                    "alternating_action_observation",
                    self.thresholds.alternating_cycles,
                    "Alternating A-B-A-B ping-pong loop detected; break the oscillation by synthesizing both observations.",
                )

        return StuckAnalysisResult(False, None, 0, "")


# ============================================================================
# 2. DEADLOCK-FREE RESOURCE LOCK MANAGER WITH FAIR FIFO LOCK
# ============================================================================


class ResourceLockTimeoutError(TimeoutError):
    """Raised when a resource lock cannot be acquired within timeout."""


class FIFOLock:
    """Fair FIFO re-entrant lock preventing thread starvation."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._owner: Optional[int] = None
        self._depth: int = 0
        self._waiters: deque[threading.Event] = deque()

    def acquire(self, timeout: float = 30.0) -> bool:
        tid = threading.get_ident()
        with self._guard:
            if self._owner == tid:
                self._depth += 1
                return True
            if self._owner is None and not self._waiters:
                self._owner = tid
                self._depth = 1
                return True
            ev = threading.Event()
            self._waiters.append(ev)

        ok = ev.wait(timeout=max(0.001, float(timeout)))
        with self._guard:
            if ok and self._owner == tid:
                return True
            if ev in self._waiters:
                self._waiters.remove(ev)
            return False

    def release(self) -> None:
        tid = threading.get_ident()
        with self._guard:
            if self._owner != tid:
                raise RuntimeError("Cannot release FIFOLock not owned by current thread")
            self._depth -= 1
            if self._depth > 0:
                return
            if self._waiters:
                nxt_ev = self._waiters.popleft()
                # Transfer ownership placeholder; waiter sets owner upon wake
                self._owner = None
                nxt_ev.set()
            else:
                self._owner = None


class ResourceLockManager:
    """Acquires per-resource FIFOLocks in sorted key order to prevent AB/BA deadlocks."""

    DEFAULT_TIMEOUTS: Dict[str, float] = {
        "file": 30.0,
        "terminal": 300.0,
        "browser": 300.0,
        "mcp": 300.0,
        "tool": 60.0,
    }

    def __init__(self, timeouts: Optional[Dict[str, float]] = None) -> None:
        self._meta = threading.Lock()
        self._locks: Dict[str, FIFOLock] = {}
        self._timeouts = dict(self.DEFAULT_TIMEOUTS)
        if timeouts:
            self._timeouts.update(timeouts)

    def _get_lock(self, key: str) -> Tuple[FIFOLock, float]:
        prefix = key.split(":", 1)[0] if ":" in key else "tool"
        t_out = self._timeouts.get(prefix, 30.0)
        with self._meta:
            lk = self._locks.get(key)
            if lk is None:
                lk = FIFOLock()
                self._locks[key] = lk
            return lk, t_out

    @contextmanager
    def lock(self, *keys: str, timeout: Optional[float] = None) -> Generator[List[str], None, None]:
        ordered = sorted({k.strip() for k in keys if k and k.strip()})
        acquired: List[FIFOLock] = []
        tid = threading.get_ident()
        try:
            for k in ordered:
                lk, def_to = self._get_lock(k)
                use_to = timeout if timeout is not None else def_to
                if not lk.acquire(timeout=use_to):
                    raise ResourceLockTimeoutError(f"Timed out acquiring lock for resource '{k}' after {use_to}s")
                with lk._guard:
                    if lk._owner is None:
                        lk._owner = tid
                        lk._depth = 1
                acquired.append(lk)
            yield ordered
        finally:
            for lk in reversed(acquired):
                lk.release()


# ============================================================================
# 3. DEFENSE-IN-DEPTH COMPOSED SHELL POLICY RAILS
# ============================================================================


class ShellSemanticPolicyRails:
    """OpenHands-style structural shell command security analyzer.

    Evaluates composed pipeline and segment threats before regex scanning:
    - `fetch-to-exec`: network download piped or passed directly to shell/interpreter
    - `raw-disk-op`: block device overwrite, partition format, or boot config mutation
    - `catastrophic-delete`: recursive force deletion of root, drive roots, or home
    """

    FETCHERS = frozenset({"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "fetch"})
    INTERPRETERS = frozenset({
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "pwsh",
        "powershell",
        "cmd",
        "python",
        "python3",
        "node",
        "perl",
        "ruby",
        "iex",
        "invoke-expression",
    })
    WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "nice", "stdbuf", "command", "builtin"})
    RAW_DISK_VERBS = frozenset({"mkfs", "fdisk", "sfdisk", "parted", "diskpart", "bcdedit", "format", "format.com"})
    CATASTROPHIC_TARGETS = frozenset({"/", "/*", "~", "~/", "$HOME", "${HOME}", "c:\\", "c:/", "c:", "f:\\", "f:/"})

    @classmethod
    def _unwrap_tokens(cls, tokens: List[str]) -> List[str]:
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            base = tok.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            if base in cls.WRAPPERS:
                idx += 1
                while idx < len(tokens) and (tokens[idx].startswith("-") or "=" in tokens[idx]):
                    idx += 1
                continue
            break
        return tokens[idx:]

    @classmethod
    def analyze_command(cls, command: str) -> Dict[str, Any]:
        cmd = (command or "").strip()
        if not cmd:
            return {"ok": True, "risk": "LOW", "matched_rail": None, "segments": [], "reason": "empty command"}

        # Split by pipeline and logical chaining while preserving structure
        raw_segments = [s.strip() for s in re.split(r"(\|\||&&|\||;|\n)", cmd) if s.strip()]
        segments: List[List[str]] = []
        operators: List[str] = []
        for item in raw_segments:
            if item in ("|", "||", "&&", ";", "\n"):
                operators.append(item)
            else:
                try:
                    toks = shlex.split(item, posix=True)
                except ValueError:
                    return {
                        "ok": False,
                        "risk": "UNKNOWN",
                        "matched_rail": "unparseable_shell_syntax",
                        "segments": [],
                        "reason": "Unbalanced quotes or malformed shell syntax",
                    }
                if toks:
                    segments.append(cls._unwrap_tokens(toks))

        # Check 1: fetch-to-exec across pipeline (`curl ... | sh` or `bash -c "$(curl ...)"`)
        has_fetcher = False
        has_interp_after_pipe = False
        for idx, seg in enumerate(segments):
            if not seg:
                continue
            verb = seg[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            joined_seg = " ".join(seg).lower()
            if verb in cls.FETCHERS or any(f in joined_seg for f in ("$(curl ", "$(wget ", "`curl ", "`wget ")):
                has_fetcher = True
            if verb in cls.INTERPRETERS and (idx > 0 or "$(" in joined_seg or "`" in joined_seg):
                if has_fetcher:
                    has_interp_after_pipe = True

        if has_fetcher and has_interp_after_pipe:
            return {
                "ok": False,
                "risk": "HIGH",
                "matched_rail": "fetch-to-exec",
                "segments": segments,
                "reason": "Remote content fetch piped or expanded directly into command interpreter",
            }

        # Check 2 & 3: per-segment raw-disk-op and catastrophic-delete (including nested `bash -c "..."`)
        for seg in segments:
            if not seg:
                continue
            verb = seg[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            args_low = [a.lower() for a in seg[1:]]

            # Nested shell runner recursion (`bash -c "..."` / `pwsh -c "..."`)
            if verb in cls.INTERPRETERS and any(flag in args_low for flag in ("-c", "-command", "/c")):
                for flag in ("-c", "-command", "/c"):
                    if flag in args_low:
                        f_idx = args_low.index(flag)
                        if f_idx + 1 < len(seg):
                            sub_res = cls.analyze_command(seg[f_idx + 1])
                            if not sub_res["ok"]:
                                return sub_res

            # Rail 2: raw-disk-op
            if verb in cls.RAW_DISK_VERBS or verb.startswith("mkfs."):
                return {
                    "ok": False,
                    "risk": "HIGH",
                    "matched_rail": "raw-disk-op",
                    "segments": segments,
                    "reason": f"Raw disk/partition operation '{verb}' blocked by policy rail",
                }
            if verb == "dd" and any(a.startswith("of=/dev/") or a.startswith("of=\\\\.\\") for a in args_low):
                return {
                    "ok": False,
                    "risk": "HIGH",
                    "matched_rail": "raw-disk-op",
                    "segments": segments,
                    "reason": "Direct block device write via 'dd' blocked by policy rail",
                }
            if verb == "cipher" and any(a.startswith("/w") for a in args_low):
                return {
                    "ok": False,
                    "risk": "HIGH",
                    "matched_rail": "raw-disk-op",
                    "segments": segments,
                    "reason": "Disk wipe via 'cipher /w' blocked by policy rail",
                }

            # Rail 3: catastrophic-delete
            if verb in ("rm", "del", "erase", "rmdir", "remove-item", "ri"):
                has_rec = any(
                    a in ("-rf", "-fr", "-r", "-recurse", "--recursive", "/s")
                    or (a.startswith("-") and not a.startswith("--") and "r" in a and "f" in a)
                    for a in args_low
                )
                targets = [a.rstrip() for a in args_low if not a.startswith("-")]
                if (has_rec or verb in ("remove-item", "rmdir")) and any(
                    t in cls.CATASTROPHIC_TARGETS or t.startswith("/etc") or t.startswith("/usr") or t.startswith("c:\\windows")
                    for t in targets
                ):
                    return {
                        "ok": False,
                        "risk": "HIGH",
                        "matched_rail": "catastrophic-delete",
                        "segments": segments,
                        "reason": f"Catastrophic recursive delete on protected target in {seg}",
                    }

        return {"ok": True, "risk": "LOW", "matched_rail": None, "segments": segments, "reason": "passed all policy rails"}


# ============================================================================
# 4. V4A MULTI-FILE PATCH ENGINE & PER-FILE UNDO EDIT STACK
# ============================================================================


class UndoEditHistory:
    """OpenHands file_editor-style per-file undo stack (`file_history`)."""

    def __init__(self) -> None:
        self._stack: Dict[str, List[Optional[str]]] = {}
        self._lock = threading.Lock()

    def push_snapshot(self, rel_path: str, previous_content: Optional[str]) -> None:
        with self._lock:
            self._stack.setdefault(rel_path, []).append(previous_content)

    def undo_last_edit(self, workspace: Path, rel_path: str) -> Dict[str, Any]:
        ws = Path(workspace).resolve()
        target = (ws / rel_path).resolve()
        if target != ws and ws not in target.parents:
            raise PermissionError(f"Path escapes workspace boundary: {rel_path}")
        norm_key = target.relative_to(ws).as_posix()
        with self._lock:
            hist = self._stack.get(norm_key) or []
            if not hist:
                return {"ok": False, "file": norm_key, "error": "No previous edit snapshot available to undo"}
            prev = hist.pop()
        if prev is None:
            if target.exists():
                target.unlink()
            return {"ok": True, "file": norm_key, "action": "deleted_newly_created_file", "remaining_history": len(hist)}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(prev, encoding="utf-8", newline="\n")
        return {"ok": True, "file": norm_key, "action": "restored_previous_version", "remaining_history": len(hist)}


class V4AMultiFilePatchEngine:
    """Parses and atomically applies OpenHands / GPT-5 V4A multi-file patches (`*** Begin Patch`)."""

    @staticmethod
    def _resolve_safe(ws: Path, rel: str) -> Path:
        p = (ws / rel.strip()).resolve()
        if p != ws and ws not in p.parents:
            raise PermissionError(f"Patch path escapes workspace: {rel}")
        return p

    @classmethod
    def _apply_update_hunks(cls, original: str, patch_lines: List[str]) -> str:
        src_lines = original.splitlines()
        hunks: List[Tuple[List[str], List[str]]] = []
        old_chunk: List[str] = []
        new_chunk: List[str] = []
        in_hunk = False

        for ln in patch_lines:
            if ln.startswith("@@"):
                if in_hunk and (old_chunk or new_chunk):
                    hunks.append((old_chunk, new_chunk))
                old_chunk = []
                new_chunk = []
                in_hunk = True
                continue
            if not in_hunk:
                in_hunk = True
            if ln.startswith("-"):
                old_chunk.append(ln[1:])
            elif ln.startswith("+"):
                new_chunk.append(ln[1:])
            elif ln.startswith(" "):
                old_chunk.append(ln[1:])
                new_chunk.append(ln[1:])
            else:
                old_chunk.append(ln)
                new_chunk.append(ln)
        if old_chunk or new_chunk:
            hunks.append((old_chunk, new_chunk))

        result = "\n".join(src_lines)
        for old_c, new_c in hunks:
            old_block = "\n".join(old_c)
            new_block = "\n".join(new_c)
            if old_block and old_block in result:
                result = result.replace(old_block, new_block, 1)
            else:
                # Fuzzy stripped-line match fallback
                old_stripped = [x.strip() for x in old_c if x.strip()]
                matched = False
                cur_lines = result.splitlines()
                win_len = len(old_c)
                for i in range(max(0, len(cur_lines) - win_len + 1)):
                    cand = [x.strip() for x in cur_lines[i : i + win_len] if x.strip()]
                    if cand == old_stripped and old_stripped:
                        cur_lines = cur_lines[:i] + new_c + cur_lines[i + win_len :]
                        result = "\n".join(cur_lines)
                        matched = True
                        break
                if not matched:
                    raise ValueError(f"Could not match hunk context: {old_block[:120]!r}")
        return result + ("\n" if original.endswith("\n") or not result.endswith("\n") else "")

    @classmethod
    def apply_patch(
        cls,
        workspace: Path,
        patch_text: str,
        *,
        undo_history: Optional[UndoEditHistory] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        ws = Path(workspace).resolve()
        lines = (patch_text or "").splitlines()
        ops: List[Dict[str, Any]] = []
        cur_op: Optional[Dict[str, Any]] = None

        for ln in lines:
            if ln.startswith("*** Begin Patch") or ln.startswith("*** End of File"):
                continue
            if ln.startswith("*** End Patch"):
                break
            if ln.startswith("*** Add File:"):
                if cur_op:
                    ops.append(cur_op)
                cur_op = {"type": "add", "path": ln.split(":", 1)[1].strip(), "lines": []}
            elif ln.startswith("*** Update File:"):
                if cur_op:
                    ops.append(cur_op)
                cur_op = {"type": "update", "path": ln.split(":", 1)[1].strip(), "move_to": None, "lines": []}
            elif ln.startswith("*** Delete File:"):
                if cur_op:
                    ops.append(cur_op)
                cur_op = {"type": "delete", "path": ln.split(":", 1)[1].strip(), "lines": []}
            elif ln.startswith("*** Move to:") and cur_op is not None:
                cur_op["move_to"] = ln.split(":", 1)[1].strip()
            elif cur_op is not None:
                cur_op["lines"].append(ln)
        if cur_op:
            ops.append(cur_op)

        if not ops:
            return {"ok": False, "error": "No valid V4A patch operations found"}

        staged_writes: List[Tuple[Path, str, Optional[str]]] = []
        staged_deletes: List[Tuple[Path, str]] = []

        try:
            for op in ops:
                p = cls._resolve_safe(ws, op["path"])
                if op["type"] == "add":
                    content = "\n".join(ln[1:] if ln.startswith("+") else ln for ln in op["lines"]) + "\n"
                    if p.suffix.lower() == ".py":
                        ast.parse(content, filename=str(p))
                    prev = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
                    staged_writes.append((p, content, prev))
                elif op["type"] == "update":
                    if not p.is_file():
                        return {"ok": False, "error": f"Update target not found: {op['path']}"}
                    prev = p.read_text(encoding="utf-8", errors="replace")
                    updated = cls._apply_update_hunks(prev, op["lines"])
                    dest = cls._resolve_safe(ws, op["move_to"]) if op.get("move_to") else p
                    if dest.suffix.lower() == ".py":
                        ast.parse(updated, filename=str(dest))
                    staged_writes.append((dest, updated, prev if dest == p else None))
                    if dest != p:
                        staged_deletes.append((p, prev))
                elif op["type"] == "delete":
                    if not p.is_file():
                        return {"ok": False, "error": f"Delete target not found: {op['path']}"}
                    staged_deletes.append((p, p.read_text(encoding="utf-8", errors="replace")))
        except Exception as exc:
            return {"ok": False, "error": f"Patch validation failed: {type(exc).__name__}: {exc}"}

        if not dry_run:
            for dest, content, prev in staged_writes:
                rel = dest.relative_to(ws).as_posix()
                if undo_history is not None:
                    undo_history.push_snapshot(rel, prev)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8", newline="\n")
            for del_p, prev in staged_deletes:
                rel = del_p.relative_to(ws).as_posix()
                if undo_history is not None:
                    undo_history.push_snapshot(rel, prev)
                if del_p.exists():
                    del_p.unlink()

        return {
            "ok": True,
            "operations_count": len(ops),
            "files_written": [d.relative_to(ws).as_posix() for d, _, _ in staged_writes],
            "files_deleted": [d.relative_to(ws).as_posix() for d, _ in staged_deletes],
            "dry_run": dry_run,
        }


# ============================================================================
# 5. TRAJECTORY CRITIC & ITERATIVE REFINEMENT ENGINE
# ============================================================================


@dataclass(frozen=True)
class IterativeRefinementConfig:
    success_threshold: float = 0.75
    max_iterations: int = 3


@dataclass(frozen=True)
class CriticEvaluationResult:
    score: float
    passed: bool
    reasons: List[str]
    followup_prompt: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.passed,
            "score": round(self.score, 4),
            "passed": self.passed,
            "reasons": self.reasons,
            "followup_prompt": self.followup_prompt,
        }


class TrajectoryCritic:
    """OpenHands-style composite critic (`AgentFinishedCritic` + `EmptyPatchCritic` + verification & stuck checks)."""

    def __init__(self, config: Optional[IterativeRefinementConfig] = None) -> None:
        self.config = config or IterativeRefinementConfig()
        self.stuck_detector = OpenHandsStuckDetector()

    def evaluate(
        self,
        events: Sequence[Dict[str, Any]],
        *,
        git_patch: Optional[str] = None,
        require_patch: bool = True,
        verify_passed: Optional[bool] = None,
        iteration: int = 1,
    ) -> CriticEvaluationResult:
        score = 1.0
        reasons: List[str] = []

        # Criterion 1: FinishAction properly invoked
        finished = any(str(ev.get("tool") or ev.get("action") or "").lower() == "finish" for ev in events)
        if not finished:
            score -= 0.35
            reasons.append("Agent did not conclude with an explicit 'finish' action")

        # Criterion 2: Non-empty git patch when mutation is expected (EmptyPatchCritic)
        if require_patch and (git_patch is None or not git_patch.strip()):
            score -= 0.40
            reasons.append("Generated git patch is empty or missing")

        # Criterion 3: Verification command check
        if verify_passed is False:
            score -= 0.45
            reasons.append("Executable verification test command failed (non-zero exit code)")

        # Criterion 4: Stuck pattern check
        stuck = self.stuck_detector.analyze(events)
        if stuck.is_stuck:
            score -= 0.30
            reasons.append(f"Stuck pattern detected: {stuck.loop_type} ({stuck.recovery_nudge})")

        final_score = max(0.0, min(1.0, round(score, 4)))
        passed = final_score >= self.config.success_threshold
        followup = ""
        if not passed:
            bullets = "\n".join(f"- {r}" for r in reasons)
            followup = (
                f"[Iterative Refinement Critic — Iteration {iteration}/{self.config.max_iterations} | "
                f"Score {final_score:.2f} < {self.config.success_threshold:.2f}]\n"
                f"Address the following deficiencies before calling finish:\n{bullets}"
            )
        return CriticEvaluationResult(final_score, passed, reasons, followup)


# ============================================================================
# 6. JUST-IN-TIME SECRET REGISTRY & MASKED OBSERVATION ENGINE
# ============================================================================


class SecretRegistry:
    """Thread-safe secret manager that masks secret values in observations and injects env vars JIT."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: Dict[str, Tuple[UnionCallableOrStr, str]] = {}

    def register_secret(self, name: str, value: str, description: str = "") -> None:
        key = name.strip()
        if not key or not value:
            return
        with self._lock:
            self._secrets[key] = (str(value), description)

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        with self._lock:
            # Sort by value length descending to prevent partial substring leaks
            items = sorted(self._secrets.items(), key=lambda kv: len(kv[1][0]), reverse=True)
        for name, (val, _) in items:
            if len(val) >= 4 and val in out:
                out = out.replace(val, f"<secret-hidden:{name}>")
        return out

    def export_env_for_command(self, command: str) -> Dict[str, str]:
        """Inject only secrets explicitly referenced in `command` (e.g. `$API_KEY` or `%API_KEY%`)."""
        cmd = command or ""
        injected: Dict[str, str] = {}
        with self._lock:
            for name, (val, _) in self._secrets.items():
                if name in cmd:
                    injected[name] = val
        return injected


UnionCallableOrStr = str


# ============================================================================
# 7. TRIGGER MICROAGENTS, ROLLING CONDENSER & THEORY-OF-MIND (ToM) CONSULTANT
# ============================================================================


@dataclass(frozen=True)
class MicroagentSkill:
    name: str
    content: str
    trigger_type: str = "keyword"  # "always" | "keyword" | "path" | "task"
    keywords: Tuple[str, ...] = ()
    paths: Tuple[str, ...] = ()
    task_command: str = ""


class TriggerMicroagentRegistry:
    """OpenHands 3-Trigger Microagent skill matcher (`KeywordTrigger`, `PathTrigger`, `TaskTrigger`)."""

    def __init__(self) -> None:
        self._skills: Dict[str, MicroagentSkill] = {}

    def register(self, skill: MicroagentSkill) -> None:
        self._skills[skill.name] = skill

    def match(
        self,
        *,
        user_message: str = "",
        touched_paths: Sequence[str] = (),
    ) -> List[MicroagentSkill]:
        low_msg = (user_message or "").lower()
        norm_paths = [p.replace("\\", "/").lstrip("./") for p in touched_paths]
        activated: List[MicroagentSkill] = []

        for sk in self._skills.values():
            tt = sk.trigger_type.lower()
            if tt == "always":
                activated.append(sk)
            elif tt == "task" and sk.task_command and low_msg.strip().startswith(sk.task_command.lower()):
                activated.append(sk)
            elif tt == "keyword" and any(k.lower() in low_msg for k in sk.keywords):
                activated.append(sk)
            elif tt == "path" and any(
                fnmatchcase(tp, pat) or fnmatchcase(tp.split("/")[-1], pat)
                for tp in norm_paths
                for pat in sk.paths
            ):
                activated.append(sk)
        return activated


class RollingCondenser:
    """OpenHands-style rolling history condenser preserving head + tail and summarizing middle turns."""

    def __init__(self, *, max_events: int = 24, head_keep: int = 2, tail_keep: int = 10) -> None:
        self.max_events = max(6, int(max_events))
        self.head_keep = max(1, int(head_keep))
        self.tail_keep = max(2, int(tail_keep))

    def condense(self, events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        ev_list = list(events)
        if len(ev_list) <= self.max_events:
            return {"condensed": False, "events": ev_list, "summary_event": None}

        head = ev_list[: self.head_keep]
        tail = ev_list[-self.tail_keep :]
        middle = ev_list[self.head_keep : len(ev_list) - self.tail_keep]

        files_touched: List[str] = []
        tools_used: Dict[str, int] = {}
        errors_seen: List[str] = []

        for ev in middle:
            t = str(ev.get("tool") or ev.get("action") or "message")
            tools_used[t] = tools_used.get(t, 0) + 1
            args = ev.get("args") or ev.get("params") or {}
            if isinstance(args, dict):
                fp = args.get("path") or args.get("file_path")
                if fp and str(fp) not in files_touched:
                    files_touched.append(str(fp))
            if ev.get("is_error") or ev.get("error"):
                errors_seen.append(str(ev.get("error") or ev.get("observation") or "")[:120])

        summary_event = {
            "kind": "condensation_summary",
            "condensed_event_count": len(middle),
            "tools_histogram": tools_used,
            "files_touched": files_touched[:30],
            "errors_resolved_or_seen": errors_seen[:10],
        }
        return {
            "condensed": True,
            "events": head + [summary_event] + tail,
            "summary_event": summary_event,
        }


class ToMIntentConsultant:
    """OpenHands `tom_consult`-inspired Theory-of-Mind user intent and ambiguity analyzer."""

    VAGUE_PRONOUNS = frozenset({"isso", "aquilo", "it", "this", "that", "stuff", "thing", "alguma coisa"})
    CONCRETE_ANCHORS = re.compile(r"([a-zA-Z0-9_/-]+\.[a-zA-Z0-9]+|`[^`]+`|https?://\S+|\bdef\s+\w+|\bclass\s+\w+)")

    @classmethod
    def consult(
        cls,
        user_message: str,
        *,
        prior_preferences: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        msg = (user_message or "").strip()
        words = [w.strip(".,?!:;\"'()[]").lower() for w in msg.split() if w.strip()]
        has_anchors = bool(cls.CONCRETE_ANCHORS.search(msg))
        vague_hits = [w for w in words if w in cls.VAGUE_PRONOUNS]

        ambiguity_score = 0.0
        if len(words) < 5 and not has_anchors:
            ambiguity_score += 0.55
        if vague_hits and not has_anchors:
            ambiguity_score += 0.35
        ambiguity_score = round(min(1.0, ambiguity_score), 3)

        recommended_mode = "clarify_first" if ambiguity_score >= 0.6 else "execute_directly"
        guidance = (
            "Objective has concrete file/symbol anchors; proceed with deterministic-first execution."
            if recommended_mode == "execute_directly"
            else "Objective is underspecified and lacks file/symbol anchors; inspect workspace context or ask 1 targeted question."
        )
        return {
            "ok": True,
            "ambiguity_score": ambiguity_score,
            "has_concrete_anchors": has_anchors,
            "recommended_mode": recommended_mode,
            "active_preferences": list(prior_preferences or ["deterministic_first", "zero_manual_offloading"]),
            "guidance": guidance,
        }


# ============================================================================
# 8. SLEEPTIME COMPUTE ENGINE (OpenHands `tom_consult.SleeptimeComputeAction`)
# ============================================================================


class SleeptimeComputeEngine:
    """Consolidates completed trajectories during idle time into a persistent user & repo profile."""

    @classmethod
    def index_trajectories(
        cls,
        workspace: Path,
        trajectories: Sequence[Dict[str, Any]],
        *,
        out_rel_path: str = ".omni_sleeptime_profile.json",
    ) -> Dict[str, Any]:
        ws = Path(workspace).resolve()
        out_p = (ws / out_rel_path).resolve()
        if out_p != ws and ws not in out_p.parents:
            raise PermissionError(f"Sleeptime profile escapes workspace: {out_rel_path}")

        file_freq: Dict[str, int] = {}
        tool_freq: Dict[str, int] = {}
        learned_rules: List[str] = []

        for traj in trajectories:
            for ev in traj.get("events") or []:
                t = str(ev.get("tool") or ev.get("action") or "")
                if t:
                    tool_freq[t] = tool_freq.get(t, 0) + 1
                args = ev.get("args") or ev.get("params") or {}
                if isinstance(args, dict):
                    fp = args.get("path") or args.get("file_path")
                    if fp:
                        file_freq[str(fp)] = file_freq.get(str(fp), 0) + 1
            rule = str(traj.get("learned_preference") or "").strip()
            if rule and rule not in learned_rules:
                learned_rules.append(rule)

        hot_files = [k for k, _ in sorted(file_freq.items(), key=lambda kv: kv[1], reverse=True)[:20]]
        top_tools = [k for k, _ in sorted(tool_freq.items(), key=lambda kv: kv[1], reverse=True)[:15]]
        profile = {
            "ok": True,
            "trajectories_indexed": len(trajectories),
            "hot_files": hot_files,
            "top_tools": top_tools,
            "learned_preferences": learned_rules,
        }
        out_p.write_text(json.dumps(profile, indent=2), encoding="utf-8", newline="\n")
        return profile


# ============================================================================
# 9. ASK ORACLE CONSULTANT (OpenHands `tools/ask_oracle`)
# ============================================================================


class AskOracleConsultant:
    """Second-opinion dilemma advisor that synthesizes a compact <500-token brief & deterministic recommendation."""

    @classmethod
    def consult_oracle(
        cls,
        question: str,
        *,
        context: Optional[str] = None,
        approaches_tried: Optional[Sequence[str]] = None,
        oracle_fn: Optional[Callable[[str], str]] = None,
    ) -> Dict[str, Any]:
        q = (question or "").strip()
        ctx = (context or "").strip()[:1200]
        tried = [str(x).strip() for x in (approaches_tried or []) if str(x).strip()]

        brief_lines = [f"Question:\n{q}"]
        if ctx:
            brief_lines.append(f"Context:\n{ctx}")
        if tried:
            brief_lines.append("Approaches already tried:\n" + "\n".join(f"- {t}" for t in tried))
        distilled_brief = "\n\n".join(brief_lines)

        if oracle_fn is not None:
            recommendation = oracle_fn(distilled_brief)
            backend = "oracle_profile_llm"
        else:
            low = (q + " " + ctx).lower()
            if "import" in low or "circular" in low or "topology" in low:
                recommendation = "Inline lightweight helpers or move shared types to the contracts layer to preserve DAG topology."
            elif "timeout" in low or "lock" in low or "deadlock" in low:
                recommendation = "Use ResourceLockManager with sorted keys and SingleFlightCoalescer to eliminate lock contention."
            elif "syntax" in low or "patch" in low:
                recommendation = "Validate replacement with V4AMultiFilePatchEngine in-memory AST parsing before writing to disk."
            else:
                recommendation = "Isolate the failing assertion via pytest_failure_diagnoser, apply minimal AST-verified diff, and re-verify."
            backend = "deterministic_oracle_heuristics"

        return {
            "ok": True,
            "profile": "oracle",
            "backend": backend,
            "brief_chars": len(distilled_brief),
            "distilled_brief": distilled_brief,
            "recommendation": recommendation,
        }


# ============================================================================
# 10. PLANNING FILE EDITOR GATE (OpenHands `tools/planning_file_editor`)
# ============================================================================


class PlanningFileEditorGate:
    """Allows editing ONLY designated plan files (`PLAN.md`, `.omni_todo.md`) during read-only PLAN mode."""

    DEFAULT_ALLOWED_PLAN_FILES = frozenset({"plan.md", ".omni_todo.md", "todo.md"})

    def __init__(self, workspace: Path, allowed_files: Optional[Iterable[str]] = None) -> None:
        self.workspace = Path(workspace).resolve()
        self.allowed = {f.lower() for f in (allowed_files or self.DEFAULT_ALLOWED_PLAN_FILES)}

    def is_allowed_plan_path(self, rel_or_abs: str) -> bool:
        p = (self.workspace / rel_or_abs).resolve() if not Path(rel_or_abs).is_absolute() else Path(rel_or_abs).resolve()
        if p != self.workspace and self.workspace not in p.parents:
            return False
        rel = p.relative_to(self.workspace).as_posix().lower()
        return rel in self.allowed or p.name.lower() in self.allowed

    def edit_plan_file(self, rel_path: str, content: str) -> Dict[str, Any]:
        if not self.is_allowed_plan_path(rel_path):
            raise PermissionError(
                f"PlanningFileEditorGate blocked edit to '{rel_path}': only {sorted(self.allowed)} may be edited in PLAN mode"
            )
        target = (self.workspace / rel_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        return {"ok": True, "plan_file": target.relative_to(self.workspace).as_posix(), "bytes_written": len(content)}


# ============================================================================
# 11. STATEFUL PYTHON SESSION KERNEL & PERSISTENT SHELL STATE
# ============================================================================


class StatefulPythonSessionKernel:
    """In-memory stateful Python AST kernel & persistent shell cwd/env state across turns."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace).resolve()
        self.cwd: Path = self.workspace
        self.env_overrides: Dict[str, str] = {}
        self.variables: Dict[str, Any] = {}
        self.cell_count: int = 0

    def _eval_expr(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.variables:
                return self.variables[node.id]
            raise NameError(f"Variable '{node.id}' is not defined in session kernel")
        if isinstance(node, ast.List):
            return [self._eval_expr(e) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval_expr(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return {self._eval_expr(k): self._eval_expr(v) for k, v in zip(node.keys, node.values) if k is not None}
        if isinstance(node, ast.BinOp):
            lhs, rhs = self._eval_expr(node.left), self._eval_expr(node.right)
            ops = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.Div: lambda a, b: a / b,
                ast.FloorDiv: lambda a, b: a // b,
                ast.Mod: lambda a, b: a % b,
                ast.Pow: lambda a, b: a**b,
            }
            if type(node.op) in ops:
                return ops[type(node.op)](lhs, rhs)
        if isinstance(node, ast.Compare):
            cur = self._eval_expr(node.left)
            cmp_ops = {
                ast.Eq: lambda a, b: a == b,
                ast.NotEq: lambda a, b: a != b,
                ast.Lt: lambda a, b: a < b,
                ast.LtE: lambda a, b: a <= b,
                ast.Gt: lambda a, b: a > b,
                ast.GtE: lambda a, b: a >= b,
            }
            for op, comp in zip(node.ops, node.comparators):
                nxt = self._eval_expr(comp)
                if not cmp_ops[type(op)](cur, nxt):
                    return False
                cur = nxt
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            safe_funcs: Dict[str, Any] = {
                "len": len,
                "sum": sum,
                "min": min,
                "max": max,
                "sorted": sorted,
                "abs": abs,
                "round": round,
                "int": int,
                "float": float,
                "str": str,
            }
            fn = safe_funcs.get(node.func.id)
            if fn is not None:
                return fn(*[self._eval_expr(a) for a in node.args])
        raise ValueError(f"Unsupported AST expression in safe kernel: {type(node).__name__}")

    def run_cell(self, code: str) -> Dict[str, Any]:
        self.cell_count += 1
        tree = ast.parse(code or "")
        last_val: Any = None
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                val = self._eval_expr(stmt.value)
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        self.variables[tgt.id] = val
                last_val = val
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                cur = self.variables.get(stmt.target.id, 0)
                rhs = self._eval_expr(stmt.value)
                if isinstance(stmt.op, ast.Add):
                    self.variables[stmt.target.id] = cur + rhs
                elif isinstance(stmt.op, ast.Sub):
                    self.variables[stmt.target.id] = cur - rhs
                elif isinstance(stmt.op, ast.Mult):
                    self.variables[stmt.target.id] = cur * rhs
                last_val = self.variables[stmt.target.id]
            elif isinstance(stmt, ast.Expr):
                last_val = self._eval_expr(stmt.value)
        return {
            "ok": True,
            "cell": self.cell_count,
            "result": last_val,
            "variables": dict(self.variables),
            "cwd": self.cwd.relative_to(self.workspace).as_posix() if self.cwd != self.workspace else ".",
        }

    def cd(self, rel_dir: str) -> Path:
        nxt = (self.cwd / rel_dir).resolve()
        if nxt != self.workspace and self.workspace not in nxt.parents:
            raise PermissionError(f"Directory escapes workspace boundary: {rel_dir}")
        self.cwd = nxt
        return self.cwd

    def export_env(self, key: str, value: str) -> None:
        self.env_overrides[str(key)] = str(value)


# ============================================================================
# 12. PARALLEL TOOL BATCH EXECUTOR & SUBAGENT SCOPE GUARD
# ============================================================================


class SubAgentScopeGuard:
    """OpenHands `subagent/scope.py`: bounds a sub-agent's tools & paths to a strict subset of its parent's."""

    def __init__(self, parent_tools: Iterable[str], parent_allowed_paths: Optional[Iterable[str]] = None) -> None:
        self.parent_tools = frozenset(parent_tools)
        self.parent_paths = tuple(parent_allowed_paths or ("**",))

    def bind_child_scope(
        self,
        requested_tools: Iterable[str],
        requested_paths: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        req_t = set(requested_tools)
        effective_tools = sorted(req_t & self.parent_tools)
        blocked_tools = sorted(req_t - self.parent_tools)
        return {
            "ok": len(blocked_tools) == 0,
            "effective_tools": effective_tools,
            "blocked_tools": blocked_tools,
            "inherited_paths": list(requested_paths or self.parent_paths),
        }


class ParallelToolBatchExecutor:
    """OpenHands `agent/parallel_executor.py`: executes parallel tool calls with per-resource FIFO locking."""

    def __init__(self, *, max_workers: int = 8, lock_manager: Optional[ResourceLockManager] = None) -> None:
        self.max_workers = max(1, int(max_workers))
        self.lock_manager = lock_manager or ResourceLockManager()

    def execute_batch(
        self,
        calls: Sequence[Dict[str, Any]],
        dispatch_fn: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        from concurrent.futures import ThreadPoolExecutor

        def _run_one(call: Dict[str, Any]) -> Dict[str, Any]:
            tool_name = str(call.get("tool") or "")
            args = dict(call.get("args") or {})
            declared = list(call.get("resources") or [])
            if not declared and ("path" in args or "file_path" in args):
                declared = [f"file:{args.get('path') or args.get('file_path')}"]
            with self.lock_manager.lock(*declared):
                return dispatch_fn(tool_name, args)

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(calls)))) as pool:
            futs = [pool.submit(_run_one, c) for c in calls]
            return [f.result() for f in futs]


# ============================================================================
# 13. OPENHUMAN ARTIFACT HANDLE VAULT (`TokenJuice` / `search_handle`) &
#     INBOUND DEBOUNCE + PLAN REVIEW TRIAGE (`crates/openhuman-core/src`)
# ============================================================================


class ArtifactHandleVault:
    """OpenHuman `TokenJuice` / `artifacts`: stores large outputs under `handle://sha256` and supports zero-token grep."""

    def __init__(self, *, inline_threshold_chars: int = 1200) -> None:
        self.inline_threshold_chars = max(200, int(inline_threshold_chars))
        self._store: Dict[str, str] = {}
        self._lock = threading.Lock()

    def store_or_inline(self, text: str) -> Dict[str, Any]:
        raw = text or ""
        if len(raw) <= self.inline_threshold_chars:
            return {"compressed": False, "handle": None, "preview": raw, "total_chars": len(raw)}
        hid = "handle://" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        with self._lock:
            self._store[hid] = raw
        head = raw[: self.inline_threshold_chars // 2]
        tail = raw[-(self.inline_threshold_chars // 2) :]
        return {
            "compressed": True,
            "handle": hid,
            "preview": f"{head}\n... [stored in {hid} ({len(raw)} chars)] ...\n{tail}",
            "total_chars": len(raw),
        }

    def search_handle(self, handle_id: str, pattern: str, *, max_matches: int = 25) -> Dict[str, Any]:
        with self._lock:
            raw = self._store.get(handle_id)
        if raw is None:
            return {"ok": False, "handle": handle_id, "error": "Handle not found"}
        rx = re.compile(pattern, re.IGNORECASE)
        hits = [
            {"line": idx, "text": ln[:200]}
            for idx, ln in enumerate(raw.splitlines(), start=1)
            if rx.search(ln)
        ]
        return {"ok": True, "handle": handle_id, "match_count": len(hits), "matches": hits[:max_matches]}


class InboundDebounceTriageEngine:
    """OpenHuman `inbound_debounce` + `triage` + `plan_review` deterministic pre-flight engine."""

    @classmethod
    def coalesce_burst_messages(
        cls,
        messages: Sequence[Dict[str, Any]],
        *,
        debounce_window_s: float = 2.5,
    ) -> Dict[str, Any]:
        """Coalesce rapid consecutive user messages within `debounce_window_s` into 1 turn."""
        if not messages:
            return {"ok": True, "input_count": 0, "coalesced_count": 0, "batches": []}
        batches: List[List[str]] = []
        last_ts: Optional[float] = None
        for m in messages:
            txt = str(m.get("text") or "").strip()
            ts = float(m.get("timestamp") or 0.0)
            if not txt:
                continue
            if last_ts is not None and (ts - last_ts) <= debounce_window_s and batches:
                batches[-1].append(txt)
            else:
                batches.append([txt])
            last_ts = ts
        merged = ["\n".join(b) for b in batches]
        return {
            "ok": True,
            "input_count": len(messages),
            "coalesced_count": len(merged),
            "saved_runs": len(messages) - len(merged),
            "batches": merged,
        }

    @classmethod
    def audit_plan_review(cls, plan_markdown: str) -> Dict[str, Any]:
        """OpenHuman `plan_review`: verify a plan contains target files, verification command, and rollback path."""
        txt = (plan_markdown or "").lower()
        has_files = bool(re.search(r"[a-z0-9_/-]+\.(py|ts|js|rs|go|md|json|yml)", txt))
        has_verify = any(k in txt for k in ("pytest", "test", "verify", "validação", "validacao", "check"))
        has_rollback = any(k in txt for k in ("rollback", "undo", "revert", "reversão", "reversao", "checkpoint"))
        approved = has_files and has_verify and has_rollback
        return {
            "ok": approved,
            "approved": approved,
            "has_target_files": has_files,
            "has_verification_step": has_verify,
            "has_rollback_strategy": has_rollback,
        }

