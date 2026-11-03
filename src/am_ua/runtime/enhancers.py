"""Runtime Enhancers — Persistent PWSH + Spill-to-Disk + Anti-Loop (DSH) + Context Condenser (OpenHands SDK)."""

from __future__ import annotations

import ast
from collections import deque
import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple


class RepeatToolLoopError(RuntimeError):
    """Raised when an agent repeats an identical tool call beyond threshold."""


class PersistentPwshSession:
    """Warm persistent PowerShell (`pwsh`) session preserving CWD & variables across turns.

    Inspired by `@deepseek-ai/dsh-root` `tool-pwsh-persistent`, bound to F:\\AetherMind_Temp.
    """

    def __init__(self, *, initial_cwd: Optional[str] = None) -> None:
        self.exe = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
        self.initial_cwd = initial_cwd or os.getcwd()
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._out_q: "queue.Queue[str]" = queue.Queue()
        self._start_session()

    def _start_session(self) -> None:
        env = dict(os.environ)
        env["TMP"] = r"F:\AetherMind_Temp"
        env["TEMP"] = r"F:\AetherMind_Temp"
        self._proc = subprocess.Popen(
            [self.exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            cwd=self.initial_cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        t = threading.Thread(target=self._reader_loop, args=(self._proc,), daemon=True)
        t.start()

    def _reader_loop(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._out_q.put(line)

    def execute(self, command: str, *, timeout: float = 30.0) -> Dict[str, Any]:
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start_session()
            assert self._proc is not None and self._proc.stdin is not None

            # Drain stale lines if any
            while not self._out_q.empty():
                try:
                    self._out_q.get_nowait()
                except queue.Empty:
                    break

            marker = f"__AM_PWSH_END_{uuid.uuid4().hex}__"
            wrapped = (
                f"$ErrorActionPreference='Continue';\n"
                f"{command}\n"
                f"$__ec = if ($null -ne $LASTEXITCODE) {{ [int]$LASTEXITCODE }} elseif ($?) {{ 0 }} else {{ 1 }};\n"
                f"Write-Output ('{marker}:' + $__ec + ':' + (Get-Location).Path)\n"
            )
            self._proc.stdin.write(wrapped)
            self._proc.stdin.flush()

            lines: List[str] = []
            deadline = time.monotonic() + timeout
            exit_code = 0
            cwd_now = self.initial_cwd

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.close()
                    raise TimeoutError(f"PersistentPwshSession timed out after {timeout}s")
                try:
                    line = self._out_q.get(timeout=min(0.25, remaining))
                except queue.Empty:
                    if self._proc.poll() is not None:
                        raise RuntimeError("PersistentPwshSession terminated unexpectedly")
                    continue

                if marker in line:
                    idx = line.index(marker)
                    prefix = line[:idx]
                    if prefix:
                        lines.append(prefix)
                    tail = line[idx + len(marker) + 1 :].strip()
                    parts = tail.split(":", 1)
                    exit_code = int(parts[0]) if parts[0].lstrip("-").isdigit() else 0
                    if len(parts) > 1 and parts[1]:
                        cwd_now = parts[1]
                    break
                lines.append(line)

            return {
                "output": "".join(lines).rstrip("\r\n"),
                "exit_code": exit_code,
                "cwd": cwd_now,
            }

    def close(self) -> None:
        if self._proc is not None:
            pid = self._proc.pid
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None


class SpillToDiskMiddleware:
    """Spills oversized tool outputs to `F:\\AetherMind_Temp\\spill` with paginated readback (`DSH spill-local`)."""

    def __init__(
        self,
        *,
        spill_dir: str = r"F:\AetherMind_Temp\spill",
        max_inline_chars: int = 16_000,
    ) -> None:
        self.spill_dir = Path(spill_dir)
        self.spill_dir.mkdir(parents=True, exist_ok=True)
        self.max_inline_chars = max_inline_chars

    def process_output(self, tool_name: str, raw_text: str) -> Dict[str, Any]:
        if len(raw_text) <= self.max_inline_chars:
            return {"spilled": False, "content": raw_text, "spill_id": None}

        sha = hashlib.sha256(raw_text.encode("utf-8", errors="replace")).hexdigest()
        spill_id = f"{tool_name}_{sha[:12]}"
        target = self.spill_dir / f"{spill_id}.txt"
        target.write_text(raw_text, encoding="utf-8")

        head_len = int(self.max_inline_chars * 0.45)
        tail_len = int(self.max_inline_chars * 0.45)
        preview = (
            f"{raw_text[:head_len]}\n\n"
            f"... [SPILLED TO DISK: id={spill_id}, total_chars={len(raw_text)}, path={target}] ...\n\n"
            f"{raw_text[-tail_len:]}"
        )
        return {
            "spilled": True,
            "spill_id": spill_id,
            "spill_path": str(target),
            "total_chars": len(raw_text),
            "sha256": sha,
            "content": preview,
        }

    def read_chunk(self, spill_id: str, *, offset: int = 0, limit: int = 8000) -> str:
        safe_id = "".join(c for c in spill_id if c.isalnum() or c in ("_", "-"))
        target = self.spill_dir / f"{safe_id}.txt"
        if not target.is_file():
            raise FileNotFoundError(f"Unknown spill_id: {spill_id}")
        data = target.read_text(encoding="utf-8")
        return data[max(0, offset) : max(0, offset) + max(1, limit)]


class RepeatToolLoopBreaker:
    """Detects repetitive identical `(tool_name, args)` loops (`DSH repeat-tool-reminder`)."""

    def __init__(self, *, window_size: int = 10, max_identical_calls: int = 3) -> None:
        self.window: Deque[str] = deque(maxlen=window_size)
        self.max_identical_calls = max_identical_calls

    def record_and_check(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, int]:
        sig = hashlib.sha256(
            json.dumps({"t": tool_name, "a": args}, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        self.window.append(sig)
        count = sum(1 for item in self.window if item == sig)
        if count >= self.max_identical_calls:
            raise RepeatToolLoopError(
                f"Anti-loop breaker tripped: tool '{tool_name}' invoked {count} times with identical args"
            )
        return True, count


class AmortizedContextCondenser:
    """OpenHands SDK style Context Condenser preserving causal anchors & compressing middle turns."""

    def __init__(self, *, head_keep: int = 2, tail_keep: int = 6, max_total_chars: int = 48_000) -> None:
        self.head_keep = head_keep
        self.tail_keep = tail_keep
        self.max_total_chars = max_total_chars

    def condense(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        total_chars = sum(len(str(m.get("content", ""))) for m in messages)
        if total_chars <= self.max_total_chars or len(messages) <= (self.head_keep + self.tail_keep + 1):
            return list(messages)

        head = messages[: self.head_keep]
        tail = messages[-self.tail_keep :]
        middle = messages[self.head_keep : -self.tail_keep]

        digest_lines = [f"[AMORTIZED CONTEXT CONDENSER — {len(middle)} intermediate events summarized]:"]
        for idx, m in enumerate(middle):
            role = m.get("role", "unknown")
            text = str(m.get("content", "")).replace("\n", " ").strip()
            snippet = text[:160] + ("..." if len(text) > 160 else "")
            digest_lines.append(f"  - ({idx + 1}) [{role}] {snippet}")

        summary_msg = {
            "role": "system",
            "content": "\n".join(digest_lines),
            "condensed_count": len(middle),
        }
        return [*head, summary_msg, *tail]


class ContextBracket(str):
    FRESH = "FRESH"          # 60-100% capacity free -> full L0-L7, rich memory hints, 800 token rule budget
    MODERATE = "MODERATE"    # 40-60% capacity free -> L0-L2 default, standard memory hints, 1500 tokens
    DEPLETED = "DEPLETED"    # 25-40% capacity free -> L0-L1 only, supress memory hints, handoff warning, 2000 tokens
    CRITICAL = "CRITICAL"    # 0-25% capacity free -> L0 constitution only, force compaction/handoff, 2500 tokens


class SynapseContextBracketEngine:
    """SYNAPSE Context Engine (JARVIS Átomo 20 / Motor Supremo v3.0).

    Computes remaining context headroom, assigns dynamic context brackets (L0-L7),
    and modulates memory hint retrieval to prevent context thrashing.
    """

    def __init__(self, max_context_tokens: int = 128_000) -> None:
        self.max_context_tokens = max_context_tokens

    def evaluate_bracket(self, current_tokens: int) -> Dict[str, Any]:
        used = max(0, int(current_tokens))
        free_ratio = max(0.0, min(1.0, 1.0 - (used / float(max(1, self.max_context_tokens)))))

        if free_ratio >= 0.60:
            bracket = ContextBracket.FRESH
            active_layers = [0, 1, 2, 3, 4, 5, 6, 7]
            allow_memory_hints = True
            handoff_warning = False
            rules_budget_tokens = 800
        elif free_ratio >= 0.40:
            bracket = ContextBracket.MODERATE
            active_layers = [0, 1, 2]
            allow_memory_hints = True
            handoff_warning = False
            rules_budget_tokens = 1500
        elif free_ratio >= 0.25:
            bracket = ContextBracket.DEPLETED
            active_layers = [0, 1]
            allow_memory_hints = False
            handoff_warning = True
            rules_budget_tokens = 2000
        else:
            bracket = ContextBracket.CRITICAL
            active_layers = [0]
            allow_memory_hints = False
            handoff_warning = True
            rules_budget_tokens = 2500

        return {
            "bracket": bracket,
            "free_ratio_pct": round(free_ratio * 100.0, 2),
            "used_tokens": used,
            "max_tokens": self.max_context_tokens,
            "active_layers": active_layers,
            "allow_memory_hints": allow_memory_hints,
            "handoff_warning": handoff_warning,
            "rules_budget_tokens": rules_budget_tokens,
        }


class SymbolicPreLLMBypass:
    """Symbolic Pre-LLM Bypass (AetherMind Apotheosis Órgão 29 / Apex Frontier v2).

    Intercepts purely arithmetic and logical expressions, solving them deterministically
    via AST in < 0.2ms with zero token expenditure and zero model latency.
    """

    SAFE_OPERATORS = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.Pow: lambda a, b: a ** b,
        ast.BitXor: lambda a, b: a ^ b,
        ast.BitAnd: lambda a, b: a & b,
        ast.BitOr: lambda a, b: a | b,
        ast.USub: lambda a: -a,
        ast.UAdd: lambda a: +a,
    }

    @classmethod
    def evaluate(cls, expression: str) -> Optional[Dict[str, Any]]:
        clean = expression.strip()
        if not clean or len(clean) > 256:
            return None
        try:
            tree = ast.parse(clean, mode="eval")
        except SyntaxError:
            return None

        def _eval_node(node: ast.AST) -> Any:
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool)):
                return node.value
            if isinstance(node, ast.BinOp) and type(node.op) in cls.SAFE_OPERATORS:
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                return cls.SAFE_OPERATORS[type(node.op)](left, right)
            if isinstance(node, ast.UnaryOp) and type(node.op) in cls.SAFE_OPERATORS:
                operand = _eval_node(node.operand)
                return cls.SAFE_OPERATORS[type(node.op)](operand)
            raise ValueError("Non-symbolic node detected")

        t0 = time.perf_counter()
        try:
            result = _eval_node(tree)
            dt_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return {
                "bypassed": True,
                "expression": clean,
                "result": result,
                "latency_ms": dt_ms,
                "tokens_saved": max(20, len(clean) // 3),
            }
        except Exception:
            return None
