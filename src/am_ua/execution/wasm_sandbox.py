"""Zero-Docker Lightweight Sandbox: Optional Wasmtime Runner + Deterministic AST Fallback (v12.0).

Inspired by OpenJarvis `sandbox/wasm_runner.py`, designed for 100% zero-dependency
portability (`dependencies = []`) on Windows/Linux even when Docker Desktop is stopped.
"""

from __future__ import annotations

import ast
import contextlib
from dataclasses import dataclass
import io
import math
import time
from typing import Any, Dict, Optional

from am_ua.security.runtime_taint import MountAllowlistGuard


_FORBIDDEN_AST_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.Delete,
)

_FORBIDDEN_NAMES = frozenset({
    "__import__",
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "breakpoint",
})

_SAFE_BUILTINS: Dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "pow": pow,
    "print": print,
    "range": range,
    "reversed": reversed,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}


@dataclass(slots=True)
class SandboxExecResult:
    ok: bool
    backend: str
    output: str = ""
    error: str = ""
    duration_s: float = 0.0
    fuel_consumed: int = 0


class WasmSandboxRunner:
    """Runs WASM modules via optional `wasmtime` or deterministic AST-guarded Python fallback."""

    def __init__(
        self,
        *,
        fuel_limit: int = 1_000_000,
        mount_guard: Optional[MountAllowlistGuard] = None,
    ) -> None:
        self.fuel_limit = max(1000, int(fuel_limit))
        self.mount_guard = mount_guard

    @staticmethod
    def wasmtime_available() -> bool:
        try:
            import wasmtime  # type: ignore[import-not-found]  # noqa: F401

            return True
        except ImportError:
            return False

    def run_wasm(self, wasm_bytes: bytes) -> SandboxExecResult:
        t0 = time.perf_counter()
        try:
            import wasmtime  # type: ignore[import-not-found]
        except ImportError:
            return SandboxExecResult(
                ok=False,
                backend="wasmtime_unavailable",
                error="wasmtime not installed; use run_restricted_python() for zero-dep isolation",
                duration_s=round(time.perf_counter() - t0, 4),
            )

        try:
            cfg = wasmtime.Config()
            cfg.consume_fuel = True
            engine = wasmtime.Engine(cfg)
            store = wasmtime.Store(engine)
            store.set_fuel(self.fuel_limit)
            module = wasmtime.Module(engine, wasm_bytes)
            linker = wasmtime.Linker(engine)
            linker.define_wasi()
            instance = linker.instantiate(store, module)
            start_fn = instance.exports(store).get("_start")
            if start_fn is not None:
                start_fn(store)
            remaining = store.get_fuel()
            return SandboxExecResult(
                ok=True,
                backend="wasmtime",
                output="ok",
                duration_s=round(time.perf_counter() - t0, 4),
                fuel_consumed=max(0, self.fuel_limit - int(remaining)),
            )
        except Exception as exc:
            return SandboxExecResult(
                ok=False,
                backend="wasmtime",
                error=f"{type(exc).__name__}: {exc}",
                duration_s=round(time.perf_counter() - t0, 4),
            )

    @staticmethod
    def _validate_ast(code: str) -> Optional[str]:
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError as exc:
            return f"SyntaxError: {exc}"
        for node in ast.walk(tree):
            if isinstance(node, _FORBIDDEN_AST_NODES):
                return f"Forbidden AST construct: {type(node).__name__}"
            if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
                return f"Forbidden identifier: {node.id}"
            if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                return f"Forbidden dunder attribute access: {node.attr}"
        return None

    def run_restricted_python(
        self,
        code: str,
        *,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> SandboxExecResult:
        """Deterministic zero-dependency AST-restricted sandbox with no I/O or imports."""
        t0 = time.perf_counter()
        err = self._validate_ast(code)
        if err:
            return SandboxExecResult(
                ok=False,
                backend="python_ast_sandbox",
                error=err,
                duration_s=round(time.perf_counter() - t0, 4),
            )

        env: Dict[str, Any] = {"__builtins__": dict(_SAFE_BUILTINS), "math": math}
        if inputs:
            env.update(inputs)
        buf = io.StringIO()
        try:
            compiled = compile(code, "<wasm_ast_sandbox>", "exec")
            with contextlib.redirect_stdout(buf):
                exec(compiled, env, env)
            return SandboxExecResult(
                ok=True,
                backend="python_ast_sandbox",
                output=buf.getvalue(),
                duration_s=round(time.perf_counter() - t0, 4),
            )
        except Exception as exc:
            return SandboxExecResult(
                ok=False,
                backend="python_ast_sandbox",
                output=buf.getvalue(),
                error=f"{type(exc).__name__}: {exc}",
                duration_s=round(time.perf_counter() - t0, 4),
            )
