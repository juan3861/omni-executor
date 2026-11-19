"""Bridge to the vendored Hermetic MicroVM Sandbox (`vendor/hermetic_sandbox`).

Provides isolated MicroVM/volatile-RAM command & stateful Python execution
when the host runtime (WSL2 on Windows or Linux `/dev/shm`) is available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


class HermeticSandboxBridge:
    """Safe, lazy-loading adapter around `vendor/hermetic_sandbox`."""

    def __init__(self, vendor_dir: Optional[Path | str] = None) -> None:
        root = Path(__file__).resolve().parents[3]
        self.vendor_dir = Path(vendor_dir or (root / "vendor" / "hermetic_sandbox")).resolve()
        self._sandbox_cls: Any = None

    def _ensure_import_path(self) -> None:
        v_str = str(self.vendor_dir)
        if self.vendor_dir.is_dir():
            if v_str in sys.path:
                sys.path.remove(v_str)
            sys.path.insert(0, v_str)

    def _load_sandbox_cls(self) -> Any:
        if self._sandbox_cls is not None:
            return self._sandbox_cls
        self._ensure_import_path()
        prefixes = ("core", "sdk", "engines", "security", "silicon_core", "hermetic_sandbox")
        stashed: Dict[str, Any] = {}
        for k in list(sys.modules.keys()):
            if k in prefixes or any(k.startswith(p + ".") for p in prefixes):
                mod = sys.modules.get(k)
                mod_file = getattr(mod, "__file__", "") or ""
                if str(self.vendor_dir) not in mod_file:
                    stashed[k] = sys.modules.pop(k)
        try:
            import hermetic_sandbox  # type: ignore[import-not-found]

            self._sandbox_cls = getattr(hermetic_sandbox, "Sandbox", None)
            return self._sandbox_cls
        finally:
            for k, mod in stashed.items():
                sys.modules[k] = mod

    def is_installed(self) -> bool:
        if not (self.vendor_dir / "hermetic_sandbox.py").is_file():
            return False
        try:
            return self._load_sandbox_cls() is not None
        except Exception:
            return False

    def is_runtime_ready(self) -> bool:
        if not self.is_installed():
            return False
        if os.name == "nt":
            wsl = shutil.which("wsl.exe")
            if not wsl:
                return False
            try:
                proc = subprocess.run(
                    [wsl, "-l", "-q"],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                return proc.returncode == 0 and bool(proc.stdout.strip())
            except Exception:
                return False
        return Path("/dev/shm").is_dir()

    def status(self) -> Dict[str, Any]:
        installed = self.is_installed()
        ready = self.is_runtime_ready() if installed else False
        return {
            "installed": installed,
            "runtime_ready": ready,
            "vendor_dir": str(self.vendor_dir),
        }

    def run_command(
        self,
        command: str,
        *,
        timeout_s: float = 60.0,
        memory_mb: int = 512,
    ) -> Dict[str, Any]:
        if not self.is_installed():
            return {"ok": False, "error": "Hermetic MicroVM Sandbox is not installed in vendor/hermetic_sandbox"}
        if not self.is_runtime_ready():
            return {"ok": False, "error": "Hermetic MicroVM runtime (WSL2 / /dev/shm) is not ready on this host"}
        Sandbox = self._load_sandbox_cls()
        with Sandbox(template="base", timeout=max(5, int(timeout_s)), memory_mb=memory_mb) as sb:
            res = sb.commands.run(command, timeout=max(5, int(timeout_s)))
            out = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
            return {
                "ok": int(res.exit_code) == 0,
                "exit_code": int(res.exit_code),
                "output": out.strip(),
                "elapsed_ms": float(res.elapsed_ms),
                "sandbox": "hermetic_microvm",
                "session_id": sb.id,
            }

    def run_code(
        self,
        code: str,
        *,
        timeout_s: float = 60.0,
        memory_mb: int = 512,
    ) -> Dict[str, Any]:
        if not self.is_installed():
            return {"ok": False, "error": "Hermetic MicroVM Sandbox is not installed in vendor/hermetic_sandbox"}
        if not self.is_runtime_ready():
            return {"ok": False, "error": "Hermetic MicroVM runtime (WSL2 / /dev/shm) is not ready on this host"}
        Sandbox = self._load_sandbox_cls()
        with Sandbox(template="base", timeout=max(5, int(timeout_s)), memory_mb=memory_mb) as sb:
            res = sb.run_code(code)
            return {
                "ok": bool(getattr(res, "success", True)),
                "stdout": getattr(res, "stdout", ""),
                "stderr": getattr(res, "stderr", ""),
                "result": getattr(res, "result", None),
                "sandbox": "hermetic_microvm",
                "session_id": sb.id,
            }
