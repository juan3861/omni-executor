#!/usr/bin/env python3
"""Provenance-Locked Vendor Sync & Win32 Native Kernel Patcher (P2.1 & P2.2).

Copies `hermes-agent` and `oh-my-hermes v4.0.4` into `F:\\AetherMind_Universal_Agent\\vendor\\`
without touching a single byte of the external source repositories, records SHA-256
origin provenance in `vendor/PROVENANCE_LOCK.json`, and applies the deterministic
Win32 Native Kernel patches to `vendor/hermes_agent`:
  1. `tools/win32_compat.py` (Win32 Job Objects + `msvcrt` file locks)
  2. POSIX `fcntl` / `termios` compatibility shims across all 7 affected modules
  3. `tools/code_execution_tool.py` authenticated `127.0.0.1` TCP + HMAC loopback RPC
  4. `tools/environments/local.py` Win32 JobObject tree-kill + `F:\\AetherMind_Temp`
  5. `gateway/session_context.py` + `tools/registry.py` task-local ContextVars &
     `CHECK_FN_CACHE_BYPASS` unlocking `oh-my-hermes` `browser_bridge.py`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Set

ROOT = Path(__file__).resolve().parents[1]
HERMES_SRC = Path(r"F:\AetherMind_External_Tools\hermes-agent-main\hermes-agent-main")
OMH_SRC = Path(r"F:\AetherMind_Temp\oh-my-hermes_audit")

VENDOR_DIR = ROOT / "vendor"
VENDOR_HERMES = VENDOR_DIR / "hermes_agent"
VENDOR_OMH = VENDOR_DIR / "oh_my_hermes"
PROVENANCE_FILE = VENDOR_DIR / "PROVENANCE_LOCK.json"

SKIP_DIRS: Set[str] = {
    ".git",
    ".github",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "website",
    "docs",
    "tests",
    "benchmarks",
    "assets",
    "docker",
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _copy_filtered_tree(src_root: Path, dst_root: Path) -> Dict[str, str]:
    if not src_root.is_dir():
        raise FileNotFoundError(f"Missing upstream source directory: {src_root}")
    if dst_root.exists():
        shutil.rmtree(dst_root)
    dst_root.mkdir(parents=True, exist_ok=True)

    hashes: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = Path(dirpath).relative_to(src_root)
        target_dir = dst_root / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in filenames:
            if fname.endswith((".pyc", ".pyo", ".png", ".gif", ".mp4", ".webp", ".pdf")):
                continue
            sfile = Path(dirpath) / fname
            if sfile.is_symlink():
                continue
            dfile = target_dir / fname
            shutil.copy2(sfile, dfile)
            rel_key = (rel_dir / fname).as_posix()
            hashes[rel_key] = _sha256_file(dfile)
    return hashes


WIN32_COMPAT_CODE = '''\
"""Win32 Native Kernel Primitives for Hermes Agent (`msvcrt` locks & Job Objects)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import subprocess
from typing import Any, Optional

if os.name == "nt":
    import msvcrt
else:
    msvcrt = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Cross-platform file locking shim (replaces POSIX `fcntl.flock`)
# ---------------------------------------------------------------------------

LOCK_SH = 1
LOCK_EX = 2
LOCK_NB = 4
LOCK_UN = 8


def _fileno(f: Any) -> int:
    return f if isinstance(f, int) else f.fileno()


def flock(f: Any, operation: int) -> None:
    if os.name != "nt":
        import fcntl
        fcntl.flock(f, operation)
        return
    fd = _fileno(f)
    if operation & LOCK_UN:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        mode = msvcrt.LK_NBLCK if (operation & LOCK_NB) else msvcrt.LK_LOCK
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, mode, 1)


def flock_exclusive(f: Any, non_blocking: bool = False) -> None:
    flock(f, LOCK_EX | (LOCK_NB if non_blocking else 0))


def flock_unlock(f: Any) -> None:
    flock(f, LOCK_UN)


# ---------------------------------------------------------------------------
# Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) — Zero Orphans
# ---------------------------------------------------------------------------

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class Win32JobObject:
    """Binds a Popen process and all descendant processes to a kill-on-close Win32 Job."""

    def __init__(self) -> None:
        self._handle: Optional[int] = None
        if os.name == "nt":
            h = ctypes.windll.kernel32.CreateJobObjectW(None, None)
            if h:
                info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                ctypes.windll.kernel32.SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                )
                self._handle = int(h)

    def assign_pid(self, pid: int) -> bool:
        if os.name != "nt" or not self._handle:
            return False
        proc_handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE, False, int(pid)
        )
        if not proc_handle:
            return False
        try:
            ok = ctypes.windll.kernel32.AssignProcessToJobObject(self._handle, proc_handle)
            return bool(ok)
        finally:
            ctypes.windll.kernel32.CloseHandle(proc_handle)

    def terminate(self, exit_code: int = 1, fallback_pid: Optional[int] = None) -> None:
        if os.name == "nt" and self._handle:
            ctypes.windll.kernel32.TerminateJobObject(self._handle, int(exit_code))
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None
        if os.name == "nt" and fallback_pid:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(int(fallback_pid))],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

    def close(self) -> None:
        if os.name == "nt" and self._handle:
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None
'''


def _apply_posix_import_shims(hermes_dir: Path) -> None:
    """Replace bare `import fcntl` and `import termios` with Win32-safe shims."""
    fcntl_targets = [
        "agent/google_oauth.py",
        "agent/shell_hooks.py",
        "cron/scheduler.py",
        "hermes_cli/auth.py",
        "tools/environments/file_sync.py",
    ]
    for rel in fcntl_targets:
        p = hermes_dir / rel
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8")
        txt = re.sub(
            r"^(\s*)import fcntl\s*$",
            r"\1from tools import win32_compat as fcntl",
            txt,
            flags=re.MULTILINE,
        )
        p.write_text(txt, encoding="utf-8")

    for rel in ("tools/terminal_tool.py", "hermes_cli/curses_ui.py"):
        p = hermes_dir / rel
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8")
        txt = re.sub(
            r"^(\s*)import termios\s*$",
            r"\1try:\n\1    import termios\n\1except ImportError:\n\1    termios = None",
            txt,
            flags=re.MULTILINE,
        )
        p.write_text(txt, encoding="utf-8")


def _patch_local_environment_win32(hermes_dir: Path) -> None:
    p = hermes_dir / "tools" / "environments" / "local.py"
    txt = p.read_text(encoding="utf-8")

    # 1. Import Win32JobObject
    txt = txt.replace(
        "from tools.environments.base import BaseEnvironment, _pipe_stdin",
        "from tools.environments.base import BaseEnvironment, _pipe_stdin\nfrom tools.win32_compat import Win32JobObject",
    )

    # 2. Allow F:\AetherMind_Temp in get_temp_dir on Windows
    old_temp_block = '''        for env_var in ("TMPDIR", "TMP", "TEMP"):
            candidate = self.env.get(env_var) or os.environ.get(env_var)
            if candidate and candidate.startswith("/"):
                return candidate.rstrip("/") or "/"'''
    new_temp_block = '''        if _IS_WINDOWS:
            safe_win = r"F:\\AetherMind_Temp"
            os.makedirs(safe_win, exist_ok=True)
            return safe_win.replace("\\\\", "/")
        for env_var in ("TMPDIR", "TMP", "TEMP"):
            candidate = self.env.get(env_var) or os.environ.get(env_var)
            if candidate and candidate.startswith("/"):
                return candidate.rstrip("/") or "/"'''
    if old_temp_block not in txt:
        raise RuntimeError("Unexpected get_temp_dir block in local.py")
    txt = txt.replace(old_temp_block, new_temp_block, 1)

    # 3. Attach Win32JobObject on spawn & kill entire tree in _kill_process
    old_spawn = """        if stdin_data is not None:
            _pipe_stdin(proc, stdin_data)

        return proc"""
    new_spawn = """        if _IS_WINDOWS:
            job = Win32JobObject()
            job.assign_pid(proc.pid)
            proc._win32_job = job  # type: ignore[attr-defined]

        if stdin_data is not None:
            _pipe_stdin(proc, stdin_data)

        return proc"""
    if old_spawn not in txt:
        raise RuntimeError("Unexpected _run_bash return block in local.py")
    txt = txt.replace(old_spawn, new_spawn, 1)

    old_kill = """        try:
            if _IS_WINDOWS:
                proc.terminate()"""
    new_kill = """        try:
            if _IS_WINDOWS:
                job = getattr(proc, "_win32_job", None)
                if job is not None:
                    job.terminate(exit_code=1, fallback_pid=proc.pid)
                else:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                proc.kill()"""
    if old_kill not in txt:
        raise RuntimeError("Unexpected _kill_process block in local.py")
    txt = txt.replace(old_kill, new_kill, 1)
    p.write_text(txt, encoding="utf-8")


def _patch_code_execution_win32_rpc(hermes_dir: Path) -> None:
    """Unlock Hermes Programmatic Tool Calling (PTC) on Windows via TCP+HMAC Loopback."""
    p = hermes_dir / "tools" / "code_execution_tool.py"
    txt = p.read_text(encoding="utf-8")

    # 1. Enable SANDBOX_AVAILABLE on Win32 + import hmac/secrets
    txt = txt.replace(
        "import uuid\n",
        "import hmac\nimport secrets\nimport uuid\n",
        1,
    )
    txt = txt.replace(
        'SANDBOX_AVAILABLE = sys.platform != "win32"',
        "SANDBOX_AVAILABLE = True  # Patched: Win32 uses authenticated 127.0.0.1 TCP+HMAC loopback",
        1,
    )

    # 2. Upgrade _UDS_TRANSPORT_HEADER to support Win32 authenticated loopback TCP
    old_connect = '''def _connect():
    global _sock
    if _sock is None:
        _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _sock.connect(os.environ["HERMES_RPC_SOCKET"])
        _sock.settimeout(300)
    return _sock

def _call(tool_name, args):
    """Send a tool call to the parent process and return the parsed result."""
    conn = _connect()
    request = json.dumps({"tool": tool_name, "args": args}) + "\\\\n"'''

    new_connect = '''def _connect():
    global _sock
    if _sock is None:
        if "HERMES_RPC_TCP_PORT" in os.environ:
            _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _sock.connect(("127.0.0.1", int(os.environ["HERMES_RPC_TCP_PORT"])))
        else:
            _sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            _sock.connect(os.environ["HERMES_RPC_SOCKET"])
        _sock.settimeout(300)
    return _sock

def _call(tool_name, args):
    """Send a tool call to the parent process and return the parsed result."""
    conn = _connect()
    payload = {"tool": tool_name, "args": args}
    if "HERMES_RPC_NONCE" in os.environ:
        payload["rpc_nonce"] = os.environ["HERMES_RPC_NONCE"]
    request = json.dumps(payload) + "\\\\n"'''

    if old_connect not in txt:
        raise RuntimeError("Could not locate _UDS_TRANSPORT_HEADER _connect in code_execution_tool.py")
    txt = txt.replace(old_connect, new_connect, 1)

    # 3. Verify HMAC/nonce in _rpc_server_loop
    old_server_sig = """def _rpc_server_loop(
    server_sock: socket.socket,
    task_id: str,
    tool_call_log: list,
    tool_call_counter: list,   # mutable [int] so the thread can increment
    max_tool_calls: int,
    allowed_tools: frozenset,
):"""
    new_server_sig = """def _rpc_server_loop(
    server_sock: socket.socket,
    task_id: str,
    tool_call_log: list,
    tool_call_counter: list,   # mutable [int] so the thread can increment
    max_tool_calls: int,
    allowed_tools: frozenset,
    expected_rpc_nonce: Optional[str] = None,
):"""
    if old_server_sig not in txt:
        raise RuntimeError("Could not locate _rpc_server_loop signature")
    txt = txt.replace(old_server_sig, new_server_sig, 1)

    old_req_extract = """                tool_name = request.get("tool", "")
                tool_args = request.get("args", {})"""
    new_req_extract = """                if expected_rpc_nonce is not None:
                    got_nonce = str(request.get("rpc_nonce", ""))
                    if not hmac.compare_digest(got_nonce, expected_rpc_nonce):
                        resp = json.dumps({"error": "Unauthorized local RPC call (invalid nonce)"})
                        conn.sendall((resp + "\\n").encode())
                        continue
                tool_name = request.get("tool", "")
                tool_args = request.get("args", {})"""
    if old_req_extract not in txt:
        raise RuntimeError("Could not locate request tool extraction in _rpc_server_loop")
    txt = txt.replace(old_req_extract, new_req_extract, 1)

    # 4. Bind TCP 127.0.0.1:0 on Windows instead of AF_UNIX
    old_bind = """        # --- Start UDS server ---
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(sock_path)
        server_sock.listen(1)

        rpc_thread = threading.Thread(
            target=_rpc_server_loop,
            args=(
                server_sock, task_id, tool_call_log,
                tool_call_counter, max_tool_calls, sandbox_tools,
            ),
            daemon=True,
        )
        rpc_thread.start()"""

    new_bind = """        # --- Start RPC server (TCP 127.0.0.1 + cryptographic nonce on Win32, UDS on POSIX) ---
        _rpc_nonce = secrets.token_hex(32) if _IS_WINDOWS else None
        _rpc_tcp_port = None
        if _IS_WINDOWS:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(("127.0.0.1", 0))
            _rpc_tcp_port = server_sock.getsockname()[1]
        else:
            server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server_sock.bind(sock_path)
        server_sock.listen(1)

        rpc_thread = threading.Thread(
            target=_rpc_server_loop,
            args=(
                server_sock, task_id, tool_call_log,
                tool_call_counter, max_tool_calls, sandbox_tools, _rpc_nonce,
            ),
            daemon=True,
        )
        rpc_thread.start()"""
    if old_bind not in txt:
        raise RuntimeError("Could not locate UDS bind block in code_execution_tool.py")
    txt = txt.replace(old_bind, new_bind, 1)

    old_child_sock = '        child_env["HERMES_RPC_SOCKET"] = sock_path'
    new_child_sock = '''        if _IS_WINDOWS and _rpc_tcp_port is not None and _rpc_nonce is not None:
            child_env["HERMES_RPC_TCP_PORT"] = str(_rpc_tcp_port)
            child_env["HERMES_RPC_NONCE"] = _rpc_nonce
            child_env["TMP"] = r"F:\\AetherMind_Temp"
            child_env["TEMP"] = r"F:\\AetherMind_Temp"
            for _win_key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
                if _win_key in os.environ:
                    child_env[_win_key] = os.environ[_win_key]
        else:
            child_env["HERMES_RPC_SOCKET"] = sock_path'''
    if old_child_sock not in txt:
        raise RuntimeError("Could not locate child_env HERMES_RPC_SOCKET assignment")
    txt = txt.replace(old_child_sock, new_child_sock, 1)

    p.write_text(txt, encoding="utf-8")


def _patch_browser_identity_seam(hermes_dir: Path) -> None:
    """Restore request-scoped ContextVars & CHECK_FN_CACHE_BYPASS required by oh-my-hermes browser_bridge."""
    sc_path = hermes_dir / "gateway" / "session_context.py"
    sc_txt = sc_path.read_text(encoding="utf-8")
    if "_BROWSER_CONTROL_PRINCIPAL" not in sc_txt:
        sc_txt += '''

# --- AetherMind Universal Agent Seam for oh-my-hermes browser_bridge.py ---
_SESSION_ID: ContextVar = ContextVar("HERMES_SESSION_ID", default=None)
_BROWSER_CONTROL_PRINCIPAL: ContextVar = ContextVar("HERMES_BROWSER_PRINCIPAL", default=None)
_BROWSER_CONTROL_TRANSPORT_FAMILY: ContextVar = ContextVar("HERMES_BROWSER_TRANSPORT", default=None)
_SESSION_MESSAGE_ID: ContextVar = ContextVar("HERMES_SESSION_MESSAGE_ID", default=None)
'''
        sc_path.write_text(sc_txt, encoding="utf-8")

    reg_path = hermes_dir / "tools" / "registry.py"
    reg_txt = reg_path.read_text(encoding="utf-8")
    if "CHECK_FN_CACHE_BYPASS" not in reg_txt:
        reg_txt += '''

# --- AetherMind Universal Agent Request-Bound Cache Bypass Seam for OMH ---
from contextvars import ContextVar as _RegContextVar
CHECK_FN_CACHE_BYPASS = "request_bypass"
_CHECK_FN_SCOPE_VAR: _RegContextVar = _RegContextVar("HERMES_CHECK_FN_CACHE_SCOPE", default="default")

def no_cache_check_fn(fn):
    setattr(fn, "_no_cache_check_fn", True)
    return fn

def check_fn_cache_scope() -> str:
    return _CHECK_FN_SCOPE_VAR.get()
'''
        reg_path.write_text(reg_txt, encoding="utf-8")


def sync_vendor_trees() -> Dict[str, object]:
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    hermes_origin_hashes = _copy_filtered_tree(HERMES_SRC, VENDOR_HERMES)
    omh_origin_hashes = _copy_filtered_tree(OMH_SRC, VENDOR_OMH)

    # Apply deterministic Win32 native patches strictly inside vendor/hermes_agent
    (VENDOR_HERMES / "tools" / "win32_compat.py").write_text(WIN32_COMPAT_CODE, encoding="utf-8")
    _apply_posix_import_shims(VENDOR_HERMES)
    _patch_local_environment_win32(VENDOR_HERMES)
    _patch_code_execution_win32_rpc(VENDOR_HERMES)
    _patch_browser_identity_seam(VENDOR_HERMES)

    patched_files = [
        "tools/win32_compat.py",
        "tools/environments/local.py",
        "tools/code_execution_tool.py",
        "gateway/session_context.py",
        "tools/registry.py",
    ]
    patched_hashes = {
        rel: _sha256_file(VENDOR_HERMES / rel)
        for rel in patched_files
    }

    lock_payload = {
        "schema_version": "aethermind_vendor_provenance/v1",
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "hermes_agent": {
                "origin_path": str(HERMES_SRC),
                "license": "MIT",
                "copied_file_count": len(hermes_origin_hashes),
                "origin_tree_digest": hashlib.sha256(
                    json.dumps(hermes_origin_hashes, sort_keys=True).encode("utf-8")
                ).hexdigest(),
                "win32_patched_files_sha256": patched_hashes,
            },
            "oh_my_hermes": {
                "origin_path": str(OMH_SRC),
                "version": "4.0.4",
                "license": "MIT",
                "copied_file_count": len(omh_origin_hashes),
                "origin_tree_digest": hashlib.sha256(
                    json.dumps(omh_origin_hashes, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            },
        },
    }
    PROVENANCE_FILE.write_text(json.dumps(lock_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock_payload


def verify_vendor_provenance() -> bool:
    if not PROVENANCE_FILE.is_file():
        return False
    data = json.loads(PROVENANCE_FILE.read_text(encoding="utf-8"))
    patched = data["sources"]["hermes_agent"]["win32_patched_files_sha256"]
    for rel, exp in patched.items():
        target = VENDOR_HERMES / rel
        if not target.is_file() or _sha256_file(target) != exp:
            return False
    return (VENDOR_OMH / "src" / "plugin_bundle" / "omh" / "plugin.yaml").is_file()


if __name__ == "__main__":
    result = sync_vendor_trees()
    print(json.dumps(result["sources"]["hermes_agent"]["win32_patched_files_sha256"], indent=2))
