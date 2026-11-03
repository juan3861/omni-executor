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
