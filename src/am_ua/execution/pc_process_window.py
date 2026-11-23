from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
import difflib
import hashlib
import json
import csv
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import time
import unicodedata
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple


def _get_psutil() -> Any:
    try:
        import psutil
        return psutil
    except ImportError:
        return None

import numpy as np
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # optional desktop visual extra (`pillow`)
    Image = ImageDraw = ImageFont = None  # type: ignore[assignment]

from am_ua.governance.seal_guard import ConstitutionalViolationError


from am_ua.execution.pc_win32_som import (
    GroundedUIElement, LocatorClause, RobocorpLocatorParser, TransactionalClipboard,
    _Win32InputShim, _get_gui_input_backend, compare_visual_signatures,
    compute_bbox_iou, compute_visual_dhash_2048, ensure_windows_input_desktop,
    fix_mangled_string, get_screen_resolution, normalize_text,
)

class DesktopProcessWindowOrgan:
    """Manages Windows top-level windows, isolated app launches, and process/port inspection."""

    def __init__(self) -> None:
        self.spawned_pids: Set[int] = set()
        self.spawned_hwnds: Set[int] = set()

    @staticmethod
    def get_active_window() -> Dict[str, Any]:
        """Return foreground window HWND, title, PID, executable, and bounding rectangle."""
        ensure_windows_input_desktop()
        if os.name != "nt":
            return {"hwnd": 0, "title": "", "pid": 0, "rect": [0, 0, 0, 0]}
        try:
            import win32gui
            import win32process
            psutil = _get_psutil()
            hwnd = int(win32gui.GetForegroundWindow())
            if not hwnd:
                return {"hwnd": 0, "title": "", "pid": 0, "rect": [0, 0, 0, 0]}
            title = win32gui.GetWindowText(hwnd) or ""
            rect = list(win32gui.GetWindowRect(hwnd))
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            exe = ""
            if pid > 0 and psutil is not None:
                try:
                    exe = psutil.Process(pid).name()
                except Exception:
                    pass
            return {
                "hwnd": hwnd,
                "title": title,
                "pid": int(pid),
                "executable": exe,
                "rect": rect,
                "class_name": win32gui.GetClassName(hwnd) or "",
            }
        except Exception as exc:
            return {"hwnd": 0, "title": "", "pid": 0, "rect": [0, 0, 0, 0], "error": str(exc)}

    @staticmethod
    def list_windows(title_filter: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        """Enumerate visible top-level windows with PID, executable name, class, and rect."""
        ensure_windows_input_desktop()
        results: List[Dict[str, Any]] = []
        if os.name != "nt":
            return results
        try:
            import win32gui
            import win32process
            psutil = _get_psutil()
            filt_norm = normalize_text(title_filter)

            def enum_cb(hwnd: int, _: Any) -> None:
                if len(results) >= limit:
                    return
                if not win32gui.IsWindowVisible(hwnd):
                    return
                title = (win32gui.GetWindowText(hwnd) or "").strip()
                if not title:
                    return
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                exe = ""
                if pid > 0 and psutil is not None:
                    try:
                        exe = psutil.Process(pid).name()
                    except Exception:
                        pass
                if filt_norm and filt_norm not in normalize_text(title) and filt_norm not in normalize_text(exe):
                    return
                try:
                    rect = list(win32gui.GetWindowRect(hwnd))
                except Exception:
                    rect = [0, 0, 0, 0]
                results.append(
                    {
                        "hwnd": int(hwnd),
                        "title": title,
                        "pid": int(pid),
                        "executable": exe,
                        "class_name": win32gui.GetClassName(hwnd) or "",
                        "rect": rect,
                    }
                )

            win32gui.EnumWindows(enum_cb, None)
        except Exception:
            pass
        return results

    def find_windows_by_locator(self, locator: str) -> List[Dict[str, Any]]:
        """Find top-level windows matching a `robocorp-windows` AST locator."""
        try:
            clauses = RobocorpLocatorParser.parse(locator)
        except ValueError:
            return []
        all_wins = self.list_windows(limit=250)
        matched: List[Dict[str, Any]] = []
        for w in all_wins:
            node = {
                "name": w["title"],
                "control_type": "WindowControl",
                "role": "window",
                "class_name": w.get("class_name", ""),
                "executable": w.get("executable", ""),
                "hwnd": w["hwnd"],
                "depth": 1,
            }
            if RobocorpLocatorParser.matches(node, clauses):
                matched.append(w)
        return matched

    def control_window(
        self,
        locator_or_title: str,
        action: str = "focus",
        *,
        rect: Optional[Tuple[int, int, int, int]] = None,
    ) -> Dict[str, Any]:
        """Focus, restore, minimize, maximize, move_resize, or close (if owned) a window."""
        ensure_windows_input_desktop()
        wins = self.find_windows_by_locator(locator_or_title)
        if not wins:
            wins = self.list_windows(title_filter=locator_or_title)
        if not wins:
            return {"ok": False, "error": f"No visible window matched {locator_or_title!r}"}

        target = wins[0]
        hwnd = int(target["hwnd"])
        pid = int(target.get("pid", 0))

        try:
            import win32con
            import win32gui
            act = action.lower().strip()
            if act == "focus":
                if win32gui.IsIconic(hwnd):
                    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                    time.sleep(0.1)
                try:
                    win32gui.SetForegroundWindow(hwnd)
                except Exception:
                    # Fallback trick: send Alt key tap via ctypes to unlock SetForegroundWindow
                    ctypes.windll.user32.keybd_event(0x12, 0, 0, 0)
                    ctypes.windll.user32.keybd_event(0x12, 0, 2, 0)
                    try:
                        win32gui.SetForegroundWindow(hwnd)
                    except Exception:
                        pass
            elif act == "minimize":
                win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
            elif act == "maximize":
                win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
            elif act == "restore":
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            elif act == "move_resize":
                if not rect or len(rect) != 4:
                    return {"ok": False, "error": "move_resize requires rect=(x, y, width, height)"}
                x, y, w, h = (int(v) for v in rect)
                win32gui.MoveWindow(hwnd, x, y, max(50, w), max(50, h), True)
            elif act == "close":
                if hwnd not in self.spawned_hwnds and pid not in self.spawned_pids:
                    return {
                        "ok": False,
                        "error": (
                            f"Isolation Law: refuses to close unowned user window {target['title']!r} "
                            f"(hwnd={hwnd}, pid={pid}). Only agent-spawned windows may be closed."
                        ),
                    }
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            else:
                return {"ok": False, "error": f"Unsupported window action: {action!r}"}

            time.sleep(0.15)
            return {
                "ok": True,
                "action": act,
                "target": target,
                "active_after": self.get_active_window(),
            }
        except Exception as exc:
            return {"ok": False, "action": action, "target": target, "error": str(exc)}

    def launch_isolated_app(
        self,
        executable_or_cmd: List[str] | str,
        *,
        cwd: Optional[Path | str] = None,
        wait_for_window_s: float = 3.0,
    ) -> Dict[str, Any]:
        """Launch an application in an isolated process and register its PID/HWND ownership."""
        cmd_list = shlex.split(executable_or_cmd) if isinstance(executable_or_cmd, str) else list(executable_or_cmd)
        if not cmd_list:
            raise ValueError("Empty command for launch_isolated_app")

        before_hwnds = {w["hwnd"] for w in self.list_windows(limit=250)}
        proc = subprocess.Popen(
            cmd_list,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.spawned_pids.add(int(proc.pid))

        deadline = time.monotonic() + max(0.2, float(wait_for_window_s))
        new_windows: List[Dict[str, Any]] = []
        while time.monotonic() < deadline:
            time.sleep(0.15)
            curr = self.list_windows(limit=250)
            new_windows = [w for w in curr if w["pid"] == proc.pid or w["hwnd"] not in before_hwnds]
            if new_windows:
                for nw in new_windows:
                    self.spawned_hwnds.add(int(nw["hwnd"]))
                break

        return {
            "ok": True,
            "pid": int(proc.pid),
            "command": cmd_list,
            "windows": new_windows,
        }

    def cleanup_spawned_apps(self) -> Dict[str, Any]:
        """Terminate all remaining agent-spawned processes cleanly."""
        psutil = _get_psutil()
        terminated: List[int] = []
        for pid in list(self.spawned_pids):
            try:
                if psutil is not None:
                    p = psutil.Process(pid)
                    p.terminate()
                    try:
                        p.wait(timeout=2.0)
                    except psutil.TimeoutExpired:
                        p.kill()
                else:
                    os.kill(int(pid), signal.SIGTERM)
                terminated.append(pid)
            except Exception:
                pass
            finally:
                self.spawned_pids.discard(pid)
        self.spawned_hwnds.clear()
        return {"terminated_pids": terminated}

    @staticmethod
    def list_processes(name_filter: str = "", limit: int = 40) -> List[Dict[str, Any]]:
        """List running OS processes sorted by memory usage."""
        psutil = _get_psutil()
        filt = (name_filter or "").strip().lower()
        rows: List[Dict[str, Any]] = []
        if psutil is not None:
            for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent", "status"]):
                try:
                    info = proc.info
                    pname = str(info.get("name") or "")
                    if filt and filt not in pname.lower():
                        continue
                    mem_mb = round((info["memory_info"].rss if info.get("memory_info") else 0) / (1024 * 1024), 2)
                    rows.append(
                        {
                            "pid": int(info["pid"]),
                            "name": pname,
                            "rss_mb": mem_mb,
                            "status": str(info.get("status") or ""),
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        elif os.name == "nt":
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            for parts in csv.reader((proc.stdout or "").splitlines()):
                if len(parts) < 5:
                    continue
                pname = parts[0].strip()
                if filt and filt not in pname.lower():
                    continue
                try:
                    pid = int(parts[1].strip())
                except ValueError:
                    continue
                mem_digits = re.sub(r"[^0-9]", "", parts[4])
                rss_mb = round((int(mem_digits) if mem_digits else 0) / 1024.0, 2)
                rows.append({"pid": pid, "name": pname, "rss_mb": rss_mb, "status": "running"})
        else:
            proc = subprocess.run(
                ["ps", "-eo", "pid=,rss=,comm="],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                try:
                    pid = int(parts[0])
                    rss_mb = round(int(parts[1]) / 1024.0, 2)
                except ValueError:
                    continue
                pname = parts[2].strip()
                if filt and filt not in pname.lower():
                    continue
                rows.append({"pid": pid, "name": pname, "rss_mb": rss_mb, "status": "running"})
        rows.sort(key=lambda r: r["rss_mb"], reverse=True)
        return rows[:limit]

    @staticmethod
    def find_port_owner(port: int) -> Dict[str, Any]:
        """Identify the process listening on or connected to a local TCP port."""
        psutil = _get_psutil()
        target_port = int(port)
        matches: List[Dict[str, Any]] = []
        try:
            if psutil is not None:
                for conn in psutil.net_connections(kind="tcp"):
                    if conn.laddr and conn.laddr.port == target_port:
                        pid = conn.pid or 0
                        pname = ""
                        if pid > 0:
                            try:
                                pname = psutil.Process(pid).name()
                            except Exception:
                                pass
                        matches.append(
                            {
                                "port": target_port,
                                "ip": conn.laddr.ip,
                                "status": conn.status,
                                "pid": pid,
                                "process_name": pname,
                            }
                        )
            elif os.name == "nt":
                proc = subprocess.run(
                    ["netstat", "-ano", "-p", "tcp"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                    check=False,
                )
                for line in (proc.stdout or "").splitlines():
                    cols = line.strip().split()
                    if len(cols) >= 4 and cols[0].upper() == "TCP":
                        local_addr = cols[1]
                        if ":" in local_addr and local_addr.rsplit(":", 1)[-1] == str(target_port):
                            pid_str = cols[-1]
                            pid = int(pid_str) if pid_str.isdigit() else 0
                            status = cols[3] if len(cols) >= 5 else "UNKNOWN"
                            matches.append(
                                {
                                    "port": target_port,
                                    "ip": local_addr.rsplit(":", 1)[0],
                                    "status": status,
                                    "pid": pid,
                                    "process_name": "",
                                }
                            )
            else:
                tcp_path = Path("/proc/net/tcp")
                if tcp_path.is_file():
                    for line in tcp_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                        cols = line.strip().split()
                        if len(cols) >= 4 and ":" in cols[1]:
                            hex_ip, hex_port = cols[1].split(":", 1)
                            if int(hex_port, 16) == target_port:
                                matches.append(
                                    {
                                        "port": target_port,
                                        "ip": hex_ip,
                                        "status": cols[3],
                                        "pid": 0,
                                        "process_name": "",
                                    }
                                )
        except Exception as exc:
            return {"port": target_port, "matches": matches, "error": str(exc)}
        return {"port": target_port, "matches": matches, "in_use": len(matches) > 0}


# ---------------------------------------------------------------------------
# 5. Unified Closed-Loop PCAutomationEngine
# ---------------------------------------------------------------------------

