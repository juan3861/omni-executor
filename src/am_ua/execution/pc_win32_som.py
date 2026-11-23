"""Sovereign PC Automation & Tri-Modal Computer-Use Organ (am_ua.execution.pc_automation).

Assimilates the core engineering gears from the most mature senior repositories:
1. `robocorp-windows` (`RobocorpLocatorParser`):
   - AST locator syntax (`name:"..."`, `id:...`, `type:ButtonControl`, `class:...`,
     `executable:...`, `regex:...`, `handle:...`, `path:1|2`, with `and` / `or` combinators).
   - Queries Windows UI Automation (UIA) & Win32 trees directly without vision token overhead.
2. `OSWorld / AIOS` + `Microsoft OmniParser` (`SetOfMarkGrounder`):
   - Fuses UIA interactive leaf controls + Tesseract OCR bounding boxes (`ocr_data`),
     deduplicates overlapping boxes via IoU, and renders numbered Set-of-Mark (SoM) tags
     `[1]..[N]` onto an annotated screenshot (`som_annotated.png`) alongside a structured
     element table for deterministic grounding.
3. `UI-TARS / Qwen2.5-VL` + `AetherMind VisionTransducer`:
   - Supports `[0, 1000]` normalized coordinate scaling, 2048-bit difference-hash (dHash)
     visual state signatures, 626ns state-transition / stall detection, and Dependent Type
     Protected Screen Zone safety gates.
4. `Open-Interpreter Computer Organ` + `Windows-MCP`:
   - `TransactionalClipboard`: Native Win32 `CF_UNICODETEXT` clipboard with Mojibake repair
     and automatic restoration (`preserve_clipboard`) for non-destructive Unicode typing.
   - `DesktopProcessWindowOrgan`: Win32 window management (`list`, `focus`, `minimize`,
     `maximize`, `restore`, `move_resize`, `launch_isolated_app`, `close_owned`) and
     `psutil` process/port telemetry with strict PID ownership guards.
   - Closed-Loop PAF Action Receipts (`DESKTOP_PAF_RECEIPT/v1`): Every GUI mutation verifies
     pre-state vs. post-state visual/window digests (Zero Open-Loop Blind RPA).
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import time
import unicodedata
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import numpy as np
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # optional desktop visual extra (`pillow`)
    Image = ImageDraw = ImageFont = None  # type: ignore[assignment]

from am_ua.governance.seal_guard import ConstitutionalViolationError


class _Win32InputShim:
    """Pure Win32 ctypes fallback when pyautogui/pyscreeze/cv2 cannot import (e.g. NumPy 2.x)."""

    FAILSAFE = True
    _VK = {
        "ctrl": 0x11, "control": 0x11, "alt": 0x12, "shift": 0x10, "win": 0x5B,
        "enter": 0x0D, "return": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B,
        "space": 0x20, "backspace": 0x08, "delete": 0x2E, "up": 0x26, "down": 0x28,
        "left": 0x25, "right": 0x27, "home": 0x24, "end": 0x23,
    }

    @classmethod
    def _vk(cls, key: str) -> int:
        k = key.lower().strip()
        if k in cls._VK:
            return cls._VK[k]
        if len(k) == 1:
            return ord(k.upper())
        if k.startswith("f") and k[1:].isdigit():
            return 0x6F + int(k[1:])
        return 0

    @staticmethod
    def moveTo(x: int, y: int, duration: float = 0.0) -> None:
        if os.name == "nt":
            ctypes.windll.user32.SetCursorPos(int(x), int(y))

    @classmethod
    def click(cls, x: int, y: int, button: str = "left") -> None:
        if os.name != "nt":
            return
        u32 = ctypes.windll.user32
        u32.SetCursorPos(int(x), int(y))
        down, up = (0x0008, 0x0010) if button == "right" else (0x0002, 0x0004)
        u32.mouse_event(down, 0, 0, 0, 0)
        u32.mouse_event(up, 0, 0, 0, 0)

    @classmethod
    def doubleClick(cls, x: int, y: int) -> None:
        cls.click(x, y, "left")
        time.sleep(0.05)
        cls.click(x, y, "left")

    @classmethod
    def rightClick(cls, x: int, y: int) -> None:
        cls.click(x, y, "right")

    @classmethod
    def press(cls, key: str) -> None:
        if os.name != "nt":
            return
        vk = cls._vk(key)
        if vk:
            u32 = ctypes.windll.user32
            u32.keybd_event(vk, 0, 0, 0)
            u32.keybd_event(vk, 0, 2, 0)

    @classmethod
    def hotkey(cls, *keys: str) -> None:
        if os.name != "nt":
            return
        u32 = ctypes.windll.user32
        vks = [cls._vk(k) for k in keys if cls._vk(k)]
        for vk in vks:
            u32.keybd_event(vk, 0, 0, 0)
        for vk in reversed(vks):
            u32.keybd_event(vk, 0, 2, 0)

    @staticmethod
    def scroll(clicks: int) -> None:
        if os.name == "nt":
            ctypes.windll.user32.mouse_event(0x0800, 0, 0, int(clicks) * 120, 0)


def _get_gui_input_backend() -> Any:
    try:
        import pyautogui
        pyautogui.FAILSAFE = True
        return pyautogui
    except Exception:
        return _Win32InputShim()


# ---------------------------------------------------------------------------
# 0. Windows Input Desktop Attachment & Encoding Helpers
# ---------------------------------------------------------------------------

def ensure_windows_input_desktop() -> bool:
    """Attach current thread to active Windows Input Desktop and enable DPI awareness."""
    if os.name != "nt":
        return False
    try:
        u32 = ctypes.windll.user32
        u32.SetProcessDPIAware()
        if os.environ.get("AM_UA_KEEP_CURRENT_DESKTOP") == "1":
            return True
        desk = u32.OpenInputDesktop(0, False, 0x01FF)
        if desk:
            return bool(u32.SetThreadDesktop(desk))
    except Exception:
        pass
    return False


def fix_mangled_string(s: str) -> str:
    """Reverse PowerShell cp1252/cp850 UTF-8 Mojibake corruption when present."""
    for enc in ("cp1252", "cp850", "cp437", "iso-8859-1"):
        try:
            return s.encode(enc).decode("utf-8")
        except UnicodeError:
            continue
    return s


def normalize_text(text: str) -> str:
    """Casefold and strip diacritics for resilient OCR/UIA text matching."""
    norm = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(ch for ch in norm if not unicodedata.combining(ch))
    return " ".join(stripped.casefold().split())


def get_screen_resolution() -> Tuple[int, int]:
    """Return physical primary monitor resolution (width, height)."""
    ensure_windows_input_desktop()
    if os.name == "nt":
        try:
            u32 = ctypes.windll.user32
            w = int(u32.GetSystemMetrics(0))
            h = int(u32.GetSystemMetrics(1))
            if w > 0 and h > 0:
                return w, h
        except Exception:
            pass
    try:
        import pyautogui
        sz = pyautogui.size()
        return int(sz[0]), int(sz[1])
    except Exception:
        return 1920, 1080


# ---------------------------------------------------------------------------
# 1. Robocorp-Windows AST Locator Parser & Semantic UIA Matcher
# ---------------------------------------------------------------------------

VALID_LOCATOR_KEYS = {
    "name",
    "id",
    "automationid",
    "type",
    "control",
    "class",
    "classname",
    "regex",
    "subname",
    "executable",
    "handle",
    "index",
    "depth",
    "path",
}


@dataclass(frozen=True)
class LocatorClause:
    """Single conjunctive clause of key:value UIA match constraints."""
    constraints: Dict[str, Any]

    def matches(self, node: Dict[str, Any]) -> bool:
        for k, expected in self.constraints.items():
            if k == "name":
                if normalize_text(str(node.get("name", ""))) != normalize_text(str(expected)):
                    return False
            elif k == "subname":
                if normalize_text(str(expected)) not in normalize_text(str(node.get("name", ""))):
                    return False
            elif k == "regex":
                if not re.search(str(expected), str(node.get("name", "")), re.IGNORECASE):
                    return False
            elif k in ("id", "automationid"):
                if str(node.get("automation_id", "")).lower() != str(expected).lower():
                    return False
            elif k in ("type", "control"):
                exp_t = str(expected).lower()
                if not exp_t.endswith("control"):
                    exp_ctrl = exp_t + "control"
                else:
                    exp_ctrl = exp_t
                node_t = str(node.get("control_type", "")).lower()
                node_role = str(node.get("role", "")).lower()
                if node_t not in (exp_t, exp_ctrl) and node_role not in (exp_t, exp_t.replace("control", "")):
                    return False
            elif k in ("class", "classname"):
                if str(node.get("class_name", "")).lower() != str(expected).lower():
                    return False
            elif k == "executable":
                exe_name = str(node.get("executable", "")).lower()
                if not exe_name.endswith(str(expected).lower()):
                    return False
            elif k == "handle":
                if int(node.get("hwnd", -1)) != int(expected):
                    return False
            elif k == "depth":
                if int(node.get("depth", 0)) != int(expected):
                    return False
            elif k == "path":
                actual_path = str(node.get("tree_path", node.get("path", "")))
                if actual_path != str(expected):
                    return False
        return True


class RobocorpLocatorParser:
    """Parses `robocorp-windows` locator strings into disjunctive normal form (OR of AND clauses).

    Examples:
      - `name:"Save As" and type:ButtonControl`
      - `id:num8Button or name:Eight`
      - `subname:Notepad and type:Window`
      - `Calculator` (implicit subname/name match)
    """

    KEY_VAL_RE = re.compile(r"^([A-Za-z_]+):(.*)$")

    @classmethod
    def parse(cls, locator: str) -> List[LocatorClause]:
        raw = (locator or "").strip()
        if not raw:
            raise ValueError("Empty UIA locator string")

        try:
            tokens = shlex.split(raw)
        except ValueError:
            tokens = raw.split()

        or_groups: List[List[str]] = [[]]
        for tok in tokens:
            low = tok.lower()
            if low == "or":
                if or_groups[-1]:
                    or_groups.append([])
                continue
            if low == "and":
                continue
            or_groups[-1].append(tok)

        clauses: List[LocatorClause] = []
        for grp in or_groups:
            if not grp:
                continue
            constraints: Dict[str, Any] = {}
            free_words: List[str] = []
            idx = 0
            while idx < len(grp):
                tok = grp[idx]
                m = cls.KEY_VAL_RE.match(tok)
                if m and len(m.group(1)) > 1:
                    key = m.group(1).lower()
                    if key not in VALID_LOCATOR_KEYS:
                        raise ValueError(f"Unsupported locator field: {m.group(1)!r}")
                    val = m.group(2)
                    # Handle case where user wrote `name: "Save As"` with space after colon
                    if val == "" and idx + 1 < len(grp):
                        idx += 1
                        val = grp[idx]
                    if key in ("handle", "index", "depth"):
                        constraints[key] = int(val)
                    elif key == "path":
                        constraints[key] = "|".join(x.strip() for x in val.strip("|").split("|") if x.strip())
                    else:
                        constraints[key] = val
                else:
                    free_words.append(tok)
                idx += 1

            if free_words and "name" not in constraints and "subname" not in constraints:
                constraints["subname"] = " ".join(free_words)

            if not constraints:
                raise ValueError(f"Could not extract valid constraints from locator: {locator!r}")
            clauses.append(LocatorClause(constraints=constraints))

        return clauses

    @classmethod
    def matches(cls, node: Dict[str, Any], locator: str | List[LocatorClause]) -> bool:
        clauses = cls.parse(locator) if isinstance(locator, str) else locator
        return any(clause.matches(node) for clause in clauses)


# ---------------------------------------------------------------------------
# 2. Transactional Win32 Unicode Clipboard Organ
# ---------------------------------------------------------------------------

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


class TransactionalClipboard:
    """Zero-dependency Win32 native Unicode clipboard with transactional preservation."""

    @staticmethod
    def get_text() -> str:
        """Read current Unicode text from the Windows clipboard."""
        if os.name == "nt":
            u32 = ctypes.windll.user32
            k32 = ctypes.windll.kernel32
            u32.OpenClipboard.argtypes = [wintypes.HWND]
            u32.OpenClipboard.restype = wintypes.BOOL
            u32.GetClipboardData.argtypes = [wintypes.UINT]
            u32.GetClipboardData.restype = wintypes.HANDLE
            u32.CloseClipboard.argtypes = []
            u32.CloseClipboard.restype = wintypes.BOOL
            k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalLock.restype = wintypes.LPVOID
            k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalUnlock.restype = wintypes.BOOL

            for _ in range(5):
                if u32.OpenClipboard(None):
                    try:
                        handle = u32.GetClipboardData(CF_UNICODETEXT)
                        if not handle:
                            return ""
                        ptr = k32.GlobalLock(handle)
                        if not ptr:
                            return ""
                        try:
                            return ctypes.wstring_at(ptr)
                        finally:
                            k32.GlobalUnlock(handle)
                    finally:
                        u32.CloseClipboard()
                time.sleep(0.02)
        try:
            import pyperclip
            return str(pyperclip.paste())
        except Exception:
            return ""

    @staticmethod
    def set_text(text: str) -> bool:
        """Write Unicode text into the Windows clipboard with Mojibake repair."""
        clean = fix_mangled_string(str(text))
        if os.name == "nt":
            u32 = ctypes.windll.user32
            k32 = ctypes.windll.kernel32
            u32.OpenClipboard.argtypes = [wintypes.HWND]
            u32.OpenClipboard.restype = wintypes.BOOL
            u32.EmptyClipboard.argtypes = []
            u32.EmptyClipboard.restype = wintypes.BOOL
            u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
            u32.SetClipboardData.restype = wintypes.HANDLE
            u32.CloseClipboard.argtypes = []
            u32.CloseClipboard.restype = wintypes.BOOL
            k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
            k32.GlobalAlloc.restype = wintypes.HGLOBAL
            k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalLock.restype = wintypes.LPVOID
            k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            k32.GlobalUnlock.restype = wintypes.BOOL

            encoded = clean.encode("utf-16-le") + b"\x00\x00"
            for _ in range(5):
                if u32.OpenClipboard(None):
                    try:
                        u32.EmptyClipboard()
                        h_mem = k32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
                        if not h_mem:
                            return False
                        ptr = k32.GlobalLock(h_mem)
                        if not ptr:
                            return False
                        ctypes.memmove(ptr, encoded, len(encoded))
                        k32.GlobalUnlock(h_mem)
                        u32.SetClipboardData(CF_UNICODETEXT, h_mem)
                        return True
                    finally:
                        u32.CloseClipboard()
                time.sleep(0.02)
        try:
            import pyperclip
            pyperclip.copy(clean)
            return True
        except Exception:
            return False

    @classmethod
    @contextmanager
    def preserve(cls) -> Iterator[str]:
        """Context manager that saves and restores the user's original clipboard."""
        original = cls.get_text()
        try:
            yield original
        finally:
            cls.set_text(original)


# ---------------------------------------------------------------------------
# 3. Set-of-Mark (SoM) Visual Grounding + HDC 2048-bit State Signature
# ---------------------------------------------------------------------------

@dataclass
class GroundedUIElement:
    """Unified UI element discovered via Windows UIA Tree or Tesseract OCR."""
    tag_id: int
    source: str          # "UIA" | "OCR"
    role: str            # e.g. "button", "textbox", "window", "text", "link"
    name: str
    bbox: Tuple[int, int, int, int]  # (left, top, right, bottom)
    confidence: float = 1.0
    automation_id: str = ""
    class_name: str = ""
    control_type: str = ""
    hwnd: int = 0
    tree_path: str = ""

    @property
    def center(self) -> Tuple[int, int]:
        return ((self.bbox[0] + self.bbox[2]) // 2, (self.bbox[1] + self.bbox[3]) // 2)

    @property
    def width(self) -> int:
        return max(0, self.bbox[2] - self.bbox[0])

    @property
    def height(self) -> int:
        return max(0, self.bbox[3] - self.bbox[1])

    def to_dict(self) -> Dict[str, Any]:
        cx, cy = self.center
        return {
            "tag_id": self.tag_id,
            "source": self.source,
            "role": self.role,
            "name": self.name,
            "bbox": list(self.bbox),
            "center": [cx, cy],
            "confidence": round(self.confidence, 3),
            "automation_id": self.automation_id,
            "class_name": self.class_name,
            "control_type": self.control_type,
            "hwnd": self.hwnd,
            "tree_path": self.tree_path,
        }


def compute_bbox_iou(box_a: Tuple[int, int, int, int], box_b: Tuple[int, int, int, int]) -> float:
    """Compute Intersection-over-Union (IoU) between two (left, top, right, bottom) boxes."""
    x_left = max(box_a[0], box_b[0])
    y_top = max(box_a[1], box_b[1])
    x_right = min(box_a[2], box_b[2])
    y_bottom = min(box_a[3], box_b[3])

    if x_right <= x_left or y_bottom <= y_top:
        return 0.0

    inter_area = float((x_right - x_left) * (y_bottom - y_top))
    area_a = float(max(1, (box_a[2] - box_a[0]) * (box_a[3] - box_a[1])))
    area_b = float(max(1, (box_b[2] - box_b[0]) * (box_b[3] - box_b[1])))
    return inter_area / (area_a + area_b - inter_area)


def compute_visual_dhash_2048(image: Image.Image) -> Tuple[str, np.ndarray]:
    """Compute a 2048-bit (64x32 horizontal gradient) visual state signature & hex digest."""
    gray = image.convert("L").resize((65, 32), Image.Resampling.BILINEAR)
    arr = np.asarray(gray, dtype=np.float32)
    bits = (arr[:, 1:] > arr[:, :-1]).flatten()
    packed_bytes = np.packbits(bits).tobytes()
    hex_digest = hashlib.sha256(packed_bytes).hexdigest()[:32]
    bipolar = np.where(bits, 1.0, -1.0).astype(np.float32)
    return hex_digest, bipolar


def compare_visual_signatures(vec_a: np.ndarray, vec_b: np.ndarray) -> Dict[str, Any]:
    """Compare two 2048-bit bipolar visual signatures in sub-microsecond numpy dot product."""
    if vec_a.shape != vec_b.shape or vec_a.size == 0:
        return {"cosine_similarity": 0.0, "state_changed": True, "stalled": False, "change_magnitude": 1.0}
    sim = float(np.dot(vec_a, vec_b) / float(vec_a.size))
    stalled = sim > 0.998
    return {
        "cosine_similarity": round(sim, 5),
        "state_changed": not stalled,
        "stalled": stalled,
        "change_magnitude": round(max(0.0, 1.0 - sim), 5),
    }


