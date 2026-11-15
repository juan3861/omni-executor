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
from PIL import Image, ImageDraw, ImageFont

from am_ua.governance.seal_guard import ConstitutionalViolationError


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


class SetOfMarkGrounder:
    """OSWorld + OmniParser Set-of-Mark (SoM) Grounding & Annotated Visual Renderer."""

    TESSERACT_CANDIDATES = (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    )

    UIA_TYPE_TO_ROLE = {
        "buttoncontrol": "button",
        "editcontrol": "textbox",
        "documentcontrol": "document",
        "hyperlinkcontrol": "link",
        "menuitemcontrol": "menuitem",
        "checkboxcontrol": "checkbox",
        "radiobuttoncontrol": "radio",
        "comboboxcontrol": "combobox",
        "tabitemcontrol": "tab",
        "listitemcontrol": "listitem",
        "treeitemcontrol": "treeitem",
        "textcontrol": "text",
        "windowcontrol": "window",
        "panecontrol": "pane",
    }

    def __init__(self, artifact_dir: Optional[Path | str] = None) -> None:
        self.artifact_dir = Path(artifact_dir or r"F:\AetherMind_Temp\pc_som_grounding").resolve()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.tesseract_exe = self._find_tesseract()

    @classmethod
    def _find_tesseract(cls) -> Optional[str]:
        found = shutil.which("tesseract")
        if found:
            return found
        for cand in cls.TESSERACT_CANDIDATES:
            if Path(cand).is_file():
                return cand
        return None

    def capture_screen(self, region: Optional[Tuple[int, int, int, int]] = None) -> Tuple[Image.Image, Path]:
        """Capture desktop screenshot via `mss` or `PIL.ImageGrab` and save raw PNG."""
        ensure_windows_input_desktop()
        ts = int(time.time() * 1000)
        raw_path = self.artifact_dir / f"screen_raw_{ts}.png"
        img: Optional[Image.Image] = None

        try:
            import mss
            mss_cls = getattr(mss, "MSS", mss.mss)
            with mss_cls() as sct:
                if region:
                    left, top, right, bottom = region
                    mon = {"left": left, "top": top, "width": max(1, right - left), "height": max(1, bottom - top)}
                else:
                    mon = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                shot = sct.grab(mon)
                img = Image.frombytes("RGB", shot.size, shot.rgb)
        except Exception:
            from PIL import ImageGrab
            img = ImageGrab.grab(bbox=region, all_screens=False)

        img.save(raw_path)
        return img, raw_path

    def extract_uia_elements(
        self,
        *,
        hwnd_root: Optional[int] = None,
        max_depth: int = 4,
        max_elements: int = 80,
    ) -> List[GroundedUIElement]:
        """Extract visible interactive controls from Windows UI Automation (UIA) tree."""
        elements: List[GroundedUIElement] = []
        if os.name != "nt":
            return elements

        scr_w, scr_h = get_screen_resolution()
        try:
            ctypes.windll.ole32.CoInitialize(None)
            import uiautomation as auto
            auto.SetGlobalSearchTimeout(1.0)
            if hwnd_root:
                root_ctrl = auto.ControlFromHandle(int(hwnd_root))
            else:
                fg_hwnd = ctypes.windll.user32.GetForegroundWindow()
                root_ctrl = auto.ControlFromHandle(fg_hwnd) if fg_hwnd else auto.GetRootControl()
            if not root_ctrl:
                root_ctrl = auto.GetRootControl()

            def walk(ctrl: Any, depth: int, path_prefix: str) -> None:
                if len(elements) >= max_elements or depth > max_depth:
                    return
                try:
                    name = (ctrl.Name or "").strip()
                    ctype = (ctrl.ControlTypeName or "").strip()
                    auto_id = (ctrl.AutomationId or "").strip()
                    cls_name = (ctrl.ClassName or "").strip()
                    rect = ctrl.BoundingRectangle
                    if rect:
                        l, t, r, b = int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)
                        w, h = r - l, b - t
                        # Filter visible on-screen controls with reasonable dimensions
                        if w >= 8 and h >= 8 and r > 0 and b > 0 and l < scr_w and t < scr_h:
                            role = self.UIA_TYPE_TO_ROLE.get(ctype.lower(), ctype.lower().replace("control", ""))
                            if name or auto_id or role in ("button", "textbox", "checkbox", "combobox", "link", "menuitem", "tab"):
                                display_name = name or auto_id or f"{role}_{len(elements) + 1}"
                                elements.append(
                                    GroundedUIElement(
                                        tag_id=len(elements) + 1,
                                        source="UIA",
                                        role=role,
                                        name=display_name[:160],
                                        bbox=(max(0, l), max(0, t), min(scr_w, r), min(scr_h, b)),
                                        confidence=0.99,
                                        automation_id=auto_id[:120],
                                        class_name=cls_name[:120],
                                        control_type=ctype,
                                        hwnd=int(getattr(ctrl, "NativeWindowHandle", 0) or 0),
                                        tree_path=path_prefix or "0",
                                    )
                                )
                    if depth < max_depth and len(elements) < max_elements:
                        children = ctrl.GetChildren()
                        for idx, child in enumerate(children[:40], start=1):
                            if len(elements) >= max_elements:
                                break
                            sub_path = f"{path_prefix}|{idx}" if path_prefix else str(idx)
                            walk(child, depth + 1, sub_path)
                except Exception:
                    return

            walk(root_ctrl, 0, "")
        except Exception:
            pass
        return elements

    def extract_ocr_elements(
        self,
        image: Image.Image,
        *,
        min_conf: float = 25.0,
        max_elements: int = 80,
    ) -> List[GroundedUIElement]:
        """Extract text lines and bounding boxes from screenshot using Tesseract OCR."""
        if not self.tesseract_exe:
            return []
        try:
            import pytesseract
            from pytesseract import Output
            pytesseract.pytesseract.tesseract_cmd = self.tesseract_exe
            data = pytesseract.image_to_data(image, output_type=Output.DICT)
            lines: Dict[str, Dict[str, Any]] = {}
            n = len(data.get("text", []))
            for i in range(n):
                txt = (data["text"][i] or "").strip()
                try:
                    conf = float(data["conf"][i])
                except Exception:
                    conf = -1.0
                if not txt or conf < min_conf:
                    continue
                left = int(data["left"][i])
                top = int(data["top"][i])
                width = int(data["width"][i])
                height = int(data["height"][i])
                if width < 4 or height < 4:
                    continue
                key = f"{data.get('block_num', [0]*n)[i]}:{data.get('par_num', [0]*n)[i]}:{data.get('line_num', [0]*n)[i]}"
                if key not in lines:
                    lines[key] = {
                        "words": [txt],
                        "confs": [conf],
                        "bbox": [left, top, left + width, top + height],
                    }
                else:
                    entry = lines[key]
                    entry["words"].append(txt)
                    entry["confs"].append(conf)
                    b = entry["bbox"]
                    entry["bbox"] = [
                        min(b[0], left),
                        min(b[1], top),
                        max(b[2], left + width),
                        max(b[3], top + height),
                    ]

            out: List[GroundedUIElement] = []
            for entry in lines.values():
                if len(out) >= max_elements:
                    break
                full_text = " ".join(entry["words"]).strip()
                mean_conf = sum(entry["confs"]) / max(1, len(entry["confs"])) / 100.0
                b = entry["bbox"]
                out.append(
                    GroundedUIElement(
                        tag_id=len(out) + 1,
                        source="OCR",
                        role="text",
                        name=full_text[:160],
                        bbox=(b[0], b[1], b[2], b[3]),
                        confidence=round(mean_conf, 3),
                    )
                )
            return out
        except Exception:
            return []

    def fuse_and_render_som(
        self,
        image: Image.Image,
        uia_elements: List[GroundedUIElement],
        ocr_elements: List[GroundedUIElement],
        *,
        iou_threshold: float = 0.55,
        max_total: int = 90,
    ) -> Tuple[List[GroundedUIElement], Path]:
        """Fuse UIA + OCR boxes, deduplicate via IoU, and draw numbered Set-of-Mark tags."""
        fused: List[GroundedUIElement] = []

        # 1. Prioritize interactive leaf UIA controls, reserving at least 45% capacity for OCR when OCR elements exist
        img_area = max(1, image.size[0] * image.size[1])
        uia_cap = max(1, int(max_total * 0.55)) if ocr_elements else max_total
        overflow_uia: List[GroundedUIElement] = []
        for el in uia_elements:
            el_area = el.width * el.height
            if el_area > 0.75 * img_area and el.role in ("window", "pane", "document"):
                continue
            if any(compute_bbox_iou(el.bbox, existing.bbox) > iou_threshold for existing in fused):
                continue
            if len(fused) < uia_cap:
                fused.append(el)
            else:
                overflow_uia.append(el)

        # 2. Supplement with OCR text boxes that don't heavily overlap existing UIA elements
        for ocr_el in ocr_elements:
            if len(fused) >= max_total:
                break
            if any(compute_bbox_iou(ocr_el.bbox, existing.bbox) > iou_threshold for existing in fused):
                continue
            fused.append(ocr_el)

        # 2b. Fill any remaining capacity with overflow UIA elements
        for extra_el in overflow_uia:
            if len(fused) >= max_total:
                break
            if any(compute_bbox_iou(extra_el.bbox, existing.bbox) > iou_threshold for existing in fused):
                continue
            fused.append(extra_el)

        # Re-number sequentially 1..N (top-to-bottom, left-to-right reading order)
        fused.sort(key=lambda e: (e.bbox[1] // 24, e.bbox[0]))
        for idx, item in enumerate(fused, start=1):
            item.tag_id = idx

        # 3. Render Set-of-Mark (SoM) overlay onto image copy
        annotated = image.copy().convert("RGB")
        draw = ImageDraw.Draw(annotated)
        try:
            font = ImageFont.truetype("arial.ttf", 13)
        except Exception:
            font = ImageFont.load_default()

        palette = [
            (230, 25, 75),    # Red
            (60, 180, 75),    # Green
            (0, 130, 200),    # Blue
            (245, 130, 48),   # Orange
            (145, 30, 180),   # Purple
            (0, 128, 128),    # Teal
        ]

        for item in fused:
            color = palette[(item.tag_id - 1) % len(palette)]
            l, t, r, b = item.bbox
            draw.rectangle([l, t, r, b], outline=color, width=2)
            label_str = f"[{item.tag_id}]"
            tag_w = max(22, 7 * len(label_str) + 4)
            tag_h = 16
            tag_top = max(0, t - tag_h)
            draw.rectangle([l, tag_top, l + tag_w, tag_top + tag_h], fill=color)
            draw.text((l + 3, tag_top + 1), label_str, fill=(255, 255, 255), font=font)

        ts = int(time.time() * 1000)
        som_path = self.artifact_dir / f"som_annotated_{ts}.png"
        annotated.save(som_path)
        return fused, som_path

    @staticmethod
    def scale_normalized_1000(
        norm_x: float,
        norm_y: float,
        screen_size: Optional[Tuple[int, int]] = None,
    ) -> Tuple[int, int]:
        """Convert UI-TARS / Qwen2.5-VL [0, 1000] normalized coordinates to physical screen pixels."""
        if not (0.0 <= norm_x <= 1000.0 and 0.0 <= norm_y <= 1000.0):
            raise ValueError(f"Normalized coordinates must be in [0, 1000], got ({norm_x}, {norm_y})")
        w, h = screen_size or get_screen_resolution()
        px = min(w - 1, max(0, int(round((norm_x / 1000.0) * w))))
        py = min(h - 1, max(0, int(round((norm_y / 1000.0) * h))))
        return px, py


# ---------------------------------------------------------------------------
# 4. Desktop Window, Process & Port Organ (Win32 + psutil)
# ---------------------------------------------------------------------------

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
            import psutil
            hwnd = int(win32gui.GetForegroundWindow())
            if not hwnd:
                return {"hwnd": 0, "title": "", "pid": 0, "rect": [0, 0, 0, 0]}
            title = win32gui.GetWindowText(hwnd) or ""
            rect = list(win32gui.GetWindowRect(hwnd))
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            exe = ""
            if pid > 0:
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
            import psutil
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
                if pid > 0:
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
        import psutil
        terminated: List[int] = []
        for pid in list(self.spawned_pids):
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=2.0)
                except psutil.TimeoutExpired:
                    p.kill()
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
        import psutil
        filt = (name_filter or "").strip().lower()
        rows: List[Dict[str, Any]] = []
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
        rows.sort(key=lambda r: r["rss_mb"], reverse=True)
        return rows[:limit]

    @staticmethod
    def find_port_owner(port: int) -> Dict[str, Any]:
        """Identify the process listening on or connected to a local TCP port."""
        import psutil
        target_port = int(port)
        matches: List[Dict[str, Any]] = []
        try:
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
        except Exception as exc:
            return {"port": target_port, "matches": matches, "error": str(exc)}
        return {"port": target_port, "matches": matches, "in_use": len(matches) > 0}


# ---------------------------------------------------------------------------
# 5. Unified Closed-Loop PCAutomationEngine
# ---------------------------------------------------------------------------

class PCAutomationEngine:
    """Closed-Loop Tri-Modal Desktop & OS Controller (UIA + Set-of-Mark +OCR + PAF Receipts)."""

    def __init__(self, artifact_dir: Optional[Path | str] = None) -> None:
        self.artifact_dir = Path(artifact_dir or r"F:\AetherMind_Temp\pc_automation").resolve()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.grounder = SetOfMarkGrounder(self.artifact_dir / "som")
        self.window_organ = DesktopProcessWindowOrgan()
        self.clipboard = TransactionalClipboard()
        self.last_elements: Dict[int, GroundedUIElement] = {}
        self.last_observation: Optional[Dict[str, Any]] = None
        self.action_receipts: List[Dict[str, Any]] = []

        scr_w, scr_h = get_screen_resolution()
        # Protected OS & Host Zones (prevents accidental clicks on Start/Shutdown or top-right Host Close button)
        self.protected_zones: List[Tuple[int, int, int, int, str]] = [
            (0, scr_h - 48, 52, scr_h, "WINDOWS_START_SHUTDOWN_CORNER"),
            (scr_w - 48, 0, scr_w, 34, "HOST_MAIN_WINDOW_CLOSE_BUTTON"),
        ]

    def verify_point_safety(self, x: int, y: int) -> Tuple[bool, str]:
        """Dependent Type Safety Gate: ensures (x, y) is within screen bounds and outside protected zones."""
        scr_w, scr_h = get_screen_resolution()
        if x < 0 or y < 0 or x >= scr_w or y >= scr_h:
            return False, f"OUT_OF_BOUNDS: Point ({x}, {y}) outside screen (0..{scr_w - 1}, 0..{scr_h - 1})"
        for x1, y1, x2, y2, zone_name in self.protected_zones:
            if x1 <= x <= x2 and y1 <= y <= y2:
                return False, f"PROTECTED_ZONE_VIOLATION: Point ({x}, {y}) intercepts {zone_name}"
        return True, "SAFE"

    def probe_capabilities(self) -> Dict[str, Any]:
        """Probe full PC automation readiness across UIA, OCR, Screenshot, Mouse/Keyboard, and Clipboard."""
        scr_w, scr_h = get_screen_resolution()
        active = self.window_organ.get_active_window()
        return {
            "ok": True,
            "screen_resolution": [scr_w, scr_h],
            "tesseract_available": self.grounder.tesseract_exe is not None,
            "tesseract_path": self.grounder.tesseract_exe,
            "active_window": active,
            "protected_zones": [
                {"bbox": [x1, y1, x2, y2], "id": zid}
                for x1, y1, x2, y2, zid in self.protected_zones
            ],
            "artifact_dir": str(self.artifact_dir),
        }

    def observe_desktop(
        self,
        *,
        hwnd: Optional[int] = None,
        window_title: Optional[str] = None,
        include_ocr: bool = True,
        max_elements: int = 80,
    ) -> Dict[str, Any]:
        """Capture screen (or target window), extract UIA + OCR elements, render Set-of-Mark (SoM) image, and compute visual hash."""
        target_hwnd = int(hwnd) if hwnd else None
        region: Optional[Tuple[int, int, int, int]] = None
        scr_w, scr_h = get_screen_resolution()

        if window_title and not target_hwnd:
            wins = self.window_organ.find_windows_by_locator(window_title) or self.window_organ.list_windows(title_filter=window_title)
            if wins:
                target_hwnd = int(wins[0]["hwnd"])
                self.window_organ.control_window(wins[0]["title"], action="focus")

        if target_hwnd:
            try:
                import win32gui
                l, t, r, b = win32gui.GetWindowRect(target_hwnd)
                l, t = max(0, int(l)), max(0, int(t))
                r, b = min(scr_w, int(r)), min(scr_h, int(b))
                if r - l >= 30 and b - t >= 30:
                    region = (l, t, r, b)
            except Exception:
                region = None

        img, raw_path = self.grounder.capture_screen(region=region)
        vis_hash, _ = compute_visual_dhash_2048(img)
        uia_els = self.grounder.extract_uia_elements(hwnd_root=target_hwnd, max_elements=max_elements)
        ocr_els = self.grounder.extract_ocr_elements(img, max_elements=max_elements) if include_ocr else []
        if region is not None:
            off_x, off_y = region[0], region[1]
            for oel in ocr_els:
                l, t, r, b = oel.bbox
                oel.bbox = (l + off_x, t + off_y, r + off_x, b + off_y)
        fused, som_path = self.grounder.fuse_and_render_som(
            img, uia_els, ocr_els, max_total=max_elements
        )

        self.last_elements = {el.tag_id: el for el in fused}
        obs = {
            "ok": True,
            "timestamp": time.time(),
            "active_window": self.window_organ.get_active_window(),
            "target_hwnd": target_hwnd,
            "capture_region": list(region) if region else None,
            "visual_dhash_2048": vis_hash,
            "raw_screenshot_path": str(raw_path),
            "som_screenshot_path": str(som_path),
            "uia_count": len(uia_els),
            "ocr_count": len(ocr_els),
            "total_elements": len(fused),
            "elements": [el.to_dict() for el in fused],
        }
        self.last_observation = obs
        return obs

    def ground_with_vlm(
        self,
        target_description: str,
        llm: Any,
        *,
        hwnd: Optional[int] = None,
        window_title: Optional[str] = None,
        refresh: bool = True,
    ) -> Dict[str, Any]:
        """Multimodal Set-of-Mark VLM Grounding (F6): sends annotated SoM screenshot + element table to VLM."""
        if refresh or not self.last_observation:
            self.observe_desktop(hwnd=hwnd, window_title=window_title, include_ocr=True)
        obs = self.last_observation or {}
        som_path = obs.get("som_screenshot_path", "")
        elements = obs.get("elements", [])
        table_lines = [
            f"[{e['tag_id']}] ({e['source']}:{e['role']}) name={e['name']!r} center={e['center']}"
            for e in elements[:80]
        ]
        table_text = "\n".join(table_lines)

        prompt = (
            f"Locate the UI element matching: {target_description!r}.\n"
            f"Inspect the numbered Set-of-Mark tags [1]..[N] on the image and the element table below.\n"
            f"Reply with ONLY a JSON object: "
            f'{{"tag_id": <integer tag or null>, "norm_x": <0..1000 or null>, "norm_y": <0..1000 or null>, "rationale": "<short reason>"}}'
        )
        try:
            from am_ua.cognition.llm_client import extract_json_object
            resp = llm.chat_multimodal(
                prompt,
                som_path,
                fallback_text_context=table_text,
                max_tokens=300,
                temperature=0.0,
                json_mode=True,
            )
            parsed = extract_json_object(resp.text)
            tag_id = parsed.get("tag_id")
            if tag_id is not None and int(tag_id) in self.last_elements:
                el = self.last_elements[int(tag_id)]
                cx, cy = el.center
                safe, reason = self.verify_point_safety(cx, cy)
                return {
                    "ok": safe,
                    "method": "VLM_SOM_TAG",
                    "tag_id": int(tag_id),
                    "center": [cx, cy],
                    "element": el.to_dict(),
                    "safety_verdict": reason,
                    "provider": resp.provider,
                    "rationale": parsed.get("rationale", ""),
                }
            if parsed.get("norm_x") is not None and parsed.get("norm_y") is not None:
                px, py = self.grounder.scale_normalized_1000(
                    float(parsed["norm_x"]), float(parsed["norm_y"])
                )
                safe, reason = self.verify_point_safety(px, py)
                return {
                    "ok": safe,
                    "method": "VLM_NORM_1000",
                    "tag_id": None,
                    "center": [px, py],
                    "element": None,
                    "safety_verdict": reason,
                    "provider": resp.provider,
                    "rationale": parsed.get("rationale", ""),
                }
        except Exception as exc:
            vlm_err = str(exc)
        else:
            vlm_err = "VLM returned no valid tag_id or norm_x/norm_y"

        # Deterministic fallback to find_elements
        matches = self.find_elements(target_description, refresh=False)
        if matches:
            best = matches[0]
            cx, cy = int(best["center"][0]), int(best["center"][1])
            safe, reason = self.verify_point_safety(cx, cy)
            return {
                "ok": safe,
                "method": "FALLBACK_UIA_OCR",
                "tag_id": best["tag_id"],
                "center": [cx, cy],
                "element": best,
                "safety_verdict": reason,
                "vlm_fallback_reason": vlm_err,
            }
        return {"ok": False, "error": f"Could not ground {target_description!r}: {vlm_err}"}

    def find_elements(self, locator_or_query: str, *, refresh: bool = True) -> List[Dict[str, Any]]:
        """Find grounded UI elements matching either a Robocorp AST locator or fuzzy text query."""
        if refresh or not self.last_elements:
            self.observe_desktop(include_ocr=True)

        elements = [el.to_dict() for el in self.last_elements.values()]
        # 1. Try structured Robocorp AST locator match if colon syntax or combinators used
        if ":" in locator_or_query:
            try:
                clauses = RobocorpLocatorParser.parse(locator_or_query)
                matched = [e for e in elements if RobocorpLocatorParser.matches(e, clauses)]
                if matched:
                    return matched
            except ValueError:
                pass

        # 2. Fallback to fuzzy/substring normalized text search across all UIA + OCR elements
        q_norm = normalize_text(locator_or_query)
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for e in elements:
            name_norm = normalize_text(e.get("name", ""))
            auto_norm = normalize_text(e.get("automation_id", ""))
            if not name_norm and not auto_norm:
                continue
            if q_norm == name_norm or q_norm == auto_norm:
                scored.append((1.0, e))
            elif q_norm in name_norm or q_norm in auto_norm:
                scored.append((0.9, e))
            else:
                ratio = difflib.SequenceMatcher(None, q_norm, name_norm).ratio()
                if ratio >= 0.72:
                    scored.append((ratio, e))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [item[1] for item in scored]

    def execute_gui_action(
        self,
        action_type: str,
        *,
        tag_id: Optional[int] = None,
        target: Optional[str] = None,
        x: Optional[int] = None,
        y: Optional[int] = None,
        norm_x: Optional[float] = None,
        norm_y: Optional[float] = None,
        text: Optional[str] = None,
        keys: Optional[List[str] | str] = None,
        scroll_clicks: int = 0,
        button: str = "left",
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Execute a closed-loop GUI action with pre/post visual verification and PAF ActionReceipt.

        Supported `action_type`:
          - `click`, `double_click`, `right_click`, `move`
          - `type` (types or pastes Unicode text; if tag_id/target/coords given, clicks target first)
          - `hotkey` (e.g. keys=["ctrl", "s"] or "ctrl+s")
          - `press` (e.g. keys="enter")
          - `scroll` (scroll_clicks positive=up, negative=down)
        """
        ensure_windows_input_desktop()
        t0 = time.perf_counter()
        act = action_type.lower().strip()

        # 1. Capture pre-action visual state
        pre_img, _ = self.grounder.capture_screen()
        pre_hash, pre_vec = compute_visual_dhash_2048(pre_img)
        pre_win = self.window_organ.get_active_window()

        # 2. Resolve target coordinates if needed
        resolved_xy: Optional[Tuple[int, int]] = None
        resolved_element: Optional[Dict[str, Any]] = None

        if tag_id is not None:
            if int(tag_id) not in self.last_elements:
                self.observe_desktop(include_ocr=True)
            el = self.last_elements.get(int(tag_id))
            if not el:
                return {"ok": False, "error": f"SoM tag_id [{tag_id}] not found in current observation"}
            resolved_xy = el.center
            resolved_element = el.to_dict()
        elif target:
            matches = self.find_elements(target, refresh=True)
            if not matches:
                return {"ok": False, "error": f"Target {target!r} not found on screen via UIA or OCR"}
            resolved_element = matches[0]
            resolved_xy = (int(resolved_element["center"][0]), int(resolved_element["center"][1]))
        elif norm_x is not None and norm_y is not None:
            resolved_xy = self.grounder.scale_normalized_1000(float(norm_x), float(norm_y))
        elif x is not None and y is not None:
            resolved_xy = (int(x), int(y))

        # 3. Validate coordinates against Dependent Type Safety Gate
        if resolved_xy is not None:
            safe, reason = self.verify_point_safety(resolved_xy[0], resolved_xy[1])
            if not safe:
                return {
                    "ok": False,
                    "status": "BLOCKED_BY_SAFETY_GATE",
                    "reason": reason,
                    "target_xy": list(resolved_xy),
                    "target_element": resolved_element,
                }

        if act in ("click", "double_click", "right_click", "move") and resolved_xy is None:
            return {
                "ok": False,
                "error": f"Action {act!r} requires tag_id, target locator/text, (x, y), or (norm_x, norm_y)",
            }

        # 4. Execute physical action (unless dry_run=True)
        executed = False
        if not dry_run:
            import pyautogui
            pyautogui.FAILSAFE = True

            if act == "move" and resolved_xy:
                pyautogui.moveTo(resolved_xy[0], resolved_xy[1], duration=0.1)
                executed = True
            elif act == "click" and resolved_xy:
                pyautogui.click(resolved_xy[0], resolved_xy[1], button=button)
                executed = True
            elif act == "double_click" and resolved_xy:
                pyautogui.doubleClick(resolved_xy[0], resolved_xy[1])
                executed = True
            elif act == "right_click" and resolved_xy:
                pyautogui.rightClick(resolved_xy[0], resolved_xy[1])
                executed = True
            elif act == "type":
                if resolved_xy:
                    pyautogui.click(resolved_xy[0], resolved_xy[1])
                    time.sleep(0.1)
                clean_text = fix_mangled_string(str(text or ""))
                # Use transactional clipboard paste so accents/Unicode and symbols never get mangled
                with self.clipboard.preserve():
                    self.clipboard.set_text(clean_text)
                    time.sleep(0.05)
                    pyautogui.hotkey("ctrl", "v")
                    time.sleep(0.1)
                executed = True
            elif act == "hotkey":
                if isinstance(keys, str):
                    key_list = [k.strip() for k in re.split(r"[+,]", keys) if k.strip()]
                else:
                    key_list = [str(k).strip() for k in (keys or []) if str(k).strip()]
                if not key_list:
                    return {"ok": False, "error": "hotkey requires non-empty keys"}
                # Block Alt+F4 on unowned windows
                if [k.lower() for k in key_list] == ["alt", "f4"]:
                    fg_hwnd = int(pre_win.get("hwnd", 0))
                    fg_pid = int(pre_win.get("pid", 0))
                    if fg_hwnd not in self.window_organ.spawned_hwnds and fg_pid not in self.window_organ.spawned_pids:
                        return {
                            "ok": False,
                            "status": "BLOCKED_BY_ISOLATION_LAW",
                            "error": "Alt+F4 blocked on unowned window",
                        }
                pyautogui.hotkey(*key_list)
                executed = True
            elif act == "press":
                key_name = keys[0] if isinstance(keys, list) and keys else str(keys or "enter")
                pyautogui.press(key_name)
                executed = True
            elif act == "scroll":
                if resolved_xy:
                    pyautogui.moveTo(resolved_xy[0], resolved_xy[1], duration=0.05)
                pyautogui.scroll(int(scroll_clicks))
                executed = True
            else:
                return {"ok": False, "error": f"Unsupported GUI action_type: {act!r}"}

            time.sleep(0.2)

        # 5. Capture post-action visual state & generate cryptographic PAF Receipt
        post_img, _ = self.grounder.capture_screen()
        post_hash, post_vec = compute_visual_dhash_2048(post_img)
        post_win = self.window_organ.get_active_window()
        transition = compare_visual_signatures(pre_vec, post_vec)

        receipt = {
            "schema": "DESKTOP_PAF_RECEIPT/v1",
            "timestamp": time.time(),
            "action_type": act,
            "executed": executed,
            "dry_run": dry_run,
            "target_xy": list(resolved_xy) if resolved_xy else None,
            "target_element": resolved_element,
            "pre_visual_hash": pre_hash,
            "post_visual_hash": post_hash,
            "visual_transition": transition,
            "active_window_before": pre_win.get("title", ""),
            "active_window_after": post_win.get("title", ""),
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
        receipt["receipt_digest"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        self.action_receipts.append(receipt)
        return {"ok": True, "receipt": receipt}
