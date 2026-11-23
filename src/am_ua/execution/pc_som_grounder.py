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


from am_ua.execution.pc_win32_som import (
    GroundedUIElement, LocatorClause, RobocorpLocatorParser, TransactionalClipboard,
    _Win32InputShim, _get_gui_input_backend, compare_visual_signatures,
    compute_bbox_iou, compute_visual_dhash_2048, ensure_windows_input_desktop,
    fix_mangled_string, get_screen_resolution, normalize_text,
)

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
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        self.artifact_dir = (
            Path(artifact_dir) if artifact_dir else resolve_omni_temp_dir("pc_som_grounding")
        ).resolve()
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

    def capture_screen(
        self,
        region: Optional[Tuple[int, int, int, int]] = None,
        *,
        target_hwnd: Optional[int] = None,
    ) -> Tuple[Image.Image, Path]:
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
            try:
                from PIL import ImageGrab
                img = ImageGrab.grab(bbox=region, all_screens=False)
            except Exception:
                img = self._capture_via_print_window(target_hwnd=target_hwnd)

        img.save(raw_path)
        return img, raw_path

    @staticmethod
    def _capture_via_print_window(*, target_hwnd: Optional[int] = None) -> Image.Image:
        """Fallback capture using Win32 PrintWindow when screen-DC grab is unavailable."""
        if os.name != "nt":
            return Image.new("RGB", (800, 600), color=(0, 0, 0))
        try:
            import win32gui
            import win32ui

            candidates: List[int] = []
            if target_hwnd:
                candidates.append(int(target_hwnd))
            fg = int(win32gui.GetForegroundWindow() or 0)
            if fg and fg not in candidates:
                candidates.append(fg)

            def _enum_cb(hwnd: int, _: Any) -> bool:
                if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                    l, t, r, b = win32gui.GetWindowRect(hwnd)
                    if (r - l) >= 40 and (b - t) >= 40 and hwnd not in candidates:
                        candidates.append(hwnd)
                return True

            win32gui.EnumWindows(_enum_cb, None)
            for hwnd in candidates:
                l, t, r, b = win32gui.GetWindowRect(hwnd)
                w, h = r - l, b - t
                if w < 40 or h < 40:
                    continue
                hdc = win32gui.GetWindowDC(hwnd)
                if not hdc:
                    continue
                try:
                    mfc = win32ui.CreateDCFromHandle(hdc)
                    save = mfc.CreateCompatibleDC()
                    bmp = win32ui.CreateBitmap()
                    bmp.CreateCompatibleBitmap(mfc, w, h)
                    save.SelectObject(bmp)
                    if ctypes.windll.user32.PrintWindow(hwnd, save.GetSafeHdc(), 2):
                        return Image.frombuffer("RGB", (w, h), bmp.GetBitmapBits(True), "raw", "BGRX", 0, 1)
                finally:
                    try:
                        win32gui.ReleaseDC(hwnd, hdc)
                    except Exception:
                        pass
        except Exception:
            pass
        return Image.new("RGB", (800, 600), color=(0, 0, 0))

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

