"""Sovereign PC Automation & Tri-Modal Computer-Use Organ (`am_ua.execution.pc_automation`)."""

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

from am_ua.execution.pc_som_grounder import SetOfMarkGrounder
from am_ua.execution.pc_process_window import DesktopProcessWindowOrgan

class PCAutomationEngine:
    """Closed-Loop Tri-Modal Desktop & OS Controller (UIA + Set-of-Mark +OCR + PAF Receipts)."""

    def __init__(self, artifact_dir: Optional[Path | str] = None) -> None:
        from am_ua.contracts.contracts import resolve_omni_temp_dir

        self.artifact_dir = (
            Path(artifact_dir) if artifact_dir else resolve_omni_temp_dir("pc_automation")
        ).resolve()
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

        img, raw_path = self.grounder.capture_screen(region=region, target_hwnd=target_hwnd)
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
            pyautogui = _get_gui_input_backend()

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
