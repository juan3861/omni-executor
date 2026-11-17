"""Deterministic Tool Output Compressor (src/am_ua/execution/output_compressor.py).

Inspired by Headroom (headroomlabs-ai/headroom) and Caveman (JuliusBrussee/caveman).
Compresses noisy tool observations (pytest logs, verbose browser DOM lists, repeated lines)
before they enter the LLM context window while preserving high-signal lines verbatim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import time
from typing import Any, Dict, List, Optional


_MULTI_BLANK_RX = re.compile(r"\n{3,}")
_ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")


class ToolOutputCompressor:
    """Loss-minimizing compressor for tool observations entering AgentLoop messages."""

    def __init__(self, *, max_obs_chars: int = 12_000, spill_dir: Optional[Path | str] = None) -> None:
        self.max_obs_chars = max_obs_chars
        self.spill_dir = Path(spill_dir or r"F:\AetherMind_Temp\tool_spill")
        self.total_chars_before = 0
        self.total_chars_after = 0
        self.spill_files: List[str] = []

    def compress_tool_payload(self, tool: str, obs: Any) -> str:
        """Return a compact JSON/text representation optimized for LLM attention."""
        if not isinstance(obs, dict):
            raw = str(obs)
            return self._track(raw, self._clip_text(raw, self.max_obs_chars))

        compact: Dict[str, Any] = dict(obs)

        if tool in ("browser_observe", "browser_act"):
            # Strip heavy proof file paths if present, keep concise indexed DOM
            if "observation" in compact and isinstance(compact["observation"], dict):
                sub = dict(compact["observation"])
                sub.pop("f12_dom_path", None)
                sub.pop("visual_screenshot_path", None)
                if isinstance(sub.get("elements"), list):
                    sub["elements"] = self._slim_dom_elements(sub["elements"])
                compact["observation"] = sub
            compact.pop("f12_dom_path", None)
            compact.pop("visual_screenshot_path", None)
            if isinstance(compact.get("elements"), list):
                compact["elements"] = self._slim_dom_elements(compact["elements"])

        elif tool == "run":
            out = str(compact.get("output", ""))
            compact["output"] = self._compress_command_output(out)

        elif tool in ("pc_observe", "pc_ground_vlm"):
            if isinstance(compact.get("elements"), list) and len(compact["elements"]) > 40:
                compact["elements"] = compact["elements"][:40]

        raw_full = json.dumps(obs, ensure_ascii=False, default=str)
        slim_str = json.dumps(compact, ensure_ascii=False, default=str)
        final_str = self._clip_text(slim_str, self.max_obs_chars)
        return self._track(raw_full, final_str)

    @staticmethod
    def _slim_dom_elements(elements: List[Any], limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for el in elements[:limit]:
            if not isinstance(el, dict):
                continue
            item = {k: el[k] for k in ("idx", "tag", "type", "name", "text", "placeholder") if el.get(k)}
            if item:
                out.append(item)
        return out

    @staticmethod
    def _compress_command_output(text: str) -> str:
        cleaned = _ANSI_RX.sub("", text or "")
        cleaned = _MULTI_BLANK_RX.sub("\n\n", cleaned)
        lines = cleaned.splitlines()
        if len(lines) <= 80:
            return cleaned
        # Deduplicate repeated consecutive lines (common in progress/install/test loops)
        deduped: List[str] = []
        repeat_count = 0
        prev = None
        for ln in lines:
            if ln == prev:
                repeat_count += 1
            else:
                if repeat_count > 0:
                    deduped.append(f"... [repeated {repeat_count}x]")
                    repeat_count = 0
                deduped.append(ln)
                prev = ln
        if repeat_count > 0:
            deduped.append(f"... [repeated {repeat_count}x]")
        if len(deduped) > 90:
            return "\n".join(deduped[:30] + [f"... [{len(deduped) - 85} middle lines compressed] ..."] + deduped[-55:])
        return "\n".join(deduped)

    def _clip_text(self, text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        spill_note = ""
        try:
            self.spill_dir.mkdir(parents=True, exist_ok=True)
            sp = self.spill_dir / f"spill_{int(time.time() * 1000)}_{len(text)}.log"
            sp.write_text(text, encoding="utf-8", errors="replace")
            self.spill_files.append(str(sp))
            spill_note = f"; full output saved to {sp}"
        except OSError:
            pass
        head = limit * 2 // 3
        return text[:head] + f"\n... [{len(text) - limit} chars omitted{spill_note}] ...\n" + text[-(limit - head) :]

    def _track(self, before: str, after: str) -> str:
        self.total_chars_before += len(before)
        self.total_chars_after += len(after)
        return after

    def stats(self) -> Dict[str, Any]:
        saved = max(0, self.total_chars_before - self.total_chars_after)
        ratio = round(saved / self.total_chars_before, 4) if self.total_chars_before else 0.0
        return {
            "chars_before": self.total_chars_before,
            "chars_after": self.total_chars_after,
            "chars_saved": saved,
            "compression_ratio": ratio,
        }
