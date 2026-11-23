from __future__ import annotations

import ast
import difflib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from am_ua.execution.fault_localization_core import (
    _CAMEL_CASE_RE, _COLON_FILE_LINE_RE, _DEF_CLASS_RE, _IDENT_RE,
    _PY_PATH_RE, _SEQUENCE_TYPE_HINTS, _SKIP_DIRS, _SNAKE_CASE_RE,
    _STOP_IDENTIFIERS, _TRACEBACK_FILE_LINE_RE, _TYPING_CONTAINER_NAMES,
    OchiaiSBFLFaultLocalizer, _extract_run_lines, _is_test_passed,
    _normalize_line_item, _split_location,
)

class SWEAgentWindowedACI:
    """Stateful SWE-agent style windowed file viewer with strict workspace containment."""

    def __init__(self) -> None:
        self.workspace: Optional[Path] = None
        self.current_file: Optional[Path] = None
        self.rel_path: Optional[str] = None
        self.lines: List[str] = []
        self.total_lines: int = 0
        self.start_line: int = 0
        self.end_line: int = 0
        self.window: int = 100

    def open_file(
        self,
        workspace: Union[Path, str],
        file_path: Union[str, Path],
        start_line: int = 1,
        window: int = 100,
    ) -> Dict[str, Any]:
        """Open a file inside `workspace` and view `[start_line, start_line + window - 1]`."""
        ws = Path(workspace).resolve()
        raw_fp = Path(file_path)
        target = (ws / raw_fp).resolve() if not raw_fp.is_absolute() else raw_fp.resolve()

        try:
            rel = target.relative_to(ws).as_posix()
        except ValueError as exc:
            raise PermissionError(f"Path '{file_path}' escapes workspace boundary '{ws}'") from exc

        if not target.exists() or not target.is_file():
            return {"ok": False, "error": f"File not found inside workspace: {rel}", "file": rel}

        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"ok": False, "error": f"Failed to read '{rel}': {exc}", "file": rel}

        self.workspace = ws
        self.current_file = target
        self.rel_path = rel
        self.lines = text.splitlines()
        self.total_lines = len(self.lines)
        self.window = max(1, int(window))

        if self.total_lines == 0:
            self.start_line = 0
            self.end_line = 0
        else:
            clamped_start = max(1, min(int(start_line), self.total_lines))
            self.start_line = clamped_start
            self.end_line = min(self.total_lines, clamped_start + self.window - 1)

        return self._render_window()

    def goto_line(self, line_num: int) -> Dict[str, Any]:
        """Jump the active window to center around `line_num`."""
        if self.current_file is None or self.rel_path is None:
            return {"ok": False, "error": "No file is currently open; call open_file() first."}

        if self.total_lines == 0:
            self.start_line = 0
            self.end_line = 0
            return self._render_window(target_line=0)

        clamped = max(1, min(int(line_num), self.total_lines))
        half = self.window // 2
        max_start = max(1, self.total_lines - self.window + 1)
        self.start_line = max(1, min(clamped - half, max_start))
        self.end_line = min(self.total_lines, self.start_line + self.window - 1)
        return self._render_window(target_line=clamped)

    def scroll_down(self) -> Dict[str, Any]:
        """Advance the window downward by one page without overflowing EOF."""
        if self.current_file is None or self.rel_path is None:
            return {"ok": False, "error": "No file is currently open; call open_file() first."}

        if self.total_lines == 0:
            return self._render_window()

        if self.end_line < self.total_lines:
            max_start = max(1, self.total_lines - self.window + 1)
            self.start_line = min(max_start, self.start_line + self.window)
            self.end_line = min(self.total_lines, self.start_line + self.window - 1)
        return self._render_window()

    def scroll_up(self) -> Dict[str, Any]:
        """Scroll the window upward by one page without underflowing line 1."""
        if self.current_file is None or self.rel_path is None:
            return {"ok": False, "error": "No file is currently open; call open_file() first."}

        if self.total_lines == 0:
            return self._render_window()

        self.start_line = max(1, self.start_line - self.window)
        self.end_line = min(self.total_lines, self.start_line + self.window - 1)
        return self._render_window()

    def search_file(
        self,
        pattern: str,
        *,
        use_regex: Optional[bool] = None,
        case_sensitive: bool = True,
        max_matches: int = 100,
    ) -> Dict[str, Any]:
        """Search the currently open file and return numbered matches and window bounds."""
        if self.current_file is None or self.rel_path is None:
            return {"ok": False, "error": "No file is currently open; call open_file() first."}

        if not pattern:
            return {
                "ok": False,
                "file": self.rel_path,
                "error": "Search pattern must not be empty.",
                "matches": [],
            }

        regex_obj, err = self._compile_search_regex(pattern, use_regex=use_regex, case_sensitive=case_sensitive)
        if err is not None:
            return {"ok": False, "file": self.rel_path, "error": err, "matches": []}

        matches: List[Dict[str, Any]] = []
        limit = max(1, int(max_matches))
        needle = pattern if case_sensitive else pattern.lower()

        for idx, line_txt in enumerate(self.lines, start=1):
            col = self._find_match_column(line_txt, needle=needle, regex_obj=regex_obj, case_sensitive=case_sensitive)
            if col is not None:
                matches.append({"line": idx, "column": col, "text": line_txt, "numbered": f"{idx}: {line_txt}"})
                if len(matches) >= limit:
                    break

        header = f"[File: {self.rel_path} ({self.total_lines} lines total)]"
        return {
            "ok": True,
            "file": self.rel_path,
            "header": header,
            "total_lines": self.total_lines,
            "pattern": pattern,
            "match_count": len(matches),
            "matches": matches,
            "match_lines": [m["line"] for m in matches],
            "numbered_lines": [m["numbered"] for m in matches],
            "window_bounds": {
                "start_line": self.start_line,
                "end_line": self.end_line,
            },
        }

    @staticmethod
    def _compile_search_regex(
        pattern: str,
        *,
        use_regex: Optional[bool],
        case_sensitive: bool,
    ) -> Tuple[Optional[re.Pattern[str]], Optional[str]]:
        looks_like_regex = (
            any(tok in pattern for tok in ("\\s", "\\w", "\\d", "\\b", ".*", ".+", "^", "$", "|"))
            or bool(re.search(r"\[[^\]]*-[^\]]*\]", pattern))
        )
        if not (use_regex is True or (use_regex is None and looks_like_regex)):
            return None, None
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.compile(pattern, flags), None
        except re.error as exc:
            if use_regex is True:
                return None, f"Invalid regex pattern: {exc}"
            return None, None

    @staticmethod
    def _find_match_column(
        line_txt: str,
        *,
        needle: str,
        regex_obj: Optional[re.Pattern[str]],
        case_sensitive: bool,
    ) -> Optional[int]:
        if regex_obj is not None:
            m = regex_obj.search(line_txt)
            return (m.start() + 1) if m is not None else None
        haystack = line_txt if case_sensitive else line_txt.lower()
        pos = haystack.find(needle)
        return (pos + 1) if pos != -1 else None

    def _render_window(self, *, target_line: Optional[int] = None) -> Dict[str, Any]:
        assert self.rel_path is not None
        header = f"[File: {self.rel_path} ({self.total_lines} lines total)]"
        if self.total_lines == 0 or self.start_line == 0:
            numbered_lines: List[str] = []
            lines_above = 0
            lines_below = 0
            rendered = f"{header}\n(empty file)"
        else:
            numbered_lines = [
                f"{ln}: {self.lines[ln - 1]}"
                for ln in range(self.start_line, self.end_line + 1)
            ]
            lines_above = max(0, self.start_line - 1)
            lines_below = max(0, self.total_lines - self.end_line)
            parts = [header]
            if lines_above > 0:
                parts.append(f"({lines_above} more lines above)")
            parts.extend(numbered_lines)
            if lines_below > 0:
                parts.append(f"({lines_below} more lines below)")
            rendered = "\n".join(parts)

        result: Dict[str, Any] = {
            "ok": True,
            "file": self.rel_path,
            "header": header,
            "total_lines": self.total_lines,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "window": self.window,
            "lines_above": lines_above,
            "lines_below": lines_below,
            "at_start": self.start_line <= 1,
            "at_end": self.end_line >= self.total_lines,
            "numbered_lines": numbered_lines,
            "content": rendered,
        }
        if target_line is not None:
            result["target_line"] = target_line
        return result


__all__ = [
    "OchiaiSBFLFaultLocalizer",
    "AgentlessThreePhaseLocalizer",
    "AutoCodeRoverASTGuardSynthesizer",
    "SWEAgentWindowedACI",
]
