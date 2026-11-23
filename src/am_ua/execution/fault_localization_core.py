"""APEX Fault Localization, Guard Synthesis & Windowed ACI (`am_ua.execution.apex_fault_localizer`).

Implements four deterministic, zero-token software fault localization and repair primitives:
1. `OchiaiSBFLFaultLocalizer`: Spectrum-Based Fault Localization (Ochiai & Tarantula formulas).
2. `AgentlessThreePhaseLocalizer`: Zero-token 3-phase file/skeleton/window localizer.
3. `AutoCodeRoverASTGuardSynthesizer`: Deterministic AST hazard detector and guard synthesizer.
4. `SWEAgentWindowedACI`: Stateful workspace-bounded windowed file viewer and searcher.
"""

from __future__ import annotations

import ast
import difflib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


_SKIP_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "vendor",
    "HANDOFF_PACK",
}

_STOP_IDENTIFIERS: Set[str] = {
    "file",
    "line",
    "traceback",
    "most",
    "recent",
    "call",
    "last",
    "error",
    "exception",
    "warning",
    "none",
    "true",
    "false",
    "self",
    "cls",
    "return",
    "import",
    "from",
    "with",
    "that",
    "this",
    "when",
    "into",
    "have",
    "has",
    "are",
    "was",
    "were",
    "for",
    "and",
    "not",
    "the",
    "module",
}

_TRACEBACK_FILE_LINE_RE = re.compile(
    r'File\s+["\']([^"\']+\.py)["\']\s*,\s*line\s+(\d+)(?:\s*,\s*in\s+([A-Za-z_][A-Za-z0-9_.<>]*))?'
)
_COLON_FILE_LINE_RE = re.compile(r"([A-Za-z0-9_.:/\\-]+\.py):(\d+)")
_PY_PATH_RE = re.compile(r"([A-Za-z0-9_.:/\\-]+\.py)\b")
_DEF_CLASS_RE = re.compile(r"\b(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
_CAMEL_CASE_RE = re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+|[A-Z][a-z0-9]{2,})\b")
_SNAKE_CASE_RE = re.compile(r"\b([a-z_][a-z0-9_]*_[a-z0-9_]+)\b")
_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b")

_TYPING_CONTAINER_NAMES: Set[str] = {
    "Any",
    "Annotated",
    "Callable",
    "ClassVar",
    "Dict",
    "Final",
    "FrozenSet",
    "Iterable",
    "Iterator",
    "List",
    "Literal",
    "Mapping",
    "MutableMapping",
    "MutableSequence",
    "Optional",
    "Sequence",
    "Set",
    "Tuple",
    "Type",
    "Union",
    "dict",
    "frozenset",
    "list",
    "set",
    "tuple",
    "type",
}

_SEQUENCE_TYPE_HINTS: Set[str] = {
    "list",
    "tuple",
    "set",
    "frozenset",
    "str",
    "bytes",
    "bytearray",
    "List",
    "Tuple",
    "Sequence",
    "MutableSequence",
}


def _split_location(location: str) -> Tuple[str, Optional[int]]:
    """Split a `file.py:42` location string into `(file_part, line_number)`."""
    if ":" in location:
        prefix, suffix = location.rsplit(":", 1)
        if suffix.isdigit():
            return prefix, int(suffix)
    return location, None


def _normalize_line_item(item: Any) -> Optional[str]:
    """Normalize diverse line coverage items into a canonical `file:line` string."""
    if isinstance(item, str):
        cleaned = item.strip()
        return cleaned or None
    if isinstance(item, (tuple, list)) and len(item) >= 2:
        return f"{item[0]}:{item[1]}"
    if isinstance(item, dict):
        if "location" in item:
            return str(item["location"]).strip() or None
        if "file" in item and "line" in item:
            return f"{item['file']}:{item['line']}"
    return None


def _is_test_passed(entry: Dict[str, Any]) -> bool:
    """Determine whether a test-run record represents a passing test."""
    if "passed" in entry:
        return bool(entry["passed"])
    if "failed" in entry:
        return not bool(entry["failed"])
    if "status" in entry:
        return str(entry["status"]).strip().lower() in {"pass", "passed", "ok", "true", "success"}
    return True


def _extract_run_lines(entry: Dict[str, Any]) -> Set[str]:
    """Extract deduplicated normalized line locations executed in one test run."""
    raw = (
        entry.get("lines")
        if "lines" in entry
        else entry.get("covered")
        if "covered" in entry
        else entry.get("executed")
        if "executed" in entry
        else entry.get("locations")
        if "locations" in entry
        else []
    )
    out: Set[str] = set()
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            norm = _normalize_line_item(item)
            if norm:
                out.add(norm)
    return out


class OchiaiSBFLFaultLocalizer:
    """Spectrum-Based Fault Localization (SBFL) engine supporting Ochiai and Tarantula."""

    SUPPORTED_FORMULAS: Tuple[str, ...] = ("ochiai", "tarantula")

    def rank_suspicious_lines(
        self,
        coverage_matrix: Union[Dict[str, Dict[str, Any]], Dict[str, Any], Sequence[Dict[str, Any]]],
        *,
        formula: str = "ochiai",
    ) -> Dict[str, Any]:
        """Rank covered lines by suspiciousness using Ochiai or Tarantula SBFL.

        Accepts:
        - A mapping `{location: {"ef": int, "nf": int, "ep": int, "np": int}}`
        - A mapping `{test_id: {"passed": bool, "lines": [...]}}`
        - A list of `{"location": str, "ef": int, "nf": int, "ep": int, "np": int}`
        - A list of test runs `{"passed": bool, "lines": [...]}`
        - A wrapper dict containing `"locations"`, `"specs"`, `"tests"`, `"runs"`, or `"test_runs"`.
        """
        formula_norm = str(formula or "ochiai").strip().lower()
        if formula_norm not in self.SUPPORTED_FORMULAS:
            return {
                "ok": False,
                "formula": formula_norm,
                "error": f"Unsupported SBFL formula '{formula}'; expected 'ochiai' or 'tarantula'.",
                "ranked": [],
            }

        specs, total_fail, total_pass = self._normalize_specs(coverage_matrix)
        if not specs:
            return {
                "ok": True,
                "formula": formula_norm,
                "total_fail": total_fail,
                "total_pass": total_pass,
                "count": 0,
                "ranked": [],
            }

        ranked: List[Dict[str, Any]] = []
        for entry in specs:
            loc = entry["location"]
            ef = max(0, int(entry["ef"]))
            nf = max(0, int(entry["nf"]))
            ep = max(0, int(entry["ep"]))
            np_val = max(0, int(entry["np"]))

            line_total_fail = (ef + nf) if (ef + nf) > 0 else total_fail
            line_total_pass = (ep + np_val) if (ep + np_val) > 0 else total_pass

            if formula_norm == "ochiai":
                denom = math.sqrt((ef + nf) * (ef + ep))
                score = 0.0 if denom <= 0.0 else (ef / denom)
            else:
                fail_ratio = (ef / line_total_fail) if line_total_fail > 0 else 0.0
                pass_ratio = (ep / line_total_pass) if line_total_pass > 0 else 0.0
                denom = fail_ratio + pass_ratio
                score = 0.0 if (line_total_fail <= 0 or denom <= 0.0) else (fail_ratio / denom)

            file_part, line_no = _split_location(loc)
            ranked.append(
                {
                    "location": loc,
                    "file": file_part,
                    "line": line_no,
                    "score": round(score, 6),
                    "ef": ef,
                    "nf": nf,
                    "ep": ep,
                    "np": np_val,
                }
            )

        ranked.sort(
            key=lambda item: (
                -item["score"],
                -item["ef"],
                item["ep"],
                item["file"],
                item["line"] if item["line"] is not None else 0,
                item["location"],
            )
        )
        for idx, item in enumerate(ranked, start=1):
            item["rank"] = idx

        return {
            "ok": True,
            "formula": formula_norm,
            "total_fail": total_fail,
            "total_pass": total_pass,
            "count": len(ranked),
            "ranked": ranked,
        }

    def _normalize_specs(
        self,
        coverage_matrix: Union[Dict[str, Dict[str, Any]], Dict[str, Any], Sequence[Dict[str, Any]]],
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        if not coverage_matrix:
            return [], 0, 0

        data, exp_fail, exp_pass = self._unwrap_coverage_payload(coverage_matrix)
        if isinstance(data, dict):
            return self._normalize_dict_specs(data, exp_fail, exp_pass)
        if isinstance(data, (list, tuple)):
            return self._normalize_list_specs(data, exp_fail, exp_pass)
        return [], 0, 0

    @staticmethod
    def _unwrap_coverage_payload(payload: Any) -> Tuple[Any, Optional[int], Optional[int]]:
        if not isinstance(payload, dict):
            return payload, None, None
        exp_fail = payload["total_fail"] if isinstance(payload.get("total_fail"), int) else None
        exp_pass = payload["total_pass"] if isinstance(payload.get("total_pass"), int) else None
        for key in ("locations", "specs", "tests", "runs", "test_runs", "coverage", "entries"):
            inner = payload.get(key)
            if isinstance(inner, (list, tuple, dict)) and inner:
                return inner, exp_fail, exp_pass
        return payload, exp_fail, exp_pass

    def _normalize_dict_specs(
        self,
        data: Dict[str, Any],
        exp_fail: Optional[int],
        exp_pass: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        values = [v for v in data.values() if isinstance(v, dict)]
        if not values:
            return [], 0, 0
        run_keys = ("passed", "failed", "status", "lines", "covered", "executed")
        if any(any(k in v for k in run_keys) for v in values):
            return self._specs_from_test_runs(values)
        raw_specs = [
            {"location": str(loc_key), **counts}
            for loc_key, counts in data.items()
            if isinstance(counts, dict)
        ]
        return self._finalize_explicit_specs(raw_specs, exp_fail, exp_pass)

    def _normalize_list_specs(
        self,
        data: Sequence[Any],
        exp_fail: Optional[int],
        exp_pass: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        items = [x for x in data if isinstance(x, dict)]
        if not items:
            return [], 0, 0
        run_keys = ("passed", "failed", "status", "lines", "covered", "executed")
        is_runs = any(
            any(k in item for k in run_keys) and not any(k in item for k in ("ef", "ep"))
            for item in items
        )
        if is_runs:
            return self._specs_from_test_runs(items)
        return self._finalize_explicit_specs(items, exp_fail, exp_pass)

    @staticmethod
    def _specs_from_test_runs(runs: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int, int]:
        total_fail = 0
        total_pass = 0
        ef_counts: Dict[str, int] = {}
        ep_counts: Dict[str, int] = {}
        all_locs: Set[str] = set()

        for run in runs:
            passed = _is_test_passed(run)
            locs = _extract_run_lines(run)
            all_locs.update(locs)
            if passed:
                total_pass += 1
                for loc in locs:
                    ep_counts[loc] = ep_counts.get(loc, 0) + 1
            else:
                total_fail += 1
                for loc in locs:
                    ef_counts[loc] = ef_counts.get(loc, 0) + 1

        specs: List[Dict[str, Any]] = []
        for loc in sorted(all_locs):
            ef = ef_counts.get(loc, 0)
            ep = ep_counts.get(loc, 0)
            specs.append(
                {
                    "location": loc,
                    "ef": ef,
                    "nf": max(0, total_fail - ef),
                    "ep": ep,
                    "np": max(0, total_pass - ep),
                }
            )
        return specs, total_fail, total_pass

    @staticmethod
    def _finalize_explicit_specs(
        raw_specs: Sequence[Dict[str, Any]],
        explicit_total_fail: Optional[int],
        explicit_total_pass: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        inferred_fail = explicit_total_fail or 0
        inferred_pass = explicit_total_pass or 0
        for item in raw_specs:
            ef = int(item.get("ef", 0))
            ep = int(item.get("ep", 0))
            nf = int(item["nf"]) if "nf" in item else 0
            np_val = int(item["np"]) if "np" in item else 0
            inferred_fail = max(inferred_fail, ef + nf, ef)
            inferred_pass = max(inferred_pass, ep + np_val, ep)

        specs: List[Dict[str, Any]] = []
        for item in raw_specs:
            loc = _normalize_line_item(item) or str(item.get("location", "")).strip()
            if not loc:
                continue
            ef = max(0, int(item.get("ef", 0)))
            ep = max(0, int(item.get("ep", 0)))
            nf = max(0, int(item["nf"])) if "nf" in item else max(0, inferred_fail - ef)
            np_val = max(0, int(item["np"])) if "np" in item else max(0, inferred_pass - ep)
            specs.append({"location": loc, "ef": ef, "nf": nf, "ep": ep, "np": np_val})

        return specs, inferred_fail, inferred_pass


