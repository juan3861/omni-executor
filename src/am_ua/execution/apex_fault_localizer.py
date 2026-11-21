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


class AgentlessThreePhaseLocalizer:
    """Zero-token Agentless 3-phase localizer: file ranking -> AST skeletons -> code windows."""

    SKIP_DIRS: Set[str] = set(_SKIP_DIRS)

    def localize(
        self,
        workspace: Union[Path, str],
        *,
        query_or_traceback: str,
        top_k_files: int = 3,
        window: int = 15,
    ) -> Dict[str, Any]:
        """Localize suspicious files, AST symbols, and numbered code windows deterministically."""
        ws = Path(workspace).resolve()
        if not ws.exists() or not ws.is_dir():
            return {
                "ok": False,
                "error": f"Workspace directory does not exist: {workspace}",
                "phase1_ranked_files": [],
                "phase2_skeletons": {},
                "phase3_windows": [],
            }

        top_k = max(1, int(top_k_files))
        win = max(0, int(window))
        query = str(query_or_traceback or "")

        parsed = self._parse_query_and_traceback(query)
        py_files = self._collect_python_files(ws)

        # Phase 1: Rank `.py` files
        scored_files: List[Dict[str, Any]] = []
        file_cache: Dict[str, Tuple[List[str], str, Optional[ast.AST]]] = {}

        for fpath in py_files:
            rel = fpath.relative_to(ws).as_posix()
            try:
                if fpath.stat().st_size > 2_000_000:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = text.splitlines()
            try:
                tree: Optional[ast.AST] = ast.parse(text)
            except SyntaxError:
                tree = None

            score, matched_ids, tb_lines, matched_subtokens = self._score_file(
                rel=rel,
                text=text,
                lines=lines,
                tree=tree,
                parsed=parsed,
            )
            if score > 0.0:
                file_cache[rel] = (lines, text, tree)
                scored_files.append(
                    {
                        "file": rel,
                        "score": round(score, 4),
                        "matched_identifiers": sorted(matched_ids),
                        "matched_subtokens": sorted(matched_subtokens),
                        "traceback_lines": sorted(tb_lines),
                        "line_count": len(lines),
                    }
                )

        scored_files.sort(key=lambda item: (-item["score"], item["file"]))
        phase1_ranked_files = scored_files[:top_k]

        # Phase 2: AST skeleton signatures of top-K files
        phase2_skeletons: Dict[str, Dict[str, Any]] = {}
        for ranked_item in phase1_ranked_files:
            rel = ranked_item["file"]
            lines, text, tree = file_cache[rel]
            phase2_skeletons[rel] = self._extract_ast_skeleton(rel, text, tree)

        # Phase 3: Numbered code windows around matched functions and traceback lines
        phase3_windows: List[Dict[str, Any]] = []
        for ranked_item in phase1_ranked_files:
            rel = ranked_item["file"]
            lines, _, _ = file_cache[rel]
            skeleton = phase2_skeletons[rel]
            windows = self._extract_windows_for_file(
                rel=rel,
                lines=lines,
                skeleton=skeleton,
                traceback_lines=ranked_item["traceback_lines"],
                matched_identifiers=set(ranked_item["matched_identifiers"]),
                query_identifiers=parsed["identifiers"],
                window=win,
            )
            phase3_windows.extend(windows)

        return {
            "ok": True,
            "query_or_traceback": query,
            "parsed_signals": {
                "traceback_paths": sorted(parsed["path_lines"].keys()),
                "identifiers": sorted(parsed["identifiers"]),
            },
            "phase1_ranked_files": phase1_ranked_files,
            "phase2_skeletons": phase2_skeletons,
            "phase3_windows": phase3_windows,
        }

    def _collect_python_files(self, ws: Path) -> List[Path]:
        out: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(ws):
            dirnames[:] = sorted(d for d in dirnames if d not in self.SKIP_DIRS)
            for fname in sorted(filenames):
                if fname.endswith(".py"):
                    out.append(Path(dirpath) / fname)
        return out

    @staticmethod
    def _normalize_tb_path(raw_path: str) -> str:
        norm = raw_path.strip().replace("\\", "/")
        if len(norm) >= 2 and norm[1] == ":" and norm[0].isalpha():
            norm = norm[2:]
        return norm.lstrip("/")

    def _parse_query_and_traceback(self, text: str) -> Dict[str, Any]:
        path_lines, tb_functions = self._extract_tb_paths_and_funcs(text)
        explicit_defs = set(_DEF_CLASS_RE.findall(text))
        camel_ids = set(_CAMEL_CASE_RE.findall(text))
        snake_ids = set(_SNAKE_CASE_RE.findall(text))
        generic_ids = {
            tok
            for tok in _IDENT_RE.findall(text)
            if tok.lower() not in _STOP_IDENTIFIERS and not tok.endswith(".py")
        }

        identifiers = explicit_defs | tb_functions | camel_ids | snake_ids | generic_ids
        strong_identifiers = explicit_defs | tb_functions | camel_ids | snake_ids
        subtokens = self._extract_subtokens(identifiers)

        return {
            "path_lines": path_lines,
            "tb_functions": tb_functions,
            "explicit_defs": explicit_defs,
            "identifiers": identifiers,
            "strong_identifiers": strong_identifiers,
            "subtokens": subtokens,
        }

    def _extract_tb_paths_and_funcs(self, text: str) -> Tuple[Dict[str, Set[int]], Set[str]]:
        path_lines: Dict[str, Set[int]] = {}
        tb_functions: Set[str] = set()

        for m in _TRACEBACK_FILE_LINE_RE.finditer(text):
            norm = self._normalize_tb_path(m.group(1))
            path_lines.setdefault(norm, set()).add(int(m.group(2)))
            func = (m.group(3) or "").strip()
            if func and not func.startswith("<"):
                tb_functions.update(p for p in func.split(".") if p and p.isidentifier())

        for m in _COLON_FILE_LINE_RE.finditer(text):
            path_lines.setdefault(self._normalize_tb_path(m.group(1)), set()).add(int(m.group(2)))

        for m in _PY_PATH_RE.finditer(text):
            path_lines.setdefault(self._normalize_tb_path(m.group(1)), set())

        return path_lines, tb_functions

    @staticmethod
    def _extract_subtokens(identifiers: Set[str]) -> Set[str]:
        subtokens: Set[str] = set()
        for ident in identifiers:
            for part in re.split(r"_+", ident):
                for sub in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+", part):
                    low = sub.lower()
                    if len(low) >= 3 and low not in _STOP_IDENTIFIERS:
                        subtokens.add(low)
        return subtokens

    def _score_file(
        self,
        *,
        rel: str,
        text: str,
        lines: List[str],
        tree: Optional[ast.AST],
        parsed: Dict[str, Any],
    ) -> Tuple[float, Set[str], Set[int], Set[str]]:
        rel_parts = [p.lower() for p in rel.split("/") if p]
        rel_name = rel_parts[-1] if rel_parts else rel.lower()
        rel_stem = Path(rel).stem.lower()

        path_score, tb_lines = self._score_traceback_paths(
            rel=rel,
            rel_parts=rel_parts,
            rel_name=rel_name,
            line_count=len(lines),
            path_lines=parsed["path_lines"],
        )
        defined_symbols = self._collect_ast_defs(tree)
        ident_score, matched_ids = self._score_identifiers(rel_stem, text, defined_symbols, parsed)
        sub_score, matched_subtokens = self._score_subtokens(rel_stem, defined_symbols, parsed["subtokens"])
        return path_score + ident_score + sub_score, matched_ids, tb_lines, matched_subtokens

    @staticmethod
    def _score_traceback_paths(
        *,
        rel: str,
        rel_parts: List[str],
        rel_name: str,
        line_count: int,
        path_lines: Dict[str, Set[int]],
    ) -> Tuple[float, Set[int]]:
        score = 0.0
        tb_lines: Set[int] = set()
        for tb_path, lines_set in path_lines.items():
            tb_parts = [p.lower() for p in tb_path.split("/") if p]
            if not tb_parts:
                continue
            matched = False
            if rel.lower() == tb_path.lower():
                score += 120.0
                matched = True
            elif len(tb_parts) >= 2 and len(rel_parts) >= 2 and (
                tb_parts[-len(rel_parts) :] == rel_parts or rel_parts[-len(tb_parts) :] == tb_parts
            ):
                score += 75.0 + 15.0 * min(len(tb_parts), len(rel_parts))
                matched = True
            elif tb_parts[-1] == rel_name:
                score += 55.0
                matched = True
            if matched:
                tb_lines.update(ln for ln in lines_set if 1 <= ln <= line_count)
        return score, tb_lines

    @staticmethod
    def _collect_ast_defs(tree: Optional[ast.AST]) -> Set[str]:
        if tree is None:
            return set()
        return {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }

    @staticmethod
    def _score_identifiers(
        rel_stem: str,
        text: str,
        defined_symbols: Set[str],
        parsed: Dict[str, Any],
    ) -> Tuple[float, Set[str]]:
        score = 0.0
        matched_ids: Set[str] = set()
        file_tokens = set(_IDENT_RE.findall(text))
        strong = parsed["strong_identifiers"]
        for ident in parsed["identifiers"]:
            if ident in defined_symbols:
                matched_ids.add(ident)
                score += 30.0 if ident in strong else 20.0
            elif ident in file_tokens:
                matched_ids.add(ident)
                score += 10.0 if ident in strong else 5.0
            if ident.lower() == rel_stem:
                matched_ids.add(ident)
                score += 12.0
        return score, matched_ids

    @staticmethod
    def _score_subtokens(
        rel_stem: str,
        defined_symbols: Set[str],
        subtokens: Set[str],
    ) -> Tuple[float, Set[str]]:
        score = 0.0
        matched: Set[str] = set()
        stem_parts = {p.lower() for p in rel_stem.split("_") if len(p) >= 3}
        def_low = {s.lower() for s in defined_symbols}
        for sub in subtokens:
            if sub in stem_parts:
                score += 4.0
                matched.add(sub)
            elif any(sub in d for d in def_low):
                score += 2.5
                matched.add(sub)
        return score, matched

    @staticmethod
    def _format_func_signature(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> str:
        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        args_str = ast.unparse(node.args)
        ret_str = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
        return f"{prefix} {node.name}({args_str}){ret_str}:"

    def _extract_ast_skeleton(
        self,
        rel: str,
        text: str,
        tree: Optional[ast.AST],
    ) -> Dict[str, Any]:
        if tree is None:
            try:
                tree = ast.parse(text)
            except SyntaxError as exc:
                return {
                    "file": rel,
                    "syntax_ok": False,
                    "error": f"SyntaxError line {exc.lineno}: {exc.msg}",
                    "classes": [],
                    "functions": [],
                }

        classes: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []
        if isinstance(tree, ast.Module):
            self._collect_skeleton_block(tree.body, classes, functions, class_name=None)

        return {
            "file": rel,
            "syntax_ok": True,
            "classes": classes,
            "functions": functions,
        }

    def _collect_skeleton_block(
        self,
        stmts: Sequence[ast.stmt],
        classes: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        *,
        class_name: Optional[str],
    ) -> None:
        compound_types = (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)
        for stmt in stmts:
            if isinstance(stmt, ast.ClassDef):
                self._record_class_skeleton(stmt, classes, functions)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._build_func_entry(stmt, class_name=class_name))
            elif isinstance(stmt, compound_types):
                self._collect_compound_branches(stmt, classes, functions, class_name=class_name)

    def _record_class_skeleton(
        self,
        stmt: ast.ClassDef,
        classes: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
    ) -> None:
        bases = [ast.unparse(b) for b in stmt.bases]
        sig = f"class {stmt.name}({', '.join(bases)}):" if bases else f"class {stmt.name}:"
        cls_methods: List[Dict[str, Any]] = []
        for member in stmt.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                m_entry = self._build_func_entry(member, class_name=stmt.name)
                cls_methods.append(m_entry)
                functions.append(m_entry)
        classes.append(
            {
                "name": stmt.name,
                "start_line": stmt.lineno,
                "end_line": getattr(stmt, "end_lineno", stmt.lineno),
                "bases": bases,
                "signature": sig,
                "methods": cls_methods,
            }
        )

    def _build_func_entry(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        *,
        class_name: Optional[str],
    ) -> Dict[str, Any]:
        qname = f"{class_name}.{node.name}" if class_name else node.name
        return {
            "name": node.name,
            "qualified_name": qname,
            "class_name": class_name,
            "start_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "is_async": isinstance(node, ast.AsyncFunctionDef),
            "signature": self._format_func_signature(node),
        }

    def _collect_compound_branches(
        self,
        stmt: ast.stmt,
        classes: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        *,
        class_name: Optional[str],
    ) -> None:
        self._collect_skeleton_block(getattr(stmt, "body", []), classes, functions, class_name=class_name)
        self._collect_skeleton_block(getattr(stmt, "orelse", []), classes, functions, class_name=class_name)
        self._collect_skeleton_block(getattr(stmt, "finalbody", []), classes, functions, class_name=class_name)
        for handler in getattr(stmt, "handlers", []):
            self._collect_skeleton_block(handler.body, classes, functions, class_name=class_name)

    def _extract_windows_for_file(
        self,
        *,
        rel: str,
        lines: List[str],
        skeleton: Dict[str, Any],
        traceback_lines: Sequence[int],
        matched_identifiers: Set[str],
        query_identifiers: Set[str],
        window: int,
    ) -> List[Dict[str, Any]]:
        total = len(lines)
        if total == 0:
            return []

        anchors = self._collect_window_anchors(
            lines=lines,
            skeleton=skeleton,
            traceback_lines=traceback_lines,
            all_targets=(matched_identifiers | query_identifiers),
        )
        merged = self._merge_window_intervals(rel=rel, anchors=anchors, total=total, window=window)
        return [self._format_window_entry(item, lines) for item in merged]

    @staticmethod
    def _collect_window_anchors(
        *,
        lines: List[str],
        skeleton: Dict[str, Any],
        traceback_lines: Sequence[int],
        all_targets: Set[str],
    ) -> List[Tuple[int, str]]:
        total = len(lines)
        anchors: List[Tuple[int, str]] = [
            (ln, f"traceback:{ln}") for ln in traceback_lines if 1 <= ln <= total
        ]
        for fn in skeleton.get("functions", []):
            cls_name = fn.get("class_name")
            if fn["name"] in all_targets or (cls_name and cls_name in all_targets):
                anchors.append((fn["start_line"], fn["qualified_name"]))
        for cls in skeleton.get("classes", []):
            if cls["name"] in all_targets:
                anchors.append((cls["start_line"], cls["name"]))
        if not anchors and all_targets:
            for idx, line_txt in enumerate(lines, start=1):
                hit = sorted(set(_IDENT_RE.findall(line_txt)) & all_targets)
                if hit:
                    anchors.append((idx, hit[0]))
                    if len(anchors) >= 4:
                        break
        return anchors or [(1, "file_head")]

    @staticmethod
    def _merge_window_intervals(
        *,
        rel: str,
        anchors: List[Tuple[int, str]],
        total: int,
        window: int,
    ) -> List[Dict[str, Any]]:
        intervals = sorted(
            (max(1, a_line - window), min(total, a_line + window), a_line, sym)
            for a_line, sym in anchors[:8]
        )
        merged: List[Dict[str, Any]] = []
        for s, e, anchor_line, sym in intervals:
            if merged and s <= merged[-1]["end_line"] + 1:
                merged[-1]["end_line"] = max(merged[-1]["end_line"], e)
                merged[-1]["anchor_lines"].add(anchor_line)
                merged[-1]["matched_symbols"].add(sym)
            else:
                merged.append(
                    {
                        "file": rel,
                        "start_line": s,
                        "end_line": e,
                        "anchor_lines": {anchor_line},
                        "matched_symbols": {sym},
                    }
                )
        return merged

    @staticmethod
    def _format_window_entry(item: Dict[str, Any], lines: List[str]) -> Dict[str, Any]:
        s = item["start_line"]
        e = item["end_line"]
        numbered = [f"{ln:4d}: {lines[ln - 1]}" for ln in range(s, e + 1)]
        return {
            "file": item["file"],
            "start_line": s,
            "end_line": e,
            "anchor_lines": sorted(item["anchor_lines"]),
            "matched_symbols": sorted(item["matched_symbols"]),
            "numbered_lines": numbered,
            "code": "\n".join(numbered),
        }


class AutoCodeRoverASTGuardSynthesizer:
    """AST-verified deterministic guard patch synthesizer (zero-div, safe .get, None guards)."""

    def synthesize_guards(
        self,
        source_code: str,
        *,
        target_line: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Parse `source_code` and synthesize AST-verified guard candidates for hazards."""
        raw = source_code or ""
        try:
            tree = ast.parse(raw)
        except SyntaxError as exc:
            return {
                "ok": False,
                "error": f"SyntaxError at line {exc.lineno}: {exc.msg}",
                "candidates_count": 0,
                "candidates": [],
            }

        if not raw.strip():
            return {"ok": True, "target_line": target_line, "candidates_count": 0, "candidates": []}

        lines = raw.splitlines(keepends=True)
        ctx: Dict[str, Any] = {
            "raw": raw,
            "lines": lines,
            "line_offsets": self._compute_line_offsets(lines),
            "nl": "\r\n" if "\r\n" in raw else "\n",
            "parent_map": self._build_parent_map(tree),
            "annotation_nodes": self._collect_annotation_nodes(tree),
        }
        ctx["imported"], ctx["classes"], ctx["funcs"] = self._collect_module_symbols(tree)
        ctx["type_hints"] = self._collect_type_annotations(tree, ctx["parent_map"])

        candidates: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[int, str, str]] = set()
        for node in ast.walk(tree):
            cand = self._inspect_ast_node(node, target_line=target_line, ctx=ctx)
            if cand is None:
                continue
            dedup = (cand["line"], cand["hazard_type"], cand["expression"])
            if dedup not in seen_keys:
                seen_keys.add(dedup)
                candidates.append(cand)

        candidates.sort(key=lambda c: (c["line"], c["hazard_type"], c["expression"]))
        for idx, cand in enumerate(candidates, start=1):
            cand["candidate_id"] = f"guard-{idx}"

        return {
            "ok": True,
            "target_line": target_line,
            "candidates_count": len(candidates),
            "candidates": candidates,
        }

    def _inspect_ast_node(
        self,
        node: ast.AST,
        *,
        target_line: Optional[int],
        ctx: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if node in ctx["annotation_nodes"]:
            return None
        lineno = getattr(node, "lineno", None)
        end_lineno = getattr(node, "end_lineno", lineno)
        if lineno is None:
            return None
        if target_line is not None and not (lineno <= target_line <= (end_lineno or lineno)):
            return None

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            return self._synthesize_div_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                nl=ctx["nl"],
                node=node,
                parent_map=ctx["parent_map"],
            )
        if isinstance(node, ast.Subscript):
            return self._synthesize_subscript_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                node=node,
                parent_map=ctx["parent_map"],
                scoped_type_hints=ctx["type_hints"],
            )
        if isinstance(node, ast.Attribute):
            return self._synthesize_attribute_guard(
                raw=ctx["raw"],
                lines=ctx["lines"],
                line_offsets=ctx["line_offsets"],
                nl=ctx["nl"],
                node=node,
                parent_map=ctx["parent_map"],
                imported_names=ctx["imported"],
                defined_classes=ctx["classes"],
                defined_funcs=ctx["funcs"],
            )
        return None

    @staticmethod
    def _compute_line_offsets(lines: List[str]) -> List[int]:
        offsets: List[int] = []
        pos = 0
        for ln in lines:
            offsets.append(pos)
            pos += len(ln)
        return offsets

    @staticmethod
    def _utf8_col_to_char(line_text: str, byte_col: int) -> int:
        raw_bytes = line_text.encode("utf-8")
        clamped = max(0, min(byte_col, len(raw_bytes)))
        return len(raw_bytes[:clamped].decode("utf-8", errors="replace"))

    def _node_char_span(
        self,
        lines: List[str],
        line_offsets: List[int],
        node: ast.AST,
    ) -> Optional[Tuple[int, int]]:
        lineno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        end_lineno = getattr(node, "end_lineno", None)
        end_col = getattr(node, "end_col_offset", None)
        if None in (lineno, col, end_lineno, end_col):
            return None
        if lineno < 1 or end_lineno > len(lines):
            return None
        s_char = line_offsets[lineno - 1] + self._utf8_col_to_char(lines[lineno - 1], col)
        e_char = line_offsets[end_lineno - 1] + self._utf8_col_to_char(lines[end_lineno - 1], end_col)
        if e_char < s_char:
            return None
        return s_char, e_char

    @staticmethod
    def _build_parent_map(tree: ast.AST) -> Dict[int, ast.AST]:
        parents: Dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        return parents

    @staticmethod
    def _collect_annotation_nodes(tree: ast.AST) -> Set[ast.AST]:
        ann_roots: List[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.annotation is not None:
                ann_roots.append(node.annotation)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
                ann_roots.append(node.returns)
            elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
                ann_roots.append(node.annotation)
        ann_nodes: Set[ast.AST] = set()
        for root in ann_roots:
            for sub in ast.walk(root):
                ann_nodes.add(sub)
        return ann_nodes

    @staticmethod
    def _collect_type_annotations(
        tree: ast.AST,
        parent_map: Dict[int, ast.AST],
    ) -> Dict[Tuple[int, str], str]:
        hints: Dict[Tuple[int, str], str] = {}

        def _scope_id(n: ast.AST) -> int:
            curr: Optional[ast.AST] = n
            while curr is not None:
                if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                    return id(curr)
                curr = parent_map.get(id(curr))
            return id(tree)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sid = id(node)
                all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
                if node.args.vararg is not None:
                    all_args.append(node.args.vararg)
                if node.args.kwarg is not None:
                    all_args.append(node.args.kwarg)
                for arg in all_args:
                    if arg.annotation is not None:
                        hints[(sid, arg.arg)] = ast.unparse(arg.annotation)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.annotation is not None:
                hints[(_scope_id(node), node.target.id)] = ast.unparse(node.annotation)
        return hints

    @staticmethod
    def _in_inline_expr_scope(node: ast.AST, parent_map: Dict[int, ast.AST]) -> bool:
        curr: Optional[ast.AST] = parent_map.get(id(node))
        while curr is not None:
            if isinstance(curr, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return True
            if isinstance(curr, (ast.stmt, ast.Module)):
                return False
            curr = parent_map.get(id(curr))
        return False

    @staticmethod
    def _collect_module_symbols(tree: ast.AST) -> Tuple[Set[str], Set[str], Set[str]]:
        imported: Set[str] = set()
        classes: Set[str] = set()
        funcs: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)
            elif isinstance(node, ast.ClassDef):
                classes.add(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.add(node.name)
        return imported, classes, funcs

    @staticmethod
    def _enclosing_stmt_and_func(
        node: ast.AST,
        parent_map: Dict[int, ast.AST],
    ) -> Tuple[Optional[ast.stmt], Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]]]:
        curr: Optional[ast.AST] = node
        enclosing_stmt: Optional[ast.stmt] = None
        enclosing_func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]] = None
        while curr is not None:
            if enclosing_stmt is None and isinstance(curr, ast.stmt):
                enclosing_stmt = curr
            if enclosing_func is None and isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                enclosing_func = curr
            curr = parent_map.get(id(curr))
        return enclosing_stmt, enclosing_func

    @staticmethod
    def _test_guards_expr(test_src: str, target_expr: str, mode: str) -> bool:
        if mode == "none":
            return f"{target_expr} is not None" in test_src or test_src == target_expr
        return f"{target_expr} != 0" in test_src or test_src == target_expr

    @classmethod
    def _has_existing_guard(
        cls,
        node: ast.AST,
        target_expr: str,
        parent_map: Dict[int, ast.AST],
        mode: str,
    ) -> bool:
        curr: Optional[ast.AST] = node
        while curr is not None:
            parent = parent_map.get(id(curr))
            if isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.And):
                for val in parent.values:
                    if val is curr:
                        break
                    if cls._test_guards_expr(ast.unparse(val), target_expr, mode):
                        return True
            elif isinstance(parent, (ast.IfExp, ast.If)):
                if cls._test_guards_expr(ast.unparse(parent.test), target_expr, mode):
                    return True
            curr = parent
        return False

    def _insert_statement_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        stmt: ast.stmt,
        guard_lines: List[str],
    ) -> Optional[Tuple[str, str]]:
        lineno = stmt.lineno
        if lineno < 1 or lineno > len(lines):
            return None
        line_text = lines[lineno - 1]
        char_col = self._utf8_col_to_char(line_text, stmt.col_offset)
        prefix = line_text[:char_col]

        if prefix.lstrip().startswith("elif "):
            return None

        if prefix.strip():
            # Handle single-line suite such as `if cond: return a / b`
            if prefix.rstrip().endswith(":"):
                outer_indent = line_text[: len(line_text) - len(line_text.lstrip(" \t"))]
                inner_indent = outer_indent + "    "
                body_tail = line_text[char_col:].lstrip()
                guard_block = "".join(f"{inner_indent}{gl}{nl}" for gl in guard_lines)
                replacement = f"{prefix.rstrip()}{nl}{guard_block}{inner_indent}{body_tail}"
                s_idx = line_offsets[lineno - 1]
                e_idx = s_idx + len(line_text)
                patched = raw[:s_idx] + replacement + raw[e_idx:]
                return patched, "\n".join(guard_lines)
            return None

        indent = prefix
        guard_block = "".join(f"{indent}{gl}{nl}" for gl in guard_lines)
        insert_pos = line_offsets[lineno - 1]
        patched = raw[:insert_pos] + guard_block + raw[insert_pos:]
        return patched, "\n".join(f"{indent}{gl}" for gl in guard_lines)

    @staticmethod
    def _verify_and_diff(raw: str, patched: str, filename: str = "source.py") -> Optional[str]:
        try:
            ast.parse(patched)
        except SyntaxError:
            return None
        return "".join(
            difflib.unified_diff(
                raw.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )

    @staticmethod
    def _default_guard_action(
        func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]],
        *,
        kind: str,
        expr: str,
    ) -> str:
        if func is None:
            msg = f"Invalid zero divisor: {expr}" if kind == "zero" else f"Unexpected None for: {expr}"
            return f'raise ValueError("{msg}")'
        if kind == "zero":
            if func.returns is not None:
                ret_txt = ast.unparse(func.returns)
                if "None" in ret_txt or "Optional" in ret_txt:
                    return "return None"
                if ret_txt == "int":
                    return "return 0"
                if ret_txt == "float":
                    return "return 0.0"
            return "return 0.0"
        return "return None"

    def _synthesize_div_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.BinOp,
        parent_map: Dict[int, ast.AST],
    ) -> Optional[Dict[str, Any]]:
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float, complex)):
            if node.right.value != 0:
                return None

        divisor_expr = ast.unparse(node.right)
        if self._has_existing_guard(node, divisor_expr, parent_map, "zero"):
            return None

        stmt, func = self._enclosing_stmt_and_func(node, parent_map)
        if stmt is None:
            return None

        patched: Optional[str] = None
        guard_code = ""

        # If inside a conditional header (e.g., `elif` / `while`) where statement insertion doesn't apply,
        # use an inline safe conditional expression fallback.
        is_elif = isinstance(stmt, ast.If) and lines[stmt.lineno - 1].lstrip().startswith("elif ")
        in_loop_test = isinstance(stmt, ast.While) and node in ast.walk(stmt.test)
        in_inline_scope = self._in_inline_expr_scope(node, parent_map)

        if not is_elif and not in_loop_test and not in_inline_scope:
            action = self._default_guard_action(func, kind="zero", expr=divisor_expr)
            res = self._insert_statement_guard(
                raw=raw,
                lines=lines,
                line_offsets=line_offsets,
                nl=nl,
                stmt=stmt,
                guard_lines=[f"if {divisor_expr} == 0:", f"    {action}"],
            )
            if res is not None:
                patched, guard_code = res

        if patched is None:
            span = self._node_char_span(lines, line_offsets, node)
            if span is None:
                return None
            orig_expr = raw[span[0] : span[1]]
            inline_guard = f"(0.0 if {divisor_expr} == 0 else {orig_expr})"
            patched = raw[: span[0]] + inline_guard + raw[span[1] :]
            guard_code = inline_guard

        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "zero_division",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": ast.unparse(node),
            "guard_description": f"Guard division against zero divisor `{divisor_expr}`.",
            "guard_code": guard_code,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    def _synthesize_subscript_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        node: ast.Subscript,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> Optional[Dict[str, Any]]:
        if self._is_skippable_subscript(node, parent_map, scoped_type_hints):
            return None

        full_span = self._node_char_span(lines, line_offsets, node)
        val_span = self._node_char_span(lines, line_offsets, node.value)
        slice_span = self._node_char_span(lines, line_offsets, node.slice)
        if full_span is None or val_span is None or slice_span is None:
            return None

        obj_src = raw[val_span[0] : val_span[1]]
        key_src = raw[slice_span[0] : slice_span[1]]
        parent = parent_map.get(id(node))
        is_chained_base = isinstance(parent, ast.Subscript) and parent.value is node
        safe_call = f"{obj_src}.get({key_src}, {{}})" if is_chained_base else f"{obj_src}.get({key_src})"

        patched = raw[: full_span[0]] + safe_call + raw[full_span[1] :]
        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "unsafe_subscript",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": raw[full_span[0] : full_span[1]],
            "guard_description": f"Replace direct indexing on `{obj_src}` with safe `.get(...)`.",
            "guard_code": safe_call,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    def _is_skippable_subscript(
        self,
        node: ast.Subscript,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> bool:
        if not isinstance(node.ctx, ast.Load):
            return True
        if isinstance(node.slice, (ast.Slice, ast.Tuple)):
            return True
        if isinstance(node.value, (ast.List, ast.Tuple, ast.Constant)):
            return True
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int) and not isinstance(node.slice.value, bool):
            return True
        if isinstance(node.value, ast.Name):
            if node.value.id in _TYPING_CONTAINER_NAMES:
                return True
            hint = self._resolve_var_type_hint(node, node.value.id, parent_map, scoped_type_hints)
            if any(hint.startswith(seq_t) for seq_t in _SEQUENCE_TYPE_HINTS):
                return True
        return False

    def _resolve_var_type_hint(
        self,
        node: ast.AST,
        var_name: str,
        parent_map: Dict[int, ast.AST],
        scoped_type_hints: Dict[Tuple[int, str], str],
    ) -> str:
        _, enclosing_func = self._enclosing_stmt_and_func(node, parent_map)
        if enclosing_func is not None:
            hint = scoped_type_hints.get((id(enclosing_func), var_name), "")
            if hint:
                return hint
        curr: Optional[ast.AST] = node
        while curr is not None and not isinstance(curr, ast.Module):
            curr = parent_map.get(id(curr))
        return scoped_type_hints.get((id(curr), var_name), "") if curr is not None else ""

    def _synthesize_attribute_guard(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.Attribute,
        parent_map: Dict[int, ast.AST],
        imported_names: Set[str],
        defined_classes: Set[str],
        defined_funcs: Set[str],
    ) -> Optional[Dict[str, Any]]:
        if self._is_skippable_attr_target(node, imported_names, defined_classes, defined_funcs):
            return None

        stmt, func = self._enclosing_stmt_and_func(node, parent_map)
        if stmt is None:
            return None
        if func is None and isinstance(node.value, ast.Name) and node.value.id.isupper():
            return None
        if isinstance(stmt, ast.If) and lines[stmt.lineno - 1].lstrip().startswith("elif "):
            return None

        obj_expr = ast.unparse(node.value)
        if self._has_existing_guard(node, obj_expr, parent_map, "none"):
            return None

        patch_res = self._build_attr_guard_patch(
            raw=raw,
            lines=lines,
            line_offsets=line_offsets,
            nl=nl,
            node=node,
            stmt=stmt,
            func=func,
            obj_expr=obj_expr,
            parent_map=parent_map,
        )
        if patch_res is None:
            return None
        patched, guard_code = patch_res
        diff = self._verify_and_diff(raw, patched)
        if diff is None:
            return None

        return {
            "hazard_type": "none_attribute",
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "expression": ast.unparse(node),
            "guard_description": f"Guard attribute `.{node.attr}` against `{obj_expr} is None`.",
            "guard_code": guard_code,
            "patched_source": patched,
            "unified_diff": diff,
            "ast_valid": True,
        }

    @staticmethod
    def _is_skippable_attr_target(
        node: ast.Attribute,
        imported_names: Set[str],
        defined_classes: Set[str],
        defined_funcs: Set[str],
    ) -> bool:
        if isinstance(node.value, (ast.Constant, ast.List, ast.Dict, ast.Set, ast.Tuple, ast.JoinedStr, ast.Call)):
            return True
        if isinstance(node.value, ast.Name):
            base_name = node.value.id
            if base_name in {"self", "cls", "super"}:
                return True
            if base_name in imported_names or base_name in defined_classes or base_name in defined_funcs:
                return True
        return False

    def _build_attr_guard_patch(
        self,
        *,
        raw: str,
        lines: List[str],
        line_offsets: List[int],
        nl: str,
        node: ast.Attribute,
        stmt: ast.stmt,
        func: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]],
        obj_expr: str,
        parent_map: Dict[int, ast.AST],
    ) -> Optional[Tuple[str, str]]:
        if self._in_inline_expr_scope(node, parent_map):
            if not isinstance(node.ctx, ast.Load):
                return None
            span = self._node_char_span(lines, line_offsets, node)
            if span is None:
                return None
            inline_guard = f"(None if {obj_expr} is None else {raw[span[0] : span[1]]})"
            return raw[: span[0]] + inline_guard + raw[span[1] :], inline_guard

        root_expr = self._root_obj_expr(node.value)
        is_chained = isinstance(node.value, ast.Attribute) and root_expr not in {"self", "cls", obj_expr}
        guard_cond = f"{root_expr} is None or {obj_expr} is None" if is_chained else f"{obj_expr} is None"
        action = self._default_guard_action(func, kind="none", expr=obj_expr)
        return self._insert_statement_guard(
            raw=raw,
            lines=lines,
            line_offsets=line_offsets,
            nl=nl,
            stmt=stmt,
            guard_lines=[f"if {guard_cond}:", f"    {action}"],
        )

    @staticmethod
    def _root_obj_expr(expr: ast.AST) -> str:
        curr = expr
        while isinstance(curr, ast.Attribute):
            curr = curr.value
        return ast.unparse(curr)


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
