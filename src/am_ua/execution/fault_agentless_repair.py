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


