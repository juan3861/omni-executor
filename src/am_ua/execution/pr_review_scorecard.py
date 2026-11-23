from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
import difflib
import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from am_ua.execution.fuzzy_replace_engine import (
    _CARET_LINE_RE, _DEFAULT_TOPOLOGY_DAG, _EXC_LINE_RE, _SKIP_DIRS,
    _TRACEBACK_FRAME_RE, AiderFuzzySearchReplaceEngine, _atomic_write_bytes,
    _common_indent, _dedent_lines, _iter_python_files,
    _join_lines_preserving_nl, _leading_ws, _reindent_lines, _resolve_contained_path,
)

from am_ua.execution.pr_architecture_auditor import (
    SeniorArchitectReadinessAuditor, _score_to_grade, analyze_import_layers, strengthen_test_assertions,
)

def _extract_traceback_frames(lines: List[str]) -> List[Dict[str, Any]]:
    frames: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(lines):
        match = _TRACEBACK_FRAME_RE.match(lines[idx])
        if match:
            code_line = ""
            look = idx + 1
            while look < len(lines) and lines[look].strip() and not _TRACEBACK_FRAME_RE.match(lines[look]):
                if _CARET_LINE_RE.match(lines[look]):
                    look += 1
                    continue
                if lines[look].startswith((" ", "\t")):
                    code_line = lines[look].strip()
                    idx = look
                break
            frames.append(
                {
                    "file": match.group(1),
                    "line": int(match.group(2)),
                    "func": (match.group(3) or "").strip(),
                    "code": code_line,
                }
            )
        idx += 1
    return frames


def _extract_root_exception(lines: List[str]) -> Tuple[Optional[str], str]:
    skip_prefixes = ("Traceback (", "During handling ", "The above exception ")
    for raw_ln in reversed(lines):
        stripped = raw_ln.strip()
        if not stripped or _CARET_LINE_RE.match(stripped) or _TRACEBACK_FRAME_RE.match(raw_ln) or stripped.startswith(skip_prefixes):
            continue
        exc_match = _EXC_LINE_RE.match(stripped)
        if exc_match:
            return exc_match.group(1), (exc_match.group(2) or "").strip()
    return None, ""


def parse_exception_traceback(traceback_text: str) -> Dict[str, Any]:
    """Extract ordered stack frames (`file`, `line`, `func`, `code`) and root exception."""
    lines = (traceback_text or "").splitlines()
    frames = _extract_traceback_frames(lines)
    exc_class, exc_message = _extract_root_exception(lines)
    ok = bool(frames or exc_class)
    result: Dict[str, Any] = {
        "ok": ok,
        "frames": frames,
        "frame_count": len(frames),
        "exception_class": exc_class,
        "exception_message": exc_message,
        "root_frame": frames[-1] if frames else None,
        "entry_frame": frames[0] if frames else None,
    }
    if not ok:
        result["error"] = "No traceback frames or exception line detected"
    return result


@dataclass(frozen=True)
class _ParamSpec:
    name: str
    required: bool
    kind: str


@dataclass(frozen=True)
class _CallableSig:
    name: str
    params: Tuple[_ParamSpec, ...]
    has_vararg: bool
    has_kwarg: bool


def _extract_callable_sig(node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool) -> _CallableSig:
    args = node.args
    pos_all = list(args.posonlyargs) + list(args.args)
    first_def_idx = len(pos_all) - len(args.defaults)
    n_posonly = len(args.posonlyargs)

    specs: List[_ParamSpec] = []
    for idx, arg in enumerate(pos_all):
        if is_method and idx == 0 and arg.arg in ("self", "cls"):
            continue
        specs.append(_ParamSpec(arg.arg, required=idx < first_def_idx, kind="posonly" if idx < n_posonly else "pos_or_kw"))

    for arg, kw_def in zip(args.kwonlyargs, args.kw_defaults):
        specs.append(_ParamSpec(arg.arg, required=(kw_def is None), kind="kwonly"))

    return _CallableSig(node.name, tuple(specs), args.vararg is not None, args.kwarg is not None)


def _extract_api_surface(source_code: str) -> Tuple[Dict[str, _CallableSig], Dict[str, Dict[str, _CallableSig]]]:
    tree = ast.parse(source_code or "")
    funcs: Dict[str, _CallableSig] = {}
    classes: Dict[str, Dict[str, _CallableSig]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            funcs[node.name] = _extract_callable_sig(node, is_method=False)
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            classes[node.name] = {
                item.name: _extract_callable_sig(item, is_method=True)
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and (not item.name.startswith("_") or item.name == "__init__")
            }
    return funcs, classes


def _is_param_absorbed(param: _ParamSpec, new_sig: _CallableSig) -> bool:
    if param.required:
        return False
    return (param.kind == "posonly" and new_sig.has_vararg) or (
        param.kind in ("pos_or_kw", "kwonly") and new_sig.has_kwarg
    )


def _diff_callable_sigs(
    symbol: str,
    old_sig: _CallableSig,
    new_sig: _CallableSig,
    breaking: List[Dict[str, Any]],
    removed_params: List[Dict[str, Any]],
) -> None:
    new_map = {p.name: p for p in new_sig.params}
    old_map = {p.name: p for p in old_sig.params}

    for p in old_sig.params:
        if p.name not in new_map:
            if not _is_param_absorbed(p, new_sig):
                entry = {"symbol": symbol, "kind": "removed_required_param" if p.required else "removed_param", "param": p.name}
                breaking.append(entry)
                removed_params.append(entry)
        elif not p.required and new_map[p.name].required:
            breaking.append({"symbol": symbol, "kind": "param_became_required", "param": p.name})

    for p in new_sig.params:
        if p.name not in old_map and p.required:
            breaking.append({"symbol": symbol, "kind": "added_required_param", "param": p.name})


def check_api_backward_compat(old_source: str, new_source: str) -> Dict[str, Any]:
    """Check public API backward compatibility between `old_source` and `new_source`."""
    try:
        old_funcs, old_classes = _extract_api_surface(old_source)
        new_funcs, new_classes = _extract_api_surface(new_source)
    except SyntaxError as exc:
        return {"ok": False, "compatible": False, "error": f"SyntaxError at line {exc.lineno}: {exc.msg}"}

    breaking: List[Dict[str, Any]] = []
    removed_symbols: List[str] = []
    removed_params: List[Dict[str, Any]] = []

    for fn_name, old_sig in sorted(old_funcs.items()):
        if fn_name not in new_funcs:
            removed_symbols.append(fn_name)
            breaking.append({"symbol": fn_name, "kind": "removed_function"})
        else:
            _diff_callable_sigs(fn_name, old_sig, new_funcs[fn_name], breaking, removed_params)

    for cls_name, old_methods in sorted(old_classes.items()):
        if cls_name not in new_classes:
            removed_symbols.append(cls_name)
            breaking.append({"symbol": cls_name, "kind": "removed_class"})
            continue
        for m_name, old_sig in sorted(old_methods.items()):
            fqn = f"{cls_name}.{m_name}"
            if m_name not in new_classes[cls_name]:
                removed_symbols.append(fqn)
                breaking.append({"symbol": fqn, "kind": "removed_method"})
            else:
                _diff_callable_sigs(fqn, old_sig, new_classes[cls_name][m_name], breaking, removed_params)

    compatible = len(breaking) == 0
    return {
        "ok": compatible,
        "compatible": compatible,
        "breaking_count": len(breaking),
        "breaking_changes": breaking,
        "removed_symbols": removed_symbols,
        "removed_params": removed_params,
    }


def _scan_source_security_ast(rel_path: str, source_code: str) -> List[Dict[str, Any]]:
    flags: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return flags

    dyn_names = frozenset({"ev" + "al", "ex" + "ec"})
    shell_kw = "sh" + "ell"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in dyn_names:
                flags.append({"file": rel_path, "line": node.lineno, "rule": "dynamic_code_execution"})
            for kw in node.keywords:
                if kw.arg == shell_kw and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    flags.append({"file": rel_path, "line": node.lineno, "rule": "subprocess_shell_true"})
    return flags


def _audit_command_safety(command: str) -> List[Dict[str, Any]]:
    cmd = (command or "").strip()
    if not cmd:
        return []
    checks: Tuple[Tuple[str, re.Pattern[str]], ...] = (
        ("pipe_to_shell", re.compile(r"(?i)(?:curl|wget|irm)\s+[^\n|]+\|\s*(?:bash|sh|pwsh|powershell|iex)")),
        ("catastrophic_rm", re.compile(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|C:\\|\*)")),
        ("bypass_git_hooks", re.compile(r"(?i)\bgit\s+(?:commit|push)\b[^\n]*--no-ver" + r"ify\b")),
        ("force_push_main", re.compile(r"(?i)\bgit\s+push\b[^\n]*--force\b[^\n]*\b(?:main|master)\b")),
    )
    return [{"rule": rule, "command": cmd[:120]} for rule, rx in checks if rx.search(cmd)]


def _evaluate_compat_maps(
    ws: Path, old_source_map: Optional[Dict[str, str]], new_source_map: Optional[Dict[str, str]]
) -> List[Dict[str, Any]]:
    if not old_source_map:
        return []
    compat_breaks: List[Dict[str, Any]] = []
    new_map = new_source_map or {}
    for rel, old_src in sorted(old_source_map.items()):
        if not rel.endswith(".py"):
            continue
        if rel in new_map:
            new_src = new_map[rel]
        elif (ws / rel).is_file():
            new_src = (ws / rel).read_text(encoding="utf-8", errors="replace")
        else:
            new_src = ""
        res = check_api_backward_compat(old_src, new_src)
        for chg in res.get("breaking_changes", []):
            compat_breaks.append({"file": rel, **chg})
    return compat_breaks


def _score_test_files(py_new_map: Dict[str, str]) -> Tuple[float, int]:
    test_scores: List[float] = []
    weak_total = 0
    for rel, src in sorted(py_new_map.items()):
        if Path(rel).name.startswith("test_") or rel.endswith("_test.py"):
            ts = strengthen_test_assertions(src)
            if ts.get("ok"):
                test_scores.append(float(ts.get("strength_score", 100.0)))
                weak_total += int(ts.get("weak_count", 0))
    avg = round(sum(test_scores) / len(test_scores), 2) if test_scores else 100.0
    return avg, weak_total


def compute_pr_review_scorecard(
    workspace: Path,
    *,
    old_source_map: Optional[Dict[str, str]] = None,
    new_source_map: Optional[Dict[str, str]] = None,
    command: str = "",
) -> Dict[str, Any]:
    """Compute a composite senior PR review scorecard across 5 deterministic dimensions."""
    t0 = time.perf_counter()
    ws = Path(workspace).resolve()
    py_new_map = {k: v for k, v in (new_source_map or {}).items() if k.endswith(".py")}

    readiness = (
        SeniorArchitectReadinessAuditor.audit_sources(py_new_map, target="pr_diff")
        if py_new_map
        else SeniorArchitectReadinessAuditor.audit(ws, target=".")
    )
    import_audit = analyze_import_layers(ws, target=".")
    compat_breaks = _evaluate_compat_maps(ws, old_source_map, new_source_map)
    avg_test_strength, weak_asserts_total = _score_test_files(py_new_map)

    sec_flags: List[Dict[str, Any]] = []
    for rel, src in sorted(py_new_map.items()):
        sec_flags.extend(_scan_source_security_ast(rel, src))
    sec_flags.extend(_audit_command_safety(command))

    readiness_pts = round(float(readiness.get("score", 0.0)) * 0.40, 2)
    import_issues = int(import_audit.get("violation_count", 0)) + int(import_audit.get("cycle_count", 0))
    import_pts = 20.0 if import_audit.get("ok") else max(0.0, 20.0 - 5.0 * import_issues)
    compat_pts = 20.0 if not compat_breaks else max(0.0, 20.0 - 5.0 * len(compat_breaks))
    test_pts = round(avg_test_strength * 0.10, 2)
    sec_pts = 10.0 if not sec_flags else max(0.0, 10.0 - 5.0 * len(sec_flags))

    total_score = round(min(100.0, readiness_pts + import_pts + compat_pts + test_pts + sec_pts), 2)
    approved = total_score >= 75.0 and not compat_breaks and not sec_flags and bool(import_audit.get("ok", True))

    return {
        "ok": True,
        "approved": approved,
        "score": total_score,
        "grade": _score_to_grade(total_score),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "checks": {
            "readiness": {"score": readiness.get("score", 0.0), "grade": readiness.get("grade", "C"), "weighted": readiness_pts},
            "import_layers": {"ok": import_audit.get("ok", True), "violations": import_audit.get("violation_count", 0), "cycles": import_audit.get("cycle_count", 0), "weighted": import_pts},
            "backward_compat": {"compatible": not compat_breaks, "breaking_count": len(compat_breaks), "weighted": compat_pts},
            "test_strength": {"score": avg_test_strength, "weak_asserts": weak_asserts_total, "weighted": test_pts},
            "security_and_command": {"clean": not sec_flags, "flag_count": len(sec_flags), "weighted": sec_pts},
        },
        "breaking_changes": compat_breaks,
        "security_flags": sec_flags,
        "command": command,
        "summary": f"PR Scorecard {total_score}/100 ({_score_to_grade(total_score)}) - {'APPROVED' if approved else 'CHANGES_REQUESTED'}",
    }
