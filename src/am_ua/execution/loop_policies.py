"""Modular Execution Policies, Statechart, EventStream & Self-Review Gates (`am_ua.execution.loop_policies`).

Extracted from `agent_loop.py` to break down the execution monolith into clean,
independently testable orthogonal policy primitives:
  - Finite-statechart transitions (`AGENT_STATE_TRANSITIONS`, `transition_state`)
  - Strict Plan vs Act mode gate (`PLAN_MODE_FORBIDDEN_TOOLS`, `assert_tool_allowed_in_mode`)
  - External plan anchor (`sync_todo_anchor`)
  - Reproducible Action -> Observation JSONL EventStream (`export_event_stream`, `replay_event_stream`)
  - Mandatory pre-finish Self-Review Diff Gate (`run_self_review_diff_gate`)
  - Deterministic pre-critic (`evaluate_pre_critic`) & JSON Schema validator (`validate_output_schema`)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


AGENT_STATE_TRANSITIONS: Dict[str, frozenset[str]] = {
    "PREFLIGHT": frozenset({"ACT", "FINISH", "ABORT"}),
    "ACT": frozenset({"ACT", "VERIFY", "HANDOFF", "HUMAN_WHEEL", "FINISH", "ABORT"}),
    "VERIFY": frozenset({"DIAGNOSE", "FINISH", "ABORT"}),
    "DIAGNOSE": frozenset({"ACT", "HANDOFF", "ABORT"}),
    "HANDOFF": frozenset({"ACT", "VERIFY", "ABORT"}),
    "HUMAN_WHEEL": frozenset({"ACT", "ABORT"}),
    "FINISH": frozenset(),
    "ABORT": frozenset(),
}

PLAN_MODE_FORBIDDEN_TOOLS: frozenset[str] = frozenset({
    "write_file",
    "replace_in_file",
    "run",
    "pc_act",
    "pc_window",
    "browser_act",
    "skill_forge",
    "skill_run",
    "restore_checkpoint",
    "mcp_call",
})


def transition_state(current: str, target: str) -> str:
    """Enforce finite-statechart transition invariants (XState-style)."""
    allowed = AGENT_STATE_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ValueError(f"Illegal AgentLoop state transition: {current} -> {target}")
    return target


def assert_tool_allowed_in_mode(tool_name: str, mode: str = "act") -> None:
    """Strict Plan vs Act execution gate at kernel level."""
    m = (mode or "act").strip().lower()
    if m == "plan" and tool_name in PLAN_MODE_FORBIDDEN_TOOLS:
        raise PermissionError(f"Tool '{tool_name}' is strictly blocked in PLAN (read-only) mode")


def sync_todo_anchor(
    workspace: Path,
    objective: str,
    tasks: List[Dict[str, str]],
    *,
    filename: str = ".omni_todo.md",
) -> Path:
    """External plan state anchor (`todo.md`) rewritten on milestones to prevent context drift."""
    ws = Path(workspace).resolve()
    p = (ws / filename).resolve()
    if ws not in p.parents and p != ws:
        raise PermissionError(f"todo anchor escapes workspace: {filename}")
    lines = ["# Mission Plan Anchor", "", f"**Objective:** {objective}", ""]
    for t in tasks:
        st = str(t.get("status", "pending")).lower()
        box = "[x]" if st in ("done", "completed", "verified") else ("[-]" if st in ("in_progress", "active") else "[ ]")
        lines.append(f"- {box} `{t.get('id', '?')}` {t.get('title', '')} ({st})")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return p


def export_event_stream(events: List[Dict[str, Any]], out_path: Path) -> Path:
    """100% reproducible Action -> Observation JSONL event stream export."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="\n") as fh:
        for idx, ev in enumerate(events, 1):
            rec = {"seq": idx, **ev}
            fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return out_path


def replay_event_stream(jsonl_path: Path) -> Dict[str, Any]:
    """Deterministically replay and audit an exported Action -> Observation JSONL stream."""
    records: List[Dict[str, Any]] = []
    actions = 0
    observations = 0
    for raw in Path(jsonl_path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        records.append(item)
        kind = str(item.get("kind") or item.get("type") or "").lower()
        if kind == "action":
            actions += 1
        elif kind == "observation":
            observations += 1
    return {
        "ok": True,
        "event_count": len(records),
        "action_count": actions,
        "observation_count": observations,
        "records": records,
    }


def run_self_review_diff_gate(workspace: Path) -> Dict[str, Any]:
    """Mandatory pre-finish self-review gate (AST syntax + SAST + git diff)."""
    from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader
    from am_ua.security.agent_shield import AgentShieldAuditor

    ws = Path(workspace).resolve()
    syn = DeterministicTaskOffloader.ast_syntax_sweep(ws)
    shield = AgentShieldAuditor().scan_directory(ws, include_source_sast=True)
    git_info = DeterministicTaskOffloader.git_forensics(ws)
    passed = bool(syn.get("ok")) and bool(shield.passed)
    return {
        "ok": passed,
        "passed": passed,
        "syntax_ok": bool(syn.get("ok")),
        "syntax_errors": syn.get("syntax_errors", []),
        "shield_grade": shield.grade,
        "shield_findings": len(shield.findings),
        "git_diff_stat": git_info.get("diff_stat", ""),
    }


def evaluate_pre_critic(
    *,
    objective: str,
    stop_reason: str,
    changed_files: List[str],
    diff: str,
    verification: Optional[Dict[str, Any]],
    tool_calls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Deterministic pre-critic (`EmptyPatch` + verification + finish discipline) before LLM Judge."""
    _ = changed_files, tool_calls
    score = 1.0
    issues: List[str] = []
    clean_finish = stop_reason == "finish"
    if not clean_finish:
        score -= 0.35
        issues.append("did_not_call_finish")

    low = (objective or "").lower()
    edit_intent = any(k in low for k in ("fix", "implement", "refactor", "update", "rename", "create", "write", "replace", "add"))
    empty_patch = not (diff or "").strip()
    if edit_intent and empty_patch:
        score -= 0.50
        issues.append("empty_patch_on_edit_task")

    verif_passed: Optional[bool] = None
    if verification is not None:
        verif_passed = bool(verification.get("passed"))
        if not verif_passed:
            score -= 0.60
            issues.append("verification_failed")

    final_score = round(max(0.0, min(1.0, score)), 3)
    return {
        "score": final_score,
        "success": final_score >= 0.5,
        "categorized_features": {
            "empty_patch": empty_patch,
            "clean_finish": clean_finish,
            "verification_passed": verif_passed,
            "agent_behavioral_issues": issues,
        },
    }


def validate_output_schema(value: Any, schema: Dict[str, Any]) -> Optional[str]:
    """Lightweight JSON-Schema validator (type, required, properties, items). Returns error or None."""
    if value is None:
        return "missing structured 'output' payload"
    expected_type = schema.get("type")
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
    }
    if expected_type in type_map:
        if expected_type == "integer" and isinstance(value, bool):
            return "expected integer, got bool"
        if not isinstance(value, type_map[expected_type]):
            return f"expected {expected_type}, got {type(value).__name__}"
    if isinstance(value, dict):
        for req_key in schema.get("required") or ():
            if req_key not in value:
                return f"missing required property '{req_key}'"
        props = schema.get("properties") or {}
        for k, sub_schema in props.items():
            if k in value and isinstance(sub_schema, dict):
                err = validate_output_schema(value[k], sub_schema)
                if err:
                    return f"property '{k}': {err}"
    elif isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, elem in enumerate(value):
                err = validate_output_schema(elem, item_schema)
                if err:
                    return f"item[{idx}]: {err}"
    return None
