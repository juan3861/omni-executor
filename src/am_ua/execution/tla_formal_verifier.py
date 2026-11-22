"""TLA+ Formal Specification Transpiler & Bounded TLC Model Checker (`am_ua.execution.tla_formal_verifier`).

Provides four deterministic, zero-dependency formal verification engines for critical agent state machines:
1. `TLASpecTranspiler`: Compiles declarative state-machine contracts into valid TLA+ (`.tla`) and TLC (`.cfg`) specs.
2. `BoundedTLCModelChecker`: Explicit-state BFS Kripke model checker with canonical SHA-256 state hashing,
   invariant verification (`[]I`), deadlock detection, and shortest counterexample trace reconstruction.
3. `HoareTripleContractVerifier`: Verifies `{P} C {Q}` Hoare triples and TLA+ `UNCHANGED <<vars>>` frame conditions.
4. `TemporalLivenessAnalyzer`: Verifies temporal leads-to (`P ~> Q`, i.e., `[](P => <>Q)`) over finite transition graphs,
   detecting non-progress livelock cycles and terminal starvation paths.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
import hashlib
import json
import re
import time
from typing import Any, Deque, Dict, List, Optional, Sequence, Set, Tuple, Union


_ARITH_DELTA_RE = re.compile(r"^([+-])\s*(\d+(?:\.\d+)?)$")
_ARITH_ASSIGN_RE = re.compile(r"^([+\-*/])=\s*(-?\d+(?:\.\d+)?)$")
_VALID_TLA_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class ModelCheckCounterexampleStep:
    """Single step in a reconstructed TLC counterexample trace."""

    step: int
    action: str
    state: Dict[str, Any]
    state_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize counterexample step into a dictionary."""
        return {
            "step": self.step,
            "action": self.action,
            "state": dict(self.state),
            "state_hash": self.state_hash,
        }


@dataclass(frozen=True)
class HoareVerificationReport:
    """Structured result of a Hoare triple `{P} C {Q}` and frame condition verification."""

    ok: bool
    hoare_implication_valid: bool
    precondition_met: bool
    postcondition_met: bool
    frame_condition_met: bool
    violated_unchanged_vars: Tuple[str, ...] = field(default_factory=tuple)
    changed_vars: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to a standard result dictionary."""
        return {
            "ok": self.ok,
            "hoare_implication_valid": self.hoare_implication_valid,
            "precondition_met": self.precondition_met,
            "postcondition_met": self.postcondition_met,
            "frame_condition_met": self.frame_condition_met,
            "unchanged_ok": self.frame_condition_met,
            "violated_unchanged_vars": list(self.violated_unchanged_vars),
            "changed_vars": list(self.changed_vars),
        }


def _sanitize_tla_identifier(raw_name: str, fallback: str = "Identifier") -> str:
    """Normalize an arbitrary string into a valid TLA+ identifier."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", str(raw_name).strip())
    if not cleaned:
        return fallback
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned if _VALID_TLA_IDENT_RE.match(cleaned) else fallback


def _format_tla_literal(value: Any) -> str:
    """Format a Python scalar, sequence, set, or mapping as a valid TLA+ literal expression."""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if value is None:
        return '"NULL"'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, (set, frozenset)):
        inner = ", ".join(_format_tla_literal(item) for item in sorted(value, key=str))
        return f"{{{inner}}}"
    if isinstance(value, (list, tuple)):
        inner = ", ".join(_format_tla_literal(item) for item in value)
        return f"<<{inner}>>"
    if isinstance(value, dict):
        if not value:
            return "[x \\in {} |-> x]"
        parts = [
            f"{_sanitize_tla_identifier(str(k))} |-> {_format_tla_literal(v)}"
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        ]
        return f"[{', '.join(parts)}]"
    return f'"{str(value)}"'


def _canonical_state_hash(state: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest over a canonical JSON state representation."""
    canonical_json = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _evaluate_atomic_comparison(actual: Any, op: str, expected: Any) -> bool:
    """Evaluate a single binary comparison operator between `actual` and `expected`."""
    normalized_op = str(op).strip().lower()
    if normalized_op in ("==", "=", "eq", "is"):
        return bool(actual == expected)
    if normalized_op in ("!=", "/=", "<>", "ne", "is_not"):
        return bool(actual != expected)
    if normalized_op in ("in", "member"):
        try:
            return bool(actual in expected)
        except TypeError:
            return False
    if normalized_op in ("not_in", "notin"):
        try:
            return bool(actual not in expected)
        except TypeError:
            return False
    if normalized_op in ("contains", "has"):
        try:
            return bool(expected in actual)
        except TypeError:
            return False
    try:
        if normalized_op in ("<", "lt"):
            return bool(actual < expected)
        if normalized_op in ("<=", "=<", "le", "lte"):
            return bool(actual <= expected)
        if normalized_op in (">", "gt"):
            return bool(actual > expected)
        if normalized_op in (">=", "=>", "ge", "gte"):
            return bool(actual >= expected)
    except TypeError:
        return False
    raise ValueError(f"Unsupported declarative comparison operator: {op!r}")


def _evaluate_condition_spec(
    state: Dict[str, Any],
    condition: Any,
    *,
    reference_pre_state: Optional[Dict[str, Any]] = None,
) -> bool:
    """Recursively evaluate a declarative guard/invariant/Hoare condition against `state`."""
    if condition is None or condition == {} or condition == []:
        return True
    if isinstance(condition, bool):
        return condition
    if isinstance(condition, (list, tuple)):
        return all(
            _evaluate_condition_spec(state, clause, reference_pre_state=reference_pre_state)
            for clause in condition
        )
    if not isinstance(condition, dict):
        return bool(condition)

    if "not_both" in condition:
        clauses = condition["not_both"]
        if not isinstance(clauses, (list, tuple)) or len(clauses) == 0:
            return True
        all_hold = all(
            _evaluate_condition_spec(state, clause, reference_pre_state=reference_pre_state)
            for clause in clauses
        )
        return not all_hold

    if "all" in condition:
        clauses = condition["all"]
        return all(
            _evaluate_condition_spec(state, clause, reference_pre_state=reference_pre_state)
            for clause in clauses
        )

    if "any" in condition:
        clauses = condition["any"]
        return any(
            _evaluate_condition_spec(state, clause, reference_pre_state=reference_pre_state)
            for clause in clauses
        )

    if "not" in condition:
        return not _evaluate_condition_spec(
            state, condition["not"], reference_pre_state=reference_pre_state
        )

    if "implies" in condition and isinstance(condition["implies"], dict):
        imp = condition["implies"]
        antecedent = _evaluate_condition_spec(
            state, imp.get("if", {}), reference_pre_state=reference_pre_state
        )
        consequent = _evaluate_condition_spec(
            state, imp.get("then", {}), reference_pre_state=reference_pre_state
        )
        return (not antecedent) or consequent

    if "if" in condition and "then" in condition:
        antecedent = _evaluate_condition_spec(
            state, condition["if"], reference_pre_state=reference_pre_state
        )
        consequent = _evaluate_condition_spec(
            state, condition["then"], reference_pre_state=reference_pre_state
        )
        return (not antecedent) or consequent

    if "var" in condition:
        var_name = str(condition["var"])
        if var_name not in state:
            return False
        actual_val = state[var_name]
        op = str(condition.get("op", "=="))
        if "val_var" in condition:
            other_var = str(condition["val_var"])
            expected_val = state.get(other_var)
        elif "pre_var" in condition and reference_pre_state is not None:
            pre_var = str(condition["pre_var"])
            base_val = reference_pre_state.get(pre_var, 0)
            delta = condition.get("delta", 0)
            try:
                expected_val = base_val + delta
            except TypeError:
                expected_val = base_val
        elif "pre_delta" in condition and reference_pre_state is not None:
            base_val = reference_pre_state.get(var_name, 0)
            try:
                expected_val = base_val + condition["pre_delta"]
            except TypeError:
                expected_val = base_val
        else:
            expected_val = condition.get("val")
        return _evaluate_atomic_comparison(actual_val, op, expected_val)

    # Direct key-value predicate mapping: {"state": "IDLE", "retries": 0}
    for key, expected in condition.items():
        if isinstance(expected, dict) and ("op" in expected or "val" in expected):
            sub_cond = dict(expected)
            sub_cond["var"] = key
            if not _evaluate_condition_spec(
                state, sub_cond, reference_pre_state=reference_pre_state
            ):
                return False
        else:
            if state.get(key) != expected:
                return False
    return True


def _apply_effect_value(current_value: Any, effect_spec: Any, state: Dict[str, Any]) -> Any:
    """Compute the next value for a state variable given an effect specification."""
    if isinstance(effect_spec, str):
        stripped = effect_spec.strip()
        delta_match = _ARITH_DELTA_RE.match(stripped)
        if delta_match and isinstance(current_value, (int, float)) and not isinstance(current_value, bool):
            sign_str, num_str = delta_match.groups()
            delta_num: Union[int, float] = float(num_str) if "." in num_str else int(num_str)
            return current_value + delta_num if sign_str == "+" else current_value - delta_num

        assign_match = _ARITH_ASSIGN_RE.match(stripped)
        if assign_match and isinstance(current_value, (int, float)) and not isinstance(current_value, bool):
            op_char, num_str = assign_match.groups()
            rhs_num: Union[int, float] = float(num_str) if "." in num_str else int(num_str)
            if op_char == "+":
                return current_value + rhs_num
            if op_char == "-":
                return current_value - rhs_num
            if op_char == "*":
                return current_value * rhs_num
            if op_char == "/" and rhs_num != 0:
                return current_value / rhs_num

    if isinstance(effect_spec, dict) and "op" in effect_spec:
        op_name = str(effect_spec["op"]).strip().lower()
        operand = effect_spec.get("val", effect_spec.get("value", 0))
        if "val_var" in effect_spec:
            operand = state.get(str(effect_spec["val_var"]), operand)
        if op_name in ("set", "assign", "="):
            return operand
        if isinstance(current_value, (int, float)) and not isinstance(current_value, bool):
            if op_name in ("add", "+", "inc", "increment"):
                return current_value + operand
            if op_name in ("sub", "-", "dec", "decrement"):
                return current_value - operand
            if op_name in ("mul", "*"):
                return current_value * operand
            if op_name in ("min",):
                return min(current_value, operand)
            if op_name in ("max",):
                return max(current_value, operand)

    return effect_spec


class TLASpecTranspiler:
    """Deterministic compiler from declarative state-machine specifications to TLA+ and TLC configs."""

    @staticmethod
    def _compile_guard_to_tla(guard: Any) -> str:
        """Render a guard specification into a valid TLA+ boolean predicate."""
        if guard is None or guard == {} or guard == []:
            return "TRUE"
        if isinstance(guard, str):
            cleaned = guard.strip()
            return cleaned if cleaned else "TRUE"
        if isinstance(guard, (list, tuple)):
            parts = [TLASpecTranspiler._compile_guard_to_tla(g) for g in guard]
            parts = [p for p in parts if p and p != "TRUE"]
            return " /\\ ".join(parts) if parts else "TRUE"
        if isinstance(guard, dict):
            if "not_both" in guard and isinstance(guard["not_both"], (list, tuple)):
                sub = [TLASpecTranspiler._compile_guard_to_tla(c) for c in guard["not_both"]]
                joined_and = " /\\ ".join(sub)
                return f"~({joined_and})" if sub else "TRUE"
            if "all" in guard and isinstance(guard["all"], (list, tuple)):
                return TLASpecTranspiler._compile_guard_to_tla(list(guard["all"]))
            if "any" in guard and isinstance(guard["any"], (list, tuple)):
                sub = [TLASpecTranspiler._compile_guard_to_tla(c) for c in guard["any"]]
                joined_or = " \\/ ".join(sub)
                return f"({joined_or})" if sub else "TRUE"
            if "var" in guard:
                var_ident = _sanitize_tla_identifier(str(guard["var"]))
                raw_op = str(guard.get("op", "==")).strip()
                tla_op_map = {
                    "==": "=",
                    "=": "=",
                    "!=": "#",
                    "/=": "#",
                    "<>": "#",
                    "<": "<",
                    "<=": "<=",
                    ">": ">",
                    ">=": ">=",
                    "in": "\\in",
                    "not_in": "\\notin",
                }
                tla_op = tla_op_map.get(raw_op, "=")
                if "val_var" in guard:
                    rhs = _sanitize_tla_identifier(str(guard["val_var"]))
                else:
                    rhs = _format_tla_literal(guard.get("val"))
                return f"{var_ident} {tla_op} {rhs}"
            clauses: List[str] = []
            for k, v in guard.items():
                clauses.append(f"{_sanitize_tla_identifier(str(k))} = {_format_tla_literal(v)}")
            return " /\\ ".join(clauses) if clauses else "TRUE"
        return "TRUE"

    @staticmethod
    def _compile_effect_to_tla(var_name: str, effect_spec: Any) -> str:
        """Render a single variable update effect into a TLA+ primed assignment (`var' = ...`)."""
        ident = _sanitize_tla_identifier(var_name)
        if isinstance(effect_spec, str):
            stripped = effect_spec.strip()
            delta_match = _ARITH_DELTA_RE.match(stripped)
            if delta_match:
                sign_str, num_str = delta_match.groups()
                return f"{ident}' = {ident} {sign_str} {num_str}"
            assign_match = _ARITH_ASSIGN_RE.match(stripped)
            if assign_match:
                op_char, num_str = assign_match.groups()
                return f"{ident}' = {ident} {op_char} {num_str}"
            if stripped.startswith("raw:"):
                return f"{ident}' = {stripped[4:].strip()}"
        if isinstance(effect_spec, dict) and "op" in effect_spec:
            op_name = str(effect_spec["op"]).strip().lower()
            operand = _format_tla_literal(effect_spec.get("val", effect_spec.get("value", 0)))
            if op_name in ("add", "+", "inc", "increment"):
                return f"{ident}' = {ident} + {operand}"
            if op_name in ("sub", "-", "dec", "decrement"):
                return f"{ident}' = {ident} - {operand}"
            if op_name in ("mul", "*"):
                return f"{ident}' = {ident} * {operand}"
            if op_name in ("set", "assign", "="):
                return f"{ident}' = {operand}"
        return f"{ident}' = {_format_tla_literal(effect_spec)}"

    @classmethod
    def generate_tla_module(
        cls,
        module_name: str,
        *,
        variables: Sequence[str],
        init_predicates: Dict[str, Any],
        transitions: Sequence[Dict[str, Any]],
        invariants: Sequence[str],
        liveness_properties: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Deterministically compile a structured contract/state-machine spec into TLA+ and `.cfg`."""
        clean_module = _sanitize_tla_identifier(module_name, fallback="AetherMindStateSpec")

        sanitized_vars: List[str] = []
        seen_vars: Set[str] = set()
        for raw_var in variables:
            v_ident = _sanitize_tla_identifier(raw_var)
            if v_ident not in seen_vars:
                sanitized_vars.append(v_ident)
                seen_vars.add(v_ident)

        for init_key in init_predicates:
            v_ident = _sanitize_tla_identifier(init_key)
            if v_ident not in seen_vars:
                sanitized_vars.append(v_ident)
                seen_vars.add(v_ident)

        if not sanitized_vars:
            sanitized_vars = ["state"]
            seen_vars.add("state")

        vars_tuple = f"<<{', '.join(sanitized_vars)}>>"

        # Build TypeOK and Init predicates
        init_conjuncts: List[str] = []
        type_ok_conjuncts: List[str] = []
        for var_ident in sanitized_vars:
            raw_val = init_predicates.get(var_ident)
            if raw_val is None and var_ident not in init_predicates:
                init_conjuncts.append(f'{var_ident} = "INIT"')
                type_ok_conjuncts.append(f'{var_ident} \\in STRING')
            else:
                init_conjuncts.append(f"{var_ident} = {_format_tla_literal(raw_val)}")
                if isinstance(raw_val, bool):
                    type_ok_conjuncts.append(f"{var_ident} \\in BOOLEAN")
                elif isinstance(raw_val, int):
                    type_ok_conjuncts.append(f"{var_ident} \\in Int")
                else:
                    type_ok_conjuncts.append(f"{var_ident} = {var_ident}")

        type_ok_block = "TypeOK ==\n    /\\ " + "\n    /\\ ".join(type_ok_conjuncts)
        init_block = "Init ==\n    /\\ " + "\n    /\\ ".join(init_conjuncts)

        # Build Action definitions with explicit UNCHANGED clauses
        action_names: List[str] = []
        action_blocks: List[str] = []
        seen_action_names: Set[str] = set()

        for idx, trans in enumerate(transitions):
            raw_action_name = str(trans.get("name") or f"Action_{idx + 1}")
            action_ident = _sanitize_tla_identifier(raw_action_name, fallback=f"Action_{idx + 1}")
            if action_ident in seen_action_names:
                action_ident = f"{action_ident}_{idx + 1}"
            seen_action_names.add(action_ident)
            action_names.append(action_ident)

            guard_spec = trans.get("guard", trans.get("pre", trans.get("precondition")))
            guard_tla = cls._compile_guard_to_tla(guard_spec)

            effects_spec = trans.get("effects", trans.get("post", trans.get("updates", {})))
            effect_lines: List[str] = []
            mutated_vars: Set[str] = set()

            if isinstance(effects_spec, dict):
                for raw_var_name, eff_val in effects_spec.items():
                    v_ident = _sanitize_tla_identifier(str(raw_var_name))
                    if v_ident in seen_vars:
                        mutated_vars.add(v_ident)
                    effect_lines.append(cls._compile_effect_to_tla(v_ident, eff_val))

            explicit_unchanged = trans.get("unchanged")
            if isinstance(explicit_unchanged, (list, tuple)):
                unchanged_vars = [
                    _sanitize_tla_identifier(str(v))
                    for v in explicit_unchanged
                    if _sanitize_tla_identifier(str(v)) in seen_vars
                ]
            else:
                unchanged_vars = [v for v in sanitized_vars if v not in mutated_vars]

            action_conjuncts: List[str] = [guard_tla]
            action_conjuncts.extend(effect_lines)

            if unchanged_vars:
                unchanged_tuple = f"<<{', '.join(unchanged_vars)}>>"
                action_conjuncts.append(f"UNCHANGED {unchanged_tuple}")
            elif not effect_lines:
                action_conjuncts.append(f"UNCHANGED {vars_tuple}")

            action_body = "\n    /\\ ".join(action_conjuncts)
            action_blocks.append(f"{action_ident} ==\n    /\\ {action_body}")

        if not action_names:
            action_names.append("Stutter")
            action_blocks.append(f"Stutter ==\n    /\\ TRUE\n    /\\ UNCHANGED {vars_tuple}")

        next_disjuncts = "\n    \\/ ".join(action_names)
        next_block = f"Next ==\n    \\/ {next_disjuncts}"

        # Compile Invariants
        invariant_defs: List[str] = []
        invariant_names: List[str] = ["TypeOK"]
        for idx, inv_item in enumerate(invariants):
            if isinstance(inv_item, dict):
                inv_name = _sanitize_tla_identifier(
                    str(inv_item.get("name") or f"Inv_{idx + 1}"),
                    fallback=f"Inv_{idx + 1}",
                )
                cond = inv_item.get("condition", inv_item.get("expr", "TRUE"))
                inv_expr = cls._compile_guard_to_tla(cond)
            else:
                raw_inv = str(inv_item).strip()
                if "==" in raw_inv:
                    lhs, rhs = raw_inv.split("==", 1)
                    inv_name = _sanitize_tla_identifier(lhs.strip(), fallback=f"Inv_{idx + 1}")
                    inv_expr = rhs.strip() or "TRUE"
                elif _VALID_TLA_IDENT_RE.match(raw_inv):
                    inv_name = raw_inv
                    inv_expr = "TRUE"
                else:
                    inv_name = f"Inv_{idx + 1}"
                    inv_expr = raw_inv if raw_inv else "TRUE"
            if inv_name != "TypeOK":
                invariant_defs.append(f"{inv_name} == {inv_expr}")
                if inv_name not in invariant_names:
                    invariant_names.append(inv_name)

        # Compile Liveness Properties
        liveness_defs: List[str] = []
        liveness_names: List[str] = []
        for idx, prop_item in enumerate(liveness_properties or ()):
            raw_prop = str(prop_item).strip()
            if "==" in raw_prop:
                lhs, rhs = raw_prop.split("==", 1)
                prop_name = _sanitize_tla_identifier(lhs.strip(), fallback=f"Liveness_{idx + 1}")
                prop_expr = rhs.strip() or "<>TRUE"
            else:
                prop_name = f"Liveness_{idx + 1}"
                prop_expr = raw_prop if raw_prop else "<>TRUE"
            liveness_defs.append(f"{prop_name} == {prop_expr}")
            liveness_names.append(prop_name)

        fairness_suffix = f" /\\ WF_vars(Next)" if liveness_names else ""
        spec_block = f"Spec == Init /\\ [][Next]_vars{fairness_suffix}"

        tla_sections: List[str] = [
            f"---- MODULE {clean_module} ----",
            "EXTENDS Naturals, Sequences, FiniteSets, TLC",
            "",
            f"VARIABLES {', '.join(sanitized_vars)}",
            "",
            f"vars == {vars_tuple}",
            "",
            type_ok_block,
            "",
            init_block,
            "",
            "\n\n".join(action_blocks),
            "",
            next_block,
            "",
        ]
        if invariant_defs:
            tla_sections.append("\n\n".join(invariant_defs))
            tla_sections.append("")
        if liveness_defs:
            tla_sections.append("\n\n".join(liveness_defs))
            tla_sections.append("")

        tla_sections.extend(
            [
                spec_block,
                "",
                "THEOREM Spec => []TypeOK",
                "====",
            ]
        )
        tla_source = "\n".join(tla_sections)

        cfg_lines: List[str] = ["SPECIFICATION Spec"]
        for inv_name in invariant_names:
            cfg_lines.append(f"INVARIANT {inv_name}")
        for prop_name in liveness_names:
            cfg_lines.append(f"PROPERTY {prop_name}")
        cfg_source = "\n".join(cfg_lines) + "\n"

        return {
            "ok": True,
            "module_name": clean_module,
            "tla_source": tla_source,
            "cfg_source": cfg_source,
            "variable_count": len(sanitized_vars),
            "action_count": len(action_names),
            "invariant_count": len(invariant_names),
            "liveness_count": len(liveness_names),
        }


class BoundedTLCModelChecker:
    """Explicit-state BFS Kripke model checker (TLC style) over declarative state transitions."""

    @staticmethod
    def _reconstruct_trace(
        target_hash: str,
        parent_map: Dict[str, Tuple[Optional[str], str, Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Reconstruct shortest counterexample path from `Init` to `target_hash`."""
        chain: List[Tuple[str, Dict[str, Any], str]] = []
        cursor: Optional[str] = target_hash
        while cursor is not None and cursor in parent_map:
            parent_hash, action_name, state_snapshot = parent_map[cursor]
            chain.append((action_name, state_snapshot, cursor))
            cursor = parent_hash
        chain.reverse()

        return [
            ModelCheckCounterexampleStep(
                step=idx,
                action=act,
                state=st,
                state_hash=sh,
            ).to_dict()
            for idx, (act, st, sh) in enumerate(chain)
        ]

    @staticmethod
    def _check_all_invariants(
        state: Dict[str, Any],
        invariants: Sequence[Dict[str, Any]],
    ) -> Optional[str]:
        """Return the name of the first violated invariant on `state`, or `None` if all hold."""
        for idx, inv in enumerate(invariants):
            inv_name = str(inv.get("name") or f"Invariant_{idx + 1}")
            condition = inv.get("condition")
            if condition is None:
                # Allow invariant dictionary to directly contain "var"/"op"/"val" or "not_both"
                condition = {k: v for k, v in inv.items() if k != "name"}
            if not _evaluate_condition_spec(state, condition):
                return inv_name
        return None

    @classmethod
    def verify_state_machine(
        cls,
        initial_state: Dict[str, Any],
        transitions: Sequence[Dict[str, Any]],
        *,
        invariants: Sequence[Dict[str, Any]],
        max_states: int = 2000,
        check_deadlock: bool = True,
        terminal_states: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Explore reachable states via BFS, checking invariants (`[]I`) and deadlock freedom."""
        start_ns = time.perf_counter_ns()
        effective_max_states = max(1, int(max_states))

        init_copy = dict(initial_state)
        init_hash = _canonical_state_hash(init_copy)

        # parent_map[state_hash] = (parent_hash, action_name, state_dict)
        parent_map: Dict[str, Tuple[Optional[str], str, Dict[str, Any]]] = {
            init_hash: (None, "Init", init_copy)
        }
        visited_hashes: Set[str] = {init_hash}
        queue: Deque[Tuple[Dict[str, Any], str, int]] = deque([(init_copy, init_hash, 0)])

        states_explored = 0
        transitions_fired = 0
        max_depth = 0
        deadlock_free = True
        invariants_held = True
        violated_invariant: Optional[str] = None
        counterexample_trace: List[Dict[str, Any]] = []
        deadlock_trace: List[Dict[str, Any]] = []

        # Check invariants on initial state first
        initial_violation = cls._check_all_invariants(init_copy, invariants)
        if initial_violation is not None:
            states_explored = 1
            invariants_held = False
            violated_invariant = initial_violation
            counterexample_trace = cls._reconstruct_trace(init_hash, parent_map)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return {
                "ok": False,
                "states_explored": states_explored,
                "transitions_fired": transitions_fired,
                "max_depth": max_depth,
                "deadlock_free": deadlock_free,
                "invariants_held": False,
                "violated_invariant": violated_invariant,
                "counterexample_trace": counterexample_trace,
                "elapsed_ms": round(elapsed_ms, 4),
            }

        while queue and states_explored < effective_max_states:
            current_state, current_hash, current_depth = queue.popleft()
            states_explored += 1
            if current_depth > max_depth:
                max_depth = current_depth

            enabled_count = 0
            for idx, trans in enumerate(transitions):
                action_name = str(trans.get("name") or f"Action_{idx + 1}")
                guard_spec = trans.get("guard", trans.get("guards", trans.get("precondition")))
                if not _evaluate_condition_spec(current_state, guard_spec):
                    continue

                enabled_count += 1
                transitions_fired += 1

                next_state = dict(current_state)
                effects_spec = trans.get("effects", trans.get("effect", trans.get("updates", {})))
                if isinstance(effects_spec, dict):
                    for var_name, eff_val in effects_spec.items():
                        next_state[var_name] = _apply_effect_value(
                            current_state.get(var_name), eff_val, current_state
                        )

                next_hash = _canonical_state_hash(next_state)
                next_depth = current_depth + 1
                is_new_state = next_hash not in visited_hashes

                if is_new_state:
                    visited_hashes.add(next_hash)
                    parent_map[next_hash] = (current_hash, action_name, next_state)
                    if next_depth > max_depth:
                        max_depth = next_depth

                violation = cls._check_all_invariants(next_state, invariants)
                if violation is not None:
                    if next_hash not in parent_map:
                        parent_map[next_hash] = (current_hash, action_name, next_state)
                    invariants_held = False
                    violated_invariant = violation
                    counterexample_trace = cls._reconstruct_trace(next_hash, parent_map)
                    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                    return {
                        "ok": False,
                        "states_explored": states_explored,
                        "transitions_fired": transitions_fired,
                        "max_depth": max_depth,
                        "deadlock_free": deadlock_free,
                        "invariants_held": False,
                        "violated_invariant": violated_invariant,
                        "counterexample_trace": counterexample_trace,
                        "elapsed_ms": round(elapsed_ms, 4),
                    }

                if is_new_state and (states_explored + len(queue)) < effective_max_states:
                    queue.append((next_state, next_hash, next_depth))

            if enabled_count == 0 and check_deadlock:
                is_terminal = False
                if terminal_states:
                    is_terminal = any(
                        _evaluate_condition_spec(current_state, term_spec)
                        for term_spec in terminal_states
                    )
                if not is_terminal:
                    deadlock_free = False
                    if not deadlock_trace:
                        deadlock_trace = cls._reconstruct_trace(current_hash, parent_map)

        if not counterexample_trace and deadlock_trace:
            counterexample_trace = deadlock_trace

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        overall_ok = bool(invariants_held and (deadlock_free or not check_deadlock))
        return {
            "ok": overall_ok,
            "states_explored": states_explored,
            "transitions_fired": transitions_fired,
            "max_depth": max_depth,
            "deadlock_free": deadlock_free,
            "invariants_held": invariants_held,
            "violated_invariant": violated_invariant,
            "counterexample_trace": counterexample_trace,
            "elapsed_ms": round(elapsed_ms, 4),
        }

    @classmethod
    def verify_integer_invariant_z3(
        cls,
        *,
        vars_bounds: Dict[str, Tuple[int, int]],
        violation_expr: str,
        max_fallback_grid: int = 25000,
    ) -> Dict[str, Any]:
        """Prove or find counterexample for an integer invariant via native `z3` (with bounded Python grid fallback)."""
        from am_ua.execution.native_backends import NativeBackendRouter

        z3_res = NativeBackendRouter.z3_check_integer_invariant(
            vars_bounds=vars_bounds,
            violation_expr=violation_expr,
        )
        if z3_res is not None:
            return z3_res

        import itertools

        names = list(vars_bounds.keys())
        if not all(n.isidentifier() for n in names):
            return {"ok": False, "error": "Invalid variable identifier", "backend": "python_bounded_smt"}
        ranges = [range(int(vars_bounds[n][0]), int(vars_bounds[n][1]) + 1) for n in names]
        total = 1
        for r in ranges:
            total *= len(r)
            if total > max_fallback_grid:
                return {
                    "ok": False,
                    "error": f"State space ({total}) exceeds fallback grid limit without z3-solver installed",
                    "backend": "python_bounded_smt",
                }
        for combo in itertools.product(*ranges):
            env = dict(zip(names, combo))
            try:
                violated = bool(eval(violation_expr, {"__builtins__": {}}, env))
            except Exception as exc:
                return {"ok": False, "error": f"Expression error: {exc}", "backend": "python_bounded_smt"}
            if violated:
                return {
                    "ok": False,
                    "invariant_holds": False,
                    "counterexample": env,
                    "backend": "python_bounded_smt",
                }
        return {
            "ok": True,
            "invariant_holds": True,
            "counterexample": None,
            "checked_points": total,
            "backend": "python_bounded_smt",
        }


class HoareTripleContractVerifier:
    """Deterministic verifier for Hoare logic triples `{P} C {Q}` and `UNCHANGED <<vars>>` frames."""

    @classmethod
    def verify_hoare_triple(
        cls,
        pre_state: Dict[str, Any],
        post_state: Dict[str, Any],
        *,
        precondition: Dict[str, Any],
        postcondition: Dict[str, Any],
        unchanged_vars: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Verify `{P} C {Q}` and TLA+ `UNCHANGED <<vars>>` frame conditions across a transition."""
        pre_met = _evaluate_condition_spec(pre_state, precondition)
        post_met = _evaluate_condition_spec(
            post_state, postcondition, reference_pre_state=pre_state
        )

        violated_unchanged: List[str] = []
        for var_name in unchanged_vars or ():
            in_pre = var_name in pre_state
            in_post = var_name in post_state
            if in_pre != in_post or pre_state.get(var_name) != post_state.get(var_name):
                violated_unchanged.append(str(var_name))

        all_keys = sorted(set(pre_state.keys()) | set(post_state.keys()))
        changed_vars = [
            str(k)
            for k in all_keys
            if (k in pre_state) != (k in post_state) or pre_state.get(k) != post_state.get(k)
        ]

        frame_ok = len(violated_unchanged) == 0
        overall_ok = bool(pre_met and post_met and frame_ok)
        implication_valid = bool((not pre_met) or (post_met and frame_ok))

        report = HoareVerificationReport(
            ok=overall_ok,
            hoare_implication_valid=implication_valid,
            precondition_met=pre_met,
            postcondition_met=post_met,
            frame_condition_met=frame_ok,
            violated_unchanged_vars=tuple(violated_unchanged),
            changed_vars=tuple(changed_vars),
        )
        return report.to_dict()


class TemporalLivenessAnalyzer:
    """Finite-state temporal liveness verifier for `P ~> Q` (`[](P => <>Q)`)."""

    @staticmethod
    def _normalize_graph(
        state_graph: Sequence[Dict[str, Any]],
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]], Dict[str, List[str]]]:
        """Parse flexible state-graph representations into `(node_order, node_props, adjacency)`."""
        node_order: List[str] = []
        node_props: Dict[str, Dict[str, Any]] = {}
        adjacency: Dict[str, List[str]] = {}

        def _ensure_node(node_id: str, props: Optional[Dict[str, Any]] = None) -> None:
            if node_id not in node_props:
                node_order.append(node_id)
                node_props[node_id] = {}
                adjacency[node_id] = []
            if props:
                node_props[node_id].update(props)

        for idx, item in enumerate(state_graph):
            if not isinstance(item, dict):
                continue

            # Edge-centric entry: {"from": ..., "to": ...}
            if ("from" in item or "source" in item) and ("to" in item or "target" in item) and "id" not in item:
                raw_src = item.get("from", item.get("source"))
                raw_dst = item.get("to", item.get("target"))
                src_id = str(raw_src.get("id", raw_src) if isinstance(raw_src, dict) else raw_src)
                dst_id = str(raw_dst.get("id", raw_dst) if isinstance(raw_dst, dict) else raw_dst)
                _ensure_node(src_id, raw_src if isinstance(raw_src, dict) else None)
                _ensure_node(dst_id, raw_dst if isinstance(raw_dst, dict) else None)
                if dst_id not in adjacency[src_id]:
                    adjacency[src_id].append(dst_id)
                continue

            # Node-centric entry
            raw_id = item.get("id", item.get("state_id", item.get("name", f"S_{idx}")))
            node_id = str(raw_id)

            extracted_props: Dict[str, Any] = {}
            for k, v in item.items():
                if k not in ("id", "state_id", "next", "transitions", "edges", "targets", "successors", "state", "props", "data"):
                    extracted_props[k] = v
            for nested_key in ("state", "props", "data"):
                nested_val = item.get(nested_key)
                if isinstance(nested_val, dict):
                    extracted_props.update(nested_val)

            _ensure_node(node_id, extracted_props)

            raw_Next = item.get(
                "next",
                item.get(
                    "transitions",
                    item.get("edges", item.get("targets", item.get("successors", []))),
                ),
            )
            if isinstance(raw_Next, (str, int)):
                raw_Next = [raw_Next]
            if isinstance(raw_Next, (list, tuple, set)):
                for target_entry in raw_Next:
                    if isinstance(target_entry, dict):
                        target_id = str(
                            target_entry.get(
                                "target",
                                target_entry.get("to", target_entry.get("id", target_entry.get("state_id"))),
                            )
                        )
                    else:
                        target_id = str(target_entry)
                    _ensure_node(target_id)
                    if target_id not in adjacency[node_id]:
                        adjacency[node_id].append(target_id)

        return node_order, node_props, adjacency

    @classmethod
    def check_leads_to(
        cls,
        state_graph: Sequence[Dict[str, Any]],
        *,
        trigger_key: str,
        trigger_val: Any,
        goal_key: str,
        goal_val: Any,
    ) -> Dict[str, Any]:
        """Verify `P ~> Q` (`[](P => <>Q)`), detecting non-goal cycles or terminal starvation paths."""
        node_order, node_props, adjacency = cls._normalize_graph(state_graph)

        trigger_states: List[str] = [
            nid for nid in node_order if node_props[nid].get(trigger_key) == trigger_val
        ]
        goal_set: Set[str] = {
            nid for nid in node_order if node_props[nid].get(goal_key) == goal_val
        }
        goal_states: List[str] = [nid for nid in node_order if nid in goal_set]

        livelock_cycles: List[List[str]] = []
        starvation_paths: List[List[str]] = []

        for start_node in trigger_states:
            if start_node in goal_set:
                continue

            # DFS over Q-avoiding paths from `start_node`
            path_stack: List[str] = [start_node]
            on_stack: Set[str] = {start_node}
            fully_explored: Set[str] = set()

            def _dfs(current: str) -> None:
                outgoing = adjacency.get(current, [])
                if not outgoing:
                    starvation_paths.append(list(path_stack))
                    return

                for nxt in outgoing:
                    if nxt in goal_set:
                        # This branch successfully reached Q
                        continue
                    if nxt in on_stack:
                        # Found a reachable cycle that avoids Q
                        cycle_start_idx = path_stack.index(nxt)
                        cycle_path = list(path_stack[cycle_start_idx:]) + [nxt]
                        if cycle_path not in livelock_cycles:
                            livelock_cycles.append(cycle_path)
                        continue
                    if nxt in fully_explored:
                        continue

                    path_stack.append(nxt)
                    on_stack.add(nxt)
                    _dfs(nxt)
                    on_stack.remove(nxt)
                    path_stack.pop()

                fully_explored.add(current)

            _dfs(start_node)

        leads_to_holds = len(livelock_cycles) == 0 and len(starvation_paths) == 0
        counterexample_path: Optional[List[str]] = None
        violation_type: Optional[str] = None
        if livelock_cycles:
            counterexample_path = livelock_cycles[0]
            violation_type = "LIVELOCK_CYCLE"
        elif starvation_paths:
            counterexample_path = starvation_paths[0]
            violation_type = "TERMINAL_STARVATION"

        return {
            "ok": leads_to_holds,
            "leads_to_holds": leads_to_holds,
            "trigger_states": trigger_states,
            "goal_states": goal_states,
            "livelock_cycles": livelock_cycles,
            "starvation_paths": starvation_paths,
            "counterexample_path": counterexample_path,
            "violation_type": violation_type,
        }


__all__ = [
    "BoundedTLCModelChecker",
    "HoareTripleContractVerifier",
    "HoareVerificationReport",
    "ModelCheckCounterexampleStep",
    "TLASpecTranspiler",
    "TemporalLivenessAnalyzer",
]
