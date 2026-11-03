"""Neuro-Symbolic Reasoning Bridge over `F:\\AetherMind_Universal_Reasoning_Engine` (P5.2).

Unites the proven URE Alpha-C10 gears into a single clean sovereign facade:
  1. `CFGGrammarSieve` (Last-Mile context-free grammar & safety sieve)
  2. `UnsatCoreSolver` (Z3 SMT consistency & Minimal Unsatisfiable Core pruning)
  3. `PearlCausalEngine` (`do(X)` counterfactual sufficiency & necessity refutation)
  4. `TimeTravelEngine` (Reversible reasoning checkpoints & reality-forking rollback)
  5. `TextVariable` / `TextualLoss` / `TextualOptimizer` (`TextGrad` backpropagation).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

URE_ROOT = Path(r"F:\AetherMind_Universal_Reasoning_Engine")
if URE_ROOT.is_dir() and str(URE_ROOT) not in sys.path:
    sys.path.insert(0, str(URE_ROOT))

from causal.pearl_refutation import PearlCausalEngine  # type: ignore[import-untyped]
from core.contracts import VariableType  # type: ignore[import-untyped]
from grammar.cfg_sieve import CFGGrammarSieve  # type: ignore[import-untyped]
from optimization.textual_backprop import (  # type: ignore[import-untyped]
    TextVariable,
    TextualLoss,
    TextualOptimizer,
)
from search.time_travel_checkpoint import TimeTravelEngine  # type: ignore[import-untyped]
from solvers.unsat_core_engine import UnsatCoreSolver  # type: ignore[import-untyped]


class URENeuroSymbolicBridge:
    """High-assurance Neuro-Symbolic Reasoning Bridge (Z3 + Pearl SCM + CFG + TimeTravel + TextGrad)."""

    TYPE_MAP = {
        "bool": VariableType.BOOLEAN,
        "boolean": VariableType.BOOLEAN,
        "int": VariableType.INTEGER,
        "integer": VariableType.INTEGER,
        "real": VariableType.REAL,
        "float": VariableType.REAL,
        "str": VariableType.STRING,
        "string": VariableType.STRING,
    }

    def __init__(self, *, smt_timeout_ms: int = 5000) -> None:
        self.sieve = CFGGrammarSieve()
        self.solver = UnsatCoreSolver(timeout_ms=smt_timeout_ms)
        self.pearl = PearlCausalEngine(solver=self.solver)
        self.time_travel = TimeTravelEngine()

    def _map_vars(self, variables: Dict[str, str]) -> Dict[str, VariableType]:
        return {
            name: self.TYPE_MAP.get(vtype.lower(), VariableType.BOOLEAN)
            for name, vtype in variables.items()
        }

    def verify_smt_constraints(
        self,
        variables: Dict[str, str],
        premises: Dict[str, str],
        hypotheses: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Run Z3 SMT verification and extract either a SAT model or Minimal Unsatisfiable Core."""
        cert = self.solver.verify_consistency(
            self._map_vars(variables),
            premises,
            hypotheses=hypotheses,
        )
        return {
            "status": cert.status,
            "is_sound": cert.is_sound,
            "sat_model": cert.sat_model,
            "unsat_core": cert.unsat_core,
            "duration_ms": cert.verification_duration_ms,
        }

    def audit_causal_hypothesis(
        self,
        variables: Dict[str, str],
        background_rules: Dict[str, str],
        *,
        cause_id: str,
        cause_expr: str,
        effect_id: str,
        effect_expr: str,
    ) -> Dict[str, Any]:
        """Run Pearl's `do(X)` counterfactual necessity & sufficiency audit."""
        report = self.pearl.audit_causal_claim(
            self._map_vars(variables),
            background_rules,
            cause_id=cause_id,
            cause_expr=cause_expr,
            effect_id=effect_id,
            effect_expr=effect_expr,
        )
        return dict(report.to_dict())

    def sieve_command_safety(self, command: str) -> Dict[str, Any]:
        """Validate command against URE CFGGrammarSieve safety rules."""
        ok, violations = self.sieve.validate_safety(command)
        return {"is_safe": bool(ok), "violations": list(violations)}

    def checkpoint_reasoning(
        self,
        step_id: str,
        premises: List[str],
        confidence: float,
        state_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        cp = self.time_travel.commit_checkpoint(step_id, premises, confidence, state_data)
        return {
            "step_id": cp.step_id,
            "step_index": cp.step_index,
            "parent_id": cp.parent_checkpoint_id,
        }

    def rollback_reasoning(self, target_step_id: str, reason: str) -> Optional[Dict[str, Any]]:
        cp = self.time_travel.time_travel_rollback(target_step_id, reason)
        if cp is None:
            return None
        return {
            "restored_step_id": cp.step_id,
            "active_premises": cp.active_premises,
            "state_data": cp.state_data,
            "fork_log_count": len(self.time_travel.fork_log),
        }

    def optimize_prompt_textgrad(
        self,
        initial_prompt: str,
        evaluator_fn: Callable[[str], Tuple[float, str]],
        *,
        steps: int = 2,
    ) -> Dict[str, Any]:
        var = TextVariable(initial_prompt, role_description="candidate_strategy")
        loss_fn = TextualLoss(evaluator_fn)
        opt = TextualOptimizer([var])
        initial_loss, _ = loss_fn.compute(var)
        var.zero_grad()
        for _ in range(steps):
            loss_val, _ = loss_fn.compute(var)
            if loss_val <= 0.0:
                break
            opt.step()
        final_loss, _ = loss_fn.compute(var)
        return {
            "initial_loss": initial_loss,
            "final_loss": final_loss,
            "optimized_text": var.value,
        }
