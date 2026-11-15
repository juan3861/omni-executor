"""Proactive Hierarchical Planner (PHP) — Agent-S2 Compositional Manager/Worker Engine (F2).

Assimilates the `simular-ai/Agent-S` (Agent S2 / S3) Proactive Hierarchical Planning architecture:
1. Splits long-horizon missions into two temporal scales:
   - High-Level Manager (`ProactiveHierarchicalPlanner`): Decomposes macro-objectives into an
     explicit DAG of verifiable `Subgoal` nodes with `suggested_modality`, `acceptance_criteria`,
     and `depends_on` edges.
   - Low-Level Worker (`AgentLoop`): Executes one atomic subgoal at a time within a bounded turn budget.
2. Proactive Dynamic Replanning (`evaluate_and_replan`):
   - After each subgoal execution, compares actual environment observations (exit code, changed files,
     desktop window/dHash state, error diagnostics) against the subgoal's expected invariants.
   - If a subgoal fails or the environment diverges, dynamically rewrites the remaining pending
     subgoals in the DAG while preserving already-completed subgoals and respecting `max_replans`.
3. Crash-Safe Persistence:
   - Serializes every plan state transition to disk (`hierarchical_plans/<plan_id>.json`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from am_ua.cognition.llm_client import LLMClient, extract_json_object


VALID_MODALITIES = (
    "code_shell",
    "adaptive_skill",
    "uia_locator",
    "visual_som",
    "cdp_browser",
    "mcp_tool",
)


@dataclass
class Subgoal:
    """Single node in a Proactive Hierarchical Plan DAG."""

    subgoal_id: str
    title: str
    description: str
    depends_on: List[str] = field(default_factory=list)
    acceptance_criteria: str = ""
    suggested_modality: str = "code_shell"
    max_turns: int = 10
    status: str = "PENDING"  # PENDING | IN_PROGRESS | COMPLETED | FAILED | SKIPPED
    outcome_summary: str = ""
    state_fingerprint: str = ""
    attempts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HierarchicalPlan:
    """Complete DAG of subgoals managed by ProactiveHierarchicalPlanner."""

    plan_id: str
    mission_id: str
    objective: str
    subgoals: List[Subgoal] = field(default_factory=list)
    replan_count: int = 0
    max_replans: int = 3
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    replan_history: List[Dict[str, Any]] = field(default_factory=list)

    def get_subgoal(self, subgoal_id: str) -> Optional[Subgoal]:
        for sg in self.subgoals:
            if sg.subgoal_id == subgoal_id:
                return sg
        return None

    def ready_subgoals(self) -> List[Subgoal]:
        """Return all PENDING subgoals whose dependencies are COMPLETED."""
        completed_ids: Set[str] = {
            sg.subgoal_id for sg in self.subgoals if sg.status == "COMPLETED"
        }
        ready: List[Subgoal] = []
        for sg in self.subgoals:
            if sg.status != "PENDING":
                continue
            if all(dep in completed_ids for dep in sg.depends_on):
                ready.append(sg)
        return ready

    def is_complete(self) -> bool:
        return len(self.subgoals) > 0 and all(
            sg.status in ("COMPLETED", "SKIPPED") for sg in self.subgoals
        )

    def has_blocked_cycle_or_deadlock(self) -> bool:
        if self.is_complete():
            return False
        pending = [sg for sg in self.subgoals if sg.status == "PENDING"]
        if not pending:
            return False
        return len(self.ready_subgoals()) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "AETHERMIND_PHP_PLAN/v1",
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "replan_count": self.replan_count,
            "max_replans": self.max_replans,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_complete": self.is_complete(),
            "subgoals": [sg.to_dict() for sg in self.subgoals],
            "replan_history": list(self.replan_history),
        }


DECOMPOSE_SYSTEM_PROMPT = """You are the High-Level Manager of a Proactive Hierarchical Planner (Agent-S2 PHP architecture).
Break the user's objective into a minimal, acyclic DAG of 2 to 5 concrete subgoals.
Respond with ONLY a valid JSON object matching this schema:
{
  "subgoals": [
    {
      "subgoal_id": "sg_1",
      "title": "Short title",
      "description": "Concrete instructions for the worker",
      "depends_on": [],
      "acceptance_criteria": "Observable condition proving this subgoal succeeded",
      "suggested_modality": "code_shell | adaptive_skill | uia_locator | visual_som | cdp_browser | mcp_tool",
      "max_turns": 8
    }
  ]
}
Rules:
1. Prefer `code_shell` or `adaptive_skill` over GUI clicking whenever a file/script/CLI can achieve the subgoal deterministically.
2. Prefer `uia_locator` over `visual_som` for native Windows controls.
3. Every `depends_on` entry must reference an earlier `subgoal_id` in the list (strictly acyclic).
"""

REPLAN_SYSTEM_PROMPT = """You are the Proactive Replanning Manager (Agent-S2 PHP architecture).
A subgoal either failed or produced an unexpected environment state.
Given the original objective, completed subgoals, the failed/diverged subgoal observation, and remaining subgoals,
output an updated list of remaining subgoals to recover and achieve the objective.
Respond with ONLY a valid JSON object:
{
  "rationale": "Why replanning is needed and how the new subgoals recover",
  "new_subgoals": [
    {
      "subgoal_id": "sg_r1",
      "title": "Recovery / next step title",
      "description": "Concrete instructions incorporating the new observation",
      "depends_on": [],
      "acceptance_criteria": "Observable condition",
      "suggested_modality": "code_shell | adaptive_skill | uia_locator | visual_som | cdp_browser | mcp_tool",
      "max_turns": 8
    }
  ]
}
"""


class ProactiveHierarchicalPlanner:
    """Agent-S2 Proactive Hierarchical Planner with deterministic fallback and disk checkpointing."""

    def __init__(
        self,
        *,
        llm: Optional[LLMClient] = None,
        storage_dir: Optional[Path | str] = None,
        max_replans: int = 3,
    ) -> None:
        self.llm = llm
        self.storage_dir = Path(
            storage_dir or r"F:\AetherMind_Temp\hierarchical_plans"
        ).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.max_replans = max(1, int(max_replans))

    @staticmethod
    def infer_modality_heuristic(text: str) -> str:
        """Infer preferred modality from subgoal text when LLM doesn't specify a valid one."""
        low = (text or "").lower()
        if any(w in low for w in ("http://", "https://", "browser", "navegador", "dom", "webpage", "html")):
            return "cdp_browser"
        if any(w in low for w in ("screenshot", "set-of-mark", "som", "image", "canvas", "pixel", "ocr")):
            return "visual_som"
        if any(w in low for w in ("window", "janela", "button", "botão", "notepad", "calculator", "uia", "locator", "click")):
            return "uia_locator"
        if any(w in low for w in ("skill_forge", "skill_run", "reusable skill", "adaptive skill")):
            return "adaptive_skill"
        if any(w in low for w in ("mcp", "external tool server")):
            return "mcp_tool"
        return "code_shell"

    def _save_plan(self, plan: HierarchicalPlan) -> Path:
        plan.updated_at = time.time()
        out_file = self.storage_dir / f"{plan.plan_id}.json"
        out_file.write_text(
            json.dumps(plan.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return out_file

    def load_plan(self, plan_id: str) -> HierarchicalPlan:
        in_file = self.storage_dir / f"{plan_id}.json"
        data = json.loads(in_file.read_text(encoding="utf-8"))
        sgs = [Subgoal(**item) for item in data.get("subgoals", [])]
        return HierarchicalPlan(
            plan_id=data["plan_id"],
            mission_id=data["mission_id"],
            objective=data["objective"],
            subgoals=sgs,
            replan_count=int(data.get("replan_count", 0)),
            max_replans=int(data.get("max_replans", self.max_replans)),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
            replan_history=list(data.get("replan_history", [])),
        )

    def _heuristic_decompose(
        self,
        objective: str,
        *,
        verify_cmd: Optional[str] = None,
    ) -> List[Subgoal]:
        """Deterministic 3-stage decomposition (Inspect -> Execute/Mutate -> Verify) if LLM is offline."""
        primary_mod = self.infer_modality_heuristic(objective)
        sg1 = Subgoal(
            subgoal_id="sg_1",
            title="Inspect workspace & environment state",
            description=f"Inspect existing files, tests, or active windows relevant to: {objective}",
            depends_on=[],
            acceptance_criteria="Environment state and target files/controls identified.",
            suggested_modality="uia_locator" if primary_mod in ("uia_locator", "visual_som") else "code_shell",
            max_turns=6,
        )
        sg2 = Subgoal(
            subgoal_id="sg_2",
            title="Execute core implementation or GUI interaction",
            description=objective,
            depends_on=["sg_1"],
            acceptance_criteria="Target changes applied or GUI actions completed with receipt.",
            suggested_modality=primary_mod,
            max_turns=12,
        )
        sg3 = Subgoal(
            subgoal_id="sg_3",
            title="Verify acceptance criteria & finalize",
            description=(
                f"Run acceptance verification ({verify_cmd}) and fix any remaining issues."
                if verify_cmd
                else "Verify the output artifacts match all requirements of the objective."
            ),
            depends_on=["sg_2"],
            acceptance_criteria=verify_cmd or "All objective invariants satisfied.",
            suggested_modality="code_shell",
            max_turns=8,
        )
        return [sg1, sg2, sg3]

    def decompose(
        self,
        objective: str,
        *,
        mission_id: Optional[str] = None,
        workspace_files: Optional[List[str]] = None,
        verify_cmd: Optional[str] = None,
        use_llm: bool = True,
    ) -> HierarchicalPlan:
        """Create a validated, acyclic `HierarchicalPlan` DAG for `objective`."""
        mid = mission_id or f"m-{uuid.uuid4().hex[:8]}"
        pid = f"plan-{mid}"
        subgoals: List[Subgoal] = []

        if use_llm and self.llm is not None:
            user_msg = (
                f"OBJECTIVE:\n{objective}\n\n"
                f"WORKSPACE FILES (sample): {(workspace_files or [])[:30]}\n"
                f"ACCEPTANCE COMMAND: {verify_cmd or 'none'}\n"
            )
            try:
                resp = self.llm.chat(
                    [
                        {"role": "system", "content": DECOMPOSE_SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    max_tokens=1200,
                    temperature=0.1,
                    json_mode=True,
                )
                parsed = extract_json_object(resp.text)
                raw_list = parsed.get("subgoals", [])
                seen_ids: Set[str] = set()
                for idx, item in enumerate(raw_list[:6], 1):
                    if not isinstance(item, dict):
                        continue
                    sid = str(item.get("subgoal_id") or f"sg_{idx}").strip()
                    if sid in seen_ids:
                        sid = f"{sid}_{idx}"
                    # Only keep dependencies that already exist in `seen_ids` -> guarantees acyclic DAG!
                    deps = [str(d) for d in item.get("depends_on", []) if str(d) in seen_ids]
                    mod = str(item.get("suggested_modality", "")).strip().lower()
                    if mod not in VALID_MODALITIES:
                        mod = self.infer_modality_heuristic(str(item.get("description", objective)))
                    seen_ids.add(sid)
                    subgoals.append(
                        Subgoal(
                            subgoal_id=sid,
                            title=str(item.get("title") or f"Step {idx}"),
                            description=str(item.get("description") or objective),
                            depends_on=deps,
                            acceptance_criteria=str(item.get("acceptance_criteria") or ""),
                            suggested_modality=mod,
                            max_turns=min(max(3, int(item.get("max_turns", 8))), 20),
                        )
                    )
            except Exception:
                subgoals = []

        if not subgoals:
            subgoals = self._heuristic_decompose(objective, verify_cmd=verify_cmd)

        plan = HierarchicalPlan(
            plan_id=pid,
            mission_id=mid,
            objective=objective,
            subgoals=subgoals,
            max_replans=self.max_replans,
        )
        self._save_plan(plan)
        return plan

    def evaluate_and_replan(
        self,
        plan: HierarchicalPlan,
        subgoal_id: str,
        *,
        passed: bool,
        observation_summary: str,
        state_fingerprint: str = "",
        error_detail: str = "",
        use_llm: bool = True,
    ) -> Tuple[HierarchicalPlan, bool]:
        """Record subgoal outcome and proactively replan remaining DAG if failed or diverged.

        Returns `(updated_plan, replanned_bool)`.
        """
        sg = plan.get_subgoal(subgoal_id)
        if sg is None:
            raise KeyError(f"Subgoal '{subgoal_id}' not found in plan '{plan.plan_id}'")

        sg.attempts += 1
        sg.outcome_summary = observation_summary[:1000]
        sg.state_fingerprint = state_fingerprint or hashlib.sha256(
            observation_summary.encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        if passed:
            sg.status = "COMPLETED"
            self._save_plan(plan)
            return plan, False

        # Subgoal failed or diverged -> check if we can replan
        sg.status = "FAILED"
        if plan.replan_count >= plan.max_replans:
            self._save_plan(plan)
            return plan, False

        completed_sgs = [s for s in plan.subgoals if s.status == "COMPLETED"]
        completed_ids = {s.subgoal_id for s in completed_sgs}
        new_subgoals: List[Subgoal] = []
        rationale = f"Fallback recovery after {subgoal_id} failed: {error_detail or observation_summary[:200]}"

        if use_llm and self.llm is not None:
            prompt = (
                f"OBJECTIVE:\n{plan.objective}\n\n"
                f"COMPLETED SUBGOALS:\n{json.dumps([s.to_dict() for s in completed_sgs], ensure_ascii=False)}\n\n"
                f"FAILED SUBGOAL:\n{json.dumps(sg.to_dict(), ensure_ascii=False)}\n"
                f"ERROR / OBSERVATION:\n{error_detail or observation_summary}\n"
            )
            try:
                resp = self.llm.chat(
                    [
                        {"role": "system", "content": REPLAN_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=1000,
                    temperature=0.1,
                    json_mode=True,
                )
                parsed = extract_json_object(resp.text)
                rationale = str(parsed.get("rationale") or rationale)
                raw_new = parsed.get("new_subgoals", [])
                seen = set(completed_ids)
                for idx, item in enumerate(raw_new[:4], 1):
                    if not isinstance(item, dict):
                        continue
                    sid = f"sg_r{plan.replan_count + 1}_{idx}"
                    deps = [str(d) for d in item.get("depends_on", []) if str(d) in seen]
                    if not deps and completed_sgs:
                        deps = [completed_sgs[-1].subgoal_id]
                    mod = str(item.get("suggested_modality", "")).strip().lower()
                    if mod not in VALID_MODALITIES:
                        mod = self.infer_modality_heuristic(str(item.get("description", plan.objective)))
                    seen.add(sid)
                    new_subgoals.append(
                        Subgoal(
                            subgoal_id=sid,
                            title=str(item.get("title") or f"Recovery Step {idx}"),
                            description=str(item.get("description") or plan.objective),
                            depends_on=deps,
                            acceptance_criteria=str(item.get("acceptance_criteria") or sg.acceptance_criteria),
                            suggested_modality=mod,
                            max_turns=min(max(4, int(item.get("max_turns", 10))), 20),
                        )
                    )
            except Exception:
                new_subgoals = []

        if not new_subgoals:
            # Deterministic escalation: if UIA failed, escalate to visual_som or code_shell; if code_shell failed, add diagnostic step
            alt_mod = "visual_som" if sg.suggested_modality == "uia_locator" else "code_shell"
            rec_id = f"sg_r{plan.replan_count + 1}_1"
            anchor_deps = [completed_sgs[-1].subgoal_id] if completed_sgs else []
            new_subgoals = [
                Subgoal(
                    subgoal_id=rec_id,
                    title=f"Recovery for: {sg.title}",
                    description=(
                        f"Previous attempt ({sg.suggested_modality}) failed with: "
                        f"{(error_detail or observation_summary)[:300]}. "
                        f"Use alternative approach ({alt_mod}) to accomplish: {sg.description}"
                    ),
                    depends_on=anchor_deps,
                    acceptance_criteria=sg.acceptance_criteria,
                    suggested_modality=alt_mod,
                    max_turns=min(sg.max_turns + 4, 20),
                )
            ]

        plan.replan_count += 1
        plan.replan_history.append(
            {
                "replan_index": plan.replan_count,
                "failed_subgoal_id": subgoal_id,
                "rationale": rationale,
                "timestamp": time.time(),
                "new_subgoal_ids": [s.subgoal_id for s in new_subgoals],
            }
        )
        # Retain completed subgoals and replace remaining failed/pending subgoals with the new recovery DAG
        plan.subgoals = completed_sgs + new_subgoals
        self._save_plan(plan)
        return plan, True
