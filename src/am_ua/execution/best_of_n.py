"""Behavior Best-of-N (bBoN) Rollout & Comparative Judge Engine (F4 — Agent-S3).

Assimilates `simular-ai/Agent-S` (Agent S2.5 / S3) Behavior Best-of-N (`bBoN`):
1. Code Rollout Best-of-N (`run_code_best_of_n`):
   - Clones the workspace into `N` isolated sandbox directories under `F:\\AetherMind_Temp\\bbon`.
   - Executes `N` trajectories (varying provider/persona/temperature or strategy).
   - Filters candidates by the executable acceptance oracle (`passed_oracle == True`).
   - Uses a Comparative Trajectory Judge (LLM + deterministic diff/efficiency tie-breaker) to
     select the highest-quality candidate and atomically syncs its changes back to the workspace.
2. GUI Plan-Level Best-of-N (`select_best_gui_plan`):
   - Because physical desktop GUI clicks are irreversible, `bBoN` for GUI missions operates at the
     plan level: generates/evaluates `N` candidate `HierarchicalPlan`s and selects the safest,
     most deterministic plan before touching the mouse/keyboard.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua.cognition.hierarchical_planner import HierarchicalPlan
from am_ua.cognition.llm_client import LLMClient, extract_json_object
from am_ua.execution.modality_router import DEFAULT_COST_WEIGHTS


SKIP_COPY_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
}


@dataclass
class RolloutCandidate:
    """Result of a single candidate rollout in Behavior Best-of-N."""

    candidate_id: str
    workspace_path: str
    status: str
    passed_oracle: bool
    turns: int
    total_tokens: int
    diff: str
    changed_files: List[str] = field(default_factory=list)
    summary: str = ""
    composite_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


COMPARATIVE_JUDGE_PROMPT = """You are an independent Comparative Behavior Best-of-N Judge (Agent-S3 bBoN).
Multiple candidate agent trajectories attempted the same software engineering objective.
Given the objective and the candidate summaries + diffs, pick the single best candidate (minimal, clean, idiomatic fix without test tampering).
Respond with ONLY a valid JSON object:
{
  "winner_candidate_id": "cand_1",
  "rationale": "Why this candidate is superior"
}
"""


class BehaviorBestOfNEngine:
    """Executes Behavior Best-of-N (bBoN) rollouts for code and plan-level BoN for GUI."""

    def __init__(
        self,
        *,
        llm: Optional[LLMClient] = None,
        scratch_root: Optional[Path | str] = None,
    ) -> None:
        self.llm = llm
        from am_ua.contracts.contracts import resolve_omni_temp_dir
        self.scratch_root = Path(
            scratch_root or resolve_omni_temp_dir("bbon_sandboxes")
        ).resolve()
        self.scratch_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_clean_git_repo(ws: Path) -> bool:
        if not (ws / ".git").exists():
            return False
        st = subprocess.run(
            ["git", "-C", str(ws), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return st.returncode == 0 and not st.stdout.strip()

    @staticmethod
    def _prepare_candidate_workspace(src: Path, dst: Path, *, use_git_worktree: bool = True) -> bool:
        """Prepare an isolated candidate workspace using fast `git worktree` when clean, else `copytree` (preserving uncommitted test patches)."""
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        if use_git_worktree and BehaviorBestOfNEngine._is_clean_git_repo(src):
            proc = subprocess.run(
                ["git", "-C", str(src), "worktree", "add", "--detach", str(dst)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode == 0 and dst.is_dir():
                return True
        BehaviorBestOfNEngine._copy_workspace(src, dst)
        return False

    @staticmethod
    def _cleanup_worktree(src: Path, dst: Path) -> None:
        subprocess.run(
            ["git", "-C", str(src), "worktree", "remove", "--force", str(dst)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)

    @staticmethod
    def _copy_workspace(src: Path, dst: Path) -> None:
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(
            src,
            dst,
            ignore=shutil.ignore_patterns(*SKIP_COPY_DIRS),
        )

    @staticmethod
    def _sync_winner_to_workspace(
        winner_ws: Path,
        target_ws: Path,
        changed_files: List[str],
        *,
        post_sync_verify_fn: Optional[Callable[[Path], bool]] = None,
    ) -> Tuple[List[str], bool]:
        """Atomically sync winner files with backup & automatic rollback if post_sync_verify_fn fails."""
        backups: Dict[Path, Optional[bytes]] = {}
        synced: List[str] = []
        for rel in changed_files:
            src_f = (winner_ws / rel).resolve()
            dst_f = (target_ws / rel).resolve()
            if target_ws not in dst_f.parents and dst_f != target_ws:
                continue
            backups[dst_f] = dst_f.read_bytes() if dst_f.is_file() else None
            if src_f.is_file():
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_f, dst_f)
                synced.append(rel)
            elif not src_f.exists() and dst_f.is_file():
                dst_f.unlink()
                synced.append(rel)

        rolled_back = False
        if post_sync_verify_fn is not None and synced:
            if not bool(post_sync_verify_fn(target_ws)):
                for dst_f, old_bytes in backups.items():
                    if old_bytes is None:
                        if dst_f.exists():
                            dst_f.unlink()
                    else:
                        dst_f.parent.mkdir(parents=True, exist_ok=True)
                        dst_f.write_bytes(old_bytes)
                synced = []
                rolled_back = True
        return synced, rolled_back

    @staticmethod
    def score_candidate(cand: RolloutCandidate) -> float:
        """Compute deterministic quality score for a rollout candidate."""
        base = 100.0 if cand.passed_oracle else 10.0
        has_diff_bonus = 15.0 if cand.changed_files else 0.0
        turn_penalty = min(30.0, cand.turns * 1.5)
        diff_lines = len(cand.diff.splitlines()) if cand.diff else 0
        bloat_penalty = min(25.0, max(0, diff_lines - 80) * 0.1)
        return round(base + has_diff_bonus - turn_penalty - bloat_penalty, 3)

    def run_code_best_of_n(
        self,
        objective: str,
        workspace: Path | str,
        runner_fn: Callable[[Path, int], Any],
        *,
        n: int = 3,
        early_stop_on_first_verified: bool = False,
        use_llm_judge: bool = True,
        parallel: bool = True,
        use_git_worktree: bool = True,
        post_sync_verify_fn: Optional[Callable[[Path], bool]] = None,
    ) -> Dict[str, Any]:
        """Run up to `n` isolated rollouts (parallel git worktrees or copies) and atomically apply the winner."""
        target_ws = Path(workspace).resolve()
        n_clamped = min(max(1, int(n)), 5)
        batch_id = f"bbon-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        batch_dir = self.scratch_root / batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)

        worktree_paths: List[Path] = []
        used_worktrees = False

        def _exec_one(idx: int, cand_ws: Path) -> RolloutCandidate:
            cand_id = f"cand_{idx}"
            res = runner_fn(cand_ws, idx)
            if hasattr(res, "status"):
                status = str(res.status)
                ver = res.verification
                passed = bool(ver and ver.get("passed")) if ver else status.startswith("VERIFIED")
                turns = int(res.turns)
                toks = int(res.tokens.get("prompt", 0) + res.tokens.get("completion", 0))
                diff = str(res.diff or "")
                changed = list(res.changed_files or [])
                summary = str(res.final_summary or "")
            else:
                status = str(res.get("status", "FAILED"))
                ver = res.get("verification")
                passed = bool(ver and ver.get("passed")) if ver else status.startswith("VERIFIED")
                turns = int(res.get("turns", 1))
                toks_dict = res.get("tokens", {})
                toks = int(toks_dict.get("prompt", 0) + toks_dict.get("completion", 0)) if isinstance(toks_dict, dict) else 0
                diff = str(res.get("diff", ""))
                changed = list(res.get("changed_files", []))
                summary = str(res.get("final_summary", ""))

            cand = RolloutCandidate(
                candidate_id=cand_id,
                workspace_path=str(cand_ws),
                status=status,
                passed_oracle=passed,
                turns=turns,
                total_tokens=toks,
                diff=diff,
                changed_files=changed,
                summary=summary,
            )
            cand.composite_score = self.score_candidate(cand)
            return cand

        candidates: List[RolloutCandidate] = []
        try:
            if parallel and not early_stop_on_first_verified and n_clamped > 1:
                prepared: List[Tuple[int, Path]] = []
                for idx in range(1, n_clamped + 1):
                    cand_ws = batch_dir / f"cand_{idx}"
                    is_wt = self._prepare_candidate_workspace(target_ws, cand_ws, use_git_worktree=use_git_worktree)
                    if is_wt:
                        used_worktrees = True
                        worktree_paths.append(cand_ws)
                    prepared.append((idx, cand_ws))
                with ThreadPoolExecutor(max_workers=n_clamped) as pool_exec:
                    futs = {pool_exec.submit(_exec_one, idx, ws_p): idx for idx, ws_p in prepared}
                    for fut in as_completed(futs):
                        candidates.append(fut.result())
                candidates.sort(key=lambda c: c.candidate_id)
            else:
                for idx in range(1, n_clamped + 1):
                    cand_ws = batch_dir / f"cand_{idx}"
                    is_wt = self._prepare_candidate_workspace(target_ws, cand_ws, use_git_worktree=use_git_worktree)
                    if is_wt:
                        used_worktrees = True
                        worktree_paths.append(cand_ws)
                    cand = _exec_one(idx, cand_ws)
                    candidates.append(cand)
                    if early_stop_on_first_verified and cand.passed_oracle:
                        break

            passing = [c for c in candidates if c.passed_oracle]
            pool = passing if passing else candidates
            pool.sort(key=lambda c: c.composite_score, reverse=True)
            winner = pool[0]
            judge_rationale = "Selected by deterministic composite score (oracle + minimal turns + clean diff)."

            if len(passing) >= 2 and use_llm_judge and self.llm is not None:
                try:
                    cand_desc = [
                        {
                            "candidate_id": c.candidate_id,
                            "turns": c.turns,
                            "changed_files": c.changed_files,
                            "summary": c.summary[:400],
                            "diff": c.diff[:3000],
                        }
                        for c in passing
                    ]
                    resp = self.llm.chat(
                        [
                            {"role": "system", "content": COMPARATIVE_JUDGE_PROMPT},
                            {
                                "role": "user",
                                "content": f"OBJECTIVE:\n{objective}\n\nCANDIDATES:\n{json.dumps(cand_desc, ensure_ascii=False)}",
                            },
                        ],
                        max_tokens=500,
                        temperature=0.0,
                        json_mode=True,
                    )
                    parsed = extract_json_object(resp.text)
                    picked_id = str(parsed.get("winner_candidate_id", ""))
                    for c in passing:
                        if c.candidate_id == picked_id:
                            winner = c
                            judge_rationale = str(parsed.get("rationale") or judge_rationale)
                            break
                except Exception:
                    pass

            synced_files: List[str] = []
            rolled_back = False
            if winner.changed_files:
                synced_files, rolled_back = self._sync_winner_to_workspace(
                    Path(winner.workspace_path),
                    target_ws,
                    winner.changed_files,
                    post_sync_verify_fn=post_sync_verify_fn,
                )

            return {
                "schema": "AETHERMIND_BBON_RESULT/v1",
                "batch_id": batch_id,
                "n_requested": n_clamped,
                "n_executed": len(candidates),
                "passing_count": len(passing),
                "winner_candidate_id": winner.candidate_id,
                "winner_passed_oracle": winner.passed_oracle,
                "winner_score": winner.composite_score,
                "judge_rationale": judge_rationale,
                "synced_files": synced_files,
                "rolled_back": rolled_back,
                "used_git_worktree": used_worktrees,
                "parallel_execution": parallel and not early_stop_on_first_verified and n_clamped > 1,
                "total_tokens_all_rollouts": sum(c.total_tokens for c in candidates),
                "candidates": [c.to_dict() for c in candidates],
            }
        finally:
            for wt_p in worktree_paths:
                self._cleanup_worktree(target_ws, wt_p)

    @staticmethod
    def score_gui_plan(plan: HierarchicalPlan) -> Tuple[float, str]:
        """Score a candidate `HierarchicalPlan` on safety, determinism, and conciseness."""
        if not plan.subgoals or plan.has_blocked_cycle_or_deadlock():
            return 0.0, "Invalid or deadlocked plan DAG"

        total_cost = sum(
            DEFAULT_COST_WEIGHTS.get(sg.suggested_modality, 500) for sg in plan.subgoals
        )
        criteria_ratio = sum(1 for sg in plan.subgoals if sg.acceptance_criteria.strip()) / len(plan.subgoals)
        determinism_bonus = sum(
            20.0
            for sg in plan.subgoals
            if sg.suggested_modality in ("adaptive_skill", "code_shell", "uia_locator")
        )
        length_penalty = max(0.0, (len(plan.subgoals) - 4) * 12.0)
        score = round(100.0 + (criteria_ratio * 25.0) + determinism_bonus - (total_cost * 0.02) - length_penalty, 3)
        return score, f"subgoals={len(plan.subgoals)}, est_cost={total_cost}, criteria_cov={criteria_ratio:.2f}"

    def select_best_gui_plan(
        self,
        plans: List[HierarchicalPlan],
    ) -> Dict[str, Any]:
        """Select the highest-scoring `HierarchicalPlan` among `N` candidates before GUI execution."""
        if not plans:
            raise ValueError("select_best_gui_plan requires at least 1 candidate plan")

        scored: List[Tuple[float, str, HierarchicalPlan]] = []
        for p in plans:
            sc, reason = self.score_gui_plan(p)
            scored.append((sc, reason, p))
        scored.sort(key=lambda item: item[0], reverse=True)
        best_score, best_reason, best_plan = scored[0]
        return {
            "winner_plan_id": best_plan.plan_id,
            "winner_score": best_score,
            "rationale": best_reason,
            "winner_plan": best_plan,
            "evaluated_count": len(plans),
            "ranking": [
                {"plan_id": p.plan_id, "score": s, "detail": r}
                for s, r, p in scored
            ],
        }
