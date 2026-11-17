"""ReasoningBank — Trajectory Capture & Replay Engine (am_ua.cognition.reasoning_bank).

Captures successful agent trajectories, indexes them, and retrieves relevant
few-shot exemplars to ground future missions in empirical past experience.
Inspired by Ruflo's ReasoningBank/SONA, but simplified to zero external DB dependencies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from am_ua.cognition.sona_memory import SONAVectorMemory


STOP_WORDS = {
    "a", "an", "the", "in", "on", "at", "to", "for", "of", "and", "or", "is", "are",
    "was", "were", "be", "been", "this", "that", "it", "with", "from", "as", "by",
    "o", "os", "um", "uma", "de", "do", "da", "em", "no", "na", "para", "com", "por",
}


def tokenize(text: str) -> Set[str]:
    words = re.findall(r"[a-zA-Z0-9_\-\.]+", text.lower())
    return {w for w in words if len(w) > 2 and w not in STOP_WORDS}


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


class ReasoningBank:
    """Indexes and retrieves past successful mission execution trajectories."""

    DEFAULT_TRACES_DIR = Path("F:/AetherMind_Universal_Agent/data/agent_traces")

    def __init__(self, traces_dir: Optional[Path] = None) -> None:
        self.traces_dir = Path(traces_dir or self.DEFAULT_TRACES_DIR).resolve()
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self._index: List[Dict[str, Any]] = []
        self.sona = SONAVectorMemory(self.traces_dir / "sona_memory.json")
        self.refresh_index()

    def refresh_index(self) -> int:
        """Loads and indexes all valid traces from the traces directory."""
        self._index.clear()
        if not self.traces_dir.exists():
            return 0

        for file in self.traces_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8", errors="replace"))
                if not isinstance(data, dict):
                    continue
                # Only index runs that succeeded or passed verification
                status = str(data.get("status", "")).upper()
                verif = data.get("verification") or {}
                verif_exit = verif.get("exit_code") if isinstance(verif, dict) else None
                brier = data.get("brier_score")

                passed = (
                    status == "PASSED"
                    or verif_exit == 0
                    or (brier is not None and float(brier) <= 0.1 and status != "FAILED")
                )
                if passed:
                    data["_tokens"] = tokenize(str(data.get("objective", "")))
                    data["_file_path"] = str(file)
                    self._index.append(data)
            except Exception:
                continue

        return len(self._index)

    def find_best_trajectory(self, objective: str, min_similarity: float = 0.25) -> Optional[Dict[str, Any]]:
        """Finds the most relevant past successful trajectory using hybrid Jaccard + SONA vector similarity."""
        target_tokens = tokenize(objective)
        if not target_tokens or not self._index:
            return None

        sona_hits = {
            hit.get("objective", ""): float(hit.get("similarity", 0.0))
            for hit in self.sona.search_similar(objective, top_k=5, min_score=0.05)
        }
        best_score = 0.0
        best_entry: Optional[Dict[str, Any]] = None

        for entry in self._index:
            jacc = jaccard_similarity(target_tokens, entry.get("_tokens", set()))
            vec_sim = sona_hits.get(str(entry.get("objective", ""))[:600], 0.0)
            score = max(jacc, 0.5 * jacc + 0.5 * vec_sim)
            if score > best_score:
                best_score = score
                best_entry = entry

        if best_entry and best_score >= min_similarity:
            result = dict(best_entry)
            result["_similarity_score"] = round(best_score, 3)
            return result

        return None

    def format_trajectory_exemplar(self, objective: str, min_similarity: float = 0.25) -> Optional[str]:
        """Formats the best matching trajectory as few-shot guidance for the LLM."""
        match = self.find_best_trajectory(objective, min_similarity=min_similarity)
        if not match:
            return None

        lines = [
            f"=== REASONING BANK: SIMILAR PAST SUCCESSFUL TRAJECTORY (Match Score: {match.get('_similarity_score')}) ===",
            f"Past Goal: {match.get('objective', '').strip()}",
            "Successful Actions Taken:",
        ]

        tool_calls = match.get("tool_calls", [])
        if isinstance(tool_calls, list):
            for i, tc in enumerate(tool_calls[:8], 1):
                if isinstance(tc, dict):
                    tool = tc.get("tool", "action")
                    args = tc.get("args", {})
                    # Compact representation of args
                    arg_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in args.items() if k not in ("content", "new"))
                    lines.append(f"  Step {i}: {tool}({arg_str})")

        summary = match.get("final_summary")
        if summary:
            lines.append(f"Resolution Summary: {summary.strip()}")

        lines.extend([
            "Guidance: Reuse the successful strategy above if applicable to your current workspace.",
            "=== END REASONING BANK EXEMPLAR ===",
            "",
        ])
        return "\n".join(lines)

    def record_run(self, run_result_dict: Dict[str, Any]) -> Optional[Path]:
        """Records a new execution run to disk and refreshes the memory index if successful."""
        mission_id = str(run_result_dict.get("mission_id") or f"run-{hash(str(run_result_dict))}")
        target_file = self.traces_dir / f"{mission_id}.json"
        try:
            target_file.write_text(json.dumps(run_result_dict, indent=2, default=str), encoding="utf-8")
            verif_ok = (run_result_dict.get("verification") or {}).get("exit_code") == 0
            status_ok = str(run_result_dict.get("status", "")).startswith("VERIFIED") or run_result_dict.get("status") == "PASSED"
            succeeded = bool(status_ok or verif_ok)
            toks = run_result_dict.get("tokens") or {}
            total_tok = int(toks.get("prompt", 0)) + int(toks.get("completion", 0))
            self.sona.record_episode(
                objective=str(run_result_dict.get("objective", "")),
                workflow=str(run_result_dict.get("workflow", "hierarchical")),
                role=str(run_result_dict.get("role", "general_engineer")),
                success=succeeded,
                tokens=total_tok,
                summary=str(run_result_dict.get("final_summary", "")),
                tools_used=[str(tc.get("tool", "")) for tc in (run_result_dict.get("tool_calls") or []) if isinstance(tc, dict)],
            )
            # Refresh if it was a success
            if succeeded:
                run_result_dict["_tokens"] = tokenize(str(run_result_dict.get("objective", "")))
                run_result_dict["_file_path"] = str(target_file)
                self._index.append(run_result_dict)
            return target_file
        except Exception:
            return None
