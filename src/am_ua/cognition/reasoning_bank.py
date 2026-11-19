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
        """Formats the best matching trajectory and SONA pitfall warnings as guidance for the LLM."""
        match = self.find_best_trajectory(objective, min_similarity=min_similarity)
        sona_hits = self.sona.search_similar(objective, top_k=3, min_score=0.2)
        pitfalls = [h for h in sona_hits if not h.get("success")]
        if not match and not pitfalls:
            return None

        lines: List[str] = []
        if match:
            lines.extend([
                f"=== REASONING BANK: SIMILAR PAST SUCCESSFUL TRAJECTORY (Match Score: {match.get('_similarity_score')}) ===",
                f"Past Goal: {match.get('objective', '').strip()}",
                "Successful Actions Taken:",
            ])

            tool_calls = match.get("tool_calls", [])
            if isinstance(tool_calls, list):
                for i, tc in enumerate(tool_calls[:8], 1):
                    if isinstance(tc, dict):
                        tool = tc.get("tool", "action")
                        args = tc.get("args", {})
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

        if pitfalls:
            p0 = pitfalls[0]
            lines.append(
                f"SONA PITFALL WARNING (sim={p0.get('similarity')}): A similar past mission failed "
                f"(tools={p0.get('tools_used', [])[:6]}; summary={str(p0.get('summary', ''))[:160]}). "
                "Avoid repeating that stall or incomplete fix."
            )
            lines.append("")
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

    def sleeptime_consolidate(self) -> Dict[str, Any]:
        """Background ToM consolidation: extract recurring tools, preferred workflow, and pitfalls."""
        from collections import Counter

        wf_counts: Counter[str] = Counter()
        tool_counts: Counter[str] = Counter()
        pitfall_summaries: List[str] = []
        trajectories_analyzed = 0

        if self.traces_dir.is_dir():
            for file in self.traces_dir.glob("*.json"):
                if file.name in ("sona_memory.json", "tom_user_model.json"):
                    continue
                try:
                    data = json.loads(file.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                trajectories_analyzed += 1
                wf = str(data.get("workflow", "react")).strip() or "react"
                status = str(data.get("status", "")).upper()
                verif_ok = isinstance(data.get("verification"), dict) and data["verification"].get("exit_code") == 0
                if status.startswith("VERIFIED") or status == "PASSED" or verif_ok:
                    wf_counts[wf] += 1
                for tc in (data.get("tool_calls") or []):
                    if isinstance(tc, dict) and tc.get("tool"):
                        tool_counts[str(tc["tool"])] += 1

        episodes = getattr(self.sona, "episodes", []) or []
        for ep in episodes:
            if not isinstance(ep, dict):
                continue
            wf = str(ep.get("workflow", "")).strip()
            if ep.get("success") and wf:
                wf_counts[wf] += 1
            elif not ep.get("success") and ep.get("summary"):
                pitfall_summaries.append(str(ep.get("summary", ""))[:180])
            for t in (ep.get("tools_used") or []):
                if t:
                    tool_counts[str(t)] += 1

        preferred_workflow = wf_counts.most_common(1)[0][0] if wf_counts else "react"
        top_tools = [t for t, _ in tool_counts.most_common(8)]
        profile_path = self.traces_dir / "tom_user_model.json"
        profile = {
            "schema": "omni_executor_tom_profile/v1",
            "trajectories_analyzed": trajectories_analyzed,
            "episodes_analyzed": len(episodes),
            "preferred_workflow": preferred_workflow,
            "top_tools": top_tools,
            "common_pitfalls": pitfall_summaries[-10:],
            "pitfalls_count": len(pitfall_summaries),
        }
        profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"ok": True, **profile, "profile_path": str(profile_path)}

    def consult_tom(self, query: str) -> Dict[str, Any]:
        """Consult the consolidated ToM user profile plus similar trajectories and pitfalls."""
        profile_path = self.traces_dir / "tom_user_model.json"
        if profile_path.is_file():
            try:
                profile = json.loads(profile_path.read_text(encoding="utf-8"))
            except Exception:
                profile = self.sleeptime_consolidate()
        else:
            profile = self.sleeptime_consolidate()

        match = self.find_best_trajectory(query, min_similarity=0.15)
        sona_hits = self.sona.search_similar(query, top_k=3, min_score=0.15)
        pitfalls = [h for h in sona_hits if not h.get("success")]

        tips: List[str] = [
            f"Preferred workflow based on history: {profile.get('preferred_workflow', 'react')}.",
        ]
        if profile.get("top_tools"):
            tips.append(f"Frequently effective tools: {', '.join(profile['top_tools'][:5])}.")
        if match and match.get("final_summary"):
            tips.append(f"Closest past resolution (sim={match.get('_similarity_score')}): {str(match['final_summary'])[:180]}")
        if pitfalls:
            tips.append(f"Avoid recurring pitfall: {str(pitfalls[0].get('summary', ''))[:160]}")

        conf = 0.85 if match else (0.65 if profile.get("episodes_analyzed", 0) > 0 else 0.4)
        return {
            "ok": True,
            "query": query,
            "preferred_workflow": profile.get("preferred_workflow", "react"),
            "suggestions": " ".join(tips),
            "confidence": round(conf, 3),
            "matched_trajectory": bool(match),
            "pitfalls_detected": len(pitfalls),
        }
