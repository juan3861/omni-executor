"""Hybrid Modality Router — Agent-S3 Native Code-GUI Selector & Mixture-of-Grounding (F3).

Assimilates `simular-ai/Agent-S` (Agent S2.5 / S3) Mixture-of-Grounding (MoG) & Native Coding Agent:
1. Never defaults to slow, brittle pixel-clicking when a deterministic code/shell script, forged
   adaptive skill, or semantic Windows UIA locator can solve the subgoal in milliseconds.
2. Ranks the 6 execution modalities by determinism & token efficiency:
   `adaptive_skill` > `code_shell` > `uia_locator` > `mcp_tool` > `cdp_browser` > `visual_som`.
3. Learns from empirical execution outcomes (`record_modality_outcome`), persisting pass/fail
   rates per `(task_category, modality)` in `modality_telemetry.json`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from am_ua.execution.adaptive_skills import AdaptiveSkillForge


class ModalityType(str, Enum):
    """Supported execution modalities ordered by determinism."""

    ADAPTIVE_SKILL = "adaptive_skill"
    CODE_SHELL = "code_shell"
    UIA_LOCATOR = "uia_locator"
    MCP_TOOL = "mcp_tool"
    CDP_BROWSER = "cdp_browser"
    VISUAL_SOM = "visual_som"


DEFAULT_COST_WEIGHTS: Dict[str, int] = {
    ModalityType.ADAPTIVE_SKILL.value: 100,
    ModalityType.CODE_SHELL.value: 250,
    ModalityType.UIA_LOCATOR.value: 350,
    ModalityType.MCP_TOOL.value: 400,
    ModalityType.CDP_BROWSER.value: 600,
    ModalityType.VISUAL_SOM.value: 1200,
}


@dataclass
class ModalityDecision:
    """Routing decision for a subgoal or task."""

    primary_modality: str
    fallback_chain: List[str]
    confidence: float
    rationale: str
    matched_skill: Optional[str] = None
    estimated_token_cost: int = 250
    recommended_tools: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


MODALITY_TOOLS_MAP: Dict[str, List[str]] = {
    ModalityType.ADAPTIVE_SKILL.value: ["skill_run", "skill_forge", "write_file"],
    ModalityType.CODE_SHELL.value: ["read_file", "replace_in_file", "write_file", "run", "search"],
    ModalityType.UIA_LOCATOR.value: ["pc_window", "pc_observe", "pc_act", "pc_clipboard"],
    ModalityType.MCP_TOOL.value: ["mcp_call", "run"],
    ModalityType.CDP_BROWSER.value: ["browser_observe", "browser_act", "browser_extract"],
    ModalityType.VISUAL_SOM.value: ["pc_observe", "pc_act", "pc_window"],
}


class HybridModalityRouter:
    """Routes subgoals across Code/Shell, Adaptive Skills, UIA, Browser CDP, MCP, and Visual SoM."""

    def __init__(
        self,
        *,
        skill_forge: Optional[AdaptiveSkillForge] = None,
        telemetry_path: Optional[Path | str] = None,
    ) -> None:
        self.skill_forge = skill_forge
        self.telemetry_path = Path(
            telemetry_path or r"F:\AetherMind_Temp\modality_telemetry.json"
        ).resolve()
        self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        self._stats: Dict[str, Dict[str, int]] = self._load_stats()

    def _load_stats(self) -> Dict[str, Dict[str, int]]:
        if not self.telemetry_path.is_file():
            return {}
        try:
            data = json.loads(self.telemetry_path.read_text(encoding="utf-8"))
            return dict(data.get("stats", {}))
        except Exception:
            return {}

    def _save_stats(self) -> None:
        payload = {
            "schema": "AETHERMIND_MODALITY_TELEMETRY/v1",
            "updated_at": time.time(),
            "stats": self._stats,
        }
        self.telemetry_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def record_outcome(self, category: str, modality: str, *, passed: bool) -> Dict[str, int]:
        key = f"{category.lower().strip()}:{modality.lower().strip()}"
        entry = self._stats.setdefault(key, {"runs": 0, "passes": 0, "failures": 0})
        entry["runs"] += 1
        if passed:
            entry["passes"] += 1
        else:
            entry["failures"] += 1
        self._save_stats()
        return dict(entry)

    def empirical_pass_rate(self, category: str, modality: str) -> float:
        key = f"{category.lower().strip()}:{modality.lower().strip()}"
        entry = self._stats.get(key)
        if not entry or entry.get("runs", 0) == 0:
            return 0.75  # neutral Laplace prior
        return (entry["passes"] + 1.0) / (entry["runs"] + 2.0)

    def select_modality(
        self,
        objective_or_subgoal: str,
        *,
        suggested_modality: Optional[str] = None,
        category: str = "general",
        prefer_code_over_gui: bool = True,
    ) -> ModalityDecision:
        """Select optimal execution modality and ordered fallback chain."""
        text = (objective_or_subgoal or "").strip()
        low = text.lower()

        # 1. Check if a high-similarity verified Adaptive Skill already exists
        if self.skill_forge is not None:
            matches = self.skill_forge.search_skills(text, top_k=1)
            if matches and float(matches[0].get("similarity", 0.0)) >= 0.55:
                skill_name = str(matches[0]["name"])
                return ModalityDecision(
                    primary_modality=ModalityType.ADAPTIVE_SKILL.value,
                    fallback_chain=[
                        ModalityType.CODE_SHELL.value,
                        ModalityType.UIA_LOCATOR.value,
                    ],
                    confidence=0.92,
                    rationale=f"Matched existing verified adaptive skill '{skill_name}' (sim={matches[0]['similarity']})",
                    matched_skill=skill_name,
                    estimated_token_cost=DEFAULT_COST_WEIGHTS[ModalityType.ADAPTIVE_SKILL.value],
                    recommended_tools=MODALITY_TOOLS_MAP[ModalityType.ADAPTIVE_SKILL.value],
                )

        # 2. Check explicit web / browser intent
        is_web = any(
            k in low
            for k in ("http://", "https://", "webpage", "browser", "navegador", "website", "dom", "html page")
        )
        if is_web:
            return ModalityDecision(
                primary_modality=ModalityType.CDP_BROWSER.value,
                fallback_chain=[
                    ModalityType.CODE_SHELL.value,
                    ModalityType.VISUAL_SOM.value,
                ],
                confidence=0.88,
                rationale="Web URL or browser DOM interaction detected; routing to CDP Indexed Browser.",
                estimated_token_cost=DEFAULT_COST_WEIGHTS[ModalityType.CDP_BROWSER.value],
                recommended_tools=MODALITY_TOOLS_MAP[ModalityType.CDP_BROWSER.value],
            )

        # 3. Check explicit GUI / desktop window intent vs code/file intent
        explicit_gui = any(
            k in low
            for k in (
                "desktop window",
                "janela",
                "pc_observe",
                "pc_act",
                "click the button",
                "clique no botão",
                "on screen",
                "na tela",
            )
        )
        can_use_code = any(
            k in low
            for k in (
                ".py",
                ".json",
                ".csv",
                ".txt",
                ".md",
                "function",
                "class ",
                "pytest",
                "refactor",
                "fix the bug",
                "implement ",
                "script",
                "process",
                "port",
            )
        )

        # Agent-S3 Native Coding Agent law: if a task can be solved via code/filesystem without
        # explicitly requiring a live GUI window interaction, always route to `code_shell` first.
        if prefer_code_over_gui and can_use_code and not explicit_gui:
            rate = self.empirical_pass_rate(category, ModalityType.CODE_SHELL.value)
            return ModalityDecision(
                primary_modality=ModalityType.CODE_SHELL.value,
                fallback_chain=[
                    ModalityType.ADAPTIVE_SKILL.value,
                    ModalityType.UIA_LOCATOR.value,
                ],
                confidence=round(min(0.96, max(0.75, rate)), 3),
                rationale="Agent-S3 Code-First Law: task is solvable deterministically via code/shell.",
                estimated_token_cost=DEFAULT_COST_WEIGHTS[ModalityType.CODE_SHELL.value],
                recommended_tools=MODALITY_TOOLS_MAP[ModalityType.CODE_SHELL.value],
            )

        if explicit_gui or suggested_modality in (ModalityType.UIA_LOCATOR.value, ModalityType.VISUAL_SOM.value):
            # Mixture-of-Grounding: try fast structural UIA + OCR locator first, escalate to VLM Visual SoM if needed
            uia_rate = self.empirical_pass_rate(category, ModalityType.UIA_LOCATOR.value)
            som_rate = self.empirical_pass_rate(category, ModalityType.VISUAL_SOM.value)
            if suggested_modality == ModalityType.VISUAL_SOM.value or som_rate > uia_rate + 0.15:
                primary = ModalityType.VISUAL_SOM.value
                fallbacks = [ModalityType.UIA_LOCATOR.value, ModalityType.CODE_SHELL.value]
                rationale = "Mixture-of-Grounding selected Visual Set-of-Mark (SoM) grounding."
            else:
                primary = ModalityType.UIA_LOCATOR.value
                fallbacks = [ModalityType.VISUAL_SOM.value, ModalityType.CODE_SHELL.value]
                rationale = "Mixture-of-Grounding selected structural Windows UIA + OCR locator first, with Visual SoM fallback."
            return ModalityDecision(
                primary_modality=primary,
                fallback_chain=fallbacks,
                confidence=round(max(uia_rate, som_rate), 3),
                rationale=rationale,
                estimated_token_cost=DEFAULT_COST_WEIGHTS[primary],
                recommended_tools=MODALITY_TOOLS_MAP[primary],
            )

        # 4. Default to code_shell
        primary = (
            suggested_modality
            if suggested_modality in DEFAULT_COST_WEIGHTS
            else ModalityType.CODE_SHELL.value
        )
        return ModalityDecision(
            primary_modality=primary,
            fallback_chain=[
                m
                for m in (
                    ModalityType.CODE_SHELL.value,
                    ModalityType.ADAPTIVE_SKILL.value,
                    ModalityType.UIA_LOCATOR.value,
                    ModalityType.VISUAL_SOM.value,
                )
                if m != primary
            ],
            confidence=0.85,
            rationale=f"Default deterministic routing to '{primary}'.",
            estimated_token_cost=DEFAULT_COST_WEIGHTS.get(primary, 250),
            recommended_tools=MODALITY_TOOLS_MAP.get(primary, MODALITY_TOOLS_MAP[ModalityType.CODE_SHELL.value]),
        )
