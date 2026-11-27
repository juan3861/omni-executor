"""Complexity-Aware Query Analyzer, SkillOrchestra Stage Router & Learned Policy (v12.0).

Zero-dependency stdlib implementation inspired by OpenJarvis:
  - `learning/routing/complexity.py` (ComplexityQueryAnalyzer)
  - `agents/hybrid/skillorchestra/stage_router.py` (StageSkillHandbook)
  - `learning/routing/learned_router.py` (LearnedRouterPolicy)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple


_CODE_PATTERNS = re.compile(
    r"```|`[^`]+`|\bdef\s|\bclass\s|\bimport\s|\bfunction\s|\bpytest\b|\btraceback\b|"
    r"\bpatch\b|\bdiff\b|\brefactor\b|\bstacktrace\b|\.py\b|\.ts\b|\.rs\b",
    re.IGNORECASE,
)
_MATH_PATTERNS = re.compile(
    r"\bsolve\b|\bintegral\b|\bequation\b|\bproof\b|\bderivative\b|\bmatrix\b|"
    r"\btheorem\b|\bcalculate\b|\bcompute\b|\bprobability\b|\bsympy\b|\bz3\b",
    re.IGNORECASE,
)
_REASONING_PATTERNS = re.compile(
    r"\bexplain\b|\banalyze\b|\bcompare\b|\bwhy\b|\broot cause\b|\bdebug\b|"
    r"\bstep[- ]by[- ]step\b|\btrade-?\s*offs?\b|\bevaluate\b|\bdiagnose\b",
    re.IGNORECASE,
)
_MULTI_STEP_PATTERNS = re.compile(
    r"\bstep\s*\d|\b(?:and\s+also|additionally|furthermore)\b|\b\d+\.\s|\bthen\b.*\bthen\b",
    re.IGNORECASE | re.DOTALL,
)
_THINKING_MODEL_PATTERNS = re.compile(
    r"qwen3\.5|qwq|deepseek-r1|o1-|o3-|o4-|thinking|reasoning",
    re.IGNORECASE,
)

TOKEN_TIERS: Dict[str, int] = {
    "trivial": 1024,
    "simple": 2048,
    "moderate": 4096,
    "complex": 8192,
    "very_complex": 16384,
}


@dataclass(frozen=True)
class ComplexityResult:
    score: float
    tier: str
    suggested_max_tokens: int
    query_class: str
    signals: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "tier": self.tier,
            "suggested_max_tokens": self.suggested_max_tokens,
            "query_class": self.query_class,
            "signals": list(self.signals),
        }


class ComplexityQueryAnalyzer:
    """Scores objective complexity (0.0-1.0) and recommends a token budget tier."""

    @staticmethod
    def classify_query(query: str) -> str:
        q = query or ""
        if _CODE_PATTERNS.search(q):
            return "code"
        if _MATH_PATTERNS.search(q):
            return "math"
        if _REASONING_PATTERNS.search(q):
            return "reasoning"
        if len(q) < 80:
            return "simple"
        return "general"

    @classmethod
    def analyze(cls, query: str, *, model_name: str = "") -> ComplexityResult:
        text = (query or "").strip()
        score = 0.0
        signals: List[str] = []

        char_len = len(text)
        if char_len > 2500:
            score += 0.30
            signals.append("very_long_prompt")
        elif char_len > 800:
            score += 0.20
            signals.append("long_prompt")
        elif char_len > 200:
            score += 0.10
            signals.append("medium_prompt")

        if _CODE_PATTERNS.search(text):
            score += 0.25
            signals.append("code")
        if _MATH_PATTERNS.search(text):
            score += 0.20
            signals.append("math")
        if _REASONING_PATTERNS.search(text):
            score += 0.20
            signals.append("reasoning")
        if _MULTI_STEP_PATTERNS.search(text):
            score += 0.15
            signals.append("multi_step")

        score = max(0.0, min(1.0, score))
        if score < 0.15:
            tier = "trivial"
        elif score < 0.35:
            tier = "simple"
        elif score < 0.55:
            tier = "moderate"
        elif score < 0.78:
            tier = "complex"
        else:
            tier = "very_complex"

        budget = TOKEN_TIERS[tier]
        if model_name and _THINKING_MODEL_PATTERNS.search(model_name):
            budget = min(32768, budget * 2)
            signals.append("thinking_headroom_2x")

        return ComplexityResult(
            score=score,
            tier=tier,
            suggested_max_tokens=budget,
            query_class=cls.classify_query(text),
            signals=tuple(signals),
        )


@dataclass
class ModelStageProfile:
    """Observed or configured performance profile for a provider/model at a specific loop stage."""

    provider: str
    model: str
    stage: str  # "locate" | "reason" | "verify"
    success_rate: float = 0.5
    avg_latency_s: float = 2.0
    cost_per_1k_usd: float = 0.0
    attempts: int = 0
    successes: int = 0
    tier: str = "free"  # "zero_token" | "free" | "frontier"

    def score(self, *, prefer_free: bool = True) -> float:
        cost_penalty = (0.25 * self.cost_per_1k_usd) if prefer_free else (0.05 * self.cost_per_1k_usd)
        speed_bonus = 0.15 / max(0.2, self.avg_latency_s)
        return self.success_rate + speed_bonus - cost_penalty


class StageSkillHandbook:
    """SkillOrchestra-style per-stage model/provider router (`locate` -> `reason` -> `verify`)."""

    FREE_PROVIDERS: Tuple[str, ...] = ("groq", "openrouter", "nvidia", "cerebras", "ollama")
    FRONTIER_PROVIDERS: Tuple[str, ...] = ("anthropic", "openai", "gemini")

    DEFAULT_STAGE_PREFERENCE: Dict[str, Tuple[str, ...]] = {
        "locate": ("groq", "openrouter", "nvidia", "cerebras", "ollama", "gemini"),
        "reason": ("groq", "openrouter", "nvidia", "anthropic", "openai", "gemini", "cerebras"),
        "verify": ("groq", "openrouter", "nvidia", "cerebras", "ollama", "gemini"),
    }

    def __init__(self, profiles: Optional[Sequence[ModelStageProfile]] = None) -> None:
        self.profiles: List[ModelStageProfile] = list(profiles or [])

    def infer_stage(self, *, turn: int, has_edits: bool, pending_verify: bool = False) -> str:
        if pending_verify:
            return "verify"
        if turn <= 2 and not has_edits:
            return "locate"
        return "reason"

    def record_outcome(
        self,
        *,
        provider: str,
        model: str,
        stage: str,
        success: bool,
        latency_s: float = 1.0,
        cost_per_1k_usd: float = 0.0,
    ) -> ModelStageProfile:
        for prof in self.profiles:
            if prof.provider == provider and prof.model == model and prof.stage == stage:
                prof.attempts += 1
                if success:
                    prof.successes += 1
                prof.success_rate = prof.successes / max(1, prof.attempts)
                prof.avg_latency_s = 0.7 * prof.avg_latency_s + 0.3 * max(0.05, latency_s)
                return prof
        prof = ModelStageProfile(
            provider=provider,
            model=model,
            stage=stage,
            success_rate=1.0 if success else 0.0,
            avg_latency_s=max(0.05, latency_s),
            cost_per_1k_usd=cost_per_1k_usd,
            attempts=1,
            successes=1 if success else 0,
        )
        self.profiles.append(prof)
        return prof

    def select_provider(
        self,
        stage: str,
        available_providers: Sequence[str],
        *,
        prefer_free: bool = True,
        allow_frontier: bool = False,
        complexity_score: float = 0.0,
    ) -> Optional[str]:
        avail = list(available_providers)
        if not avail:
            return None
        pool = list(avail)
        if prefer_free and not allow_frontier:
            free_only = [p for p in avail if p not in self.FRONTIER_PROVIDERS]
            if free_only:
                pool = free_only
        elif allow_frontier and complexity_score >= 0.78:
            frontier_avail = [p for p in self.FRONTIER_PROVIDERS if p in avail]
            if frontier_avail:
                return frontier_avail[0]
        stage_key = stage if stage in self.DEFAULT_STAGE_PREFERENCE else "reason"
        candidates = [p for p in self.profiles if p.stage == stage_key and p.provider in pool and p.attempts >= 3]
        if candidates:
            best = max(candidates, key=lambda p: p.score(prefer_free=prefer_free))
            return best.provider
        for pref in self.DEFAULT_STAGE_PREFERENCE[stage_key]:
            if pref in pool:
                return pref
        return pool[0]


class LearnedRouterPolicy:
    """Trace-driven router learning `query_class -> best_provider` with minimum-sample gating."""

    def __init__(self, *, min_samples: int = 5, store_path: Optional[Path | str] = None) -> None:
        self.min_samples = max(1, int(min_samples))
        self.store_path = Path(store_path) if store_path else None
        # query_class -> provider -> {"attempts": int, "reward_sum": float}
        self._stats: Dict[str, Dict[str, Dict[str, float]]] = {}
        if self.store_path and self.store_path.is_file():
            self.load(self.store_path)

    def observe(self, query: str, provider: str, *, reward: float) -> str:
        qclass = ComplexityQueryAnalyzer.classify_query(query)
        bucket = self._stats.setdefault(qclass, {}).setdefault(provider, {"attempts": 0.0, "reward_sum": 0.0})
        bucket["attempts"] += 1.0
        bucket["reward_sum"] += max(0.0, min(1.0, float(reward)))
        if self.store_path:
            self.save(self.store_path)
        return qclass

    def select_provider(
        self,
        query: str,
        available_providers: Sequence[str],
        *,
        default_provider: Optional[str] = None,
    ) -> Optional[str]:
        avail = list(available_providers)
        if not avail:
            return default_provider
        qclass = ComplexityQueryAnalyzer.classify_query(query)
        class_stats = self._stats.get(qclass, {})
        eligible = [
            (prov, data["reward_sum"] / max(1.0, data["attempts"]), int(data["attempts"]))
            for prov, data in class_stats.items()
            if prov in avail and int(data.get("attempts", 0)) >= self.min_samples
        ]
        if eligible:
            eligible.sort(key=lambda item: (item[1], item[2]), reverse=True)
            return eligible[0][0]
        if default_provider and default_provider in avail:
            return default_provider
        return avail[0]

    def policy_snapshot(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for qclass, providers in self._stats.items():
            ranked = sorted(
                (
                    {
                        "provider": prov,
                        "attempts": int(d["attempts"]),
                        "avg_reward": round(d["reward_sum"] / max(1.0, d["attempts"]), 4),
                    }
                    for prov, d in providers.items()
                ),
                key=lambda r: (r["avg_reward"], r["attempts"]),
                reverse=True,
            )
            out[qclass] = {"candidates": ranked}
        return out

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._stats, indent=2, ensure_ascii=False), encoding="utf-8")

    def load(self, path: Path | str) -> None:
        p = Path(path)
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._stats = data
            except (OSError, json.JSONDecodeError):
                pass
