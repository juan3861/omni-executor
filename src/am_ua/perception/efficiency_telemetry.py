"""Efficiency Telemetry: TTFT, Inter-Token Latency (ITL), Throughput & Estimated GFLOPs (v12.0).

Zero-dependency stdlib implementation inspired by OpenJarvis telemetry/efficiency.py,
telemetry/flops.py, and telemetry/itl.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import statistics
from typing import Any, Dict, List, Optional


def estimate_transformer_gflops(
    *,
    prompt_tokens: int,
    completion_tokens: int,
    active_params_billions: float = 8.0,
) -> float:
    """Standard 2*N*tokens dense/active-parameter FLOP approximation returned in GFLOPs."""
    total_tokens = max(0, int(prompt_tokens)) + max(0, int(completion_tokens))
    # 2 * (active_params_billions * 1e9) * total_tokens / 1e9 == 2 * active_params_billions * total_tokens
    return round(2.0 * max(0.1, float(active_params_billions)) * total_tokens, 2)


def compute_itl_percentiles(inter_token_latencies_ms: List[float]) -> Dict[str, float]:
    """Return mean, p50, and p95 inter-token latency in milliseconds."""
    vals = sorted(max(0.0, float(v)) for v in inter_token_latencies_ms)
    if not vals:
        return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0}
    p50 = statistics.median(vals)
    p95_idx = min(len(vals) - 1, int(round(0.95 * (len(vals) - 1))))
    return {
        "mean_ms": round(statistics.fmean(vals), 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(vals[p95_idx], 3),
    }


@dataclass
class TurnEfficiencySample:
    turn: int
    provider: str
    model: str
    stage: str
    prompt_tokens: int
    completion_tokens: int
    latency_s: float
    ttft_ms: float = 0.0
    itl_ms: List[float] = field(default_factory=list)
    cost_usd: float = 0.0
    active_params_b: float = 8.0


class EfficiencyTracker:
    """Aggregates per-turn latency, ITL, throughput, GFLOPs, and cost efficiency."""

    def __init__(self) -> None:
        self.samples: List[TurnEfficiencySample] = []

    def record(
        self,
        *,
        turn: int,
        provider: str,
        model: str,
        stage: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_s: float,
        ttft_ms: float = 0.0,
        itl_ms: Optional[List[float]] = None,
        cost_usd: float = 0.0,
        active_params_b: float = 8.0,
    ) -> TurnEfficiencySample:
        sample = TurnEfficiencySample(
            turn=int(turn),
            provider=provider,
            model=model,
            stage=stage,
            prompt_tokens=max(0, int(prompt_tokens)),
            completion_tokens=max(0, int(completion_tokens)),
            latency_s=max(0.001, float(latency_s)),
            ttft_ms=max(0.0, float(ttft_ms)),
            itl_ms=list(itl_ms or []),
            cost_usd=max(0.0, float(cost_usd)),
            active_params_b=max(0.1, float(active_params_b)),
        )
        self.samples.append(sample)
        return sample

    def summary(self, *, quality_score: float = 1.0) -> Dict[str, Any]:
        if not self.samples:
            return {
                "turns": 0,
                "total_prompt_tokens": 0,
                "total_completion_tokens": 0,
                "total_latency_s": 0.0,
                "tokens_per_sec": 0.0,
                "ttft_mean_ms": 0.0,
                "itl": {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0},
                "estimated_gflops": 0.0,
                "total_cost_usd": 0.0,
                "efficiency_score": 0.0,
            }
        tot_p = sum(s.prompt_tokens for s in self.samples)
        tot_c = sum(s.completion_tokens for s in self.samples)
        tot_lat = sum(s.latency_s for s in self.samples)
        tot_cost = sum(s.cost_usd for s in self.samples)
        tot_gflops = sum(
            estimate_transformer_gflops(
                prompt_tokens=s.prompt_tokens,
                completion_tokens=s.completion_tokens,
                active_params_billions=s.active_params_b,
            )
            for s in self.samples
        )
        all_itl = [x for s in self.samples for x in s.itl_ms]
        ttft_vals = [s.ttft_ms for s in self.samples if s.ttft_ms > 0.0]
        tps = round(tot_c / max(0.001, tot_lat), 2)
        eff_score = round(max(0.0, quality_score) / (1.0 + tot_cost * 100.0 + tot_lat / 60.0), 4)
        return {
            "turns": len(self.samples),
            "total_prompt_tokens": tot_p,
            "total_completion_tokens": tot_c,
            "total_latency_s": round(tot_lat, 3),
            "tokens_per_sec": tps,
            "ttft_mean_ms": round(statistics.fmean(ttft_vals), 2) if ttft_vals else 0.0,
            "itl": compute_itl_percentiles(all_itl),
            "estimated_gflops": round(tot_gflops, 2),
            "total_cost_usd": round(tot_cost, 6),
            "efficiency_score": eff_score,
        }
