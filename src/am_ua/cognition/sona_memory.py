"""SONA Vector Memory & Adaptive Strategy Router (src/am_ua/cognition/sona_memory.py).

Inspired by Ruflo's AgentDB (HNSW-style vector similarity) and SONA
(Self-Optimizing Neural Architecture) Q-utility strategy routing.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


_TOKEN_RX = re.compile(r"[a-z0-9_]{2,}")


def _embed_text(text: str, dim: int = 128) -> np.ndarray:
    """Deterministic sub-millisecond signed hash-projection embedding (L2-normalized)."""
    vec = np.zeros(dim, dtype=np.float32)
    tokens = _TOKEN_RX.findall((text or "").lower())
    if not tokens:
        return vec
    # Unigrams + bigrams for richer semantic matching
    grams = list(tokens) + [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
    for g in grams:
        digest = hashlib.blake2b(g.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % dim
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign
    norm = float(np.linalg.norm(vec))
    if norm > 1e-9:
        vec /= norm
    return vec


class SONAVectorMemory:
    """Hybrid dense-vector + token-overlap memory with SONA Q-utility strategy bandit."""

    def __init__(self, storage_path: Optional[Path | str] = None, *, dim: int = 128) -> None:
        self.dim = dim
        self.storage_path = Path(storage_path) if storage_path else None
        self.episodes: List[Dict[str, Any]] = []
        self._vectors: Optional[np.ndarray] = None
        self.q_table: Dict[str, Dict[str, float]] = {}  # strategy_key -> {"q": float, "n": int}
        if self.storage_path and self.storage_path.is_file():
            self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
            self.episodes = list(data.get("episodes", []))
            self.q_table = dict(data.get("q_table", {}))
            self._rebuild_matrix()
        except Exception:
            pass

    def _save(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"episodes": self.episodes[-500:], "q_table": self.q_table}
        self.storage_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    def _rebuild_matrix(self) -> None:
        if not self.episodes:
            self._vectors = None
            return
        self._vectors = np.vstack([_embed_text(ep.get("objective", ""), dim=self.dim) for ep in self.episodes])

    def record_episode(
        self,
        *,
        objective: str,
        workflow: str,
        role: str,
        success: bool,
        tokens: int = 0,
        summary: str = "",
        tools_used: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ep = {
            "objective": objective[:600],
            "workflow": workflow,
            "role": role,
            "success": bool(success),
            "tokens": int(tokens),
            "summary": summary[:400],
            "tools_used": list(tools_used or [])[:20],
        }
        self.episodes.append(ep)
        self._rebuild_matrix()

        # SONA Q-utility update (reward penalized mildly by token volume)
        key = f"{workflow}:{role}"
        entry = self.q_table.get(key, {"q": 0.5, "n": 0})
        reward = (1.0 if success else 0.0) - min(0.15, tokens / 1_000_000.0)
        alpha = 0.3
        new_q = (1.0 - alpha) * float(entry["q"]) + alpha * reward
        self.q_table[key] = {"q": round(new_q, 5), "n": int(entry["n"]) + 1}
        self._save()
        return {"episode_count": len(self.episodes), "strategy": key, "q_value": self.q_table[key]["q"]}

    def search_similar(self, query: str, *, top_k: int = 3, min_score: float = 0.15) -> List[Dict[str, Any]]:
        if not self.episodes or self._vectors is None:
            return []
        q_vec = _embed_text(query, dim=self.dim)
        sims = self._vectors @ q_vec
        q_toks = set(_TOKEN_RX.findall((query or "").lower()))
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for idx, ep in enumerate(self.episodes):
            cos = float(sims[idx])
            ep_toks = set(_TOKEN_RX.findall(ep.get("objective", "").lower()))
            jacc = (len(q_toks & ep_toks) / max(1, len(q_toks | ep_toks))) if q_toks else 0.0
            hybrid = 0.7 * cos + 0.3 * jacc
            if hybrid >= min_score:
                scored.append((hybrid, {**ep, "similarity": round(hybrid, 4)}))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    def recommend_strategy(self, default_workflow: str = "hierarchical", default_role: str = "general_engineer") -> Dict[str, Any]:
        if not self.q_table:
            return {"workflow": default_workflow, "role": default_role, "q_value": 0.5, "source": "default"}
        best_key, best_val = max(self.q_table.items(), key=lambda kv: kv[1]["q"])
        wf, role = best_key.split(":", 1) if ":" in best_key else (default_workflow, default_role)
        return {"workflow": wf, "role": role, "q_value": best_val["q"], "samples": best_val["n"], "source": "sona_q"}
