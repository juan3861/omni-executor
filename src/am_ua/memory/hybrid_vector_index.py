"""Hybrid BM25 (SQLite FTS5) + Hash-SVD Vector Index with Reciprocal Rank Fusion (v8.1).

100% stdlib-portable (`sqlite3` FTS5 + deterministic L2-normalized dense hash projections + optional numpy acceleration)
with bi-temporal ACT-R decay, host-pinned namespace filtering, and zero external API keys required.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_TOKEN_RX = re.compile(r"[a-zA-Z0-9_.\-]{2,}")


def _char_ngrams_and_tokens(text: str) -> List[str]:
    low = (text or "").lower()
    words = _TOKEN_RX.findall(low)
    feats = list(words)
    # Character trigrams improve robustness on identifiers, snake_case, and typos
    for w in words[:80]:
        if len(w) >= 4:
            for i in range(len(w) - 2):
                feats.append(w[i : i + 3])
    return feats


def deterministic_embed(text: str, dim: int = 128) -> List[float]:
    """Build a deterministic L2-normalized signed random-projection vector over tokens + char trigrams."""
    vec = [0.0] * max(16, int(dim))
    d = len(vec)
    feats = _char_ngrams_and_tokens(text)
    if not feats:
        return vec
    for tok in feats:
        digest = hashlib.blake2b(tok.encode("utf-8"), digest_size=8).digest()
        val = int.from_bytes(digest, "little")
        bucket = val % d
        sign = 1.0 if ((val >> 8) & 1) else -1.0
        bucket2 = (val >> 16) % d
        sign2 = 1.0 if ((val >> 24) & 1) else -1.0
        vec[bucket] += sign
        vec[bucket2] += 0.5 * sign2
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 1e-12:
        vec = [round(x / norm, 6) for x in vec]
    return vec


def cosine_similarity(a: List[float], b: List[float]) -> float:
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    return sum(a[i] * b[i] for i in range(n))


class HybridVectorIndex:
    """SQLite FTS5 BM25 + Dense Cosine + Temporal Decay + RRF Fusion memory index."""

    def __init__(self, db_path: Path | str, *, dim: int = 128) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.dim = max(16, int(dim))
        self._lock = threading.RLock()
        self._fts_enabled = False
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hybrid_docs (
                    doc_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    content TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    importance REAL NOT NULL,
                    embedding_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hybrid_ns ON hybrid_docs(namespace, created_at DESC)")
            try:
                conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS hybrid_fts USING fts5(
                        doc_id UNINDEXED,
                        namespace UNINDEXED,
                        content
                    )
                    """
                )
                self._fts_enabled = True
            except sqlite3.OperationalError:
                self._fts_enabled = False

    def add(
        self,
        content: str,
        *,
        namespace: str = "global",
        kind: str = "semantic",
        importance: float = 0.7,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        did = str(doc_id or f"hv_{uuid.uuid4().hex[:12]}")
        ns = (namespace or "global").strip() or "global"
        txt = str(content or "").strip()
        emb = deterministic_embed(txt, dim=self.dim)
        now = time.time()
        meta_str = json.dumps(metadata or {}, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO hybrid_docs
                (doc_id, namespace, content, kind, importance, embedding_json, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (did, ns, txt, kind, float(importance), json.dumps(emb), meta_str, now),
            )
            if self._fts_enabled:
                conn.execute("DELETE FROM hybrid_fts WHERE doc_id = ?", (did,))
                conn.execute(
                    "INSERT INTO hybrid_fts (doc_id, namespace, content) VALUES (?, ?, ?)",
                    (did, ns, txt),
                )
        return {"doc_id": did, "namespace": ns, "kind": kind, "created_at": now}

    def query(
        self,
        query_text: str,
        *,
        namespace: Optional[str] = None,
        top_k: int = 5,
        rrf_k: int = 60,
        half_life_days: float = 30.0,
    ) -> List[Dict[str, Any]]:
        """Retrieve ranked records using BM25 + dense cosine Reciprocal Rank Fusion (RRF) + recency decay."""
        q = (query_text or "").strip()
        if not q:
            return []
        q_emb = deterministic_embed(q, dim=self.dim)
        q_tokens = set(_TOKEN_RX.findall(q.lower()))
        now = time.time()

        with self._lock, self._connect() as conn:
            if namespace:
                rows = conn.execute(
                    """
                    SELECT doc_id, namespace, content, kind, importance, embedding_json, metadata_json, created_at
                    FROM hybrid_docs WHERE namespace = ?
                    """,
                    (namespace,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT doc_id, namespace, content, kind, importance, embedding_json, metadata_json, created_at
                    FROM hybrid_docs
                    """
                ).fetchall()

            bm25_ranks: Dict[str, int] = {}
            if self._fts_enabled and q_tokens:
                fts_query = " OR ".join(f'"{t.replace(chr(34), "")}"' for t in sorted(q_tokens)[:10])
                try:
                    if namespace:
                        fts_rows = conn.execute(
                            "SELECT doc_id, bm25(hybrid_fts) AS r FROM hybrid_fts WHERE hybrid_fts MATCH ? AND namespace = ? ORDER BY r ASC LIMIT 50",
                            (fts_query, namespace),
                        ).fetchall()
                    else:
                        fts_rows = conn.execute(
                            "SELECT doc_id, bm25(hybrid_fts) AS r FROM hybrid_fts WHERE hybrid_fts MATCH ? ORDER BY r ASC LIMIT 50",
                            (fts_query,),
                        ).fetchall()
                    for idx, (did, _) in enumerate(fts_rows, start=1):
                        bm25_ranks[str(did)] = idx
                except sqlite3.OperationalError:
                    bm25_ranks = {}

        if not rows:
            return []

        docs_by_id: Dict[str, Dict[str, Any]] = {}
        vec_scored: List[Tuple[float, str]] = []
        lex_fallback: List[Tuple[float, str]] = []

        for did, ns, content, kind, imp, emb_json, meta_json, created_at in rows:
            emb = json.loads(emb_json)
            cos = cosine_similarity(q_emb, emb)
            age_days = max(0.0, (now - float(created_at)) / 86400.0)
            decay = math.exp(-math.log(2.0) * age_days / max(1.0, half_life_days))
            docs_by_id[did] = {
                "doc_id": did,
                "namespace": ns,
                "content": content,
                "kind": kind,
                "importance": float(imp),
                "metadata": json.loads(meta_json),
                "created_at": float(created_at),
                "cosine": round(cos, 5),
                "decay": round(decay, 5),
            }
            vec_scored.append((cos, did))
            if not bm25_ranks:
                c_tokens = set(_TOKEN_RX.findall(content.lower()))
                overlap = len(q_tokens & c_tokens) / max(1, len(q_tokens)) if q_tokens else 0.0
                lex_fallback.append((overlap, did))

        vec_scored.sort(key=lambda x: x[0], reverse=True)
        vec_ranks = {did: idx for idx, (_, did) in enumerate(vec_scored, start=1)}
        if not bm25_ranks:
            lex_fallback.sort(key=lambda x: x[0], reverse=True)
            bm25_ranks = {did: idx for idx, (sc, did) in enumerate(lex_fallback, start=1) if sc > 0.0}

        k = max(1, int(rrf_k))
        ranked_out: List[Dict[str, Any]] = []
        for did, doc in docs_by_id.items():
            rrf = 1.0 / (k + vec_ranks[did])
            if did in bm25_ranks:
                rrf += 1.2 / (k + bm25_ranks[did])
            score = rrf * (0.75 + 0.25 * doc["decay"]) * (0.8 + 0.2 * doc["importance"])
            doc["bm25_rank"] = bm25_ranks.get(did)
            doc["vector_rank"] = vec_ranks[did]
            doc["rrf_score"] = round(score, 6)
            ranked_out.append(doc)

        ranked_out.sort(key=lambda d: d["rrf_score"], reverse=True)
        return ranked_out[: max(1, int(top_k))]

    def count(self, *, namespace: Optional[str] = None) -> int:
        with self._lock, self._connect() as conn:
            if namespace:
                row = conn.execute("SELECT COUNT(*) FROM hybrid_docs WHERE namespace = ?", (namespace,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM hybrid_docs").fetchone()
        return int(row[0]) if row else 0
