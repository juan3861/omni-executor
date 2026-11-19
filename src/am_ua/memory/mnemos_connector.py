"""Layer 2: F:\\Mnemos Bi-Temporal Cognitive Memory Adapter (P3.2).

Connects `AetherMind Universal Agent` directly to the proven `F:\\Mnemos` engine
(Modern Hopfield + ACT-R + FSRS + Hippocampal PPR + Graphiti Bi-Temporal +
Metamemory Abstention + Prospective Triggers + MarkdownVault ADR projection)
using an isolated database at `F:\\AetherMind_Universal_Agent\\data\\mnemos_ua.db`.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]

MNEMOS_SRC = Path(r"F:\Mnemos\src")
if MNEMOS_SRC.is_dir() and str(MNEMOS_SRC) not in sys.path:
    sys.path.insert(0, str(MNEMOS_SRC))

try:
    from mnemos.core.engine import MemoryEngine  # type: ignore[import-untyped]
    MNEMOS_AVAILABLE = True
except ImportError:  # pragma: no cover
    MemoryEngine = None  # type: ignore[assignment,misc]
    MNEMOS_AVAILABLE = False


@dataclass
class _PortableRecord:
    id: str
    content: str
    memory_type: str
    importance: float
    valid_from: float
    valid_to: Optional[float]
    invalidated_at: Optional[float]
    metadata: Dict[str, Any]


class _PortableMeta:
    def __init__(self, confidence: float, should_abstain: bool, reason: str) -> None:
        self.confidence = confidence
        self.should_abstain = should_abstain
        self.reason = reason


class _PortableRetrieveResult(list):
    def __init__(self, items: List[Dict[str, Any]], metamemory: _PortableMeta) -> None:
        super().__init__(items)
        self.metamemory = metamemory
        self.draft_clues: List[Any] = []
        self.reflections: List[Any] = []
        self.reminders: List[Any] = []


class _PortableSQLiteMemoryEngine:
    """Self-contained SQLite WAL bi-temporal fallback when external `mnemos` package is absent."""

    def __init__(self, db_path: str, embedding_dim: int = 256) -> None:
        _ = embedding_dim
        self.db_path = db_path
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    memory_type TEXT NOT NULL,
                    importance REAL NOT NULL,
                    valid_from REAL NOT NULL,
                    valid_to REAL,
                    invalidated_at REAL,
                    metadata_json TEXT NOT NULL
                )
                """
            )

    def write(
        self,
        *,
        content: str,
        memory_type: str = "semantic",
        importance: float = 0.6,
        valid_from: Optional[float] = None,
        valid_to: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
        links_to: Optional[List[str]] = None,
        auto_invalidate_conflicts: bool = False,
        sanitize_pii: bool = False,
    ) -> _PortableRecord:
        _ = links_to, auto_invalidate_conflicts, sanitize_pii
        now = time.time()
        vf = float(valid_from if valid_from is not None else now)
        mid = f"mem-{uuid.uuid4().hex[:12]}"
        meta = dict(metadata or {})
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            conn.execute(
                "INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
                (mid, content, memory_type, float(importance), vf, valid_to, json.dumps(meta, ensure_ascii=False)),
            )
        return _PortableRecord(mid, content, memory_type, float(importance), vf, valid_to, None, meta)

    def retrieve(
        self,
        *,
        query: str,
        context: Optional[str] = None,
        limit: int = 5,
        as_of_time: Optional[float] = None,
        include_invalidated: bool = False,
        memory_type: Optional[str] = None,
    ) -> _PortableRetrieveResult:
        _ = context
        q_tokens = {w for w in (query or "").lower().split() if len(w) > 1}
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            rows = conn.execute(
                "SELECT id, content, memory_type, importance, valid_from, valid_to, invalidated_at, metadata_json FROM memories"
            ).fetchall()
        scored: List[Dict[str, Any]] = []
        for mid, content, mtype, imp, vf, vt, inv, mjson in rows:
            if not include_invalidated and inv is not None:
                continue
            if memory_type and mtype != memory_type:
                continue
            if as_of_time is not None and vf > as_of_time:
                continue
            c_tokens = {w for w in content.lower().split() if len(w) > 1}
            overlap = len(q_tokens & c_tokens) / max(1, len(q_tokens)) if q_tokens else 0.5
            score = round(0.7 * overlap + 0.3 * float(imp), 4)
            scored.append(
                {
                    "id": mid,
                    "content": content,
                    "memory_type": mtype,
                    "importance": imp,
                    "score": score,
                    "valid_from": vf,
                    "valid_to": vt,
                    "invalidated_at": inv,
                    "metadata": json.loads(mjson),
                }
            )
        scored.sort(key=lambda x: x["score"], reverse=True)
        top = scored[: max(1, int(limit))]
        conf = top[0]["score"] if top else 0.0
        return _PortableRetrieveResult(top, _PortableMeta(conf, not bool(top), "portable_sqlite"))

    def update(
        self,
        *,
        memory_id: str,
        new_content: str,
        reason: str = "evidence_revision",
        as_of_time: Optional[float] = None,
    ) -> Optional[_PortableRecord]:
        now = float(as_of_time if as_of_time is not None else time.time())
        with sqlite3.connect(self.db_path, timeout=30.0) as conn:
            row = conn.execute(
                "SELECT memory_type, importance, metadata_json FROM memories WHERE id = ?",
                (memory_id,),
            ).fetchone()
            if row is None:
                return None
            mtype, imp, mjson = row
            conn.execute("UPDATE memories SET invalidated_at = ? WHERE id = ?", (now, memory_id))
        meta = json.loads(mjson)
        meta["supersedes"] = memory_id
        meta["revision_reason"] = reason
        return self.write(content=new_content, memory_type=mtype, importance=imp, valid_from=now, metadata=meta)


class MnemosBiTemporalAdapter:
    """High-assurance bi-temporal episodic/semantic/procedural adapter over F:\\Mnemos."""

    def __init__(self, db_path: Optional[Path | str] = None, embedding_dim: int = 256) -> None:
        root = Path(__file__).resolve().parents[3]
        resolved_db = Path(db_path or (root / "data" / "mnemos_ua.db")).resolve()
        resolved_db.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = resolved_db
        self._lock = threading.RLock()
        self._lock_path = resolved_db.with_suffix(".lock")
        with self._exclusive_db_lock():
            engine_cls = MemoryEngine if MemoryEngine is not None else _PortableSQLiteMemoryEngine
            self.engine = engine_cls(db_path=str(resolved_db), embedding_dim=embedding_dim)

    @contextmanager
    def _exclusive_db_lock(self) -> Iterator[None]:
        with self._lock:
            fh = self._lock_path.open("a+b")
            locked = False
            try:
                if msvcrt is not None:
                    deadline = time.monotonic() + 30.0
                    while True:
                        try:
                            fh.seek(0)
                            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                            locked = True
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"Timed out acquiring Mnemos lock {self._lock_path}")
                            time.sleep(0.015)
                yield
            finally:
                if locked and msvcrt is not None:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                fh.close()

    def write_memory(
        self,
        content: str,
        *,
        memory_type: str = "semantic",
        importance: float = 0.6,
        valid_from: Optional[float] = None,
        valid_to: Optional[float] = None,
        source_origin: str = "agent_observation",
        trust_level: str = "TRUSTED_INTERNAL",
        metadata: Optional[Dict[str, Any]] = None,
        links_to: Optional[List[str]] = None,
        auto_invalidate_conflicts: bool = False,
        sanitize_pii: bool = False,
    ) -> Dict[str, Any]:
        """Persist a bi-temporal memory atom with provenance & validity metadata."""
        enriched_meta: Dict[str, Any] = dict(metadata or {})
        enriched_meta.update(
            {
                "source_origin": source_origin,
                "trust_level": trust_level,
                "recorded_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        with self._exclusive_db_lock():
            rec = self.engine.write(
                content=content,
                memory_type=memory_type,
                importance=importance,
                valid_from=valid_from,
                valid_to=valid_to,
                metadata=enriched_meta,
                links_to=links_to,
                auto_invalidate_conflicts=auto_invalidate_conflicts,
                sanitize_pii=sanitize_pii,
            )
        return {
            "id": rec.id,
            "content": rec.content,
            "memory_type": rec.memory_type,
            "importance": rec.importance,
            "valid_from": rec.valid_from,
            "valid_to": rec.valid_to,
            "invalidated_at": rec.invalidated_at,
            "metadata": rec.metadata,
        }

    def retrieve(
        self,
        query: str,
        *,
        context: Optional[str] = None,
        limit: int = 5,
        as_of_time: Optional[float] = None,
        include_invalidated: bool = False,
        memory_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run Hopfield + ACT-R + FSRS + PPR retrieval with calibrated metamemory."""
        with self._exclusive_db_lock():
            res = self.engine.retrieve(
                query=query,
                context=context,
                limit=limit,
                as_of_time=as_of_time,
                include_invalidated=include_invalidated,
                memory_type=memory_type,
            )
        meta_obj = getattr(res, "metamemory", None)
        meta_dict = {
            "confidence": float(getattr(meta_obj, "confidence", 0.0)) if meta_obj else 0.0,
            "should_abstain": bool(getattr(meta_obj, "should_abstain", False)) if meta_obj else False,
            "reason": str(getattr(meta_obj, "reason", "")) if meta_obj else "",
        }
        return {
            "items": list(res),
            "metamemory": meta_dict,
            "draft_clues": list(getattr(res, "draft_clues", []) or []),
            "reflections": list(getattr(res, "reflections", []) or []),
            "reminders": [
                {"id": getattr(r, "id", ""), "action": getattr(r, "action", str(r))}
                for r in (getattr(res, "reminders", []) or [])
            ],
        }

    def supersede_fact(
        self,
        old_memory_id: str,
        new_content: str,
        *,
        reason: str = "evidence_revision",
        as_of_time: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Bi-temporally invalidate outdated belief while preserving audit lineage."""
        updated = self.engine.update(
            memory_id=old_memory_id,
            new_content=new_content,
            reason=reason,
            as_of_time=as_of_time,
        )
        if updated is None:
            return None
        return {
            "id": updated.id,
            "content": updated.content,
            "supersedes": old_memory_id,
            "valid_from": updated.valid_from,
            "metadata": updated.metadata,
        }

    def export_adr_markdown(self, output_path: Path | str, query: str = "architecture") -> Path:
        """Render human-readable Markdown ADR/notes projection from verified memories."""
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        recalled = self.retrieve(query, limit=20, include_invalidated=True)
        lines = [
            "# Architectural & Episodic Memory Projection (Derived Vault)",
            "",
            f"- Source DB: `{self.db_path}`",
            f"- Query Filter: `{query}`",
            "",
        ]
        for item in recalled["items"]:
            status = "SUPERSEDED" if item.get("invalidated_at") else "ACTIVE"
            lines.append(
                f"- **[{status}]** (`{item['id'][:8]}`, type=`{item['memory_type']}`, "
                f"score=`{item['score']:.3f}`): {item['content']}"
            )
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
