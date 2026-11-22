"""Layer 3 (Native Python v8.1): MSEA Frankenstein Memory v5 Engine.

100% pure-Python portable implementation with cross-platform file locking (`msvcrt` / `fcntl`),
zero Node.js or external `F:\\` path dependency:
  - Empirical `Q-value` TD learning (`learn_outcome`) with strict ancestor-only credit propagation
  - Astra R13 conflict preservation (`conflictsWith` + `conflictResolution='pending'`, no silent overwrite)
  - Low-confidence / UNTRUSTED_DATA quarantine (`confidence < threshold -> status='quarantined'`)
  - Composite deterministic retrieval + atomic evidence projection (`answerFromEvidence`).
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import math
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


_WORD_RX = re.compile(r"[a-zA-Z0-9_.\-]{2,}")


def _tokenize(text: str) -> Set[str]:
    return {w.lower() for w in _WORD_RX.findall(text or "")}


def extract_atomic_fact_value(atom: Dict[str, Any]) -> str:
    """Extract concise factual clause from an MSEA atom."""
    content = str(atom.get("content") or "").strip()
    if ":" in content:
        head, tail = content.split(":", 1)
        if len(head) <= 48 and tail.strip():
            return tail.strip()
    return content


class NativeMSEAEngine:
    """Portable pure-Python MSEA Frankenstein Memory v5 store & governance engine."""

    def __init__(self, store_path: Path | str) -> None:
        self.store_path = Path(store_path).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.store_path.with_suffix(".lock")
        self._thread_lock = threading.RLock()

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            fh = self._lock_path.open("a+b")
            locked_msvcrt = False
            locked_fcntl = False
            try:
                if msvcrt is not None:
                    deadline = time.monotonic() + 30.0
                    while True:
                        try:
                            fh.seek(0)
                            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                            locked_msvcrt = True
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"Timed out acquiring lock {self._lock_path}")
                            time.sleep(0.01)
                elif fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                    locked_fcntl = True
                yield
            finally:
                if locked_msvcrt and msvcrt is not None:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                if locked_fcntl and fcntl is not None:
                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                fh.close()

    def _read_store(self) -> Dict[str, Any]:
        if not self.store_path.is_file():
            return {"version": 5, "atoms": []}
        try:
            raw = self.store_path.read_text(encoding="utf-8").strip()
            if not raw:
                return {"version": 5, "atoms": []}
            data = json.loads(raw)
            if isinstance(data, list):
                return {"version": 5, "atoms": data}
            if isinstance(data, dict):
                atoms = data.get("atoms")
                if isinstance(atoms, list):
                    return data
        except Exception:
            pass
        return {"version": 5, "atoms": []}

    def _write_store(self, data: Dict[str, Any]) -> None:
        tmp = self.store_path.with_suffix(f".tmp.{uuid.uuid4().hex[:6]}")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
        tmp.replace(self.store_path)

    def ingest(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        now_ms = int(time.time() * 1000)
        written: List[Dict[str, Any]] = []
        with self._exclusive_lock():
            store = self._read_store()
            atoms: List[Dict[str, Any]] = list(store.get("atoms") or [])
            by_id: Dict[str, Dict[str, Any]] = {str(a.get("id")): a for a in atoms if a.get("id")}

            for raw in items:
                aid = str(raw.get("id") or f"msea_{uuid.uuid4().hex[:12]}")
                content = str(raw.get("content") or "").strip()
                kw = raw.get("keywords")
                if not isinstance(kw, list) or not kw:
                    kw = sorted(_tokenize(content))[:16]
                atom: Dict[str, Any] = {
                    "id": aid,
                    "kind": str(raw.get("kind") or "semantic"),
                    "content": content,
                    "factKey": raw.get("factKey"),
                    "confidence": float(raw.get("confidence", 0.75)),
                    "importance": float(raw.get("importance", 0.6)),
                    "source": str(raw.get("source") or "am_ua://triad"),
                    "parentIds": [str(p) for p in (raw.get("parentIds") or [])],
                    "keywords": [str(k) for k in kw],
                    "entityRefs": [str(e) for e in (raw.get("entityRefs") or [])],
                    "qValue": float(raw.get("qValue", 0.0)),
                    "qUpdates": int(raw.get("qUpdates", 0)),
                    "status": str(raw.get("status") or "active"),
                    "conflictsWith": list(raw.get("conflictsWith") or []),
                    "conflictResolution": str(raw.get("conflictResolution") or "none"),
                    "createdAt": int(raw.get("createdAt") or now_ms),
                    "updatedAt": now_ms,
                }
                if aid in by_id:
                    idx = atoms.index(by_id[aid])
                    atoms[idx] = atom
                else:
                    atoms.append(atom)
                by_id[aid] = atom
                written.append(atom)

            store["atoms"] = atoms
            store["updatedAt"] = now_ms
            self._write_store(store)
        return {"written": written}

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 5,
        separator: str = "|",
    ) -> Dict[str, Any]:
        q_tokens = _tokenize(query)
        with self._exclusive_lock():
            store = self._read_store()
            atoms: List[Dict[str, Any]] = list(store.get("atoms") or [])

        hits: List[Dict[str, Any]] = []
        for atom in atoms:
            if atom.get("status", "active") != "active":
                continue
            content = str(atom.get("content") or "")
            c_tokens = _tokenize(content) | {str(k).lower() for k in (atom.get("keywords") or [])}
            overlap = len(q_tokens & c_tokens) / max(1, len(q_tokens)) if q_tokens else 0.4
            conf = float(atom.get("confidence", 0.5))
            q_val = float(atom.get("qValue", 0.0))
            q_boost = 0.2 * math.tanh(q_val)
            score = round(0.65 * overlap + 0.15 * conf + q_boost + 0.05 * float(atom.get("importance", 0.5)), 6)
            if not q_tokens or overlap > 0.0 or conf >= 0.7:
                hits.append(
                    {
                        "id": atom["id"],
                        "score": score,
                        "atom": atom,
                        "value": extract_atomic_fact_value(atom),
                    }
                )
        hits.sort(key=lambda h: h["score"], reverse=True)
        top = hits[: max(1, int(limit))]
        evidence = separator.join(str(h["value"]) for h in top if h.get("value"))
        return {"hits": top, "evidence": evidence, "engine": "native_python_v5"}

    def learn_outcome(
        self,
        memory_ids: List[str],
        passed: bool,
        *,
        alpha: float = 0.3,
        structural_alpha: float = 0.08,
    ) -> Dict[str, Any]:
        reward = 1.0 if passed else -0.5
        now_ms = int(time.time() * 1000)
        direct_updated: List[str] = []
        ancestor_updated: List[str] = []

        with self._exclusive_lock():
            store = self._read_store()
            atoms: List[Dict[str, Any]] = list(store.get("atoms") or [])
            by_id: Dict[str, Dict[str, Any]] = {str(a.get("id")): a for a in atoms if a.get("id")}

            seen_direct: Set[str] = set()
            ancestor_hops: Dict[str, int] = {}

            for mid in memory_ids:
                sid = str(mid)
                atom = by_id.get(sid)
                if atom is None:
                    continue
                if sid not in seen_direct:
                    old_q = float(atom.get("qValue", 0.0))
                    atom["qValue"] = round(old_q + float(alpha) * (reward - old_q), 6)
                    atom["qUpdates"] = int(atom.get("qUpdates", 0)) + 1
                    atom["updatedAt"] = now_ms
                    seen_direct.add(sid)
                    direct_updated.append(sid)

                # Strict ancestor-only BFS along parentIds (siblings/descendants untouched)
                frontier = [(str(pid), 1) for pid in (atom.get("parentIds") or [])]
                visited_anc: Set[str] = set(seen_direct)
                while frontier:
                    anc_id, hop = frontier.pop(0)
                    if anc_id in visited_anc or anc_id not in by_id:
                        continue
                    visited_anc.add(anc_id)
                    if anc_id not in ancestor_hops or hop < ancestor_hops[anc_id]:
                        ancestor_hops[anc_id] = hop
                    for gp in by_id[anc_id].get("parentIds") or []:
                        frontier.append((str(gp), hop + 1))

            for anc_id, hop in ancestor_hops.items():
                if anc_id in seen_direct:
                    continue
                anc = by_id[anc_id]
                eff_alpha = float(structural_alpha) * (0.7 ** (hop - 1))
                old_q = float(anc.get("qValue", 0.0))
                anc["qValue"] = round(old_q + eff_alpha * (reward - old_q), 6)
                anc["qUpdates"] = int(anc.get("qUpdates", 0)) + 1
                anc["updatedAt"] = now_ms
                ancestor_updated.append(anc_id)

            store["atoms"] = atoms
            store["updatedAt"] = now_ms
            self._write_store(store)

        return {
            "outcome": {
                "passed": bool(passed),
                "reward": reward,
                "directUpdated": direct_updated,
                "ancestorUpdated": ancestor_updated,
            },
            "atoms": atoms,
        }

    def govern(self, *, confidence_threshold: float = 0.25) -> Dict[str, Any]:
        """Run Astra R13 conflict preservation + low-confidence quarantine."""
        now_ms = int(time.time() * 1000)
        quarantined: List[str] = []
        conflicts: List[Dict[str, Any]] = []

        with self._exclusive_lock():
            store = self._read_store()
            atoms: List[Dict[str, Any]] = list(store.get("atoms") or [])

            # 1. Low-confidence quarantine
            for atom in atoms:
                conf = float(atom.get("confidence", 0.0))
                if conf < float(confidence_threshold):
                    atom["status"] = "quarantined"
                    atom["updatedAt"] = now_ms
                    quarantined.append(str(atom["id"]))
                elif atom.get("status") != "superseded":
                    atom["status"] = "active"

            # 2. R13 Conflict preservation on same factKey (never overwrite!)
            by_key: Dict[str, List[Dict[str, Any]]] = {}
            for atom in atoms:
                if atom.get("status") != "active":
                    continue
                fk = str(atom.get("factKey") or "").strip()
                if fk:
                    by_key.setdefault(fk, []).append(atom)

            for fk, group in by_key.items():
                if len(group) < 2:
                    continue
                norm_contents = {str(a.get("content") or "").strip().lower() for a in group}
                if len(norm_contents) < 2:
                    continue
                ids = [str(a["id"]) for a in group]
                for atom in group:
                    cur_id = str(atom["id"])
                    others = [oid for oid in ids if oid != cur_id]
                    merged = sorted(set(str(x) for x in (atom.get("conflictsWith") or [])) | set(others))
                    atom["conflictsWith"] = merged
                    atom["conflictResolution"] = "pending"
                    atom["updatedAt"] = now_ms
                conflicts.append({"factKey": fk, "atomIds": ids, "resolution": "pending"})

            store["atoms"] = atoms
            store["updatedAt"] = now_ms
            self._write_store(store)

        return {
            "report": {
                "quarantined": quarantined,
                "conflicts": conflicts,
                "confidenceThreshold": float(confidence_threshold),
                "totalAtoms": len(atoms),
            },
            "atoms": atoms,
        }

    def inspect(self, *, include_inactive: bool = True) -> Dict[str, Any]:
        with self._exclusive_lock():
            store = self._read_store()
            atoms = list(store.get("atoms") or [])
        if not include_inactive:
            atoms = [a for a in atoms if a.get("status", "active") == "active"]
        extracted = [{"id": a.get("id"), "value": extract_atomic_fact_value(a)} for a in atoms]
        return {"atoms": atoms, "extracted": extracted}
