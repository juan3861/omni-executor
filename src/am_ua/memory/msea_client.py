"""Layer 3: MSEA Frankenstein Memory v5 Client (P3.3 / Astra R13).

Wraps `msea_memory_bridge.mjs` over `F:\\Modular Self-Evolving Agent (MSEA)` with:
  - Empirical `Q-value` utility updates (`learn_outcome`)
  - Ancestor-only structural credit propagation (`parentIds` receive credit; unrelated
    descendants/siblings are never contaminated)
  - Explicit conflict preservation (`R13`: conflicting `factKey` atoms are both kept
    with `conflictsWith` + `conflictResolution='pending'` instead of silent overwrite)
  - Low-confidence quarantine (`confidence < threshold -> status='quarantined'`)
  - Deterministic evidence projection (`answerFromEvidence`).
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]


def _resolve_node_exe() -> str:
    canonical = r"C:\Program Files\nodejs\node.exe"
    if os.path.isfile(canonical):
        return canonical
    found = shutil.which("node")
    if found:
        return found
    raise FileNotFoundError("Node.js runtime not found for MSEA Frankenstein bridge")


class MSEAFrankensteinClient:
    """Python client driving MSEA Frankenstein Memory v5 on an isolated atom store."""

    def __init__(
        self,
        store_path: Optional[Path | str] = None,
        msea_root: Optional[Path | str] = None,
    ) -> None:
        root = Path(__file__).resolve().parents[3]
        self.store_path = Path(
            store_path or (root / "data" / "msea_frankenstein_atoms.json")
        ).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.bridge_script = Path(__file__).resolve().parent / "msea_memory_bridge.mjs"
        self.msea_root = Path(
            msea_root or r"F:\Modular Self-Evolving Agent (MSEA)"
        ).resolve()
        self.node_exe = _resolve_node_exe()
        self._thread_lock = threading.RLock()
        self._lock_path = self.store_path.with_suffix(".lock")

    @contextmanager
    def _exclusive_store_lock(self) -> Iterator[None]:
        with self._thread_lock:
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
                                raise TimeoutError(f"Timed out acquiring MSEA store lock {self._lock_path}")
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

    def _invoke(self, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._exclusive_store_lock():
            env = os.environ.copy()
            env["MSEA_ROOT"] = str(self.msea_root)
            env["TMP"] = r"F:\AetherMind_Temp"
            env["TEMP"] = r"F:\AetherMind_Temp"
            req = {
                "action": action,
                "storePath": str(self.store_path),
                "payload": payload or {},
            }
            proc = subprocess.run(
                [self.node_exe, str(self.bridge_script)],
                input=json.dumps(req),
                text=True,
                encoding="utf-8",
                capture_output=True,
                env=env,
                timeout=30,
                check=False,
            )
            raw_out = (proc.stdout or "").strip()
            if not raw_out:
                raise RuntimeError(
                    f"MSEA bridge '{action}' returned empty stdout (rc={proc.returncode}): {proc.stderr}"
                )
            last_line = raw_out.splitlines()[-1]
            parsed = json.loads(last_line)
            if proc.returncode != 0 or not parsed.get("ok"):
                raise RuntimeError(
                    f"MSEA bridge '{action}' failed: {parsed.get('error') or proc.stderr}"
                )
            return parsed["result"]

    def ingest_atom(
        self,
        content: str,
        *,
        kind: str = "semantic",
        fact_key: Optional[str] = None,
        confidence: float = 0.75,
        importance: float = 0.6,
        source: str = "am_ua://triad",
        parent_ids: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        entity_refs: Optional[List[str]] = None,
        atom_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        item: Dict[str, Any] = {
            "kind": kind,
            "content": content,
            "factKey": fact_key,
            "confidence": confidence,
            "importance": importance,
            "source": source,
            "parentIds": parent_ids or [],
            "keywords": keywords or [],
            "entityRefs": entity_refs or [],
        }
        if atom_id:
            item["id"] = atom_id
        res = self._invoke("ingest", {"items": [item]})
        written = res.get("written", [])
        if not written:
            raise RuntimeError("MSEA ingest failed to persist atom")
        return written[0]

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 5,
        separator: str = "|",
    ) -> Dict[str, Any]:
        return self._invoke(
            "retrieve",
            {
                "query": query,
                "options": {"limit": limit, "topK": limit},
                "contract": {"separator": separator},
            },
        )

    def learn_outcome(
        self,
        memory_ids: List[str],
        passed: bool,
        *,
        alpha: float = 0.3,
        structural_alpha: float = 0.08,
    ) -> Dict[str, Any]:
        return self._invoke(
            "learn_outcome",
            {
                "memoryIds": memory_ids,
                "pass": passed,
                "options": {"alpha": alpha, "structuralAlpha": structural_alpha},
            },
        )

    def govern(self, *, confidence_threshold: float = 0.25) -> Dict[str, Any]:
        """Run R13 conflict detection/preservation + low-confidence quarantine."""
        return self._invoke(
            "govern",
            {"confidenceThreshold": confidence_threshold},
        )

    def inspect_atoms(self, *, include_inactive: bool = True) -> List[Dict[str, Any]]:
        res = self._invoke("inspect", {"includeInactive": include_inactive})
        return list(res.get("atoms", []))
