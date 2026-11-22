"""Layer 3: MSEA Frankenstein Memory v5 Client (P3.3 / Astra R13 — Portable Native v8.1).

Uses `NativeMSEAEngine` (100% pure-Python portable store with cross-platform file locking)
by default so Triad Memory operates identically on Windows, Linux, and macOS CI runners.
Optionally delegates to the legacy Node ESM bridge when `prefer_node_bridge=True` and the
external MSEA repository is available locally.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .msea_native import NativeMSEAEngine

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


def _resolve_node_exe() -> Optional[str]:
    canonical = r"C:\Program Files\nodejs\node.exe"
    if os.path.isfile(canonical):
        return canonical
    return shutil.which("node")


class MSEAFrankensteinClient:
    """Portable Python client driving MSEA Frankenstein Memory v5 on an isolated atom store."""

    def __init__(
        self,
        store_path: Optional[Path | str] = None,
        msea_root: Optional[Path | str] = None,
        *,
        prefer_node_bridge: bool = False,
    ) -> None:
        root = Path(__file__).resolve().parents[3]
        self.store_path = Path(
            store_path or (root / "data" / "msea_frankenstein_atoms.json")
        ).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.bridge_script = Path(__file__).resolve().parent / "msea_memory_bridge.mjs"
        default_msea = Path(r"F:\Modular Self-Evolving Agent (MSEA)") if os.name == "nt" else (root / "vendor" / "msea")
        self.msea_root = Path(msea_root or default_msea).resolve()
        self.node_exe = _resolve_node_exe()
        self.native_engine = NativeMSEAEngine(self.store_path)
        self.use_node_bridge = bool(
            prefer_node_bridge
            and self.node_exe
            and self.bridge_script.is_file()
            and (self.msea_root / "src" / "msea" / "memory" / "memory_organ.mjs").is_file()
        )
        self.backend = "node_bridge" if self.use_node_bridge else "native_python"
        self._thread_lock = threading.RLock()
        self._lock_path = self.store_path.with_suffix(".lock")

    @contextmanager
    def _exclusive_store_lock(self) -> Iterator[None]:
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
                                raise TimeoutError(f"Timed out acquiring MSEA store lock {self._lock_path}")
                            time.sleep(0.015)
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

    def _invoke(self, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_payload = payload or {}
        if not self.use_node_bridge:
            if action == "ingest":
                items = list(req_payload.get("items") or [req_payload])
                return self.native_engine.ingest(items)
            if action == "retrieve":
                opts = req_payload.get("options") or {}
                contract = req_payload.get("contract") or {}
                return self.native_engine.retrieve(
                    str(req_payload.get("query") or ""),
                    limit=int(opts.get("limit", opts.get("topK", 5))),
                    separator=str(contract.get("separator", "|")),
                )
            if action == "learn_outcome":
                opts = req_payload.get("options") or {}
                return self.native_engine.learn_outcome(
                    list(req_payload.get("memoryIds") or []),
                    bool(req_payload.get("pass")),
                    alpha=float(opts.get("alpha", 0.3)),
                    structural_alpha=float(opts.get("structuralAlpha", 0.08)),
                )
            if action == "govern":
                return self.native_engine.govern(
                    confidence_threshold=float(req_payload.get("confidenceThreshold", 0.25))
                )
            if action == "inspect":
                return self.native_engine.inspect(
                    include_inactive=bool(req_payload.get("includeInactive", True))
                )
            raise RuntimeError(f"Unsupported native MSEA action: {action}")

        with self._exclusive_store_lock():
            env = os.environ.copy()
            env["MSEA_ROOT"] = str(self.msea_root)
            tmp_dir = tempfile.gettempdir()
            env["TMP"] = tmp_dir
            env["TEMP"] = tmp_dir
            req = {
                "action": action,
                "storePath": str(self.store_path),
                "payload": req_payload,
            }
            proc = subprocess.run(
                [self.node_exe, str(self.bridge_script)],  # type: ignore[list-item]
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
