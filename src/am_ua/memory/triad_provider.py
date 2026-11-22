"""TriadMemoryProvider — Unified Hermes `MemoryProvider` Subclass (P3.4).

Unifies all 3 memory tiers behind the official `hermes-agent` `MemoryProvider` ABC:
  1. `CoreMemoryBlockStore` (Letta self-editable RAM blocks)
  2. `MnemosBiTemporalAdapter` (Hopfield + ACT-R + FSRS + Graphiti bi-temporal)
  3. `MSEAFrankensteinClient` (Q-Utility learning, ancestor provenance credit,
     R13 conflict preservation, low-confidence quarantine, evidence projection).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[3]
VENDOR_HERMES = ROOT / "vendor" / "hermes_agent"
if VENDOR_HERMES.is_dir() and str(VENDOR_HERMES) not in sys.path:
    sys.path.insert(0, str(VENDOR_HERMES))

from agent.memory_provider import MemoryProvider  # type: ignore[import-untyped]

from .core_blocks import CoreMemoryBlockStore
from .hybrid_vector_index import HybridVectorIndex
from .mnemos_connector import MnemosBiTemporalAdapter
from .msea_client import MSEAFrankensteinClient


_NAMESPACE_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ScopedMemoryFacade:
    """Host-pinned memory namespace isolation facade (prevents cross-tenant memory poisoning)."""

    def __init__(self, provider: "TriadMemoryProvider", namespace: str) -> None:
        ns = (namespace or "").strip()
        if not ns or ".." in ns or "/" in ns or "\\" in ns or "\x00" in ns or not _NAMESPACE_RX.match(ns):
            raise ValueError(f"Invalid memory namespace: {namespace!r}")
        self._provider = provider
        self._namespace = ns

    @property
    def namespace(self) -> str:
        return self._namespace

    def write(
        self,
        content: str,
        *,
        memory_type: str = "semantic",
        confidence: float = 0.8,
        **ignored_metadata: Any,
    ) -> Dict[str, Any]:
        """Write scoped memory bound strictly to the host-pinned namespace (ignores caller namespace args)."""
        _ = ignored_metadata  # caller/LLM cannot override namespace
        tag = f"[ns:{self._namespace}]"
        scoped_content = f"{tag} {content.strip()}"
        mn_rec = self._provider.mnemos.write_memory(
            scoped_content,
            memory_type=memory_type,
            importance=max(0.1, min(1.0, float(confidence))),
            source_origin=f"ns:{self._namespace}",
            auto_invalidate_conflicts=False,
        )
        ms_atom = self._provider.msea.ingest_atom(
            scoped_content,
            kind=memory_type,
            confidence=confidence,
            source=f"ns://{self._namespace}",
        )
        hv_rec = self._provider.hybrid_index.add(
            scoped_content,
            namespace=self._namespace,
            kind=memory_type,
            importance=max(0.1, min(1.0, float(confidence))),
            metadata={"msea_id": ms_atom.get("id")},
        )
        return {
            "ok": True,
            "namespace": self._namespace,
            "mnemos_record": mn_rec,
            "msea_atom": ms_atom,
            "hybrid_doc": hv_rec,
        }

    def recall(self, query: str, *, limit: int = 4, **ignored_metadata: Any) -> Dict[str, Any]:
        """Recall only entries belonging to the host-pinned namespace."""
        _ = ignored_metadata
        tag = f"[ns:{self._namespace}]"
        raw = self._provider.recall_triad(query, limit=max(10, limit * 4))
        mn_hits = [
            item
            for item in raw.get("mnemos", {}).get("items", [])
            if tag in str(item.get("content", "")) or item.get("source_origin") == f"ns:{self._namespace}"
        ][:limit]
        ms_hits: List[Dict[str, Any]] = []
        for hit in raw.get("msea", {}).get("hits", []):
            atom = hit.get("atom", hit)
            if tag in str(atom.get("content", "")) or atom.get("source") == f"ns://{self._namespace}":
                ms_hits.append(hit)
                if len(ms_hits) >= limit:
                    break
        return {
            "ok": True,
            "namespace": self._namespace,
            "mnemos": {"items": mn_hits},
            "msea": {"hits": ms_hits},
        }


class TriadMemoryProvider(MemoryProvider):
    """Sovereign Triad Memory Provider implementing Hermes `MemoryProvider` ABC."""

    def __init__(
        self,
        data_dir: Optional[Path | str] = None,
        *,
        embedding_dim: int = 256,
    ) -> None:
        base_dir = Path(data_dir or (ROOT / "data" / "triad_memory")).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = base_dir
        self.core_blocks = CoreMemoryBlockStore(base_dir / "core_blocks.json")
        self.mnemos = MnemosBiTemporalAdapter(base_dir / "mnemos_triad.db", embedding_dim=embedding_dim)
        self.msea = MSEAFrankensteinClient(base_dir / "msea_atoms.json")
        self.hybrid_index = HybridVectorIndex(base_dir / "hybrid_vectors.db", dim=min(256, max(64, int(embedding_dim))))
        self._session_id: str = "default"
        self._agent_context: str = "primary"
        self._prefetched_cache: Dict[str, str] = {}
        self._last_recalled_msea_ids: Dict[str, List[str]] = {}

    @property
    def name(self) -> str:
        return "aethermind_triad"

    def is_available(self) -> bool:
        return True

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        self._session_id = session_id or "default"
        self._agent_context = str(kwargs.get("agent_context", "primary"))

    def system_prompt_block(self) -> str:
        return self.core_blocks.compile_system_prompt()

    def recall_triad(self, query: str, *, limit: int = 4) -> Dict[str, Any]:
        """Cross-tier retrieval combining Mnemos bi-temporal + MSEA Q-utility + Hybrid BM25/Vector RRF + conflicts."""
        mnemos_res = self.mnemos.retrieve(query, limit=limit)
        msea_res = self.msea.retrieve(query, limit=limit)
        hybrid_hits = self.hybrid_index.query(query, top_k=limit)
        all_atoms = self.msea.inspect_atoms(include_inactive=False)
        unresolved_conflicts = [
            {
                "id": a["id"],
                "factKey": a.get("factKey"),
                "content": a.get("content"),
                "conflictsWith": a.get("conflictsWith", []),
            }
            for a in all_atoms
            if a.get("conflictsWith")
        ]
        return {
            "mnemos": mnemos_res,
            "msea": msea_res,
            "hybrid": hybrid_hits,
            "unresolved_conflicts": unresolved_conflicts,
        }

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        sid = session_id or self._session_id
        if sid in self._prefetched_cache and not query.strip():
            return self._prefetched_cache.pop(sid)
        if not query or not query.strip():
            return ""
        recalled = self.recall_triad(query, limit=3)
        recalled_ids: List[str] = []
        lines: List[str] = ["<triad_memory_recall>"]
        for item in recalled["mnemos"]["items"]:
            lines.append(
                f"  <mnemos id='{item['id'][:8]}' score='{item['score']:.3f}'>{item['content']}</mnemos>"
            )
        for hit in recalled["msea"].get("hits", []):
            atom = hit.get("atom", hit)
            aid = str(atom.get("id", ""))
            if aid:
                recalled_ids.append(aid)
            q_val = float(atom.get("qValue", 0.0))
            lines.append(
                f"  <msea id='{aid[:8]}' q='{q_val:.3f}'>{atom.get('content', '')}</msea>"
            )
        for h_item in recalled.get("hybrid") or []:
            lines.append(
                f"  <hybrid id='{str(h_item.get('doc_id', ''))[:8]}' rrf='{float(h_item.get('rrf_score', 0.0)):.4f}'>{h_item.get('content', '')}</hybrid>"
            )
        for conf in recalled["unresolved_conflicts"]:
            lines.append(
                f"  <conflict factKey='{conf['factKey']}' id='{str(conf['id'])[:8]}'>{conf['content']}</conflict>"
            )
        lines.append("</triad_memory_recall>")
        rendered = "\n".join(lines) if len(lines) > 2 else ""
        self._prefetched_cache[sid] = rendered
        self._last_recalled_msea_ids[sid] = recalled_ids
        return rendered

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        if query and query.strip():
            self.prefetch(query, session_id=session_id)

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "") -> None:
        if self._agent_context not in ("primary", ""):
            return
        summary = f"User: {user_content.strip()[:240]} | Agent: {assistant_content.strip()[:240]}"
        if not summary.strip(" |User:Agent"):
            return
        self.mnemos.write_memory(
            summary,
            memory_type="episodic",
            importance=0.55,
            source_origin=f"session:{session_id or self._session_id}",
        )
        self.msea.ingest_atom(
            summary,
            kind="episodic",
            confidence=0.75,
            source=f"session://{session_id or self._session_id}",
        )
        self.hybrid_index.add(
            summary,
            namespace="global",
            kind="episodic",
            importance=0.55,
            metadata={"session_id": session_id or self._session_id},
        )
        sid = session_id or self._session_id
        recalled_ids = self._last_recalled_msea_ids.pop(sid, [])
        if recalled_ids and "[VERIFIED" in assistant_content:
            self.msea.learn_outcome(recalled_ids, passed=True)

    def record_verified_fact(
        self,
        content: str,
        *,
        fact_key: Optional[str] = None,
        confidence: float = 0.85,
        parent_msea_ids: Optional[List[str]] = None,
        trust_level: str = "TRUSTED_INTERNAL",
    ) -> Dict[str, Any]:
        """Write a structured fact to both Mnemos and MSEA and trigger R13 governance."""
        if trust_level == "UNTRUSTED_DATA":
            confidence = min(confidence, 0.20)
        mn_rec = self.mnemos.write_memory(
            content,
            memory_type="semantic",
            importance=max(0.1, min(1.0, confidence)),
            trust_level=trust_level,
            auto_invalidate_conflicts=False,
        )
        ms_atom = self.msea.ingest_atom(
            content,
            kind="semantic",
            fact_key=fact_key,
            confidence=confidence,
            parent_ids=parent_msea_ids,
            source=f"triad://{trust_level.lower()}",
        )
        gov = self.msea.govern(confidence_threshold=0.25)
        if trust_level != "UNTRUSTED_DATA" and confidence >= 0.25:
            self.hybrid_index.add(
                content,
                namespace="global",
                kind="semantic",
                importance=max(0.1, min(1.0, confidence)),
                metadata={"fact_key": fact_key, "msea_id": ms_atom.get("id")},
            )
        return {"mnemos_record": mn_rec, "msea_atom": ms_atom, "governance": gov}

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "core_memory_append",
                "description": "Append concise text to a pinned RAM CoreMemoryBlock.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["label", "content"],
                },
            },
            {
                "name": "core_memory_replace",
                "description": "Surgically replace an exact substring inside a CoreMemoryBlock.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "old_substring": {"type": "string"},
                        "new_substring": {"type": "string"},
                    },
                    "required": ["label", "old_substring", "new_substring"],
                },
            },
            {
                "name": "triad_recall",
                "description": "Recall bi-temporal Mnemos + utility-weighted MSEA memories.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "default": 4},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "triad_record_outcome",
                "description": "Reinforce or penalize MSEA memory atoms based on empirical test outcome.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_ids": {"type": "array", "items": {"type": "string"}},
                        "passed": {"type": "boolean"},
                    },
                    "required": ["memory_ids", "passed"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any], **kwargs: Any) -> str:
        if tool_name == "core_memory_append":
            blk = self.core_blocks.append(str(args["label"]), str(args["content"]))
            return json.dumps({"ok": True, "label": blk.label, "revision": blk.revision})
        if tool_name == "core_memory_replace":
            blk = self.core_blocks.replace(
                str(args["label"]),
                str(args["old_substring"]),
                str(args["new_substring"]),
            )
            return json.dumps({"ok": True, "label": blk.label, "revision": blk.revision})
        if tool_name == "triad_recall":
            res = self.recall_triad(str(args["query"]), limit=int(args.get("limit", 4)))
            return json.dumps({"ok": True, **res}, default=str)
        if tool_name == "triad_record_outcome":
            out = self.msea.learn_outcome(
                list(args.get("memory_ids", [])),
                bool(args["passed"]),
            )
            return json.dumps({"ok": True, "outcome": out}, default=str)
        return json.dumps({"ok": False, "error": f"Unsupported Triad tool: {tool_name}"})

    def on_memory_write(self, action: str, target: str, content: str) -> None:
        block_label = "USER_PREFS" if target == "user" else "ACTIVE_MISSION"
        if action == "add" and content.strip():
            self.mnemos.write_memory(content, memory_type="semantic", source_origin=f"builtin:{target}")
            if len(self.core_blocks.get(block_label).value) + len(content) + 2 <= self.core_blocks.get(block_label).limit:
                self.core_blocks.append(block_label, content, source_origin=f"mirror:{target}")

    def shutdown(self) -> None:
        self._prefetched_cache.clear()

    def scoped(self, namespace: str) -> ScopedMemoryFacade:
        """Return a memory facade bound immutably by the host to `namespace`."""
        return ScopedMemoryFacade(self, namespace)
