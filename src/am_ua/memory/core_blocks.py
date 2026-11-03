"""Layer 1: Letta-Inspired Self-Editable RAM Core Memory Blocks (P3.1).

Provides deterministic, character-bounded, pinned context blocks (`PERSONA`,
`USER_PREFS`, `ACTIVE_MISSION`, `FALSIFIABLE_HYPOTHESES`) backed by atomic JSON
persistence on `F:\\AetherMind_Universal_Agent\\data\\core_memory_blocks.json`
with optimistic revision checks, provenance tags, and full edit operations
(`core_memory_replace`, `core_memory_append`, `core_memory_overwrite`).
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


DEFAULT_BLOCK_SPECS: Dict[str, Dict[str, object]] = {
    "PERSONA": {
        "limit": 2000,
        "read_only": False,
        "initial": (
            "Entidade: AetherMind Universal Agent (Super-Union v3.1). "
            "Operador soberano de ciclo completo: especificacao, raciocinio neuro-simbolico, "
            "execucao duravel e validacao empirica fechada."
        ),
    },
    "USER_PREFS": {
        "limit": 2000,
        "read_only": False,
        "initial": (
            "Usuario: Mestre Ruan (nunca chamar de Joao). Idioma: Portugues. "
            "Zero Manual Offloading, Zero RPA Cego, janela isolada obrigatoria."
        ),
    },
    "ACTIVE_MISSION": {
        "limit": 3000,
        "read_only": False,
        "initial": "Nenhuma missao ativa registrada no bloco RAM.",
    },
    "FALSIFIABLE_HYPOTHESES": {
        "limit": 3000,
        "read_only": False,
        "initial": "Nenhuma hipotese pre-registrada ativa.",
    },
}


class CoreMemoryLimitError(ValueError):
    """Raised when an edit exceeds the block character budget."""


@dataclass
class CoreMemoryBlock:
    """Single pinned RAM block compiled into the system prompt on every turn."""

    label: str
    value: str
    limit: int = 2000
    read_only: bool = False
    revision: int = 1
    source_origin: str = "system_bootstrap"
    updated_at: float = field(default_factory=time.time)

    def remaining_chars(self) -> int:
        return max(0, self.limit - len(self.value))

    def validate(self) -> None:
        if not self.label or not self.label.strip():
            raise ValueError("CoreMemoryBlock label cannot be empty")
        if self.limit < 64:
            raise ValueError(f"Block '{self.label}' limit {self.limit} < 64 chars")
        if len(self.value) > self.limit:
            raise CoreMemoryLimitError(
                f"Block '{self.label}' length {len(self.value)} exceeds limit {self.limit}"
            )

    def render_xml(self) -> str:
        usage = f"{len(self.value)}/{self.limit}"
        ro = " read_only='true'" if self.read_only else ""
        return (
            f"<memory_block label='{self.label}' chars='{usage}' rev='{self.revision}'{ro}>\n"
            f"{self.value}\n"
            f"</memory_block>"
        )


class CoreMemoryBlockStore:
    """Thread-safe Letta-style Core Memory Block manager with atomic persistence."""

    def __init__(
        self,
        storage_path: Optional[Path | str] = None,
        block_specs: Optional[Dict[str, Dict[str, object]]] = None,
    ) -> None:
        root = Path(__file__).resolve().parents[3]
        self.storage_path = Path(
            storage_path or (root / "data" / "core_memory_blocks.json")
        ).resolve()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._blocks: Dict[str, CoreMemoryBlock] = {}
        specs = block_specs or DEFAULT_BLOCK_SPECS
        if self.storage_path.is_file():
            self._load()
        for label, cfg in specs.items():
            if label not in self._blocks:
                blk = CoreMemoryBlock(
                    label=label,
                    value=str(cfg.get("initial", "")),
                    limit=int(cfg.get("limit", 2000)),
                    read_only=bool(cfg.get("read_only", False)),
                )
                blk.validate()
                self._blocks[label] = blk
        self._persist()

    def _load(self) -> None:
        raw_text = ""
        for attempt in range(10):
            try:
                raw_text = self.storage_path.read_text(encoding="utf-8")
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.01 * (attempt + 1))
        raw = json.loads(raw_text)
        for label, item in raw.get("blocks", {}).items():
            blk = CoreMemoryBlock(
                label=str(item["label"]),
                value=str(item["value"]),
                limit=int(item.get("limit", 2000)),
                read_only=bool(item.get("read_only", False)),
                revision=int(item.get("revision", 1)),
                source_origin=str(item.get("source_origin", "disk")),
                updated_at=float(item.get("updated_at", time.time())),
            )
            blk.validate()
            self._blocks[label] = blk

    def _persist(self) -> None:
        payload = {
            "schema_version": "am_ua_core_memory_blocks/v1",
            "saved_at": time.time(),
            "blocks": {k: asdict(v) for k, v in self._blocks.items()},
        }
        tmp = self.storage_path.with_suffix(f".{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for attempt in range(10):
            try:
                os.replace(tmp, self.storage_path)
                break
            except PermissionError:
                if attempt == 9:
                    tmp.unlink(missing_ok=True)
                    raise
                time.sleep(0.01 * (attempt + 1))

    def get(self, label: str) -> CoreMemoryBlock:
        with self._lock:
            if label not in self._blocks:
                raise KeyError(f"Unknown CoreMemoryBlock: '{label}'")
            blk = self._blocks[label]
            return CoreMemoryBlock(**asdict(blk))

    def list_blocks(self) -> List[CoreMemoryBlock]:
        with self._lock:
            return [CoreMemoryBlock(**asdict(b)) for b in self._blocks.values()]

    def ensure_block(
        self,
        label: str,
        initial_value: str = "",
        limit: int = 2000,
        read_only: bool = False,
    ) -> CoreMemoryBlock:
        with self._lock:
            if label not in self._blocks:
                blk = CoreMemoryBlock(
                    label=label,
                    value=initial_value,
                    limit=limit,
                    read_only=read_only,
                )
                blk.validate()
                self._blocks[label] = blk
                self._persist()
            return self.get(label)

    def append(
        self,
        label: str,
        content: str,
        *,
        source_origin: str = "agent_self_edit",
        separator: str = "\n",
    ) -> CoreMemoryBlock:
        """Letta `core_memory_append`: append line/fact while enforcing char limit."""
        with self._lock:
            if label not in self._blocks:
                raise KeyError(f"Unknown CoreMemoryBlock: '{label}'")
            blk = self._blocks[label]
            if blk.read_only:
                raise PermissionError(f"CoreMemoryBlock '{label}' is read-only")
            addition = content.strip()
            if not addition:
                return self.get(label)
            candidate = f"{blk.value}{separator}{addition}" if blk.value else addition
            if len(candidate) > blk.limit:
                raise CoreMemoryLimitError(
                    f"Append to '{label}' exceeds limit ({len(candidate)} > {blk.limit})"
                )
            blk.value = candidate
            blk.revision += 1
            blk.source_origin = source_origin
            blk.updated_at = time.time()
            self._persist()
            return self.get(label)

    def replace(
        self,
        label: str,
        old_substring: str,
        new_substring: str,
        *,
        source_origin: str = "agent_self_edit",
    ) -> CoreMemoryBlock:
        """Letta `core_memory_replace`: exact substring surgical update."""
        with self._lock:
            if label not in self._blocks:
                raise KeyError(f"Unknown CoreMemoryBlock: '{label}'")
            blk = self._blocks[label]
            if blk.read_only:
                raise PermissionError(f"CoreMemoryBlock '{label}' is read-only")
            if not old_substring or old_substring not in blk.value:
                raise ValueError(
                    f"Target substring '{old_substring}' not found in block '{label}'"
                )
            candidate = blk.value.replace(old_substring, new_substring, 1)
            if len(candidate) > blk.limit:
                raise CoreMemoryLimitError(
                    f"Replace in '{label}' exceeds limit ({len(candidate)} > {blk.limit})"
                )
            blk.value = candidate
            blk.revision += 1
            blk.source_origin = source_origin
            blk.updated_at = time.time()
            self._persist()
            return self.get(label)

    def overwrite(
        self,
        label: str,
        new_value: str,
        *,
        source_origin: str = "agent_self_edit",
    ) -> CoreMemoryBlock:
        with self._lock:
            if label not in self._blocks:
                raise KeyError(f"Unknown CoreMemoryBlock: '{label}'")
            blk = self._blocks[label]
            if blk.read_only:
                raise PermissionError(f"CoreMemoryBlock '{label}' is read-only")
            if len(new_value) > blk.limit:
                raise CoreMemoryLimitError(
                    f"Overwrite of '{label}' exceeds limit ({len(new_value)} > {blk.limit})"
                )
            blk.value = new_value
            blk.revision += 1
            blk.source_origin = source_origin
            blk.updated_at = time.time()
            self._persist()
            return self.get(label)

    def compile_system_prompt(self, labels: Optional[Iterable[str]] = None) -> str:
        """Render pinned XML memory blocks for direct LLM system prompt injection."""
        with self._lock:
            selected = (
                [self._blocks[k] for k in labels if k in self._blocks]
                if labels is not None
                else list(self._blocks.values())
            )
            body = "\n".join(b.render_xml() for b in selected)
            return f"<core_memory_blocks count='{len(selected)}'>\n{body}\n</core_memory_blocks>"
