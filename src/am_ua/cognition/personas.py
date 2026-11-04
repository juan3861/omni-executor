"""Persona Manager (am_ua.cognition.personas).

Loads, parses, and injects contractual engineering personas defined in Markdown-as-Code.
Inspired by Agency Agents, but strictly confined to elite hardcore engineering roles:
  - general_engineer
  - systems_architect
  - strict_auditor
  - security_reverse_engineer
  - performance_sre
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


class PersonaContract:
    """Represents a validated engineering persona contract."""

    def __init__(self, role: str, metadata: Dict[str, str], body: str, file_path: Path) -> None:
        self.role = role
        self.metadata = metadata
        self.body = body.strip()
        self.file_path = file_path
        self.name = metadata.get("name", role)
        self.description = metadata.get("description", "")
        self.vibe = metadata.get("vibe", "")
        self.emoji = metadata.get("emoji", "🤖")

    def format_system_injection(self) -> str:
        """Formats the persona contract for inclusion in the agent's system prompt."""
        lines = [
            f"=== ACTIVE SPECIALIZED PERSONA: {self.name} {self.emoji} ===",
            f"Role Identity: {self.description}",
            f"Operational Vibe: {self.vibe}",
            "",
            self.body,
            "=== END PERSONA CONTRACT ===",
            "",
        ]
        return "\n".join(lines)


class PersonaManager:
    """Manages the discovery, loading, and injection of engineering personas."""

    DEFAULT_PERSONAS_DIR = Path("F:/AetherMind_Universal_Agent/constitution/personas")

    def __init__(self, personas_dir: Optional[Path] = None) -> None:
        self.personas_dir = Path(personas_dir or self.DEFAULT_PERSONAS_DIR).resolve()
        self._cache: Dict[str, PersonaContract] = {}
        self._discover()

    def _discover(self) -> None:
        if not self.personas_dir.exists():
            return
        for md_file in self.personas_dir.glob("*.md"):
            role = md_file.stem.lower()
            try:
                contract = self._load_file(md_file, role)
                self._cache[role] = contract
            except Exception:
                continue

    @staticmethod
    def _parse_yaml_frontmatter(text: str) -> tuple[Dict[str, str], str]:
        match = FRONTMATTER_RE.match(text)
        if not match:
            return {}, text

        raw_yaml = match.group(1)
        body = text[match.end():]
        metadata: Dict[str, str] = {}
        for line in raw_yaml.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                metadata[key.strip()] = val.strip().strip("\"'")
        return metadata, body

    def _load_file(self, path: Path, role: str) -> PersonaContract:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = self._parse_yaml_frontmatter(raw_text)
        assigned_role = meta.get("role", role).lower()
        return PersonaContract(role=assigned_role, metadata=meta, body=body, file_path=path)

    def list_roles(self) -> List[str]:
        """Lists all registered persona roles."""
        return sorted(self._cache.keys())

    def available_roles(self) -> List[str]:
        """Alias for list_roles."""
        return self.list_roles()

    def get_persona(self, role: str) -> PersonaContract:
        """Retrieves a persona contract by role identifier, defaulting to general_engineer."""
        normalized = (role or "general_engineer").lower().strip()
        if normalized in self._cache:
            return self._cache[normalized]

        # Alias mappings
        aliases = {
            "architect": "systems_architect",
            "auditor": "strict_auditor",
            "security": "security_reverse_engineer",
            "reverse_engineer": "security_reverse_engineer",
            "sre": "performance_sre",
            "perf": "performance_sre",
            "general": "general_engineer",
            "coder": "general_engineer",
        }
        mapped = aliases.get(normalized)
        if mapped and mapped in self._cache:
            return self._cache[mapped]

        if "general_engineer" in self._cache:
            return self._cache["general_engineer"]

        # Synthetic fallback if no persona files exist on disk
        return PersonaContract(
            role="general_engineer",
            metadata={"name": "General Senior Engineer"},
            body="Inspect before modifying. Make minimal surgical changes. Verify empirically with tests.",
            file_path=self.personas_dir / "general_engineer.md",
        )

    def inject_persona(self, base_system_prompt: str, role: str) -> str:
        """Injects the specified persona contract directly into the system prompt."""
        persona = self.get_persona(role)
        injection = persona.format_system_injection()
        return f"{injection}\n{base_system_prompt}"
