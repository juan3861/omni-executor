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

        # Alias mappings (gstack + Ruflo + ECC executive & engineering hierarchy)
        aliases = {
            "ceo": "product_ceo",
            "architect": "systems_architect",
            "supervisor": "eng_supervisor",
            "lead": "eng_supervisor",
            "auditor": "strict_auditor",
            "security": "security_auditor",
            "reverse_engineer": "security_reverse_engineer",
            "sre": "performance_sre",
            "perf": "performance_sre",
            "tdd": "tdd_enforcer",
            "build": "build_error_resolver",
            "general": "general_engineer",
            "coder": "general_engineer",
        }
        mapped = aliases.get(normalized, normalized)
        if mapped in self._cache:
            return self._cache[mapped]

        builtin_contracts: Dict[str, tuple[str, str, str]] = {
            "product_ceo": (
                "Executive Product CEO",
                "Strategic, zero-bloat, outcome-obsessed",
                "Define product scope, reject unnecessary complexity, lock high-leverage acceptance criteria, and align all squads on user ROI.",
            ),
            "systems_architect": (
                "Principal Systems Architect",
                "Structural, deterministic, boundary-strict",
                "Map module topology, enforce clean dependency contracts, prevent circular imports, and design fault-tolerant state transitions.",
            ),
            "eng_supervisor": (
                "Engineering Supervisor & Tech Lead",
                "Coordinating, rigorous, gate-keeping",
                "Supervise parallel developer workers, reconcile cross-file diffs, prevent regressions, and block unverified handoffs.",
            ),
            "tdd_enforcer": (
                "Red-Green TDD Enforcer",
                "Falsification-driven, edge-case hunter",
                "Require failing reproduction or assertion before code changes, test boundary/empty/malformed inputs, and verify 100% test pass.",
            ),
            "security_auditor": (
                "Principal Security & SAST Auditor",
                "Zero-trust, adversarial, taint-aware",
                "Audit code and configs for secret leaks, command injection, unsafe deserialization, SSRF, and constitutional boundary violations.",
            ),
            "build_error_resolver": (
                "Compiler & Build Error Resolver",
                "Diagnostic, root-cause surgical",
                "Isolate syntax, import, type, and dependency errors; fix root causes with minimal blast radius.",
            ),
            "performance_sre": (
                "Performance & Low-Latency SRE",
                "Sub-millisecond, algorithmic, resource-frugal",
                "Eliminate algorithmic bottlenecks, redundant I/O, and memory bloat; enforce strict latency and RAM budgets.",
            ),
            "strict_auditor": (
                "OMEGA Strict Empirical Auditor",
                "Skeptical, triple-proof verifier",
                "Demand physical, logical, and visual/output proof before approving any deliverable; reject stubs, mocks, and partial fixes.",
            ),
        }
        if mapped in builtin_contracts:
            title, vibe, body = builtin_contracts[mapped]
            return PersonaContract(
                role=mapped,
                metadata={"name": title, "description": title, "vibe": vibe},
                body=body,
                file_path=self.personas_dir / f"{mapped}.md",
            )

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
