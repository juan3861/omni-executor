"""Deterministic Task Offloader (`am_ua.execution.deterministic_offloader`).

Reduces LLM token spend and enables lightweight ("flyweight") models to match
frontier models by offloading repeatable diagnostic, audit, preflight, and
verification workflows to zero-token deterministic execution rails.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DeterministicRailSpec:
    name: str
    description: str
    estimated_tokens_saved: int


BUILTIN_DETERMINISTIC_RAILS: Dict[str, DeterministicRailSpec] = {
    "shield_audit": DeterministicRailSpec(
        name="shield_audit",
        description="Run static SAST & secret scan across workspace without LLM turns.",
        estimated_tokens_saved=3500,
    ),
    "repo_topology_map": DeterministicRailSpec(
        name="repo_topology_map",
        description="Build polyglot PageRank RepoMap and AST symbol summary deterministically.",
        estimated_tokens_saved=4000,
    ),
    "ast_syntax_sweep": DeterministicRailSpec(
        name="ast_syntax_sweep",
        description="Parse all Python files in workspace to catch SyntaxError/IndentationError in 0 tokens.",
        estimated_tokens_saved=2500,
    ),
    "verify_only_check": DeterministicRailSpec(
        name="verify_only_check",
        description="Execute verification command directly when objective asks only to run/verify tests.",
        estimated_tokens_saved=3000,
    ),
    "workspace_preflight": DeterministicRailSpec(
        name="workspace_preflight",
        description="Single-shot deterministic bundle: file inventory + AST sweep + SAST + RepoMap.",
        estimated_tokens_saved=6000,
    ),
}

# Never intercept tasks that ask to modify, create, fix, or refactor code.
_MUTATION_INTENT_RX = re.compile(
    r"\b(fix|implement|create|write|add|edit|modify|refactor|update|patch|build|remove|delete|"
    r"corrija|conserte|implemente|crie|escreva|adicione|edite|altere|refatore|atualize|remova)\b",
    re.IGNORECASE,
)


class DeterministicTaskOffloader:
    """Matches pure-diagnostic objectives to 0-token rails and builds single-call preflight bundles."""

    @staticmethod
    def list_rails() -> List[Dict[str, Any]]:
        return [
            {
                "name": s.name,
                "description": s.description,
                "estimated_tokens_saved": s.estimated_tokens_saved,
            }
            for s in BUILTIN_DETERMINISTIC_RAILS.values()
        ]

    @staticmethod
    def match_zero_token_rail(objective: str, *, verify_cmd: Optional[str] = None) -> Optional[str]:
        """Return a deterministic rail name ONLY if the objective is purely diagnostic/read-only."""
        text = (objective or "").strip()
        if not text or _MUTATION_INTENT_RX.search(text):
            return None
        low = text.lower()
        if any(k in low for k in ("security audit", "sast scan", "agent shield", "auditoria de seguranca", "auditoria sast")):
            return "shield_audit"
        if any(k in low for k in ("repomap", "repo map", "symbol map", "mapa de simbolos", "pagerank map")):
            return "repo_topology_map"
        if any(k in low for k in ("syntax check", "ast sweep", "check python syntax", "verificar sintaxe")):
            return "ast_syntax_sweep"
        if verify_cmd and any(k in low for k in ("only run verify", "run tests only", "rodar testes apenas", "somente verificar")):
            return "verify_only_check"
        return None

    @staticmethod
    def ast_syntax_sweep(workspace: Path) -> Dict[str, Any]:
        """Deterministically parse all `.py` files under `workspace` for syntax errors."""
        errors: List[Dict[str, Any]] = []
        checked = 0
        skip = {".git", "__pycache__", "node_modules", ".venv", "venv"}
        for py in workspace.rglob("*.py"):
            if any(part in skip for part in py.parts):
                continue
            checked += 1
            try:
                src = py.read_text(encoding="utf-8", errors="replace")
                ast.parse(src, filename=str(py))
            except SyntaxError as exc:
                errors.append(
                    {
                        "file": py.relative_to(workspace).as_posix(),
                        "line": exc.lineno,
                        "msg": exc.msg,
                    }
                )
        return {"ok": len(errors) == 0, "files_checked": checked, "syntax_errors": errors}

    @classmethod
    def run_preflight_bundle(cls, workspace: Path, *, max_chars: int = 3500) -> Dict[str, Any]:
        """Single-shot deterministic bundle replacing 4-6 exploratory LLM turns."""
        from am_ua.perception.polyglot_repomap import PolyglotRepoMapper
        from am_ua.security.agent_shield import AgentShieldAuditor

        ws = Path(workspace).resolve()
        syntax = cls.ast_syntax_sweep(ws)
        shield_rep = AgentShieldAuditor().scan_directory(ws, include_source_sast=True)
        ranked, repomap_txt = PolyglotRepoMapper(ws).build_ranked_map(max_chars=max_chars)
        return {
            "ok": True,
            "rail": "workspace_preflight",
            "estimated_tokens_saved": BUILTIN_DETERMINISTIC_RAILS["workspace_preflight"].estimated_tokens_saved,
            "syntax": syntax,
            "shield": {
                "grade": shield_rep.grade,
                "passed": shield_rep.passed,
                "finding_count": len(shield_rep.findings),
            },
            "repomap_files": len(ranked),
            "repomap": repomap_txt,
        }

    @classmethod
    def execute_rail(
        cls,
        rail_name: str,
        workspace: Path,
        *,
        verify_cmd: Optional[str] = None,
        run_fn: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Execute a zero-token deterministic rail and return structured verification data."""
        ws = Path(workspace).resolve()
        spec = BUILTIN_DETERMINISTIC_RAILS.get(rail_name)
        if spec is None:
            return {"ok": False, "error": f"Unknown deterministic rail: {rail_name}"}

        if rail_name == "shield_audit":
            from am_ua.security.agent_shield import AgentShieldAuditor

            rep = AgentShieldAuditor().scan_directory(ws, include_source_sast=True)
            return {
                "ok": rep.passed,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"AgentShield {rep.grade} ({len(rep.findings)} findings across {rep.files_scanned} files)",
                "details": rep.to_dict(),
            }
        if rail_name == "repo_topology_map":
            from am_ua.perception.polyglot_repomap import PolyglotRepoMapper

            ranked, txt = PolyglotRepoMapper(ws).build_ranked_map(max_chars=4000)
            return {
                "ok": True,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"PageRank RepoMap generated ({len(ranked)} files)",
                "details": {"file_count": len(ranked), "repomap": txt},
            }
        if rail_name == "ast_syntax_sweep":
            syn = cls.ast_syntax_sweep(ws)
            return {
                "ok": syn["ok"],
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"AST syntax sweep: {syn['files_checked']} files checked, {len(syn['syntax_errors'])} errors",
                "details": syn,
            }
        if rail_name == "verify_only_check":
            if not verify_cmd or run_fn is None:
                return {"ok": False, "rail": rail_name, "error": "verify_cmd and run_fn required"}
            v = run_fn({"command": verify_cmd, "timeout_s": 600})
            passed = int(v.get("exit_code", 1)) == 0
            return {
                "ok": passed,
                "rail": rail_name,
                "estimated_tokens_saved": spec.estimated_tokens_saved,
                "summary": f"Verification command exited {v.get('exit_code')}",
                "details": v,
            }
        return cls.run_preflight_bundle(ws)
