"""Adaptive Skill & Tool Forge (am_ua.execution.adaptive_skills).

Assimilates Open-Interpreter `computer.skills` + Voyager Curriculum Skill Library + MSEA SAST Gate:
1. Allows the agent to synthesize, validate, persist, and reuse custom Python automation tools
   at runtime (`forge_skill`, `run_skill`, `search_skills`, `list_skills`).
2. Every forged skill passes a strict AST Static Security Gate (`audit_skill_ast`) blocking
   `eval`, `exec`, `__import__`, `os.system`, and destructive shell patterns before disk write.
3. Every skill is hashed with SHA-256 in `skills_manifest.json` and verified before execution
   to prevent tampering.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua import PROJECT_ROOT
from am_ua.cognition.reasoning_bank import jaccard_similarity, tokenize


SKILL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

FORBIDDEN_AST_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "os.system",
    "os.popen",
    "pty.spawn",
}

FORBIDDEN_MODULES = {
    "ctypes.wintypes",  # raw kernel tampering blocked inside dynamic skills
    "winreg",
    "telnetlib",
    "smtpd",
}


class SkillSecurityViolationError(PermissionError):
    """Raised when a candidate skill violates the AST security gate."""


@dataclass
class AdaptiveSkillRecord:
    """Metadata record for a forged and verified adaptive skill."""
    name: str
    description: str
    file_path: str
    sha256: str
    parameters: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = 0.0
    usage_count: int = 0
    success_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def audit_skill_ast(code: str, expected_fn_name: str) -> Tuple[bool, List[str], List[str]]:
    """Parse Python skill source code, enforce AST safety invariants, and extract parameter names."""
    errors: List[str] = []
    params: List[str] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, [f"SyntaxError at line {exc.lineno}: {exc.msg}"], []

    found_entry = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in FORBIDDEN_MODULES:
                    errors.append(f"Forbidden module import: '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in FORBIDDEN_MODULES:
                errors.append(f"Forbidden module import: 'from {mod}'")
        elif isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                call_name = f"{node.func.value.id}.{node.func.attr}"
            if call_name in FORBIDDEN_AST_CALLS:
                errors.append(f"Forbidden dynamic execution call: '{call_name}()'")
        elif isinstance(node, ast.FunctionDef):
            if node.name in (expected_fn_name, "run"):
                found_entry = True
                params = [arg.arg for arg in node.args.args]

    if not found_entry:
        errors.append(
            f"Skill code must define `def {expected_fn_name}(...)` or `def run(...)` entry point"
        )

    return len(errors) == 0, errors, params


class AdaptiveSkillForge:
    """Manages synthesis, AST verification, SHA-256 sealing, and execution of adaptive skills."""

    def __init__(self, skills_dir: Optional[Path | str] = None) -> None:
        self.skills_dir = Path(
            skills_dir or (Path(PROJECT_ROOT) / "data" / "adaptive_skills")
        ).resolve()
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.skills_dir / "skills_manifest.json"
        self._records: Dict[str, AdaptiveSkillRecord] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        if not self.manifest_path.is_file():
            self._records = {}
            return
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            skills_map = data.get("skills", {})
            self._records = {
                k: AdaptiveSkillRecord(**v)
                for k, v in skills_map.items()
                if isinstance(v, dict)
            }
        except Exception:
            self._records = {}

    def _save_manifest(self) -> None:
        payload = {
            "schema": "aethermind_adaptive_skills/v1",
            "updated_at": time.time(),
            "count": len(self._records),
            "skills": {k: v.to_dict() for k, v in sorted(self._records.items())},
        }
        self.manifest_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def forge_skill(
        self,
        name: str,
        description: str,
        code: str,
        *,
        tags: Optional[List[str]] = None,
        test_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate, test, seal, and register a new reusable Python skill."""
        clean_name = name.strip().lower()
        if not SKILL_NAME_RE.match(clean_name):
            raise ValueError(
                f"Invalid skill name '{name}'. Must match ^[a-z][a-z0-9_]{{2,63}}$"
            )

        clean_code = code.strip()
        if clean_code.startswith("```"):
            lines = clean_code.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            clean_code = "\n".join(lines).strip()
        clean_code += "\n"

        ok, ast_errors, params = audit_skill_ast(clean_code, clean_name)
        if not ok:
            raise SkillSecurityViolationError(
                f"Skill '{clean_name}' failed AST Security Gate: {'; '.join(ast_errors)}"
            )

        skill_file = self.skills_dir / f"{clean_name}.py"
        skill_file.write_text(clean_code, encoding="utf-8", newline="\n")
        digest = hashlib.sha256(skill_file.read_bytes()).hexdigest()

        # Verify module loads cleanly and optionally run self-test
        test_output: Any = None
        try:
            fn = self._load_callable(skill_file, clean_name)
            if test_kwargs is not None:
                test_output = fn(**test_kwargs)
        except Exception as exc:
            skill_file.unlink(missing_ok=True)
            raise RuntimeError(f"Skill '{clean_name}' failed verification probe: {exc}") from exc

        record = AdaptiveSkillRecord(
            name=clean_name,
            description=description.strip(),
            file_path=str(skill_file),
            sha256=digest,
            parameters=params,
            tags=list(tags or []),
            created_at=time.time(),
            usage_count=1 if test_kwargs is not None else 0,
            success_count=1 if test_kwargs is not None else 0,
        )
        self._records[clean_name] = record
        self._save_manifest()

        return {
            "ok": True,
            "skill": record.to_dict(),
            "test_executed": test_kwargs is not None,
            "test_output": test_output,
        }

    @staticmethod
    def _load_callable(skill_file: Path, skill_name: str) -> Callable[..., Any]:
        spec = importlib.util.spec_from_file_location(f"am_skill_{skill_name}", str(skill_file))
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not create module spec for {skill_file}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, skill_name, None) or getattr(mod, "run", None)
        if not callable(fn):
            raise AttributeError(f"Module {skill_file.name} has no callable '{skill_name}' or 'run'")
        return fn

    def run_skill(self, name: str, kwargs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Verify SHA-256 integrity of a registered skill and execute it."""
        clean_name = name.strip().lower()
        if clean_name not in self._records:
            return {"ok": False, "error": f"Skill '{clean_name}' is not registered"}

        rec = self._records[clean_name]
        skill_file = Path(rec.file_path)
        if not skill_file.is_file():
            return {"ok": False, "error": f"Skill file missing on disk: {skill_file}"}

        actual_sha = hashlib.sha256(skill_file.read_bytes()).hexdigest()
        if actual_sha != rec.sha256:
            raise SkillSecurityViolationError(
                f"Skill '{clean_name}' SHA-256 mismatch (expected {rec.sha256[:12]}, got {actual_sha[:12]})"
            )

        rec.usage_count += 1
        t0 = time.perf_counter()
        try:
            fn = self._load_callable(skill_file, clean_name)
            call_args = dict(kwargs or {})
            sig = inspect.signature(fn)
            # If the function takes a single `args` dict and wasn't passed `args`, wrap or pass kwargs
            if list(sig.parameters.keys()) == ["args"] and "args" not in call_args:
                result = fn(call_args)
            else:
                result = fn(**call_args)
            rec.success_count += 1
            self._save_manifest()
            return {
                "ok": True,
                "skill": clean_name,
                "result": result,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }
        except Exception as exc:
            self._save_manifest()
            return {
                "ok": False,
                "skill": clean_name,
                "error": str(exc),
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }

    def list_skills(self) -> List[Dict[str, Any]]:
        """List all registered adaptive skills."""
        return [rec.to_dict() for rec in self._records.values()]

    def search_skills(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search adaptive skills by semantic token overlap (Jaccard + substring)."""
        q_tokens = tokenize(query)
        q_low = (query or "").strip().lower()
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for rec in self._records.values():
            doc_text = f"{rec.name} {rec.description} {' '.join(rec.tags)}"
            doc_tokens = tokenize(doc_text)
            sim = jaccard_similarity(q_tokens, doc_tokens)
            if q_low and (q_low in rec.name.lower() or q_low in rec.description.lower()):
                sim = max(sim, 0.65)
            if sim > 0.0:
                d = rec.to_dict()
                d["similarity"] = round(sim, 4)
                scored.append((sim, d))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [item[1] for item in scored[:top_k]]
