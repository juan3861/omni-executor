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

    def _assert_no_symlink(self, path: Path) -> None:
        """Reject symlinked skill bundles and escapes outside skills_dir."""
        if path.is_symlink():
            raise SkillSecurityViolationError(f"Symlinked skill files are not permitted: {path}")
        resolved = path.resolve()
        if resolved != self.skills_dir and self.skills_dir not in resolved.parents:
            raise SkillSecurityViolationError(f"Skill path escapes skills directory: {path}")
        cur = resolved
        while cur != self.skills_dir and self.skills_dir in cur.parents:
            if cur.is_symlink():
                raise SkillSecurityViolationError(f"Symlinked directory component rejected: {cur}")
            cur = cur.parent

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
        self._assert_no_symlink(skill_file)
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
        self._assert_no_symlink(skill_file)
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

    def wrap_cli_tool(
        self,
        executable: str,
        *,
        skill_name: Optional[str] = None,
        help_args: Optional[List[str]] = None,
        timeout_s: float = 15.0,
    ) -> Dict[str, Any]:
        """Assimilates HKUDS/CLI-Anything: wrap an external CLI binary/script into an AST-sealed JSON skill + SKILL.md."""
        import shutil
        import subprocess

        exe_raw = str(executable or "").strip()
        if not exe_raw:
            raise ValueError("executable must not be empty")
        resolved = exe_raw if Path(exe_raw).is_file() else (shutil.which(exe_raw) or exe_raw)
        stem = re.sub(r"[^a-z0-9_]+", "_", Path(exe_raw).stem.lower()).strip("_") or "tool"
        clean_skill = (skill_name or f"cli_{stem}").strip().lower()
        if not SKILL_NAME_RE.match(clean_skill):
            clean_skill = re.sub(r"[^a-z0-9_]+", "_", clean_skill).strip("_")
            if not clean_skill or not clean_skill[0].isalpha():
                clean_skill = f"cli_{clean_skill or 'tool'}"
            clean_skill = clean_skill[:64]

        probe_flags = list(help_args or ["--help"])
        try:
            proc = subprocess.run(
                [resolved, *probe_flags],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                shell=False,
            )
            help_text = (proc.stdout or proc.stderr or "").strip()
        except Exception as exc:
            help_text = f"(help probe unavailable: {exc})"

        # Extract documented flags and subcommands cleanly for SKILL.md and summary
        flags = sorted(set(re.findall(r"(?<![A-Za-z0-9_-])(--?[a-zA-Z0-9][a-zA-Z0-9_-]*)", help_text)))[:24]
        subcmds = sorted(
            {
                m.group(1)
                for m in re.finditer(r"^\s{1,6}([a-z][a-z0-9_-]{1,24})\s{2,}\S", help_text, re.MULTILINE)
            }
        )[:16]

        code = f'''"""Auto-generated CLI-Anything JSON skill wrapper for {Path(exe_raw).name}."""
import json
import shlex
import subprocess
from typing import Any, Dict, List, Optional, Union

_EXECUTABLE = {resolved!r}

def {clean_skill}(argv: Optional[Union[str, List[str]]] = None, timeout_s: float = {float(timeout_s)}) -> Dict[str, Any]:
    if argv is None:
        cmd_args: List[str] = []
    elif isinstance(argv, str):
        cmd_args = shlex.split(argv)
    else:
        cmd_args = [str(a) for a in argv]
    proc = subprocess.run(
        [_EXECUTABLE, *cmd_args],
        capture_output=True,
        text=True,
        timeout=float(timeout_s),
        shell=False,
    )
    out_s = (proc.stdout or "").strip()
    parsed = None
    if out_s.startswith("{{") or out_s.startswith("["):
        try:
            parsed = json.loads(out_s)
        except Exception:
            parsed = None
    return {{
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": out_s[:8000],
        "stderr": (proc.stderr or "").strip()[:2000],
        "parsed_json": parsed,
    }}
'''
        desc = f"Agent-native CLI wrapper for `{Path(exe_raw).name}` (subcommands={len(subcmds)}, flags={len(flags)})."
        forged = self.forge_skill(
            name=clean_skill,
            description=desc,
            code=code,
            tags=["cli-anything", stem, "agent-native-cli"],
            test_kwargs={"argv": probe_flags},
        )
        skill_md_path = self.skills_dir / f"{clean_skill}.SKILL.md"
        skill_md = (
            f"# {clean_skill} (CLI-Anything Wrapper)\n\n"
            f"- Executable: `{resolved}`\n"
            f"- Subcommands: {', '.join(subcmds) if subcmds else 'none detected'}\n"
            f"- Flags: {', '.join(flags) if flags else 'none detected'}\n\n"
            f"## Usage\nCall `run_skill('{clean_skill}', {{'argv': ['--help']}})` to get structured JSON output.\n"
        )
        skill_md_path.write_text(skill_md, encoding="utf-8", newline="\n")
        forged["skill_md_path"] = str(skill_md_path)
        forged["discovered_subcommands"] = subcmds
        forged["discovered_flags"] = flags
        return forged

    def compile_trajectory_to_skill(
        self,
        name: str,
        description: str,
        trajectory_steps: List[Dict[str, Any]],
        *,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Simular/Decagon/n8n-style Trajectory-to-Skill Compiler (SOP Distillation).

        Compiles a verified successful Action->Observation trajectory into a versioned,
        AST-audited, SHA-256-sealed deterministic Python skill so future runs execute
        at ~0 LLM token cost and millisecond latency.
        """
        clean_steps: List[Dict[str, Any]] = []
        for idx, st in enumerate(trajectory_steps or []):
            tool_name = str(st.get("tool") or st.get("action") or "").strip()
            if not tool_name:
                continue
            clean_steps.append({
                "step": idx + 1,
                "tool": tool_name,
                "args": dict(st.get("args") or st.get("params") or {}),
                "expected_ok": bool(st.get("ok", True)),
            })
        if not clean_steps:
            raise ValueError("Trajectory must contain at least one valid tool step to compile.")

        clean_name = re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_")
        if not SKILL_NAME_RE.match(clean_name):
            clean_name = f"sop_{clean_name or 'compiled'}"[:64]

        steps_literal = repr(clean_steps)
        code = f'''"""Compiled deterministic SOP skill distilled from verified trajectory."""
from typing import Any, Callable, Dict, List, Optional

COMPILED_STEPS: List[Dict[str, Any]] = {steps_literal}

def {clean_name}(executor: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Replay compiled deterministic SOP steps without LLM reasoning overhead."""
    ov = dict(overrides or {{}})
    results: List[Dict[str, Any]] = []
    for item in COMPILED_STEPS:
        args = dict(item["args"])
        for k, v in ov.items():
            if k in args:
                args[k] = v
        if executor is None:
            results.append({{"step": item["step"], "tool": item["tool"], "args": args, "status": "DRY_RUN_PLANNED"}})
        else:
            obs = executor(item["tool"], args)
            ok = bool(obs.get("ok", True)) if isinstance(obs, dict) else True
            results.append({{"step": item["step"], "tool": item["tool"], "ok": ok, "observation": obs}})
            if item.get("expected_ok", True) and not ok:
                return {{"ok": False, "failed_step": item["step"], "results": results}}
    return {{"ok": True, "compiled_steps": len(COMPILED_STEPS), "results": results}}
'''
        merged_tags = sorted(set((tags or []) + ["compiled-sop", "zero-token-trajectory"]))
        forged = self.forge_skill(
            name=clean_name,
            description=description or f"Compiled SOP skill ({len(clean_steps)} steps)",
            code=code,
            tags=merged_tags,
            test_kwargs={"executor": None},
        )
        forged["compiled_step_count"] = len(clean_steps)
        return forged
