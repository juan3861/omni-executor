"""SWE-bench Official Compatibility Harness & Patch Exporter (`am_ua.execution.swebench_harness`).

Ingests standard SWE-bench instances (`instance_id`, `repo`, `base_commit`, `problem_statement`,
`FAIL_TO_PASS`, `PASS_TO_PASS`), runs deterministic or agentic solvers against an isolated
workspace, verifies `FAIL_TO_PASS` and `PASS_TO_PASS` test targets, and exports official
`predictions.json` (`instance_id`, `model_name_or_path`, `model_patch`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import difflib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional


@dataclass
class SWEBenchInstance:
    instance_id: str
    repo: str
    base_commit: str
    problem_statement: str
    fail_to_pass: List[str] = field(default_factory=list)
    pass_to_pass: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SWEBenchInstance":
        f2p = data.get("FAIL_TO_PASS") or data.get("fail_to_pass") or []
        p2p = data.get("PASS_TO_PASS") or data.get("pass_to_pass") or []
        if isinstance(f2p, str):
            f2p = json.loads(f2p) if f2p.strip().startswith("[") else [f2p]
        if isinstance(p2p, str):
            p2p = json.loads(p2p) if p2p.strip().startswith("[") else [p2p]
        return cls(
            instance_id=str(data["instance_id"]),
            repo=str(data.get("repo", "local/repo")),
            base_commit=str(data.get("base_commit", "HEAD")),
            problem_statement=str(data.get("problem_statement", "")),
            fail_to_pass=[str(x) for x in f2p],
            pass_to_pass=[str(x) for x in p2p],
        )


class SWEBenchHarness:
    """Deterministic evaluator and prediction exporter for SWE-bench instances."""

    def __init__(self, *, model_name: str = "omni-executor-v5.3") -> None:
        self.model_name = model_name

    @staticmethod
    def snapshot_files(workspace: Path) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        skip = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
        for fp in sorted(workspace.rglob("*")):
            if any(part in skip for part in fp.parts) or not fp.is_file():
                continue
            try:
                if fp.stat().st_size <= 512_000:
                    snap[fp.relative_to(workspace).as_posix()] = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return snap

    @staticmethod
    def compute_model_patch(before: Dict[str, str], after: Dict[str, str]) -> str:
        diffs: List[str] = []
        all_paths = sorted(set(before) | set(after))
        for rel in all_paths:
            old_txt = before.get(rel, "")
            new_txt = after.get(rel, "")
            if old_txt == new_txt:
                continue
            lines = list(
                difflib.unified_diff(
                    old_txt.splitlines(keepends=True),
                    new_txt.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                )
            )
            if lines:
                diffs.append("".join(lines))
        return "\n".join(diffs)

    @staticmethod
    def _run_pytest_targets(workspace: Path, targets: List[str]) -> Dict[str, Any]:
        if not targets:
            return {"ok": True, "exit_code": 0, "output": ""}
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-2000:],
        }

    def evaluate_instance(
        self,
        instance: SWEBenchInstance,
        workspace: Path | str,
        solver_fn: Callable[[Path, SWEBenchInstance], Any],
    ) -> Dict[str, Any]:
        ws = Path(workspace).resolve()
        t0 = time.perf_counter()
        before = self.snapshot_files(ws)

        solver_fn(ws, instance)

        after = self.snapshot_files(ws)
        patch = self.compute_model_patch(before, after)
        f2p_res = self._run_pytest_targets(ws, instance.fail_to_pass)
        p2p_res = self._run_pytest_targets(ws, instance.pass_to_pass)
        resolved = bool(f2p_res["ok"]) and bool(p2p_res["ok"]) and bool(patch.strip())
        return {
            "instance_id": instance.instance_id,
            "model_name_or_path": self.model_name,
            "model_patch": patch,
            "resolved": resolved,
            "fail_to_pass_ok": f2p_res["ok"],
            "pass_to_pass_ok": p2p_res["ok"],
            "elapsed_s": round(time.perf_counter() - t0, 2),
        }

    @staticmethod
    def export_predictions(records: List[Dict[str, Any]], out_path: Path | str) -> Path:
        p = Path(out_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        clean = [
            {
                "instance_id": r["instance_id"],
                "model_name_or_path": r.get("model_name_or_path", "omni-executor-v5.3"),
                "model_patch": r.get("model_patch", ""),
            }
            for r in records
        ]
        p.write_text(json.dumps(clean, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        return p
