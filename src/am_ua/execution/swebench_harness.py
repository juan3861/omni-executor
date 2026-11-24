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
import re
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence


@dataclass
class SWEBenchInstance:
    instance_id: str
    repo: str
    base_commit: str
    problem_statement: str
    fail_to_pass: List[str] = field(default_factory=list)
    pass_to_pass: List[str] = field(default_factory=list)
    test_patch: str = ""
    hints_text: str = ""

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
            test_patch=str(data.get("test_patch", "")),
            hints_text=str(data.get("hints_text", "")),
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
    def extract_test_patch_targets(test_patch: str) -> List[str]:
        """Extract `file::test_name` targets added or modified in a SWE-bench `test_patch` diff."""
        if not test_patch or not test_patch.strip():
            return []
        targets: List[str] = []
        current_file = ""
        current_hunk_func = ""
        for line in test_patch.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                current_hunk_func = ""
            elif line.startswith("@@"):
                m_ctx = re.search(r"def\s+(test_[A-Za-z0-9_]+)\s*\(", line)
                current_hunk_func = m_ctx.group(1) if m_ctx else ""
                if current_file and current_hunk_func:
                    node = f"{current_file}::{current_hunk_func}"
                    if node not in targets:
                        targets.append(node)
            elif current_file and line.startswith("+") and not line.startswith("+++"):
                m_def = re.match(r"^\+\s*def\s+(test_[A-Za-z0-9_]+)\s*\(", line)
                if m_def:
                    node = f"{current_file}::{m_def.group(1)}"
                    if node not in targets:
                        targets.append(node)
        return targets

    @staticmethod
    def sanitize_pytest_target(raw_target: str) -> str:
        """Repair malformed space-truncated parametrized SWE-bench test nodeids."""
        t = str(raw_target or "").strip()
        if not t:
            return ""
        if "[" in t and ("]" not in t or " " in t[t.find("[") :]):
            t = t[: t.find("[")].strip()
        return t

    @classmethod
    def select_priority_tests(cls, instance: SWEBenchInstance, *, limit: int = 6) -> List[str]:
        """Prioritize tests added/changed in `test_patch` before raw `fail_to_pass` ordering."""
        ordered: List[str] = []
        seen_keys: set[str] = set()
        candidates = [*cls.extract_test_patch_targets(instance.test_patch), *instance.fail_to_pass]
        for raw in candidates:
            cleaned = cls.sanitize_pytest_target(raw)
            if not cleaned:
                continue
            fn_tail = cleaned.split("::")[-1]
            key = f"{cleaned.split('::')[0]}::{fn_tail}" if "::" in cleaned else fn_tail
            if key in seen_keys:
                continue
            seen_keys.add(key)
            ordered.append(cleaned)
            if len(ordered) >= max(1, int(limit)):
                break
        return ordered

    @classmethod
    def resolve_repo_test_command(
        cls,
        workspace: Path,
        raw_targets: Sequence[str],
        *,
        repo: str = "",
        python_exe: str = sys.executable,
    ) -> Dict[str, Any]:
        """Build a repo-aware test command (SymPy `bin/test` for XFAIL correctness, else `pytest`)."""
        node_args: List[str] = []
        files: List[str] = []
        k_exprs: List[str] = []
        for raw in raw_targets:
            t = cls.sanitize_pytest_target(raw)
            if not t:
                continue
            if "::" in t:
                parts = t.split("::")
                rel_file = parts[0]
                if len(parts) == 2 and (workspace / rel_file).is_file():
                    if rel_file not in files:
                        files.append(rel_file)
                    if parts[1] not in k_exprs:
                        k_exprs.append(parts[1])
                else:
                    if t not in node_args:
                        node_args.append(t)
            elif t.endswith(".py"):
                if t not in files:
                    files.append(t)
            else:
                if t not in k_exprs:
                    k_exprs.append(t)
                for p in workspace.rglob("*.py"):
                    if "test" not in p.name.lower():
                        continue
                    try:
                        if f"def {t}" in p.read_text(encoding="utf-8", errors="ignore"):
                            rel = p.relative_to(workspace).as_posix()
                            if rel not in files:
                                files.append(rel)
                    except OSError:
                        pass

        k_joined = " or ".join(k_exprs) if k_exprs else ""
        use_sympy_runner = "sympy" in (repo or "").lower() and (workspace / "bin" / "test").is_file()
        if use_sympy_runner:
            cmd = [python_exe, "-B", "bin/test", *files]
            if k_joined:
                cmd.extend(["-k", k_joined])
            return {"runner": "sympy_bin_test", "cmd": cmd, "files": files, "k_expr": k_joined}

        pytest_args = [*node_args, *files]
        if k_joined:
            pytest_args.extend(["-k", k_joined])
        cmd = [python_exe, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *pytest_args]
        return {"runner": "pytest", "cmd": cmd, "files": files, "node_args": node_args, "k_expr": k_joined}

    @staticmethod
    def build_docker_command(
        workspace: Path | str,
        pytest_targets: List[str],
        *,
        docker_bin: str = "docker",
        docker_image: str = "python:3.11-slim",
        hardened: bool = True,
        read_only_root: bool = False,
    ) -> List[str]:
        t_list = " ".join(pytest_targets)
        cmd = [docker_bin, "run", "--rm", "--network=none"]
        if hardened:
            cmd.extend([
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pids-limit=256",
                "--memory=1g",
            ])
        if read_only_root:
            cmd.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid"])
        cmd.extend([
            "-v",
            f"{workspace}:/ws",
            "-w",
            "/ws",
            docker_image,
            "sh",
            "-lc",
            f"python -m pytest -q -p no:cacheprovider {t_list}",
        ])
        return cmd

    @staticmethod
    def _run_pytest_targets(
        workspace: Path,
        targets: List[str],
        *,
        use_docker: bool = False,
        docker_image: str = "python:3.11-slim",
        hardened_docker: bool = True,
        read_only_root: bool = False,
    ) -> Dict[str, Any]:
        if not targets:
            return {"ok": True, "exit_code": 0, "output": "", "backend": "none"}
        if use_docker:
            import shutil

            docker_bin = shutil.which("docker")
            if not docker_bin:
                return {"ok": False, "exit_code": 127, "output": "docker CLI not found", "backend": "docker"}
            cmd = SWEBenchHarness.build_docker_command(
                workspace,
                targets,
                docker_bin=docker_bin,
                docker_image=docker_image,
                hardened=hardened_docker,
                read_only_root=read_only_root,
            )
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240, check=False)
            return {
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "output": ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-2000:],
                "backend": "docker",
            }
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
            "backend": "host_python",
        }

    def evaluate_instance(
        self,
        instance: SWEBenchInstance,
        workspace: Path | str,
        solver_fn: Callable[[Path, SWEBenchInstance], Any],
        *,
        use_docker: bool = False,
        docker_image: str = "python:3.11-slim",
    ) -> Dict[str, Any]:
        ws = Path(workspace).resolve()
        t0 = time.perf_counter()
        before = self.snapshot_files(ws)

        solver_fn(ws, instance)

        after = self.snapshot_files(ws)
        patch = self.compute_model_patch(before, after)
        f2p_res = self._run_pytest_targets(ws, instance.fail_to_pass, use_docker=use_docker, docker_image=docker_image)
        p2p_res = self._run_pytest_targets(ws, instance.pass_to_pass, use_docker=use_docker, docker_image=docker_image)
        resolved = bool(f2p_res["ok"]) and bool(p2p_res["ok"]) and bool(patch.strip())
        return {
            "instance_id": instance.instance_id,
            "model_name_or_path": self.model_name,
            "model_patch": patch,
            "resolved": resolved,
            "fail_to_pass_ok": f2p_res["ok"],
            "pass_to_pass_ok": p2p_res["ok"],
            "eval_backend": f2p_res.get("backend", "host_python"),
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

    FREE_TIER_MODELS: Dict[str, str] = {
        "groq": "llama-3.3-70b-versatile",
        "openrouter": "qwen/qwen-2.5-coder-32b-instruct:free",
        "ollama": "qwen2.5-coder:7b",
    }

    @staticmethod
    def load_instances(
        source: Path | str,
        *,
        limit: Optional[int] = None,
        split: str = "test",
    ) -> List[SWEBenchInstance]:
        """Load SWE-bench instances on demand from local `.jsonl`/`.json` or HF `datasets`."""
        p = Path(str(source))
        rows: List[Dict[str, Any]] = []
        if p.is_file():
            raw_text = p.read_text(encoding="utf-8", errors="replace").strip()
            if p.suffix.lower() == ".json" or raw_text.startswith("["):
                loaded = json.loads(raw_text) if raw_text else []
                rows = list(loaded) if isinstance(loaded, list) else [loaded]
            else:
                for line in raw_text.splitlines():
                    s = line.strip()
                    if s:
                        rows.append(json.loads(s))
        else:
            try:
                from datasets import load_dataset  # type: ignore[import-not-found]
            except ImportError as exc:
                raise FileNotFoundError(
                    f"SWE-bench dataset path {source!r} not found locally and optional 'datasets' package is not installed"
                ) from exc
            ds = load_dataset(str(source), split=split)
            for row in ds:
                rows.append(dict(row))
                if limit is not None and len(rows) >= limit:
                    break

        if limit is not None:
            rows = rows[: max(0, int(limit))]

        instances: List[SWEBenchInstance] = []
        for row in rows:
            f2p = row.get("FAIL_TO_PASS") or row.get("fail_to_pass") or []
            p2p = row.get("PASS_TO_PASS") or row.get("pass_to_pass") or []
            if isinstance(f2p, str):
                f2p = json.loads(f2p) if f2p.strip().startswith("[") else [x.strip() for x in f2p.split(",") if x.strip()]
            if isinstance(p2p, str):
                p2p = json.loads(p2p) if p2p.strip().startswith("[") else [x.strip() for x in p2p.split(",") if x.strip()]
            instances.append(
                SWEBenchInstance(
                    instance_id=str(row.get("instance_id", "")),
                    repo=str(row.get("repo", "")),
                    base_commit=str(row.get("base_commit", "")),
                    problem_statement=str(row.get("problem_statement", "")),
                    fail_to_pass=[str(x) for x in f2p],
                    pass_to_pass=[str(x) for x in p2p],
                    test_patch=str(row.get("test_patch", "")),
                    hints_text=str(row.get("hints_text", "")),
                )
            )
        return instances

    @staticmethod
    def prepare_instance_workspace(
        instance: SWEBenchInstance,
        source_repo: Path | str,
        *,
        worktree_root: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Checkout `instance.base_commit` into an isolated git worktree when `source_repo` is a git repo."""
        from am_ua.execution.git_worktree_manager import GitWorktreeManager

        repo_path = Path(source_repo).resolve()
        if not (repo_path / ".git").exists():
            return {"ok": True, "isolated": False, "workspace": str(repo_path), "mode": "direct_dir"}

        mgr = GitWorktreeManager(repo_path, worktree_root=Path(worktree_root) if worktree_root else None)
        wt = mgr.create_worktree(
            worker_id=f"swe_{instance.instance_id.replace('/', '_')[:24]}",
            base_ref=instance.base_commit or "HEAD",
        )
        return {"ok": True, "isolated": True, "workspace": str(wt.path), "branch": wt.branch, "mode": "git_worktree"}

    def run_dataset(
        self,
        instances: List[SWEBenchInstance],
        *,
        workspace_map: Optional[Dict[str, Path | str]] = None,
        workspace_root: Optional[Path | str] = None,
        provider: str = "groq",
        max_cost_usd: Optional[float] = None,
        max_turns: int = 20,
        use_docker: bool = False,
        docker_image: str = "python:3.11-slim",
        solver_fn: Optional[Callable[[Path, SWEBenchInstance], Any]] = None,
        out_predictions: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """Execute SWE-bench instances on demand, prioritizing zero-cost free-tier LLMs unless overridden."""
        from am_ua.cognition.llm_client import LLMClient
        from am_ua.execution.agent_loop import AgentLoop
        from am_ua.execution.durable_engine import DurableExecutionEngine
        from am_ua.governance.seal_guard import ConstitutionSealGuard

        results: List[Dict[str, Any]] = []
        total_cost_usd = 0.0
        aborted_by_budget = False
        prov_key = (provider or "groq").strip().lower()
        free_model = self.FREE_TIER_MODELS.get(prov_key, "llama-3.3-70b-versatile")

        def _default_llm_solver(ws: Path, inst: SWEBenchInstance) -> Dict[str, Any]:
            nonlocal total_cost_usd
            seal = ConstitutionSealGuard()
            engine = DurableExecutionEngine(ws / ".am_swe_state")
            llm = LLMClient(
                provider=prov_key,
                model_map={prov_key: free_model} if prov_key in self.FREE_TIER_MODELS else None,
            )
            loop = AgentLoop(engine=engine, seal_guard=seal, llm=llm)
            prompt = (
                f"Fix the following repository issue for {inst.instance_id} ({inst.repo}).\n"
                f"Fail-to-pass targets: {inst.fail_to_pass}\n"
                f"Issue:\n{inst.problem_statement}\n"
            )
            if inst.hints_text:
                prompt += f"\nHints:\n{inst.hints_text}\n"
            res = loop.run(
                objective=prompt,
                workspace=ws,
                actor_provider=prov_key,
                max_turns=max_turns,
                use_judge=False,
            )
            est_cost = 0.0 if prov_key in ("groq", "ollama") or free_model.endswith(":free") else float(
                getattr(res, "estimated_cost_usd", 0.0) or 0.0
            )
            total_cost_usd += est_cost
            return {"status": res.status, "turns": res.turns, "estimated_cost_usd": est_cost}

        active_solver = solver_fn or _default_llm_solver

        for inst in instances:
            if max_cost_usd is not None and total_cost_usd >= float(max_cost_usd):
                aborted_by_budget = True
                break
            if workspace_map and inst.instance_id in workspace_map:
                ws_candidate = Path(workspace_map[inst.instance_id]).resolve()
            elif workspace_root is not None:
                cand = Path(workspace_root).resolve() / inst.instance_id
                ws_candidate = cand if cand.exists() else Path(workspace_root).resolve()
            else:
                ws_candidate = Path.cwd().resolve()

            rec = self.evaluate_instance(
                inst,
                ws_candidate,
                active_solver,
                use_docker=use_docker,
                docker_image=docker_image,
            )
            results.append(rec)

        resolved_count = sum(1 for r in results if r.get("resolved"))
        total = len(results)
        pred_file = str(self.export_predictions(results, out_predictions)) if out_predictions else None
        return {
            "ok": not aborted_by_budget,
            "model_name": self.model_name,
            "provider": prov_key,
            "model": free_model,
            "free_tier_default": prov_key in ("groq", "ollama") or free_model.endswith(":free"),
            "max_cost_usd": max_cost_usd,
            "total_cost_usd": round(total_cost_usd, 6),
            "aborted_by_budget": aborted_by_budget,
            "evaluated": total,
            "resolved": resolved_count,
            "resolve_rate": round(resolved_count / max(1, total), 4),
            "predictions_path": pred_file,
            "results": results,
        }


class PublicBenchmarkSuiteAdapter:
    """Unified normalizer & deterministic evaluator across SWE-bench, Terminal-Bench, OSWorld, and WebArena."""

    SUPPORTED_SUITES = ("swebench", "terminal_bench", "osworld", "webarena")

    @classmethod
    def normalize_task(cls, raw: Dict[str, Any], *, suite: str) -> Dict[str, Any]:
        s = (suite or "swebench").strip().lower().replace("-", "_")
        if s not in cls.SUPPORTED_SUITES:
            raise ValueError(f"Unsupported benchmark suite: {suite!r}")
        tid = str(raw.get("instance_id") or raw.get("task_id") or raw.get("id") or "task_0")
        prompt = str(
            raw.get("problem_statement")
            or raw.get("instruction")
            or raw.get("intent")
            or raw.get("prompt")
            or ""
        )
        return {
            "suite": s,
            "task_id": tid,
            "prompt": prompt,
            "verify_cmd": raw.get("verify_cmd"),
            "fail_to_pass": list(raw.get("fail_to_pass") or []),
            "start_url": raw.get("start_url") or "",
            "expected_keywords": list(raw.get("expected_keywords") or []),
            "metadata": dict(raw.get("metadata") or {}),
        }

    @classmethod
    def load_tasks_jsonl(cls, path: Path | str, *, suite: str, limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with Path(path).open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(cls.normalize_task(json.loads(line), suite=suite))
                    if len(out) >= limit:
                        break
        return out

    @classmethod
    def evaluate_suite(
        cls,
        tasks: Sequence[Dict[str, Any]],
        *,
        runner_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        zero_token_tasks = 0
        total_cost = 0.0
        for t in tasks:
            t0 = time.perf_counter()
            out = dict(runner_fn(t))
            passed = bool(out.get("ok") or out.get("resolved") or out.get("passed"))
            llm_calls = int(out.get("llm_calls", 0))
            if llm_calls == 0:
                zero_token_tasks += 1
            total_cost += float(out.get("cost_usd", 0.0) or 0.0)
            results.append(
                {
                    "suite": t.get("suite"),
                    "task_id": t.get("task_id"),
                    "passed": passed,
                    "llm_calls": llm_calls,
                    "elapsed_s": round(time.perf_counter() - t0, 3),
                }
            )
        passed_n = sum(1 for r in results if r["passed"])
        n = len(results)
        return {
            "ok": passed_n == n and n > 0,
            "evaluated": n,
            "passed": passed_n,
            "pass_rate": round(passed_n / max(1, n), 4),
            "zero_token_rate": round(zero_token_tasks / max(1, n), 4),
            "total_cost_usd": round(total_cost, 6),
            "results": results,
        }
