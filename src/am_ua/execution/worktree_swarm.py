"""Real Parallel Git Worktree Swarm Coordinator (v8.1 — Fase 2).

Elevates multi-agent execution from in-memory role slots to real parallel isolated
coding workers:
  1. `GitWorktreeManager`: Creates isolated `git worktree` directories & branches per
     worker (`.omni_worktrees/<worker_id>`), captures per-branch diffs/commits, executes
     3-way merges back into the base branch (with optional LLM conflict resolution or
     atomic `git merge --abort`), and guarantees cleanup.
  2. `WorktreeSwarmCoordinator`: Spawns concurrent `AgentLoop` (or custom worker)
     instances across N worktrees via `ThreadPoolExecutor`, coordinates Role/Provider
     affinity (`ROLE_PROVIDER_PROFILES`), merges verified worker branches, and runs
     final acceptance verification.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
import shutil
import subprocess
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


@dataclass
class WorktreeHandle:
    worker_id: str
    branch_name: str
    worktree_path: Path
    used_git_worktree: bool
    base_commit: str = ""


@dataclass
class SwarmWorkerOutcome:
    worker_id: str
    role: str
    objective: str
    branch_name: str
    status: str
    ok: bool
    changed_files: List[str] = field(default_factory=list)
    diff: str = ""
    tokens_used: int = 0
    elapsed_s: float = 0.0
    summary: str = ""
    error: str = ""
    merge_status: str = "pending"
    conflict_files: List[str] = field(default_factory=list)


class GitWorktreeManager:
    """Thread-safe manager for isolated per-worker `git worktree` branches and 3-way merges."""

    def __init__(
        self,
        repo_root: Path | str,
        *,
        worktrees_dir: Optional[Path | str] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.worktrees_dir = Path(worktrees_dir or (self.repo_root / ".omni_worktrees")).resolve()

    def _git(self, args: Sequence[str], *, cwd: Optional[Path] = None, timeout_s: float = 30.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(cwd or self.repo_root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
        )

    def has_git_history(self) -> bool:
        if not (self.repo_root / ".git").exists():
            return False
        proc = self._git(["rev-parse", "--verify", "HEAD"])
        return proc.returncode == 0

    def current_head(self) -> str:
        proc = self._git(["rev-parse", "HEAD"])
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def current_branch(self) -> str:
        proc = self._git(["rev-parse", "--abbrev-ref", "HEAD"])
        return proc.stdout.strip() if proc.returncode == 0 else "HEAD"

    def create_worktree(self, worker_id: str, *, base_ref: str = "HEAD") -> WorktreeHandle:
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in worker_id)
        branch = f"omni/swarm-{safe_id}-{uuid.uuid4().hex[:6]}"
        wt_path = self.worktrees_dir / f"{safe_id}_{uuid.uuid4().hex[:6]}"
        wt_path.parent.mkdir(parents=True, exist_ok=True)
        if wt_path.exists():
            shutil.rmtree(wt_path, ignore_errors=True)

        if self.has_git_history():
            base_sha = self.current_head()
            proc = self._git(["worktree", "add", "-b", branch, str(wt_path), base_ref])
            if proc.returncode == 0 and wt_path.is_dir():
                return WorktreeHandle(
                    worker_id=worker_id,
                    branch_name=branch,
                    worktree_path=wt_path,
                    used_git_worktree=True,
                    base_commit=base_sha,
                )

        # Portable copy fallback for repos without git commits yet
        shutil.copytree(
            self.repo_root,
            wt_path,
            ignore=shutil.ignore_patterns(".git", ".omni_worktrees", "__pycache__", ".pytest_cache", ".ci_pytest_tmp", "node_modules"),
        )
        return WorktreeHandle(
            worker_id=worker_id,
            branch_name=branch,
            worktree_path=wt_path,
            used_git_worktree=False,
            base_commit="",
        )

    def collect_changes(self, handle: WorktreeHandle) -> Tuple[List[str], str]:
        if not handle.used_git_worktree:
            return [], ""
        st = self._git(["status", "--porcelain"], cwd=handle.worktree_path)
        changed: List[str] = []
        for line in (st.stdout or "").splitlines():
            if len(line) >= 4:
                changed.append(line[3:].strip())
        diff_proc = self._git(["diff", handle.base_commit or "HEAD"], cwd=handle.worktree_path)
        return changed, (diff_proc.stdout or "")

    def commit_worktree(self, handle: WorktreeHandle, message: str) -> Tuple[bool, List[str], str]:
        """Stage all modified/untracked files inside `handle.worktree_path` and commit onto its branch."""
        if not handle.used_git_worktree:
            return False, [], ""
        changed, pre_diff = self.collect_changes(handle)
        if not changed:
            return False, [], ""
        add_proc = self._git(["add", "-A"], cwd=handle.worktree_path)
        if add_proc.returncode != 0:
            return False, changed, pre_diff
        c_proc = self._git(
            [
                "-c", "user.name=OmniExecutor Swarm",
                "-c", "user.email=swarm@omni-executor.local",
                "commit",
                "-m",
                message[:200],
            ],
            cwd=handle.worktree_path,
        )
        full_diff_proc = self._git(["diff", f"{handle.base_commit}..HEAD"], cwd=handle.worktree_path)
        full_diff = full_diff_proc.stdout if full_diff_proc.returncode == 0 else pre_diff
        return (c_proc.returncode == 0), changed, (full_diff or pre_diff)

    def merge_branch(
        self,
        branch_name: str,
        *,
        conflict_resolver_fn: Optional[Callable[[Path, List[str], str], bool]] = None,
    ) -> Tuple[str, List[str]]:
        """Execute a real 3-way `git merge --no-ff` of `branch_name` into current repo HEAD."""
        ahead = self._git(["rev-list", "--count", f"HEAD..{branch_name}"])
        if ahead.returncode != 0 or ahead.stdout.strip() in ("", "0"):
            return "no_changes", []

        m_proc = self._git(
            [
                "-c", "user.name=OmniExecutor Swarm",
                "-c", "user.email=swarm@omni-executor.local",
                "merge",
                "--no-ff",
                "--no-edit",
                branch_name,
            ]
        )
        if m_proc.returncode == 0:
            return "merged", []

        # Collect conflict list
        cf_proc = self._git(["diff", "--name-only", "--diff-filter=U"])
        conflicts = [c.strip() for c in (cf_proc.stdout or "").splitlines() if c.strip()]
        if conflict_resolver_fn is not None and conflicts:
            try:
                resolved = bool(conflict_resolver_fn(self.repo_root, conflicts, branch_name))
            except Exception:
                resolved = False
            if resolved:
                self._git(["add", *conflicts])
                fin = self._git(
                    [
                        "-c", "user.name=OmniExecutor Swarm",
                        "-c", "user.email=swarm@omni-executor.local",
                        "commit",
                        "--no-edit",
                    ]
                )
                if fin.returncode == 0:
                    return "merged_after_conflict_resolution", conflicts

        self._git(["merge", "--abort"])
        return "conflict_aborted", conflicts

    def cleanup_worktree(self, handle: WorktreeHandle) -> None:
        if handle.used_git_worktree:
            self._git(["worktree", "remove", "--force", str(handle.worktree_path)])
            self._git(["worktree", "prune"])
            self._git(["branch", "-D", handle.branch_name])
        for attempt in range(4):
            if not handle.worktree_path.exists():
                break
            shutil.rmtree(handle.worktree_path, ignore_errors=True)
            if handle.worktree_path.exists() and attempt < 3:
                time.sleep(0.05)

    def cleanup_empty_container(self) -> None:
        if self.worktrees_dir.is_dir():
            for attempt in range(3):
                shutil.rmtree(self.worktrees_dir, ignore_errors=True)
                if not self.worktrees_dir.exists():
                    break
                if attempt < 2:
                    time.sleep(0.05)


class WorktreeSwarmCoordinator:
    """Executes concurrent worker agents across isolated git worktrees and 3-way merges results."""

    def __init__(
        self,
        repo_root: Path | str,
        *,
        max_workers: int = 4,
        llm: Any = None,
        seal_guard: Any = None,
        memory_provider: Any = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.max_workers = max(1, min(16, int(max_workers)))
        self.llm = llm
        self.seal_guard = seal_guard
        self.memory_provider = memory_provider
        self.manager = GitWorktreeManager(self.repo_root)

    def run_swarm(
        self,
        tasks: Sequence[Dict[str, Any]],
        *,
        worker_runner_fn: Optional[Callable[[Dict[str, Any], Path], Dict[str, Any]]] = None,
        merge_results: bool = True,
        conflict_resolver_fn: Optional[Callable[[Path, List[str], str], bool]] = None,
        final_verify_cmd: Optional[str] = None,
        timeout_s: float = 300.0,
    ) -> Dict[str, Any]:
        """Spawn parallel isolated worktree workers, collect diffs/verifications, merge 3-way, and cleanup."""
        task_list = [dict(t) for t in tasks]
        if not task_list:
            return {"ok": True, "workers_executed": 0, "merged_branches": [], "workers": []}

        t0 = time.perf_counter()
        handles: List[Tuple[int, Dict[str, Any], WorktreeHandle]] = []
        outcomes: Dict[int, SwarmWorkerOutcome] = {}

        try:
            for idx, spec in enumerate(task_list):
                wid = str(spec.get("id") or f"w{idx + 1}")
                handle = self.manager.create_worktree(wid)
                handles.append((idx, spec, handle))

            def _run_one(idx: int, spec: Dict[str, Any], handle: WorktreeHandle) -> SwarmWorkerOutcome:
                t_w0 = time.perf_counter()
                wid = handle.worker_id
                role = str(spec.get("role") or "general_engineer")
                obj = str(spec.get("objective") or "")
                verify_cmd = spec.get("verify_cmd")
                try:
                    if worker_runner_fn is not None:
                        res = dict(worker_runner_fn(spec, handle.worktree_path) or {})
                        ok = bool(res.get("ok", str(res.get("status", "")).startswith("VERIFIED") or res.get("stop_reason") == "finish"))
                        status = str(res.get("status") or ("VERIFIED" if ok else "FAILED"))
                        tokens_used = int(res.get("tokens_used") or 0)
                        summary = str(res.get("summary") or res.get("final_summary") or "")
                    else:
                        res = self._default_agent_loop_runner(spec, handle.worktree_path, role=role, verify_cmd=verify_cmd)
                        ok = bool(res.get("ok"))
                        status = str(res.get("status") or "FAILED")
                        tokens_used = int(res.get("tokens_used") or 0)
                        summary = str(res.get("summary") or "")

                    committed, changed, diff_txt = self.manager.commit_worktree(
                        handle,
                        f"omni-swarm({wid}/{role}): {obj[:80]}",
                    )
                    if not handle.used_git_worktree:
                        changed = list(res.get("changed_files") or [])
                    return SwarmWorkerOutcome(
                        worker_id=wid,
                        role=role,
                        objective=obj,
                        branch_name=handle.branch_name,
                        status=status,
                        ok=ok,
                        changed_files=changed,
                        diff=diff_txt[:16000],
                        tokens_used=tokens_used,
                        elapsed_s=round(time.perf_counter() - t_w0, 3),
                        summary=summary[:1000],
                        merge_status="ready" if (committed and ok) else ("no_changes" if not changed else "skipped_failed"),
                    )
                except Exception as exc:
                    return SwarmWorkerOutcome(
                        worker_id=wid,
                        role=role,
                        objective=obj,
                        branch_name=handle.branch_name,
                        status="ERROR",
                        ok=False,
                        elapsed_s=round(time.perf_counter() - t_w0, 3),
                        error=f"{type(exc).__name__}: {str(exc)[:300]}",
                        merge_status="error",
                    )

            pool_size = min(self.max_workers, len(handles))
            with ThreadPoolExecutor(max_workers=pool_size) as pool:
                fut_map = {
                    pool.submit(_run_one, idx, spec, h): idx
                    for idx, spec, h in handles
                }
                for fut in as_completed(fut_map, timeout=max(5.0, float(timeout_s))):
                    idx = fut_map[fut]
                    outcomes[idx] = fut.result()

            ordered_outcomes = [outcomes[i] for i in sorted(outcomes)]
            merged_branches: List[str] = []
            conflict_branches: List[Dict[str, Any]] = []

            if merge_results and self.manager.has_git_history():
                for out in ordered_outcomes:
                    if not out.ok or out.merge_status != "ready":
                        continue
                    m_status, conflicts = self.manager.merge_branch(
                        out.branch_name,
                        conflict_resolver_fn=conflict_resolver_fn,
                    )
                    out.merge_status = m_status
                    out.conflict_files = conflicts
                    if m_status in ("merged", "merged_after_conflict_resolution"):
                        merged_branches.append(out.branch_name)
                    elif m_status == "conflict_aborted":
                        conflict_branches.append({"worker_id": out.worker_id, "branch": out.branch_name, "conflicts": conflicts})

            final_verification: Optional[Dict[str, Any]] = None
            final_verify_ok = True
            if final_verify_cmd:
                proc = subprocess.run(
                    final_verify_cmd,
                    shell=True,
                    cwd=str(self.repo_root),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=180,
                    check=False,
                )
                final_verify_ok = proc.returncode == 0
                final_verification = {
                    "command": final_verify_cmd,
                    "exit_code": proc.returncode,
                    "passed": final_verify_ok,
                    "output_tail": ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-2000:],
                }

            all_workers_ok = all(o.ok for o in ordered_outcomes)
            no_conflicts = len(conflict_branches) == 0
            return {
                "ok": all_workers_ok and no_conflicts and final_verify_ok,
                "repo_root": str(self.repo_root),
                "base_branch": self.manager.current_branch(),
                "workers_executed": len(ordered_outcomes),
                "workers_passed": sum(1 for o in ordered_outcomes if o.ok),
                "merged_branches": merged_branches,
                "conflict_branches": conflict_branches,
                "final_verification": final_verification,
                "total_tokens": sum(o.tokens_used for o in ordered_outcomes),
                "elapsed_s": round(time.perf_counter() - t0, 3),
                "workers": [asdict(o) for o in ordered_outcomes],
            }
        finally:
            for _, _, handle in handles:
                self.manager.cleanup_worktree(handle)
            self.manager.cleanup_empty_container()

    def _default_agent_loop_runner(
        self,
        spec: Dict[str, Any],
        wt_path: Path,
        *,
        role: str,
        verify_cmd: Optional[str],
    ) -> Dict[str, Any]:
        """Instantiate and run a real `AgentLoop` isolated to `wt_path`."""
        from am_ua.cognition.llm_client import LLMClient
        from am_ua.execution.agent_loop import AgentLoop
        from am_ua.execution.durable_engine import DurableExecutionEngine
        from am_ua.execution.subagent_bus import ROLE_PROVIDER_PROFILES
        from am_ua.governance.seal_guard import ConstitutionSealGuard

        import tempfile
        seal = self.seal_guard if self.seal_guard is not None else (
            ConstitutionSealGuard(wt_path)
            if (wt_path / "constitution" / "IMMUTABLE_CONSTITUTION.json").is_file()
            else ConstitutionSealGuard()
        )
        db_file = Path(tempfile.gettempdir()) / f"am_swarm_{uuid.uuid4().hex[:8]}.db"
        engine = DurableExecutionEngine(db_file)
        llm = self.llm or LLMClient()
        loop = AgentLoop(
            engine=engine,
            seal_guard=seal,
            llm=llm,
            memory_provider=self.memory_provider,
        )
        prof = ROLE_PROVIDER_PROFILES.get(role, {})
        prefer_prov = spec.get("provider")
        if not prefer_prov and prof.get("preferred_providers"):
            avail = set(llm.available())
            for cand in prof["preferred_providers"]:
                if cand in avail:
                    prefer_prov = cand
                    break

        try:
            res = loop.run(
                str(spec.get("objective") or ""),
                wt_path,
                verify_cmd=verify_cmd,
                max_turns=int(spec.get("max_turns", 15)),
                actor_provider=prefer_prov,
                role=role,
                workflow=str(spec.get("workflow", "react")),
                use_judge=bool(spec.get("use_judge", False)),
            )
            ok = bool(res.verification and res.verification.get("passed")) if verify_cmd else (
                res.status.startswith("VERIFIED") or res.stop_reason == "finish"
            )
            return {
                "ok": ok,
                "status": res.status,
                "tokens_used": int(res.tokens.get("prompt", 0) + res.tokens.get("completion", 0)),
                "summary": res.final_summary,
                "changed_files": res.changed_files,
            }
        finally:
            for ext in ("", "-wal", "-shm"):
                p = Path(str(db_file) + ext)
                if p.is_file():
                    try:
                        p.unlink()
                    except OSError:
                        pass
