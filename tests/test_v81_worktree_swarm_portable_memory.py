"""Empirical verification suite for OmniExecutor v8.1 (Fase 2):
  - Real Parallel `git worktree` Swarm (`GitWorktreeManager` + `WorktreeSwarmCoordinator`)
    executing real concurrent `AgentLoop` workers, committing branches, 3-way merging,
    verifying final acceptance command, and guaranteeing worktree/branch cleanup
  - 3-way conflict detection, safe `git merge --abort`, and callback conflict resolution
  - `SubAgentSessionBus.spawn_live_worker_fleet` persistence into SQLite WAL
  - Portable `NativeMSEAEngine` & `HybridVectorIndex` (SQLite FTS5 BM25 + dense cosine + RRF)
  - Live `TriadMemoryProvider` Turn-0 prefetch + Q-utility reinforcement inside `AgentLoop`
  - Zero-orphan module reachability audit (`67/67`) + `OMNI_TOPOLOGY_V2` compliance.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional

import pytest

from am_ua.cognition.llm_client import LLMResponse, ToolCall
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.subagent_bus import SubAgentSessionBus
from am_ua.execution.worktree_swarm import GitWorktreeManager, WorktreeSwarmCoordinator
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.memory.hybrid_vector_index import HybridVectorIndex, deterministic_embed
from am_ua.memory.msea_native import NativeMSEAEngine
from am_ua.memory.triad_provider import TriadMemoryProvider
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate


def _init_git_repo(repo_dir: Path) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    cmds = [
        ["git", "init"],
        ["git", "config", "user.name", "Test Operator"],
        ["git", "config", "user.email", "test@omni.local"],
    ]
    for c in cmds:
        proc = subprocess.run(c, cwd=str(repo_dir), capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stderr

    (repo_dir / "base.py").write_text("BASE = 10\n", encoding="utf-8", newline="\n")
    (repo_dir / "test_all.py").write_text(
        "import importlib\n"
        "def test_merged_modules():\n"
        "    a = importlib.import_module('feat_a')\n"
        "    b = importlib.import_module('feat_b')\n"
        "    assert a.val_a() + b.val_b() == 30\n",
        encoding="utf-8",
        newline="\n",
    )
    subprocess.run(["git", "add", "-A"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo_dir), check=True, capture_output=True)


def test_v81_real_parallel_git_worktree_swarm_with_agent_loops_and_3way_merge(tmp_path: Path) -> None:
    repo = tmp_path / "swarm_repo"
    _init_git_repo(repo)
    seal = ConstitutionSealGuard()

    class SwarmFakeLLM:
        """Thread-safe fake LLM producing distinct files per worker objective inside separate worktrees."""

        def __init__(self) -> None:
            self.calls = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["swarm_mock"]

        def chat(
            self,
            messages: List[Dict[str, Any]],
            *,
            max_tokens: int = 2048,
            temperature: Optional[float] = 0.2,
            json_mode: bool = False,
            prefer: Optional[str] = None,
            exclude: Optional[Any] = None,
            tools: Optional[List[Dict[str, Any]]] = None,
            tool_choice: Optional[Any] = None,
            enable_prompt_cache: bool = True,
            reasoning_effort: Optional[str] = None,
        ) -> LLMResponse:
            self.calls += 1
            self.total_prompt_tokens += 100
            self.total_completion_tokens += 30
            user_txt = "\n".join(str(m.get("content") or "") for m in messages if m.get("role") == "user")
            has_tool_res = any(m.get("role") == "tool" for m in messages)

            if not has_tool_res:
                if "feat_a" in user_txt:
                    return LLMResponse(
                        text="",
                        provider="swarm_mock",
                        model="mock-v81",
                        prompt_tokens=100,
                        completion_tokens=30,
                        latency_ms=2.0,
                        tool_calls=[
                            ToolCall(
                                id="tc_write_a",
                                name="write_file",
                                arguments={"path": "feat_a.py", "content": "def val_a() -> int:\n    return 12\n"},
                            )
                        ],
                    )
                return LLMResponse(
                    text="",
                    provider="swarm_mock",
                    model="mock-v81",
                    prompt_tokens=100,
                    completion_tokens=30,
                    latency_ms=2.0,
                    tool_calls=[
                        ToolCall(
                            id="tc_write_b",
                            name="write_file",
                            arguments={"path": "feat_b.py", "content": "def val_b() -> int:\n    return 18\n"},
                        )
                    ],
                )
            return LLMResponse(
                text="",
                provider="swarm_mock",
                model="mock-v81",
                prompt_tokens=80,
                completion_tokens=20,
                latency_ms=2.0,
                tool_calls=[ToolCall(id="tc_fin", name="finish", arguments={"summary": "Implemented feature.", "confidence": 1.0})],
            )

    bus = SubAgentSessionBus(tmp_path / "bus.db")
    tasks = [
        {"id": "worker_a", "role": "coder", "objective": "Create feat_a module returning 12", "max_turns": 4},
        {"id": "worker_b", "role": "coder", "objective": "Create feat_b module returning 18", "max_turns": 4},
    ]
    res = bus.spawn_live_worker_fleet(
        tasks,
        workspace=repo,
        max_workers=2,
        merge_results=True,
        final_verify_cmd=f'"{sys.executable}" -m pytest test_all.py -q',
        llm=SwarmFakeLLM(),
        seal_guard=seal,
    )

    assert res["ok"] is True, res
    assert res["workers_executed"] == 2
    assert res["workers_passed"] == 2
    assert len(res["merged_branches"]) == 2
    assert res["conflict_branches"] == []
    assert res["final_verification"]["passed"] is True
    assert (repo / "feat_a.py").is_file()
    assert (repo / "feat_b.py").is_file()

    # Worktrees and temporary branches must be cleanly removed
    wt_list = subprocess.run(["git", "-C", str(repo), "worktree", "list"], capture_output=True, text=True, check=True)
    assert len([ln for ln in wt_list.stdout.splitlines() if ln.strip()]) == 1
    assert not (repo / ".omni_worktrees").exists()

    # SubAgentSessionBus DB recorded both sessions
    sessions = bus.list_sessions(parent_id="worktree-swarm-coordinator")
    assert len(sessions) == 2
    assert all(s["status"] == "COMPLETED" for s in sessions)


def test_v81_git_worktree_3way_conflict_abort_and_resolution(tmp_path: Path) -> None:
    repo = tmp_path / "conflict_repo"
    _init_git_repo(repo)
    coord = WorktreeSwarmCoordinator(repo, max_workers=2)

    def conflict_worker(spec: Dict[str, Any], wt_path: Path) -> Dict[str, Any]:
        # Both workers intentionally modify line 1 of base.py to distinct values
        val = 100 if spec["id"] == "c1" else 200
        (wt_path / "base.py").write_text(f"BASE = {val}\n", encoding="utf-8", newline="\n")
        return {"ok": True, "status": "VERIFIED", "summary": f"Set BASE={val}", "changed_files": ["base.py"]}

    res_abort = coord.run_swarm(
        [{"id": "c1", "objective": "set 100"}, {"id": "c2", "objective": "set 200"}],
        worker_runner_fn=conflict_worker,
        merge_results=True,
    )
    assert res_abort["ok"] is False
    assert len(res_abort["merged_branches"]) == 1
    assert len(res_abort["conflict_branches"]) == 1
    assert "base.py" in res_abort["conflict_branches"][0]["conflicts"]
    # Repository must NOT be left in MERGE_HEAD dirty state after safe abort
    st = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True, check=True)
    assert st.stdout.strip() == ""

    # Now re-run conflict with an explicit resolver callback
    def resolver(root: Path, conflicts: List[str], branch: str) -> bool:
        (root / "base.py").write_text("BASE = 300\n", encoding="utf-8", newline="\n")
        return True

    res_resolved = coord.run_swarm(
        [{"id": "c3", "objective": "set 400"}],
        worker_runner_fn=lambda spec, wt: (
            (wt / "base.py").write_text("BASE = 400\n", encoding="utf-8", newline="\n")
            and None
            or {"ok": True, "status": "VERIFIED", "summary": "Set 400", "changed_files": ["base.py"]}
        ),
        merge_results=True,
        conflict_resolver_fn=resolver,
    )
    assert res_resolved["ok"] is True


def test_v81_hybrid_vector_index_rrf_and_namespace_isolation(tmp_path: Path) -> None:
    idx = HybridVectorIndex(tmp_path / "hybrid.db", dim=128)
    idx.add("SQLite WAL mode prevents lock contention in durable engine", namespace="proj_a", importance=0.9)
    idx.add("Playwright CDP indexed DOM browser supports self-healing selectors", namespace="proj_a", importance=0.8)
    idx.add("Secret Stripe token must never be queried by proj_a", namespace="proj_b", importance=0.95)

    hits_a = idx.query("SQLite WAL durable engine lock", namespace="proj_a", top_k=2)
    assert len(hits_a) == 2
    assert "SQLite WAL" in hits_a[0]["content"]
    assert hits_a[0]["bm25_rank"] == 1
    assert all(h["namespace"] == "proj_a" for h in hits_a)

    # Identical content embeddings must produce cosine ~ 1.0
    v1 = deterministic_embed("Hello AgentLoop v8.1", dim=128)
    v2 = deterministic_embed("Hello AgentLoop v8.1", dim=128)
    assert sum(a * b for a, b in zip(v1, v2)) == pytest.approx(1.0, abs=1e-4)


def test_v81_agent_loop_triad_memory_prefetch_and_q_reinforcement(tmp_path: Path) -> None:
    ws = tmp_path / "mem_ws"
    ws.mkdir()
    (ws / "config.py").write_text("TIMEOUT_S = 15\n", encoding="utf-8")

    triad = TriadMemoryProvider(tmp_path / "triad_data")
    assert triad.is_available() is True
    triad.initialize("sess-v81")
    fact = triad.record_verified_fact(
        "Project uses TIMEOUT_S = 30 for gateway resilience",
        fact_key="gateway.timeout_s",
        confidence=0.95,
    )
    atom_id = fact["msea_atom"]["id"]

    seen_user_prompts: List[str] = []

    class MemAwareFakeLLM:
        calls = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["mem_mock"]

        def chat(
            self,
            messages: List[Dict[str, Any]],
            *,
            max_tokens: int = 2048,
            temperature: Optional[float] = 0.2,
            json_mode: bool = False,
            prefer: Optional[str] = None,
            exclude: Optional[Any] = None,
            tools: Optional[List[Dict[str, Any]]] = None,
            tool_choice: Optional[Any] = None,
            enable_prompt_cache: bool = True,
            reasoning_effort: Optional[str] = None,
        ) -> LLMResponse:
            self.calls += 1
            if self.calls == 1:
                for m in messages:
                    if m.get("role") == "user":
                        seen_user_prompts.append(str(m.get("content") or ""))
                return LLMResponse(
                    text="",
                    provider="mem_mock",
                    model="mock-v81",
                    prompt_tokens=100,
                    completion_tokens=20,
                    latency_ms=2.0,
                    tool_calls=[
                        ToolCall(id="tc_fin", name="finish", arguments={"summary": "Verified timeout policy.", "confidence": 0.99})
                    ],
                )
            return LLMResponse(
                text="",
                provider="mem_mock",
                model="mock-v81",
                prompt_tokens=50,
                completion_tokens=10,
                latency_ms=1.0,
                tool_calls=[ToolCall(id="tc_fin2", name="finish", arguments={"summary": "Done.", "confidence": 1.0})],
            )

    engine = DurableExecutionEngine(tmp_path / "durable_mem.db")
    loop = AgentLoop(engine=engine, seal_guard=ConstitutionSealGuard(), llm=MemAwareFakeLLM(), memory_provider=triad)  # type: ignore[arg-type]
    res = loop.run(
        "Verify gateway resilience timeout setting",
        ws,
        verify_cmd=f'"{sys.executable}" -c "print(1)"',
        use_judge=False,
        enable_zero_token_offload=False,
    )

    assert res.status == "VERIFIED"
    assert any("<triad_memory_recall>" in p and "TIMEOUT_S = 30" in p for p in seen_user_prompts)
    # Verified run must reinforce recalled MSEA atom Q-value > 0
    atoms = {a["id"]: a for a in triad.msea.inspect_atoms(include_inactive=True)}
    assert atoms[atom_id]["qValue"] > 0.0
    assert triad.hybrid_index.count() >= 2


def test_v81_zero_orphan_modules_and_topology_v2_compliance() -> None:
    root = Path(__file__).resolve().parents[1]
    pkg = root / "src" / "am_ua"
    topo = InterRepoTopologyGate().audit_package_imports(pkg)
    assert topo["ok"] is True, f"Topology violations: {topo['violations']}"

    all_files: Dict[Path, str] = {}
    for p in pkg.rglob("*.py"):
        rel = p.relative_to(pkg.parent).with_suffix("").as_posix().replace("/", ".")
        if p.name == "__init__.py":
            rel = rel.rsplit(".__init__", 1)[0]
        all_files[p] = rel

    graph: Dict[str, set[str]] = {}
    for p, mod in all_files.items():
        is_pkg_init = p.name == "__init__.py"
        tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        imps: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imps.add(a.name)
            elif isinstance(node, ast.ImportFrom) and (node.module or node.level > 0):
                if node.level > 0:
                    parts = mod.split(".")
                    base_parts = parts if is_pkg_init else parts[:-1]
                    if node.level > 1:
                        base_parts = base_parts[: -(node.level - 1)]
                    full = ".".join(base_parts + ([node.module] if node.module else []))
                    imps.add(full)
                    for a in node.names:
                        imps.add(full + "." + a.name)
                else:
                    assert node.module is not None
                    imps.add(node.module)
                    for a in node.names:
                        imps.add(node.module + "." + a.name)
        graph[mod] = imps

    roots = ["am_ua", "am_ua.agent_kernel", "am_ua.cli", "am_ua.execution.agent_loop"]
    visited: set[str] = set()
    q = list(roots)
    all_mods = set(all_files.values())
    while q:
        cur = q.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        for target in graph.get(cur, ()):
            if target in all_mods and target not in visited:
                q.append(target)

    leaf_mods = {m for p, m in all_files.items() if p.name != "__init__.py"}
    orphans = sorted(leaf_mods - visited)
    assert orphans == [], f"Orphan modules detected outside reachable core graph: {orphans}"
