"""v5.0 Verification Suite: 7 Orthogonal Layers / 12 Extracted Missing Gears (E1-E12)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def test_v50_layer1_kernel_plan_act_todo_anchor_and_event_replay(tmp_path: Path) -> None:
    """E1 (Plan/Act Gate), E2 (todo.md Anchor), E3 (Deterministic EventStream Replay), E6 (Self-Review Diff Gate)."""
    from am_ua.execution.agent_loop import AgentLoop

    # E1: Plan vs Act mode gate
    AgentLoop.assert_tool_allowed_in_mode("read_file", mode="plan")
    AgentLoop.assert_tool_allowed_in_mode("write_file", mode="act")
    with pytest.raises(PermissionError):
        AgentLoop.assert_tool_allowed_in_mode("write_file", mode="plan")
    with pytest.raises(PermissionError):
        AgentLoop.assert_tool_allowed_in_mode("run", mode="plan")

    # E2: todo.md external plan anchor
    ws = tmp_path / "ws_kernel"
    ws.mkdir()
    todo_path = AgentLoop.sync_todo_anchor(
        ws,
        "Ship v5.0 orthogonal architecture",
        [
            {"id": "t1", "title": "Implement Plan/Act gate", "status": "done"},
            {"id": "t2", "title": "Verify diff gate", "status": "in_progress"},
        ],
    )
    txt = todo_path.read_text(encoding="utf-8")
    assert "- [x] `t1` Implement Plan/Act gate (done)" in txt
    assert "- [-] `t2` Verify diff gate (in_progress)" in txt

    # E3: Deterministic Action -> Observation EventStream replay
    ev_file = ws / "events.jsonl"
    AgentLoop.export_event_stream(
        [
            {"kind": "action", "tool": "read_file", "args": {"file": "app.py"}},
            {"kind": "observation", "tool": "read_file", "ok": True},
        ],
        ev_file,
    )
    rep = AgentLoop.replay_event_stream(ev_file)
    assert rep["ok"] is True and rep["event_count"] == 2 and rep["action_count"] == 1 and rep["observation_count"] == 1

    # E6: Self-Review Diff Gate (pass on valid code, fail on syntax error)
    (ws / "good.py").write_text("def ok() -> int:\n    return 42\n", encoding="utf-8")
    gate_ok = AgentLoop.run_self_review_diff_gate(ws)
    assert gate_ok["ok"] is True and gate_ok["syntax_ok"] is True and gate_ok["shield_grade"] == "A"

    (ws / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    gate_bad = AgentLoop.run_self_review_diff_gate(ws)
    assert gate_bad["ok"] is False and gate_bad["syntax_ok"] is False


def test_v50_layer2_and_layer3_dual_cognition_grounding_and_ledger_audit(tmp_path: Path) -> None:
    """E4 (System 1/2 Cognitive Split), E5 (Citation Grounding & Abstention), E7 (Rail 27 Double-Entry Ledger)."""
    from am_ua.execution.deterministic_offloader import BUILTIN_DETERMINISTIC_RAILS, DeterministicTaskOffloader
    from am_ua.routing.omni_router import classify_cognitive_system, verify_citation_grounding

    # E4: System 1 vs System 2
    s1 = classify_cognitive_system("rename variable foo to bar in utils.py", context_chars=500, risk_level="LOW")
    s2 = classify_cognitive_system(
        "architect distributed consensus kernel with Z3 formal proof and security audit",
        context_chars=30000,
        risk_level="CRITICAL",
    )
    assert s1.system == "SYSTEM_1" and s1.use_best_of_n is False
    assert s2.system == "SYSTEM_2" and s2.use_best_of_n is True

    # E5: Citation Grounding & Calibrated Abstention
    sources = {"doc1": "fastmft uses leaf-separated graph aggregation and Casimir potential well."}
    g_ok = verify_citation_grounding(["fastmft uses leaf-separated graph aggregation"], sources)
    assert g_ok["ok"] is True and g_ok["verdict"] == "GROUNDED"
    g_abstain = verify_citation_grounding(["quantum teleportation powers Mars rovers via dark matter"], sources)
    assert g_abstain["ok"] is False and g_abstain["verdict"] == "INSUFFICIENT_EVIDENCE"

    # E7: Rail 27 Double-Entry Ledger Audit (exact Decimal)
    assert "ledger_audit" in BUILTIN_DETERMINISTIC_RAILS
    assert len(BUILTIN_DETERMINISTIC_RAILS) >= 27

    balanced = DeterministicTaskOffloader.execute_rail(
        "ledger_audit",
        tmp_path,
        params={
            "entries": [
                {"tx_id": "J1", "account": "Cash", "debit": "100.10", "credit": "0"},
                {"tx_id": "J1", "account": "Revenue", "debit": "0", "credit": "100.10"},
                {"tx_id": "J2", "account": "Expense", "debit": "0.20", "credit": "0"},
                {"tx_id": "J2", "account": "Cash", "debit": "0", "credit": "0.20"},
            ]
        },
    )
    assert balanced["ok"] is True and balanced["balanced"] is True and balanced["net_delta"] == "0.00"
    assert balanced["account_balances"]["Cash"] == "99.90"

    unbalanced = DeterministicTaskOffloader.execute_rail(
        "ledger_audit",
        tmp_path,
        params={
            "entries": [
                {"tx_id": "J_BAD", "account": "Cash", "debit": "50.00", "credit": "0"},
                {"tx_id": "J_BAD", "account": "Revenue", "debit": "0", "credit": "49.99"},
            ]
        },
    )
    assert unbalanced["ok"] is False and unbalanced["balanced"] is False and len(unbalanced["unbalanced_transactions"]) == 1


def test_v50_layer4_and_layer5_worktree_bbon_merkle_acl(tmp_path: Path) -> None:
    """E8 (Parallel Git Worktree bBoN + Rollback), E9 (Merkle Incremental Index), E11 (ACL/RBAC Retrieval)."""
    from am_ua.execution.best_of_n import BehaviorBestOfNEngine
    from am_ua.perception.knowledge_index import HierarchicalKnowledgeIndex

    # E8: Parallel Git Worktree bBoN + atomic rollback
    repo = tmp_path / "git_bbon_repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@omni.local"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "OmniTest"], check=True, capture_output=True)
    (repo / "val.txt").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "val.txt"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)

    bbon = BehaviorBestOfNEngine(scratch_root=tmp_path / "bbon_scratch")

    def _runner(cand_ws: Path, idx: int) -> dict:
        (cand_ws / "val.txt").write_text(f"winner_{idx}\n", encoding="utf-8")
        return {
            "status": "VERIFIED" if idx == 2 else "FAILED",
            "verification": {"passed": idx == 2},
            "turns": idx,
            "changed_files": ["val.txt"],
            "diff": f"+winner_{idx}",
            "final_summary": f"cand {idx}",
        }

    res = bbon.run_code_best_of_n("Update val.txt", repo, _runner, n=2, parallel=True, use_git_worktree=True, use_llm_judge=False)
    assert res["used_git_worktree"] is True and res["parallel_execution"] is True
    assert res["winner_candidate_id"] == "cand_2" and res["rolled_back"] is False
    assert (repo / "val.txt").read_text(encoding="utf-8") == "winner_2\n"

    # Verify rollback when post_sync_verify_fn rejects
    res_rb = bbon.run_code_best_of_n(
        "Update with failing post-verify",
        repo,
        _runner,
        n=1,
        use_git_worktree=True,
        use_llm_judge=False,
        post_sync_verify_fn=lambda _: False,
    )
    assert res_rb["rolled_back"] is True and (repo / "val.txt").read_text(encoding="utf-8") == "winner_2\n"

    # E9 (Merkle Tree Incremental Index) + E11 (ACL/RBAC)
    k_root = tmp_path / "kb"
    (k_root / "public").mkdir(parents=True)
    (k_root / "finance").mkdir(parents=True)
    (k_root / "public" / "guide.md").write_text("# Public Guide\nAlpha beta gamma\n", encoding="utf-8")
    (k_root / "finance" / "payroll.md").write_text("# Payroll\nExecutive salary secret alpha\n", encoding="utf-8")

    kidx = HierarchicalKnowledgeIndex(k_root)
    root_hash_1 = kidx.merkle_root
    assert len(root_hash_1) == 64

    # ACL isolation
    kidx.set_acl_policy("finance", {"role:cfo", "scope:payroll"})
    pub_q = kidx.query("salary alpha", principal_scopes={"role:guest"})
    assert all("finance/" not in h["file"] for h in pub_q["hits"])
    assert pub_q["acl_filtered_nodes"] >= 1
    cfo_q = kidx.query("salary alpha", principal_scopes={"role:cfo"})
    assert any("finance/payroll.md" == h["file"] for h in cfo_q["hits"])

    # Merkle incremental sync
    (k_root / "public" / "guide.md").write_text("# Public Guide v2\nUpdated content delta\n", encoding="utf-8")
    sync_res = kidx.sync_incremental()
    assert sync_res["updated"] == ["public/guide.md"]
    assert sync_res["unchanged_count"] >= 1
    assert kidx.merkle_root != root_hash_1


def test_v50_layer6_and_layer7_skill_compiler_a2a_and_parallel_supervisor(tmp_path: Path) -> None:
    """E10 (Trajectory-to-Skill Compiler), E12a (A2A Protocol), E12b (Parallel Policy & DLP Supervisor)."""
    from am_ua.execution.a2a_protocol import AgentCard, OmniA2AServer
    from am_ua.execution.adaptive_skills import AdaptiveSkillForge
    from am_ua.execution.hook_engine import ParallelPolicySupervisor

    # E10: Trajectory-to-Skill Compiler (SOP Distillation)
    forge = AdaptiveSkillForge(skills_dir=tmp_path / "compiled_skills")
    compiled = forge.compile_trajectory_to_skill(
        name="deploy_preflight_sop",
        description="Compiled zero-token preflight SOP",
        trajectory_steps=[
            {"tool": "ast_syntax_sweep", "args": {"target": "src"}, "ok": True},
            {"tool": "shield_audit", "args": {"target": "."}, "ok": True},
        ],
    )
    assert compiled["ok"] is True and compiled["compiled_step_count"] == 2
    executed_calls = []

    def _fake_exec(tool: str, args: dict) -> dict:
        executed_calls.append((tool, args))
        return {"ok": True, "tool": tool}

    run_res = forge.run_skill("deploy_preflight_sop", kwargs={"executor": _fake_exec})
    assert run_res["ok"] is True and run_res["result"]["compiled_steps"] == 2
    assert [c[0] for c in executed_calls] == ["ast_syntax_sweep", "shield_audit"]

    # E12a: A2A Protocol (AgentCard + tasks/send + tasks/get + tasks/cancel)
    srv = OmniA2AServer(
        card=AgentCard(name="omni-executor", version="5.0.0"),
        task_handler=lambda skill_id, payload: {"ok": True, "skill": skill_id, "echo": payload.get("q")},
    )
    card_resp = srv.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "agent/card"})
    assert card_resp["result"]["name"] == "omni-executor" and card_resp["result"]["capabilities"]["opaqueArtifacts"] is True

    send_resp = srv.handle_rpc({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tasks/send",
        "params": {"id": "t-a2a-1", "skillId": "deterministic_rails", "input": {"q": "verify"}},
    })
    assert send_resp["result"]["state"] == "completed"
    assert send_resp["result"]["artifacts"][0]["data"]["echo"] == "verify"

    get_resp = srv.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "tasks/get", "params": {"id": "t-a2a-1"}})
    assert get_resp["result"]["task_id"] == "t-a2a-1"

    cancel_resp = srv.handle_rpc({"jsonrpc": "2.0", "id": 4, "method": "tasks/cancel", "params": {"id": "t-a2a-1"}})
    assert cancel_resp["result"]["state"] == "canceled"

    # E12b: Parallel Independent Policy & DLP Supervisor
    sup = ParallelPolicySupervisor(zero_retention=True, block_on_pii=True)
    sup.register_rule("no_prod_drop", lambda txt: "DROP TABLE forbidden" if "DROP TABLE" in txt.upper() else None)

    clean_v = sup.audit_parallel("All 27 deterministic rails passed verification.")
    assert clean_v.allowed is True and clean_v.zero_retention is True and not clean_v.pii_hits

    dirty_v = sup.audit_parallel("User CPF 123.456.789-00 ran DROP TABLE users;")
    assert dirty_v.allowed is False
    assert "brazilian_cpf" in dirty_v.pii_hits
    assert "[REDACTED_BRAZILIAN_CPF]" in dirty_v.redacted_text
    assert any("no_prod_drop" in r for r in dirty_v.veto_reasons)
