"""Verification suite for OmniExecutor v6.1 TLA+ Formal Contracts, Raft/Paxos Self-Healing & CPU Cache Hardware Telemetry (150 Rails)."""

from __future__ import annotations

from pathlib import Path

from am_ua.execution.cpu_cache_telemetry import (
    CPUCacheTopologyProbe,
    CacheLineFalseSharingAnalyzer,
    RooflineHardwareTelemetryModel,
    SetAssociativeCacheSimulator,
)
from am_ua.execution.deterministic_offloader import (
    BUILTIN_DETERMINISTIC_RAILS,
    DeterministicTaskOffloader,
)
from am_ua.execution.raft_paxos_healing import (
    DeterministicPaxosSynod,
    DeterministicRaftCluster,
    PhiAccrualSelfHealingSupervisor,
)
from am_ua.execution.tla_formal_verifier import (
    BoundedTLCModelChecker,
    HoareTripleContractVerifier,
    TLASpecTranspiler,
    TemporalLivenessAnalyzer,
)


def test_v61_150_deterministic_rails_registered_and_nl_triggers() -> None:
    """Verify exactly 150 deterministic rails are registered and Domain J keyword triggers match."""
    assert len(BUILTIN_DETERMINISTIC_RAILS) == 150
    assert len(DeterministicTaskOffloader.list_rails()) == 150

    assert DeterministicTaskOffloader.match_zero_token_rail("compile tla+ formal specification") == "tla_plus_spec_transpiler"
    assert DeterministicTaskOffloader.match_zero_token_rail("run tlc model check on state machine") == "tla_bounded_model_checker"
    assert DeterministicTaskOffloader.match_zero_token_rail("verify hoare triple contract") == "hoare_triple_contract_verifier"
    assert DeterministicTaskOffloader.match_zero_token_rail("simulate raft consensus leader election") == "raft_consensus_election_sim"
    assert DeterministicTaskOffloader.match_zero_token_rail("run paxos synod decree verification") == "paxos_synod_decree_verifier"
    assert DeterministicTaskOffloader.match_zero_token_rail("evaluate phi accrual failure detector") == "phi_accrual_cluster_healer"
    assert DeterministicTaskOffloader.match_zero_token_rail("probe cpu cache hierarchy") == "cpu_cache_hierarchy_probe"
    assert DeterministicTaskOffloader.match_zero_token_rail("audit struct for false sharing") == "cache_line_false_sharing_audit"
    assert DeterministicTaskOffloader.match_zero_token_rail("compute roofline arithmetic intensity") == "roofline_arithmetic_intensity"


def test_v61_tla_formal_verifier_four_organs() -> None:
    """Verify TLASpecTranspiler, BoundedTLCModelChecker (safety, counterexample trace, deadlock), HoareTripleContractVerifier, and TemporalLivenessAnalyzer."""
    # 1. TLASpecTranspiler
    spec_res = TLASpecTranspiler.generate_tla_module(
        "RaftLeaderSafety",
        variables=["role", "term", "committed"],
        init_predicates={"role": "FOLLOWER", "term": 0, "committed": False},
        transitions=[
            {
                "name": "BecomeLeader",
                "guard": {"var": "role", "op": "==", "val": "FOLLOWER"},
                "effects": {"role": "LEADER", "term": "+1"},
            },
            {
                "name": "CommitLog",
                "guard": {"var": "role", "op": "==", "val": "LEADER"},
                "effects": {"committed": True},
            },
        ],
        invariants=["TermMonotonic == term >= 0"],
        liveness_properties=["EventuallyCommitted == <>(committed = TRUE)"],
    )
    assert spec_res["ok"] is True
    assert "---- MODULE RaftLeaderSafety ----" in spec_res["tla_source"]
    assert "EXTENDS Naturals, Sequences, FiniteSets, TLC" in spec_res["tla_source"]
    assert "UNCHANGED <<committed>>" in spec_res["tla_source"]
    assert "THEOREM Spec => []TypeOK" in spec_res["tla_source"]
    assert "INVARIANT TypeOK" in spec_res["cfg_source"]
    assert "INVARIANT TermMonotonic" in spec_res["cfg_source"]
    assert "PROPERTY EventuallyCommitted" in spec_res["cfg_source"]

    # 2a. BoundedTLCModelChecker: valid state machine holds all invariants and is deadlock-free
    valid_mc = BoundedTLCModelChecker.verify_state_machine(
        {"state": "IDLE", "count": 0},
        [
            {
                "name": "Increment",
                "guard": {"var": "count", "op": "<", "val": 3},
                "effects": {"state": "BUSY", "count": "+1"},
            },
            {
                "name": "Reset",
                "guard": {"var": "count", "op": "==", "val": 3},
                "effects": {"state": "IDLE", "count": 0},
            },
        ],
        invariants=[{"name": "CountBounded", "condition": {"var": "count", "op": "<=", "val": 3}}],
    )
    assert valid_mc["ok"] is True
    assert valid_mc["invariants_held"] is True
    assert valid_mc["deadlock_free"] is True
    assert valid_mc["states_explored"] >= 4

    # 2b. BoundedTLCModelChecker: invariant violation produces shortest counterexample trace
    bad_mc = BoundedTLCModelChecker.verify_state_machine(
        {"n1": "FOLLOWER", "n2": "FOLLOWER"},
        [
            {
                "name": "ElectN1",
                "guard": {"var": "n1", "op": "==", "val": "FOLLOWER"},
                "effects": {"n1": "LEADER"},
            },
            {
                "name": "SplitBrainElectN2",
                "guard": {"var": "n2", "op": "==", "val": "FOLLOWER"},
                "effects": {"n2": "LEADER"},
            },
        ],
        invariants=[
            {
                "name": "NoTwoLeaders",
                "condition": {
                    "not_both": [
                        {"var": "n1", "op": "==", "val": "LEADER"},
                        {"var": "n2", "op": "==", "val": "LEADER"},
                    ]
                },
            }
        ],
    )
    assert bad_mc["ok"] is False
    assert bad_mc["invariants_held"] is False
    assert bad_mc["violated_invariant"] == "NoTwoLeaders"
    assert len(bad_mc["counterexample_trace"]) == 3
    assert bad_mc["counterexample_trace"][0]["action"] == "Init"
    assert bad_mc["counterexample_trace"][-1]["state"] == {"n1": "LEADER", "n2": "LEADER"}

    # 2c. BoundedTLCModelChecker: deadlock detection
    deadlock_mc = BoundedTLCModelChecker.verify_state_machine(
        {"phase": "START"},
        [
            {
                "name": "EnterStuckState",
                "guard": {"var": "phase", "op": "==", "val": "START"},
                "effects": {"phase": "STUCK"},
            }
        ],
        invariants=[{"name": "PhaseDefined", "condition": {"var": "phase", "op": "!=", "val": ""}}],
        check_deadlock=True,
    )
    assert deadlock_mc["ok"] is False
    assert deadlock_mc["invariants_held"] is True
    assert deadlock_mc["deadlock_free"] is False
    assert deadlock_mc["counterexample_trace"][-1]["state"]["phase"] == "STUCK"

    # 3. HoareTripleContractVerifier: {P} C {Q} + UNCHANGED <<vars>>
    hoare_ok = HoareTripleContractVerifier.verify_hoare_triple(
        {"balance": 200, "nonce": 1, "owner": "ruan"},
        {"balance": 350, "nonce": 2, "owner": "ruan"},
        precondition={"var": "balance", "op": ">=", "val": 100},
        postcondition={"var": "balance", "op": "==", "pre_delta": 150},
        unchanged_vars=["owner"],
    )
    assert hoare_ok["ok"] is True
    assert hoare_ok["frame_condition_met"] is True
    assert hoare_ok["violated_unchanged_vars"] == []

    hoare_bad_frame = HoareTripleContractVerifier.verify_hoare_triple(
        {"balance": 200, "owner": "ruan"},
        {"balance": 350, "owner": "intruder"},
        precondition={"var": "balance", "op": ">=", "val": 100},
        postcondition={"var": "balance", "op": ">=", "val": 200},
        unchanged_vars=["owner"],
    )
    assert hoare_bad_frame["ok"] is False
    assert hoare_bad_frame["frame_condition_met"] is False
    assert "owner" in hoare_bad_frame["violated_unchanged_vars"]

    # 4. TemporalLivenessAnalyzer: P ~> Q holds vs livelock cycle violation
    live_ok = TemporalLivenessAnalyzer.check_leads_to(
        [
            {"id": "S0", "status": "PENDING", "next": ["S1"]},
            {"id": "S1", "status": "VALIDATING", "next": ["S2"]},
            {"id": "S2", "status": "DONE", "next": ["S2"]},
        ],
        trigger_key="status",
        trigger_val="PENDING",
        goal_key="status",
        goal_val="DONE",
    )
    assert live_ok["ok"] is True and live_ok["leads_to_holds"] is True

    live_cycle = TemporalLivenessAnalyzer.check_leads_to(
        [
            {"id": "S0", "status": "PENDING", "next": ["S1"]},
            {"id": "S1", "status": "RETRY", "next": ["S0"]},
        ],
        trigger_key="status",
        trigger_val="PENDING",
        goal_key="status",
        goal_val="DONE",
    )
    assert live_cycle["ok"] is False
    assert live_cycle["leads_to_holds"] is False
    assert live_cycle["violation_type"] == "LIVELOCK_CYCLE"
    assert len(live_cycle["livelock_cycles"]) >= 1


def test_v61_raft_paxos_and_phi_accrual_self_healing_three_organs() -> None:
    """Verify DeterministicRaftCluster (split-brain healing), DeterministicPaxosSynod, and PhiAccrualSelfHealingSupervisor."""
    # 1. DeterministicRaftCluster: elect leader, replicate command, and heal split-brain partition
    cluster = DeterministicRaftCluster(node_ids=["n1", "n2", "n3", "n4", "n5"])
    el = cluster.elect_leader("n1")
    assert el["ok"] is True and el["elected"] is True and el["leader_id"] == "n1"
    assert el["quorum_size"] == 3 and el["votes_received"] == 5

    rep = cluster.replicate_command({"op": "write", "key": "k1", "val": "v1"})
    assert rep["ok"] is True and rep["committed"] is True and rep["commit_index"] == 1

    heal = cluster.simulate_partition_and_heal(
        ["n1", "n2"],
        new_leader_candidate="n3",
        heal_commands=[
            {"op": "write", "key": "k2", "val": "v2"},
            {"op": "write", "key": "k3", "val": "v3"},
        ],
    )
    assert heal["ok"] is True and heal["healed"] is True
    assert heal["old_leader_id"] == "n1"
    assert heal["old_leader_stepped_down"] is True
    assert cluster.nodes["n1"].role == "FOLLOWER"
    assert heal["new_leader_id"] == "n3"
    assert heal["commit_index"] == 3
    assert heal["log_sha256_verified"] is True

    # 2. DeterministicPaxosSynod: competing proposers adopt highest-numbered promised value
    synod = DeterministicPaxosSynod.run_synod_consensus(
        5,
        [
            {"proposer_id": "p1", "proposal_number": 10, "value": "config_alpha"},
            {"proposer_id": "p2", "proposal_number": 20, "value": "config_beta"},
        ],
        failed_acceptors=[4],
    )
    assert synod["ok"] is True and synod["consensus_reached"] is True
    assert synod["safety_invariant_holds"] is True
    assert synod["chosen_value"] == "config_alpha"
    assert synod["distinct_chosen_values"] == ["config_alpha"]
    assert synod["rounds"][1]["phase2a_accept"]["adopted_prior_value"] is True

    # 3. PhiAccrualSelfHealingSupervisor: healthy vs conviction failover + Byzantine divergence
    intervals = [100.0, 101.0, 99.0, 100.5, 99.5, 100.0, 102.0, 98.0]
    healthy = PhiAccrualSelfHealingSupervisor.evaluate_cluster_health(
        intervals,
        elapsed_since_last_ms=101.0,
        phi_threshold=8.0,
    )
    assert healthy["ok"] is True and healthy["status"] == "HEALTHY"

    failover = PhiAccrualSelfHealingSupervisor.evaluate_cluster_health(
        intervals,
        elapsed_since_last_ms=250.0,
        phi_threshold=8.0,
        node_states={
            "n1": {"state_hash": "aaa111"},
            "n2": {"state_hash": "aaa111"},
            "n3": {"state_hash": "aaa111"},
            "n4": {"state_hash": "corrupted_999"},
        },
    )
    assert failover["ok"] is True
    assert failover["status"] == "CONVICTION_FAILOVER"
    assert failover["phi"] >= 8.0
    assert failover["byzantine_divergence_detected"] is True
    assert "n4" in failover["byzantine_nodes"]
    assert "quarantine_byzantine_node" in failover["healing_actions"]
    assert "trigger_raft_election" in failover["healing_actions"]
    assert "rebalance_shards" in failover["healing_actions"]


def test_v61_cpu_cache_telemetry_four_organs() -> None:
    """Verify CPUCacheTopologyProbe, CacheLineFalseSharingAnalyzer, SetAssociativeCacheSimulator, and RooflineHardwareTelemetryModel."""
    # 1. CPUCacheTopologyProbe
    topo = CPUCacheTopologyProbe.probe_hierarchy(l1d_kb=32, l2_kb=512, l3_kb=16384, cache_line_bytes=64)
    assert topo["ok"] is True
    assert topo["cache_line_bytes"] == 64
    assert topo["fp64_elements_per_cache_line"] == 8
    assert topo["l1d_cache_lines"] == 512
    assert topo["optimal_fp64_tile_block_dim"] == 36

    # 2. CacheLineFalseSharingAnalyzer: 64-byte false sharing detection & alignas(64) padding synthesis
    fs_res = CacheLineFalseSharingAnalyzer.analyze_struct_layout(
        [
            {"name": "producer_seq", "size_bytes": 8, "writer_thread": "producer_thread"},
            {"name": "consumer_seq", "size_bytes": 8, "writer_thread": "consumer_thread"},
            {"name": "cross_line_buf", "size_bytes": 64, "writer_thread": "producer_thread"},
        ],
        cache_line_bytes=64,
    )
    assert fs_res["ok"] is True
    assert fs_res["false_sharing_detected"] is True
    assert fs_res["collision_count"] >= 1
    assert fs_res["straddling_count"] >= 1
    assert fs_res["padding_bytes_inserted"] > 0
    assert any("alignas(64)" in d for d in fs_res["alignas_64_directives"])

    # 3. SetAssociativeCacheSimulator: 8-way set-associative LRU hit/miss simulation
    # Sequential 8-byte FP64 accesses across 16 cache lines repeated twice
    trace = [i * 8 for i in range(128)] + [i * 8 for i in range(128)]
    sim = SetAssociativeCacheSimulator.simulate_access_trace(
        trace,
        cache_size_bytes=32768,
        line_size_bytes=64,
        associativity=8,
    )
    assert sim["ok"] is True
    assert sim["total_accesses"] == 256
    assert sim["compulsory_misses"] == 16
    assert sim["capacity_or_conflict_misses"] == 0
    assert sim["hits"] == 240
    assert sim["hit_rate_pct"] == 93.75
    assert sim["amat_cycles"] < 10.0

    # 4. RooflineHardwareTelemetryModel: memory-bound vs compute-bound classification
    mem_bound = RooflineHardwareTelemetryModel.evaluate_kernel(
        flops=1_000_000_000,
        bytes_transferred=1_000_000_000,
        elapsed_s=0.05,
        peak_gflops=512.0,
        peak_bandwidth_gbps=64.0,
    )
    assert mem_bound["ok"] is True
    assert mem_bound["arithmetic_intensity_flops_per_byte"] == 1.0
    assert mem_bound["ridge_point_flops_per_byte"] == 8.0
    assert mem_bound["bottleneck_regime"] == "MEMORY_BANDWIDTH_BOUND"
    assert mem_bound["attainable_gflops"] == 64.0

    comp_bound = RooflineHardwareTelemetryModel.evaluate_kernel(
        flops=16_000_000_000,
        bytes_transferred=1_000_000_000,
        elapsed_s=0.04,
        peak_gflops=512.0,
        peak_bandwidth_gbps=64.0,
    )
    assert comp_bound["ok"] is True
    assert comp_bound["arithmetic_intensity_flops_per_byte"] == 16.0
    assert comp_bound["bottleneck_regime"] == "COMPUTE_BOUND"
    assert comp_bound["attainable_gflops"] == 512.0


def test_v61_execute_all_15_new_rails_via_offloader(tmp_path: Path) -> None:
    """Execute Rails 136 through 150 through DeterministicTaskOffloader.execute_rail."""
    # Rail 136: tla_plus_spec_transpiler
    r136 = DeterministicTaskOffloader.execute_rail("tla_plus_spec_transpiler", tmp_path)
    assert r136["ok"] is True and "---- MODULE " in r136["tla_source"]

    # Rail 137: tla_bounded_model_checker
    r137 = DeterministicTaskOffloader.execute_rail("tla_bounded_model_checker", tmp_path)
    assert r137["ok"] is True and r137["invariants_held"] is True and r137["deadlock_free"] is True

    # Rail 138: hoare_triple_contract_verifier
    r138 = DeterministicTaskOffloader.execute_rail("hoare_triple_contract_verifier", tmp_path)
    assert r138["ok"] is True and r138["frame_condition_met"] is True

    # Rail 139: temporal_liveness_leads_to
    r139 = DeterministicTaskOffloader.execute_rail("temporal_liveness_leads_to", tmp_path)
    assert r139["ok"] is True and r139["leads_to_holds"] is True

    # Rail 140: raft_consensus_election_sim
    r140 = DeterministicTaskOffloader.execute_rail("raft_consensus_election_sim", tmp_path)
    assert r140["ok"] is True and r140["commit_index"] >= 1

    # Rail 141: raft_partition_self_healer
    r141 = DeterministicTaskOffloader.execute_rail("raft_partition_self_healer", tmp_path)
    assert r141["ok"] is True and r141["old_leader_stepped_down"] is True and r141["log_sha256_verified"] is True

    # Rail 142: paxos_synod_decree_verifier
    r142 = DeterministicTaskOffloader.execute_rail("paxos_synod_decree_verifier", tmp_path)
    assert r142["ok"] is True and r142["consensus_reached"] is True and r142["safety_invariant_holds"] is True

    # Rail 143: phi_accrual_cluster_healer
    r143 = DeterministicTaskOffloader.execute_rail(
        "phi_accrual_cluster_healer",
        tmp_path,
        params={"elapsed_since_last_ms": 220.0, "phi_threshold": 8.0},
    )
    assert r143["ok"] is True and r143["status"] == "CONVICTION_FAILOVER"

    # Rail 144: cpu_cache_hierarchy_probe
    r144 = DeterministicTaskOffloader.execute_rail("cpu_cache_hierarchy_probe", tmp_path)
    assert r144["ok"] is True and r144["optimal_fp64_tile_block_dim"] == 36

    # Rail 145: cache_line_false_sharing_audit
    r145 = DeterministicTaskOffloader.execute_rail("cache_line_false_sharing_audit", tmp_path)
    assert r145["ok"] is True and r145["false_sharing_detected"] is True and r145["padding_bytes_inserted"] > 0

    # Rail 146: set_associative_cache_simulator
    r146 = DeterministicTaskOffloader.execute_rail("set_associative_cache_simulator", tmp_path)
    assert r146["ok"] is True and r146["hit_rate_pct"] > 80.0

    # Rail 147: roofline_arithmetic_intensity
    r147 = DeterministicTaskOffloader.execute_rail("roofline_arithmetic_intensity", tmp_path)
    assert r147["ok"] is True and r147["bottleneck_regime"] in ("MEMORY_BANDWIDTH_BOUND", "COMPUTE_BOUND")

    # Rail 148: loop_tiling_cache_optimizer
    r148 = DeterministicTaskOffloader.execute_rail("loop_tiling_cache_optimizer", tmp_path)
    assert r148["ok"] is True
    assert r148["l1_tile_block_dim"] == 36
    assert r148["expected_miss_reduction_pct"] > 50.0
    assert r148["simulated_tiled_hit_rate_pct"] > r148["simulated_naive_hit_rate_pct"]

    # Rail 149: distributed_contract_safety_gate
    r149 = DeterministicTaskOffloader.execute_rail("distributed_contract_safety_gate", tmp_path)
    assert r149["ok"] is True
    assert r149["tla_model_check"]["ok"] is True
    assert r149["raft_quorum_verification"]["ok"] is True

    # Rail 150: omega_150_supreme_frontier_sweep
    r150 = DeterministicTaskOffloader.execute_rail("omega_150_supreme_frontier_sweep", tmp_path)
    assert r150["ok"] is True
    assert r150["version"] == "6.1.0"
    assert r150["total_deterministic_rails"] == 150
    assert r150["tla_bounded_model_check"]["ok"] is True
    assert r150["raft_partition_self_healing"]["ok"] is True
    assert r150["cpu_cache_hierarchy"]["ok"] is True
    assert r150["false_sharing_audit"]["false_sharing_detected"] is True
    assert r150["roofline_telemetry"]["ok"] is True
