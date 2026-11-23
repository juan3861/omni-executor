from __future__ import annotations

import ast
import base64
import csv
from decimal import Decimal, InvalidOperation
import difflib
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import xml.etree.ElementTree as ET
import zipfile

_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    "vendor",
    "HANDOFF_PACK",
}


from am_ua.execution.matrix_rails_helpers import _WORKSPACE_SNAPSHOT_GUARDS, _iter_py, _safe_path

def execute_tla_raft_cpu(
    rail_name: str,
    ws: Path,
    target: str,
    args: Dict[str, Any],
    execute_rail_fn: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    # --- DOMAIN J: TLA+ FORMAL CONTRACTS, RAFT/PAXOS SELF-HEALING & CPU CACHE TELEMETRY (136-150) ---
    if rail_name == "tla_plus_spec_transpiler":
        from am_ua.execution.tla_formal_verifier import TLASpecTranspiler

        mod_name = str(args.get("module_name") or "OmniConsensusContract")
        variables = list(args.get("variables") or ["state", "term", "committed"])
        init_preds = dict(
            args.get("init_predicates") or {"state": "FOLLOWER", "term": 0, "committed": False}
        )
        transitions = list(
            args.get("transitions")
            or [
                {
                    "name": "ElectLeader",
                    "guard": {"var": "state", "op": "==", "val": "FOLLOWER"},
                    "effects": {"state": "LEADER", "term": "+1"},
                },
                {
                    "name": "CommitEntry",
                    "guard": {"var": "state", "op": "==", "val": "LEADER"},
                    "effects": {"committed": True},
                },
            ]
        )
        invariants = list(args.get("invariants") or ["TermNonNegative == term >= 0"])
        liveness = args.get("liveness_properties")
        return {
            "rail": rail_name,
            **TLASpecTranspiler.generate_tla_module(
                mod_name,
                variables=variables,
                init_predicates=init_preds,
                transitions=transitions,
                invariants=invariants,
                liveness_properties=liveness,
            ),
        }

    if rail_name == "tla_bounded_model_checker":
        from am_ua.execution.tla_formal_verifier import BoundedTLCModelChecker

        init_state = dict(
            args.get("initial_state") or {"state": "IDLE", "counter": 0}
        )
        transitions = list(
            args.get("transitions")
            or [
                {
                    "name": "Start",
                    "guard": [
                        {"var": "state", "op": "==", "val": "IDLE"},
                        {"var": "counter", "op": "<", "val": 10},
                    ],
                    "effects": {"state": "ACTIVE", "counter": "+1"},
                },
                {
                    "name": "Complete",
                    "guard": {"var": "state", "op": "==", "val": "ACTIVE"},
                    "effects": {"state": "IDLE"},
                },
                {
                    "name": "Reset",
                    "guard": [
                        {"var": "state", "op": "==", "val": "IDLE"},
                        {"var": "counter", "op": "==", "val": 10},
                    ],
                    "effects": {"counter": 0},
                },
            ]
        )
        invariants = list(
            args.get("invariants")
            or [
                {
                    "name": "CounterBounded",
                    "condition": {"var": "counter", "op": "<=", "val": 10},
                }
            ]
        )
        return {
            "rail": rail_name,
            **BoundedTLCModelChecker.verify_state_machine(
                init_state,
                transitions,
                invariants=invariants,
                max_states=int(args.get("max_states", 2000)),
                check_deadlock=bool(args.get("check_deadlock", True)),
                terminal_states=args.get("terminal_states"),
            ),
        }

    if rail_name == "hoare_triple_contract_verifier":
        from am_ua.execution.tla_formal_verifier import HoareTripleContractVerifier

        pre_state = dict(
            args.get("pre_state") or {"balance": 100, "tx_count": 1, "owner": "alice"}
        )
        post_state = dict(
            args.get("post_state") or {"balance": 150, "tx_count": 2, "owner": "alice"}
        )
        precond = dict(
            args.get("precondition") or {"var": "balance", "op": ">=", "val": 0}
        )
        postcond = dict(
            args.get("postcondition") or {"var": "balance", "op": ">=", "val": 100}
        )
        unchanged = args.get("unchanged_vars")
        if unchanged is None and "pre_state" not in args:
            unchanged = ["owner"]
        return {
            "rail": rail_name,
            **HoareTripleContractVerifier.verify_hoare_triple(
                pre_state,
                post_state,
                precondition=precond,
                postcondition=postcond,
                unchanged_vars=unchanged,
            ),
        }

    if rail_name == "temporal_liveness_leads_to":
        from am_ua.execution.tla_formal_verifier import TemporalLivenessAnalyzer

        state_graph = list(
            args.get("state_graph")
            or [
                {"id": "S0", "phase": "REQUESTED", "next": ["S1"]},
                {"id": "S1", "phase": "PROCESSING", "next": ["S2"]},
                {"id": "S2", "phase": "COMMITTED", "next": ["S2"]},
            ]
        )
        return {
            "rail": rail_name,
            **TemporalLivenessAnalyzer.check_leads_to(
                state_graph,
                trigger_key=str(args.get("trigger_key") or "phase"),
                trigger_val=args.get("trigger_val", "REQUESTED"),
                goal_key=str(args.get("goal_key") or "phase"),
                goal_val=args.get("goal_val", "COMMITTED"),
            ),
        }

    if rail_name == "raft_consensus_election_sim":
        from am_ua.execution.raft_paxos_healing import DeterministicRaftCluster

        node_ids = list(
            args.get("node_ids") or ["node-1", "node-2", "node-3", "node-4", "node-5"]
        )
        candidate_id = str(args.get("candidate_id") or node_ids[0])
        cluster = DeterministicRaftCluster(node_ids=node_ids)
        election = cluster.elect_leader(candidate_id)
        commands = list(args.get("commands") or [])
        if not commands and args.get("command") is not None:
            commands = [dict(args["command"])]
        if not commands:
            commands = [{"op": "set", "key": "epoch", "val": 1}]
        replications = [cluster.replicate_command(cmd) for cmd in commands]
        last_rep = replications[-1] if replications else {}
        return {
            "ok": bool(election.get("elected") and all(r.get("committed") for r in replications)),
            "rail": rail_name,
            "leader_id": cluster.leader_id,
            "current_term": cluster.current_term,
            "commit_index": cluster.commit_index,
            "quorum_size": cluster.quorum_size,
            "election": election,
            "replication": last_rep,
            "replications": replications,
        }

    if rail_name == "raft_partition_self_healer":
        from am_ua.execution.raft_paxos_healing import DeterministicRaftCluster

        node_ids = list(
            args.get("node_ids") or ["node-1", "node-2", "node-3", "node-4", "node-5"]
        )
        initial_leader = str(args.get("initial_leader") or node_ids[0])
        isolated = list(args.get("isolated_nodes") or [initial_leader, node_ids[1]])
        new_candidate = str(args.get("new_leader_candidate") or node_ids[2])
        heal_cmds = list(
            args.get("heal_commands")
            or [{"op": "quorum_heal_write", "epoch": 2}]
        )
        cluster = DeterministicRaftCluster(node_ids=node_ids)
        cluster.elect_leader(initial_leader)
        cluster.replicate_command({"op": "genesis", "epoch": 1})
        res = cluster.simulate_partition_and_heal(
            isolated,
            new_leader_candidate=new_candidate,
            heal_commands=heal_cmds,
        )
        return {"rail": rail_name, **res}

    if rail_name == "paxos_synod_decree_verifier":
        from am_ua.execution.raft_paxos_healing import DeterministicPaxosSynod

        num_acc = int(args.get("num_acceptors", 5))
        proposals = list(
            args.get("proposals")
            or [
                {"proposer_id": "proposer-1", "proposal_number": 1, "value": "decree-v1"},
                {"proposer_id": "proposer-2", "proposal_number": 2, "value": "decree-v2"},
            ]
        )
        failed_acc = args.get("failed_acceptors")
        return {
            "rail": rail_name,
            **DeterministicPaxosSynod.run_synod_consensus(
                num_acc,
                proposals,
                failed_acceptors=failed_acc,
            ),
        }

    if rail_name == "phi_accrual_cluster_healer":
        from am_ua.execution.raft_paxos_healing import PhiAccrualSelfHealingSupervisor

        intervals = list(
            args.get("heartbeat_intervals_ms")
            or [100.0, 102.0, 98.0, 101.0, 99.0, 100.0, 103.0, 97.0]
        )
        elapsed_ms = float(args.get("elapsed_since_last_ms", 125.0))
        phi_thresh = float(args.get("phi_threshold", 8.0))
        node_states = args.get("node_states")
        return {
            "rail": rail_name,
            **PhiAccrualSelfHealingSupervisor.evaluate_cluster_health(
                intervals,
                elapsed_since_last_ms=elapsed_ms,
                phi_threshold=phi_thresh,
                node_states=node_states,
            ),
        }

    if rail_name == "cpu_cache_hierarchy_probe":
        from am_ua.execution.cpu_cache_telemetry import CPUCacheTopologyProbe

        return {
            "rail": rail_name,
            **CPUCacheTopologyProbe.probe_hierarchy(
                l1d_kb=int(args.get("l1d_kb", 32)),
                l2_kb=int(args.get("l2_kb", 512)),
                l3_kb=int(args.get("l3_kb", 16384)),
                cache_line_bytes=int(args.get("cache_line_bytes", 64)),
            ),
        }

    if rail_name == "cache_line_false_sharing_audit":
        from am_ua.execution.cpu_cache_telemetry import CacheLineFalseSharingAnalyzer

        fields = list(
            args.get("fields")
            or [
                {"name": "worker_a_counter", "size_bytes": 8, "writer_thread": "thread_0"},
                {"name": "worker_b_counter", "size_bytes": 8, "writer_thread": "thread_1"},
                {"name": "readonly_config", "size_bytes": 16, "writer_thread": None},
            ]
        )
        return {
            "rail": rail_name,
            **CacheLineFalseSharingAnalyzer.analyze_struct_layout(
                fields,
                cache_line_bytes=int(args.get("cache_line_bytes", 64)),
            ),
        }

    if rail_name == "set_associative_cache_simulator":
        from am_ua.execution.cpu_cache_telemetry import SetAssociativeCacheSimulator

        addresses = list(
            args.get("addresses")
            or [i * 8 for i in range(64)] + [i * 8 for i in range(64)]
        )
        return {
            "rail": rail_name,
            **SetAssociativeCacheSimulator.simulate_access_trace(
                addresses,
                cache_size_bytes=int(args.get("cache_size_bytes", 32768)),
                line_size_bytes=int(args.get("line_size_bytes", 64)),
                associativity=int(args.get("associativity", 8)),
            ),
        }

    if rail_name == "roofline_arithmetic_intensity":
        from am_ua.execution.cpu_cache_telemetry import RooflineHardwareTelemetryModel

        return {
            "rail": rail_name,
            **RooflineHardwareTelemetryModel.evaluate_kernel(
                flops=int(args.get("flops", 2_000_000_000)),
                bytes_transferred=int(args.get("bytes_transferred", 1_000_000_000)),
                elapsed_s=float(args.get("elapsed_s", 0.02)),
                peak_gflops=float(args.get("peak_gflops", 512.0)),
                peak_bandwidth_gbps=float(args.get("peak_bandwidth_gbps", 64.0)),
            ),
        }

    if rail_name == "loop_tiling_cache_optimizer":
        from am_ua.execution.cpu_cache_telemetry import (
            CPUCacheTopologyProbe,
            SetAssociativeCacheSimulator,
        )

        l1d_kb = int(args.get("l1d_kb", 32))
        l2_kb = int(args.get("l2_kb", 512))
        line_bytes = int(args.get("cache_line_bytes", 64))
        matrix_n = int(args.get("matrix_n", 64))
        plan = CPUCacheTopologyProbe.compute_loop_tiling_plan(
            matrix_n=matrix_n,
            l1d_kb=l1d_kb,
            l2_kb=l2_kb,
            cache_line_bytes=line_bytes,
        )
        tile_b = int(plan["l1_tile_block_dim"])
        # Simulate a small cache comparing large-stride column access vs contiguous tiled block access
        sim_cache_bytes = int(args.get("sim_cache_size_bytes", 1024))
        naive_trace: List[int] = []
        for rep in range(4):
            for row in range(32):
                naive_trace.append((row * 64) % 4096)
        tiled_trace: List[int] = []
        for rep in range(4):
            for elem in range(32):
                tiled_trace.append((elem * 8) % 256)
        naive_sim = SetAssociativeCacheSimulator.simulate_access_trace(
            naive_trace,
            cache_size_bytes=sim_cache_bytes,
            line_size_bytes=line_bytes,
            associativity=4,
        )
        tiled_sim = SetAssociativeCacheSimulator.simulate_access_trace(
            tiled_trace,
            cache_size_bytes=sim_cache_bytes,
            line_size_bytes=line_bytes,
            associativity=4,
        )
        sim_miss_reduction = round(
            max(0.0, float(naive_sim["miss_rate_pct"]) - float(tiled_sim["miss_rate_pct"])),
            4,
        )
        return {
            "ok": True,
            "rail": rail_name,
            "l1_tile_block_dim": tile_b,
            "l2_tile_block_dim": int(plan["l2_tile_block_dim"]),
            "expected_miss_reduction_pct": float(plan["expected_miss_reduction_pct"]),
            "simulated_naive_hit_rate_pct": float(naive_sim["hit_rate_pct"]),
            "simulated_tiled_hit_rate_pct": float(tiled_sim["hit_rate_pct"]),
            "simulated_miss_rate_reduction_pct": sim_miss_reduction,
            "tiling_plan": plan,
            "naive_simulation": naive_sim,
            "tiled_simulation": tiled_sim,
        }

    if rail_name == "distributed_contract_safety_gate":
        from am_ua.execution.raft_paxos_healing import DeterministicRaftCluster
        from am_ua.execution.tla_formal_verifier import BoundedTLCModelChecker

        tla_init = dict(
            args.get("initial_state")
            or {"n1": "FOLLOWER", "n2": "FOLLOWER", "term": 0}
        )
        tla_transitions = list(
            args.get("transitions")
            or [
                {
                    "name": "ElectN1",
                    "guard": [
                        {"var": "n1", "op": "==", "val": "FOLLOWER"},
                        {"var": "n2", "op": "!=", "val": "LEADER"},
                    ],
                    "effects": {"n1": "LEADER", "term": "+1"},
                },
                {
                    "name": "StepDownN1",
                    "guard": {"var": "n1", "op": "==", "val": "LEADER"},
                    "effects": {"n1": "FOLLOWER"},
                },
            ]
        )
        tla_invariants = list(
            args.get("invariants")
            or [
                {
                    "name": "SingleLeaderPerTerm",
                    "condition": {
                        "not_both": [
                            {"var": "n1", "op": "==", "val": "LEADER"},
                            {"var": "n2", "op": "==", "val": "LEADER"},
                        ]
                    },
                }
            ]
        )
        tla_res = BoundedTLCModelChecker.verify_state_machine(
            tla_init,
            tla_transitions,
            invariants=tla_invariants,
            max_states=int(args.get("max_states", 500)),
        )
        node_ids = list(
            args.get("node_ids") or ["node-1", "node-2", "node-3", "node-4", "node-5"]
        )
        raft = DeterministicRaftCluster(node_ids=node_ids)
        elect_res = raft.elect_leader(node_ids[0])
        rep_res = raft.replicate_command({"op": "safety_gate_barrier", "term": 1})
        overall_ok = bool(
            tla_res.get("ok")
            and elect_res.get("elected")
            and rep_res.get("committed")
        )
        return {
            "ok": overall_ok,
            "rail": rail_name,
            "tla_model_check": tla_res,
            "raft_quorum_verification": {
                "ok": bool(elect_res.get("elected") and rep_res.get("committed")),
                "leader_id": raft.leader_id,
                "quorum_size": raft.quorum_size,
                "commit_index": raft.commit_index,
                "log_sha256": rep_res.get("sha256"),
            },
        }

    if rail_name == "omega_150_supreme_frontier_sweep":
        from am_ua.execution.cpu_cache_telemetry import (
            CPUCacheTopologyProbe,
            CacheLineFalseSharingAnalyzer,
            RooflineHardwareTelemetryModel,
        )
        from am_ua.execution.raft_paxos_healing import DeterministicRaftCluster
        from am_ua.execution.tla_formal_verifier import BoundedTLCModelChecker

        tla_check = BoundedTLCModelChecker.verify_state_machine(
            {"leader_count": 0, "epoch": 0},
            [
                {
                    "name": "AcquireLeadership",
                    "guard": {"var": "leader_count", "op": "==", "val": 0},
                    "effects": {"leader_count": 1, "epoch": "+1"},
                },
                {
                    "name": "ReleaseLeadership",
                    "guard": {"var": "leader_count", "op": "==", "val": 1},
                    "effects": {"leader_count": 0},
                },
            ],
            invariants=[
                {
                    "name": "AtMostOneLeader",
                    "condition": {"var": "leader_count", "op": "<=", "val": 1},
                }
            ],
            max_states=200,
        )
        raft_cluster = DeterministicRaftCluster(
            node_ids=("node-1", "node-2", "node-3", "node-4", "node-5")
        )
        raft_cluster.elect_leader("node-1")
        raft_cluster.replicate_command({"op": "init_state", "v": 1})
        raft_heal = raft_cluster.simulate_partition_and_heal(
            ["node-1", "node-2"],
            new_leader_candidate="node-3",
            heal_commands=[{"op": "quorum_commit", "v": 2}],
        )
        cache_probe = CPUCacheTopologyProbe.probe_hierarchy()
        false_sharing = CacheLineFalseSharingAnalyzer.analyze_struct_layout(
            [
                {"name": "t0_hot_counter", "size_bytes": 8, "writer_thread": "t0"},
                {"name": "t1_hot_counter", "size_bytes": 8, "writer_thread": "t1"},
            ]
        )
        roofline = RooflineHardwareTelemetryModel.evaluate_kernel(
            flops=4_000_000_000,
            bytes_transferred=250_000_000,
            elapsed_s=0.01,
            peak_gflops=512.0,
            peak_bandwidth_gbps=64.0,
        )
        overall_ok = bool(
            tla_check.get("ok")
            and raft_heal.get("ok")
            and cache_probe.get("ok")
            and false_sharing.get("ok")
            and roofline.get("ok")
        )
        return {
            "ok": overall_ok,
            "rail": rail_name,
            "version": "6.1.0",
            "total_deterministic_rails": 150,
            "tla_bounded_model_check": tla_check,
            "raft_partition_self_healing": {
                "ok": raft_heal.get("ok"),
                "old_leader_stepped_down": raft_heal.get("old_leader_stepped_down"),
                "new_leader_id": raft_heal.get("new_leader_id"),
                "commit_index": raft_heal.get("commit_index"),
                "log_sha256_verified": raft_heal.get("log_sha256_verified"),
            },
            "cpu_cache_hierarchy": {
                "ok": cache_probe.get("ok"),
                "cache_line_bytes": cache_probe.get("cache_line_bytes"),
                "optimal_fp64_tile_block_dim": cache_probe.get("optimal_fp64_tile_block_dim"),
            },
            "false_sharing_audit": {
                "ok": false_sharing.get("ok"),
                "false_sharing_detected": false_sharing.get("false_sharing_detected"),
                "padding_bytes_inserted": false_sharing.get("padding_bytes_inserted"),
            },
            "roofline_telemetry": {
                "ok": roofline.get("ok"),
                "arithmetic_intensity_flops_per_byte": roofline.get("arithmetic_intensity_flops_per_byte"),
                "bottleneck_regime": roofline.get("bottleneck_regime"),
            },
        }

    return None
