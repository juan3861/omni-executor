"""Deterministic Raft Consensus, Lamport Paxos Synod & Phi-Accrual Self-Healing (`am_ua.execution.raft_paxos_healing`).

Implements three zero-token distributed consensus and self-healing organs using
only the Python standard library:
1. `DeterministicRaftCluster`: Multi-node in-process Raft consensus state machine
   with leader election (§5.2, §5.4.1 log up-to-dateness), log replication
   (`AppendEntries` with SHA-256 chaining), network partition simulation, stale
   leader step-down, and cryptographic log reconciliation.
2. `DeterministicPaxosSynod`: Lamport's Single-Decree / Multi-Paxos synod protocol
   executing Phase 1a (`Prepare`), Phase 1b (`Promise`), Phase 2a (`Accept` with
   highest-numbered promised value invariant), and Phase 2b (`Accepted`).
3. `PhiAccrualSelfHealingSupervisor`: Hayashibara's Phi-Accrual Failure Detector
   computing suspicion level Phi(t) = -log10(1 - F_normal(t)) via `math.erf`,
   detecting Byzantine state-hash divergence, and emitting deterministic
   self-healing actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def _canonical_json_sha256(payload: Any) -> str:
    """Compute a deterministic SHA-256 hex digest over canonical JSON."""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _compute_log_entry_sha256(
    term: int,
    index: int,
    command: Dict[str, Any],
    prev_sha256: str,
) -> str:
    """Compute a chained SHA-256 digest for a single Raft log entry."""
    return _canonical_json_sha256(
        {
            "command": command,
            "index": index,
            "prev_sha256": prev_sha256,
            "term": term,
        }
    )


def _compute_full_log_sha256(log: Sequence[Dict[str, Any]]) -> str:
    """Compute a deterministic SHA-256 root digest over an entire Raft log."""
    return _canonical_json_sha256(list(log))


@dataclass
class RaftNodeState:
    """Per-node Raft consensus state container supporting attribute and mapping access."""

    node_id: str
    role: str = "FOLLOWER"
    current_term: int = 0
    voted_for: Optional[str] = None
    log: List[Dict[str, Any]] = field(default_factory=list)
    commit_index: int = 0

    def last_log_term_and_index(self) -> Tuple[int, int]:
        """Return `(last_log_term, last_log_index)` for Raft §5.4.1 comparison."""
        if not self.log:
            return (0, 0)
        last_entry = self.log[-1]
        return (int(last_entry["term"]), int(last_entry["index"]))

    def last_log_sha256(self) -> str:
        """Return the SHA-256 digest of the latest log entry, or 64 zeros if empty."""
        if not self.log:
            return "0" * 64
        return str(self.log[-1]["sha256"])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node state into a plain dictionary."""
        return {
            "node_id": self.node_id,
            "role": self.role,
            "current_term": self.current_term,
            "voted_for": self.voted_for,
            "log": [dict(entry) for entry in self.log],
            "log_length": len(self.log),
            "commit_index": self.commit_index,
            "log_sha256": _compute_full_log_sha256(self.log),
        }

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style subscription on node state."""
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        """Allow `.get(key, default)` mapping lookup on node state."""
        return self.to_dict().get(key, default)


class DeterministicRaftCluster:
    """In-process multi-node Raft consensus and network-partition self-healing engine."""

    def __init__(
        self,
        node_ids: Sequence[str] = ("node-1", "node-2", "node-3", "node-4", "node-5"),
    ) -> None:
        """Initialize a Raft cluster with the given unique node identifiers."""
        cleaned_ids = [str(nid).strip() for nid in node_ids if str(nid).strip()]
        if not cleaned_ids:
            raise ValueError("DeterministicRaftCluster requires at least one node_id.")
        deduped_ids: List[str] = []
        for nid in cleaned_ids:
            if nid not in deduped_ids:
                deduped_ids.append(nid)

        self.node_ids: List[str] = deduped_ids
        self.nodes: Dict[str, RaftNodeState] = {
            nid: RaftNodeState(node_id=nid) for nid in self.node_ids
        }
        self.partitioned_nodes: Set[str] = set()
        self.leader_id: Optional[str] = None

    @property
    def quorum_size(self) -> int:
        """Return strict majority quorum `(N // 2) + 1`."""
        return (len(self.node_ids) // 2) + 1

    @property
    def current_term(self) -> int:
        """Return the highest `current_term` across all nodes in the cluster."""
        return max((n.current_term for n in self.nodes.values()), default=0)

    @property
    def commit_index(self) -> int:
        """Return the highest `commit_index` across all nodes in the cluster."""
        return max((n.commit_index for n in self.nodes.values()), default=0)

    def _reachable_peers(self, origin_id: str) -> List[str]:
        """Return node IDs reachable from `origin_id` given current network partition."""
        if origin_id in self.partitioned_nodes:
            return [origin_id]
        return [nid for nid in self.node_ids if nid not in self.partitioned_nodes]

    @staticmethod
    def _is_candidate_log_up_to_date(
        candidate_state: RaftNodeState,
        voter_state: RaftNodeState,
    ) -> bool:
        """Implement Raft §5.4.1 log up-to-dateness comparison `(last_term, last_index)`."""
        cand_term, cand_idx = candidate_state.last_log_term_and_index()
        voter_term, voter_idx = voter_state.last_log_term_and_index()
        if cand_term != voter_term:
            return cand_term > voter_term
        return cand_idx >= voter_idx

    def _process_vote_request(
        self,
        candidate: RaftNodeState,
        voter: RaftNodeState,
    ) -> Tuple[bool, bool]:
        """Evaluate `RequestVote` from `candidate` on `voter`.

        Returns `(vote_granted, stepped_down_due_to_higher_term)`.
        """
        if voter.current_term > candidate.current_term:
            candidate.current_term = voter.current_term
            candidate.role = "FOLLOWER"
            candidate.voted_for = None
            return (False, True)

        if voter.current_term < candidate.current_term:
            voter.current_term = candidate.current_term
            voter.voted_for = None
            if voter.role != "FOLLOWER":
                voter.role = "FOLLOWER"

        can_vote = voter.voted_for is None or voter.voted_for == candidate.node_id
        log_ok = self._is_candidate_log_up_to_date(candidate, voter)
        if can_vote and log_ok:
            voter.voted_for = candidate.node_id
            return (True, False)
        return (False, False)

    def elect_leader(self, candidate_id: str) -> Dict[str, Any]:
        """Run Raft RequestVote protocol for `candidate_id` across reachable nodes."""
        if candidate_id not in self.nodes:
            raise ValueError(f"Unknown candidate node_id: {candidate_id}")

        candidate = self.nodes[candidate_id]
        reachable_ids = self._reachable_peers(candidate_id)

        candidate.current_term += 1
        candidate.role = "CANDIDATE"
        candidate.voted_for = candidate_id
        votes_granted: List[str] = [candidate_id]

        for peer_id in reachable_ids:
            if peer_id == candidate_id:
                continue
            voter = self.nodes[peer_id]
            granted, higher_term_seen = self._process_vote_request(candidate, voter)
            if higher_term_seen:
                return {
                    "ok": False,
                    "elected": False,
                    "candidate_id": candidate_id,
                    "leader_id": self.leader_id,
                    "term": candidate.current_term,
                    "current_term": candidate.current_term,
                    "votes_received": len(votes_granted),
                    "voters": votes_granted,
                    "quorum_size": self.quorum_size,
                    "total_nodes": len(self.node_ids),
                    "partitioned_nodes": sorted(self.partitioned_nodes),
                    "node_roles": {nid: n.role for nid, n in self.nodes.items()},
                    "reason": "Stepped down due to higher term discovered on voter.",
                }
            if granted:
                votes_granted.append(peer_id)

        elected = len(votes_granted) >= self.quorum_size
        if elected:
            candidate.role = "LEADER"
            self.leader_id = candidate_id
            for peer_id in reachable_ids:
                if peer_id != candidate_id:
                    self.nodes[peer_id].role = "FOLLOWER"
        else:
            candidate.role = "FOLLOWER"

        return {
            "ok": elected,
            "elected": elected,
            "candidate_id": candidate_id,
            "leader_id": self.leader_id if elected else None,
            "term": candidate.current_term,
            "current_term": candidate.current_term,
            "votes_received": len(votes_granted),
            "voters": sorted(votes_granted),
            "quorum_size": self.quorum_size,
            "total_nodes": len(self.node_ids),
            "partitioned_nodes": sorted(self.partitioned_nodes),
            "node_roles": {nid: n.role for nid, n in self.nodes.items()},
        }

    def _active_leader(self) -> Optional[RaftNodeState]:
        """Locate the current active leader node."""
        if self.leader_id and self.leader_id in self.nodes:
            leader = self.nodes[self.leader_id]
            if leader.role == "LEADER":
                return leader
        for nid in self.node_ids:
            node = self.nodes[nid]
            if node.role == "LEADER" and nid not in self.partitioned_nodes:
                self.leader_id = nid
                return node
        for nid in self.node_ids:
            node = self.nodes[nid]
            if node.role == "LEADER":
                return node
        return None

    @staticmethod
    def _sync_follower_log(leader: RaftNodeState, follower: RaftNodeState) -> bool:
        """Reconcile `follower.log` to match `leader.log` per Raft §5.3 Log Matching.

        Returns True if divergent or missing entries were repaired on `follower`.
        """
        repaired = False
        common_len = min(len(leader.log), len(follower.log))
        diverge_at = common_len
        for idx in range(common_len):
            if follower.log[idx]["sha256"] != leader.log[idx]["sha256"]:
                diverge_at = idx
                break

        if diverge_at < len(follower.log):
            del follower.log[diverge_at:]
            repaired = True

        if len(follower.log) < len(leader.log):
            for entry in leader.log[len(follower.log) :]:
                follower.log.append(
                    {
                        "term": int(entry["term"]),
                        "index": int(entry["index"]),
                        "command": dict(entry["command"]),
                        "sha256": str(entry["sha256"]),
                    }
                )
            repaired = True

        return repaired

    def replicate_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Append `command` to the current leader and run `AppendEntries` across followers."""
        leader = self._active_leader()
        if leader is None:
            return {
                "ok": False,
                "committed": False,
                "leader_id": None,
                "error": "No active leader in cluster.",
                "quorum_size": self.quorum_size,
            }

        new_index = len(leader.log) + 1
        prev_sha = leader.last_log_sha256()
        cmd_copy = dict(command)
        entry_sha = _compute_log_entry_sha256(
            term=leader.current_term,
            index=new_index,
            command=cmd_copy,
            prev_sha256=prev_sha,
        )
        entry: Dict[str, Any] = {
            "term": leader.current_term,
            "index": new_index,
            "command": cmd_copy,
            "sha256": entry_sha,
        }
        leader.log.append(entry)

        reachable_ids = self._reachable_peers(leader.node_id)
        ack_nodes: List[str] = [leader.node_id]

        for peer_id in reachable_ids:
            if peer_id == leader.node_id:
                continue
            follower = self.nodes[peer_id]
            if follower.current_term > leader.current_term:
                leader.current_term = follower.current_term
                leader.role = "FOLLOWER"
                leader.voted_for = None
                if self.leader_id == leader.node_id:
                    self.leader_id = None
                return {
                    "ok": False,
                    "committed": False,
                    "leader_id": None,
                    "term": leader.current_term,
                    "current_term": leader.current_term,
                    "index": new_index,
                    "commit_index": leader.commit_index,
                    "entry": dict(entry),
                    "sha256": entry_sha,
                    "ack_nodes": ack_nodes,
                    "ack_count": len(ack_nodes),
                    "quorum_size": self.quorum_size,
                    "reason": "Leader stepped down due to higher term on follower.",
                }

            follower.current_term = leader.current_term
            follower.role = "FOLLOWER"
            self._sync_follower_log(leader, follower)
            ack_nodes.append(peer_id)

        committed = len(ack_nodes) >= self.quorum_size
        if committed:
            leader.commit_index = new_index
            for peer_id in ack_nodes:
                self.nodes[peer_id].commit_index = new_index

        return {
            "ok": committed,
            "committed": committed,
            "leader_id": leader.node_id,
            "term": leader.current_term,
            "current_term": leader.current_term,
            "index": new_index,
            "commit_index": leader.commit_index,
            "entry": dict(entry),
            "sha256": entry_sha,
            "ack_nodes": sorted(ack_nodes),
            "ack_count": len(ack_nodes),
            "quorum_size": self.quorum_size,
        }

    def _prepare_partition_state(
        self,
        isolated_set: Set[str],
    ) -> Optional[str]:
        """Record or establish initial leader before isolating `isolated_set`."""
        old_leader = self._active_leader()
        if old_leader is None and isolated_set:
            first_isolated = sorted(isolated_set)[0]
            self.elect_leader(first_isolated)
            old_leader = self._active_leader()

        old_leader_id = old_leader.node_id if old_leader is not None else None
        self.partitioned_nodes = set(isolated_set)

        if old_leader is not None and old_leader.node_id in self.partitioned_nodes:
            if len(old_leader.log) == old_leader.commit_index:
                stale_idx = len(old_leader.log) + 1
                stale_cmd = {"op": "_isolated_minority_uncommitted_write", "node": old_leader.node_id}
                stale_sha = _compute_log_entry_sha256(
                    term=old_leader.current_term,
                    index=stale_idx,
                    command=stale_cmd,
                    prev_sha256=old_leader.last_log_sha256(),
                )
                old_leader.log.append(
                    {
                        "term": old_leader.current_term,
                        "index": stale_idx,
                        "command": stale_cmd,
                        "sha256": stale_sha,
                    }
                )
        return old_leader_id

    def _heal_partition_and_reconcile(
        self,
        new_leader: RaftNodeState,
    ) -> Tuple[List[str], str, bool]:
        """Clear network partition, force stale leaders to step down, and reconcile logs."""
        self.partitioned_nodes.clear()
        reconciled_nodes: List[str] = []

        for nid in self.node_ids:
            if nid == new_leader.node_id:
                continue
            node = self.nodes[nid]
            had_stale_role = node.role != "FOLLOWER"
            had_lower_term = node.current_term < new_leader.current_term
            node.current_term = new_leader.current_term
            node.role = "FOLLOWER"
            node.voted_for = new_leader.node_id
            log_repaired = self._sync_follower_log(new_leader, node)
            node.commit_index = new_leader.commit_index
            if had_stale_role or had_lower_term or log_repaired:
                reconciled_nodes.append(nid)

        leader_digest = _compute_full_log_sha256(new_leader.log)
        all_verified = all(
            _compute_full_log_sha256(n.log) == leader_digest
            and n.commit_index == new_leader.commit_index
            and n.current_term == new_leader.current_term
            and (n.role == "LEADER" if n.node_id == new_leader.node_id else n.role == "FOLLOWER")
            for n in self.nodes.values()
        )
        return (reconciled_nodes, leader_digest, all_verified)

    def simulate_partition_and_heal(
        self,
        isolated_nodes: Sequence[str],
        *,
        new_leader_candidate: str,
        heal_commands: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Isolate `isolated_nodes`, elect `new_leader_candidate`, commit `heal_commands`, and heal."""
        isolated_set = {str(nid) for nid in isolated_nodes if str(nid) in self.nodes}
        if new_leader_candidate not in self.nodes:
            raise ValueError(f"Unknown new_leader_candidate: {new_leader_candidate}")
        if new_leader_candidate in isolated_set:
            raise ValueError("new_leader_candidate cannot be inside isolated_nodes.")

        old_leader_id = self._prepare_partition_state(isolated_set)
        election_res = self.elect_leader(new_leader_candidate)
        if not election_res.get("elected", False):
            return {
                "ok": False,
                "healed": False,
                "partition_healed": False,
                "old_leader_id": old_leader_id,
                "new_leader_id": None,
                "isolated_nodes": sorted(isolated_set),
                "election_result": election_res,
                "error": "Failed to elect new leader in majority partition.",
            }

        committed_count = 0
        for cmd in list(heal_commands or ()):
            rep_res = self.replicate_command(cmd)
            if rep_res.get("committed", False):
                committed_count += 1

        new_leader = self.nodes[new_leader_candidate]
        reconciled_nodes, leader_digest, all_verified = self._heal_partition_and_reconcile(new_leader)
        old_leader_role = self.nodes[old_leader_id].role if old_leader_id else None
        old_stepped_down = (old_leader_role == "FOLLOWER") if old_leader_id else True

        return {
            "ok": bool(all_verified and old_stepped_down),
            "healed": bool(all_verified and old_stepped_down),
            "partition_healed": True,
            "old_leader_id": old_leader_id,
            "old_leader_stepped_down": old_stepped_down,
            "old_leader_role": old_leader_role,
            "new_leader_id": new_leader_candidate,
            "leader_id": new_leader_candidate,
            "new_term": new_leader.current_term,
            "current_term": new_leader.current_term,
            "isolated_nodes": sorted(isolated_set),
            "commands_committed": committed_count,
            "commit_index": new_leader.commit_index,
            "reconciled_nodes": reconciled_nodes,
            "divergent_logs_reconciled": len(reconciled_nodes),
            "log_sha256": leader_digest,
            "log_sha256_verified": all_verified,
            "cluster_converged": all_verified,
            "node_states": {nid: n.to_dict() for nid, n in self.nodes.items()},
        }


@dataclass
class _PaxosAcceptorState:
    """Internal state of a single Lamport Paxos Synod acceptor."""

    acceptor_id: int
    promised_n: int = -1
    accepted_n: int = -1
    accepted_value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize acceptor state to a dictionary."""
        return {
            "acceptor_id": self.acceptor_id,
            "promised_n": self.promised_n,
            "accepted_n": self.accepted_n,
            "accepted_value": self.accepted_value,
        }


class DeterministicPaxosSynod:
    """Lamport's Single-Decree / Multi-Paxos Synod consensus verifier."""

    @staticmethod
    def _normalize_proposal(idx: int, raw: Dict[str, Any]) -> Tuple[str, int, Any]:
        """Extract `(proposer_id, ballot_n, value)` from a proposal dictionary."""
        proposer_id = str(
            raw.get("proposer_id")
            or raw.get("proposer")
            or raw.get("node_id")
            or f"proposer-{idx + 1}"
        )
        raw_n = (
            raw.get("proposal_number")
            if "proposal_number" in raw
            else (raw.get("ballot") if "ballot" in raw else raw.get("n", idx + 1))
        )
        ballot_n = int(raw_n)
        if "value" in raw:
            value = raw["value"]
        elif "v" in raw:
            value = raw["v"]
        else:
            value = f"value-{idx + 1}"
        return (proposer_id, ballot_n, value)

    @staticmethod
    def _run_phase1_prepare(
        ballot_n: int,
        live_acceptors: Sequence[_PaxosAcceptorState],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Execute Paxos Phase 1a (`Prepare(n)`) and Phase 1b (`Promise(n, v_max)`)."""
        promises: List[Dict[str, Any]] = []
        rejections: List[Dict[str, Any]] = []
        for acc in live_acceptors:
            if ballot_n > acc.promised_n:
                acc.promised_n = ballot_n
                promises.append(
                    {
                        "acceptor_id": acc.acceptor_id,
                        "promised_n": acc.promised_n,
                        "accepted_n": acc.accepted_n,
                        "accepted_value": acc.accepted_value,
                    }
                )
            else:
                rejections.append(
                    {
                        "acceptor_id": acc.acceptor_id,
                        "promised_n": acc.promised_n,
                        "reason": "Ballot <= highest promised ballot.",
                    }
                )
        return (promises, rejections)

    @staticmethod
    def _select_phase2a_value(
        proposed_value: Any,
        promises: Sequence[Dict[str, Any]],
    ) -> Tuple[Any, bool, Optional[int]]:
        """Enforce Lamport's Phase 2a highest-numbered promised value invariant."""
        prior_accepted = [p for p in promises if int(p["accepted_n"]) >= 0]
        if not prior_accepted:
            return (proposed_value, False, None)
        highest = max(prior_accepted, key=lambda p: int(p["accepted_n"]))
        return (highest["accepted_value"], True, int(highest["accepted_n"]))

    @staticmethod
    def _run_phase2_accept(
        ballot_n: int,
        value_to_accept: Any,
        live_acceptors: Sequence[_PaxosAcceptorState],
    ) -> List[int]:
        """Execute Paxos Phase 2a (`Accept(n, v)`) and Phase 2b (`Accepted(n, v)`)."""
        accepted_by: List[int] = []
        for acc in live_acceptors:
            if ballot_n >= acc.promised_n:
                acc.promised_n = ballot_n
                acc.accepted_n = ballot_n
                acc.accepted_value = value_to_accept
                accepted_by.append(acc.acceptor_id)
        return accepted_by

    @staticmethod
    def _normalize_failed_acceptors(
        num_acceptors: int,
        failed_acceptors: Optional[Sequence[int]],
    ) -> Set[int]:
        """Normalize failed acceptor indices into `0 .. num_acceptors - 1`."""
        raw_failed = [int(a) for a in (failed_acceptors or ())]
        failed_set: Set[int] = set()
        for f_idx in raw_failed:
            if 0 <= f_idx < num_acceptors:
                failed_set.add(f_idx)
            elif f_idx == num_acceptors and 0 not in raw_failed:
                failed_set.add(f_idx - 1)
        return failed_set

    @classmethod
    def _execute_single_synod_round(
        cls,
        idx: int,
        raw_prop: Dict[str, Any],
        live_acceptors: Sequence[_PaxosAcceptorState],
        quorum_size: int,
    ) -> Tuple[Dict[str, Any], bool, Any, int, str]:
        """Run one Paxos round (Phase 1a/1b + Phase 2a/2b) for a single proposal."""
        proposer_id, ballot_n, prop_val = cls._normalize_proposal(idx, raw_prop)
        promises, rejections = cls._run_phase1_prepare(ballot_n, live_acceptors)
        p1_quorum = len(promises) >= quorum_size

        if not p1_quorum:
            trace = {
                "round_index": idx + 1,
                "proposer_id": proposer_id,
                "ballot": ballot_n,
                "proposed_value": prop_val,
                "phase1a_prepare": {"ballot": ballot_n},
                "phase1b_promises": promises,
                "phase1b_rejections": rejections,
                "phase1_quorum": False,
                "phase2_quorum": False,
                "accepted": False,
            }
            return (trace, False, None, ballot_n, proposer_id)

        val_2a, adopted_prior, prior_ballot = cls._select_phase2a_value(prop_val, promises)
        accepted_by = cls._run_phase2_accept(ballot_n, val_2a, live_acceptors)
        p2_quorum = len(accepted_by) >= quorum_size

        trace = {
            "round_index": idx + 1,
            "proposer_id": proposer_id,
            "ballot": ballot_n,
            "proposed_value": prop_val,
            "phase1a_prepare": {"ballot": ballot_n},
            "phase1b_promises": promises,
            "phase1_quorum": True,
            "phase2a_accept": {
                "ballot": ballot_n,
                "value": val_2a,
                "adopted_prior_value": adopted_prior,
                "prior_accepted_ballot": prior_ballot,
            },
            "phase2b_accepted_by": accepted_by,
            "phase2_quorum": p2_quorum,
            "accepted": p2_quorum,
            "chosen_value": val_2a if p2_quorum else None,
        }
        return (trace, p2_quorum, val_2a, ballot_n, proposer_id)

    @classmethod
    def run_synod_consensus(
        cls,
        num_acceptors: int = 5,
        proposals: Sequence[Dict[str, Any]] = (),
        *,
        failed_acceptors: Optional[Sequence[int]] = None,
    ) -> Dict[str, Any]:
        """Execute Lamport's Paxos Synod Phase 1a/1b and Phase 2a/2b across proposals."""
        if num_acceptors <= 0:
            raise ValueError("num_acceptors must be >= 1.")

        failed_set = cls._normalize_failed_acceptors(num_acceptors, failed_acceptors)
        quorum_size = (num_acceptors // 2) + 1
        acceptors = [_PaxosAcceptorState(acceptor_id=i) for i in range(num_acceptors)]
        live_acceptors = [acc for acc in acceptors if acc.acceptor_id not in failed_set]

        normalized_proposals = list(proposals) if proposals else [
            {"proposer_id": "proposer-1", "proposal_number": 1, "value": "decree-alpha"},
            {"proposer_id": "proposer-2", "proposal_number": 2, "value": "decree-beta"},
        ]

        rounds: List[Dict[str, Any]] = []
        chosen_history: List[Any] = []
        chosen_value: Any = None
        chosen_ballot: Optional[int] = None
        winning_proposer: Optional[str] = None

        for idx, raw_prop in enumerate(normalized_proposals):
            trace, decided, val_2a, ballot_n, proposer_id = cls._execute_single_synod_round(
                idx, raw_prop, live_acceptors, quorum_size
            )
            rounds.append(trace)
            if decided:
                chosen_value = val_2a
                chosen_ballot = ballot_n
                winning_proposer = proposer_id
                if val_2a not in chosen_history:
                    chosen_history.append(val_2a)

        consensus_reached = chosen_value is not None
        safety_holds = len(chosen_history) <= 1

        return {
            "ok": bool(consensus_reached and safety_holds),
            "consensus_reached": consensus_reached,
            "chosen_value": chosen_value,
            "chosen_ballot": chosen_ballot,
            "winning_proposer": winning_proposer,
            "num_acceptors": num_acceptors,
            "live_acceptors": len(live_acceptors),
            "failed_acceptors": sorted(failed_set),
            "quorum_size": quorum_size,
            "quorum_available": len(live_acceptors) >= quorum_size,
            "safety_invariant_holds": safety_holds,
            "distinct_chosen_values": chosen_history,
            "rounds": rounds,
            "acceptor_states": [acc.to_dict() for acc in acceptors],
        }


class PhiAccrualSelfHealingSupervisor:
    """Hayashibara's Phi-Accrual Failure Detector and Byzantine self-healing supervisor."""

    @staticmethod
    def _compute_mean_and_std(intervals_ms: Sequence[float]) -> Tuple[float, float]:
        """Compute empirical mean and standard deviation of heartbeat arrival intervals."""
        cleaned = [float(x) for x in intervals_ms if float(x) >= 0.0]
        if not cleaned:
            return (1000.0, 100.0)
        mean_val = sum(cleaned) / len(cleaned)
        if len(cleaned) < 2:
            return (mean_val, max(1.0, abs(mean_val) * 0.1))
        variance = sum((x - mean_val) ** 2 for x in cleaned) / (len(cleaned) - 1)
        std_val = math.sqrt(variance)
        min_std = max(1e-3, abs(mean_val) * 0.01)
        return (mean_val, max(std_val, min_std))

    @staticmethod
    def _compute_phi_from_normal_cdf(
        elapsed_ms: float,
        mean_ms: float,
        std_ms: float,
    ) -> Tuple[float, float, float]:
        """Compute `(phi, cdf_normal, survival_prob)` using `math.erf` normal CDF."""
        z = (elapsed_ms - mean_ms) / (std_ms * math.sqrt(2.0))
        cdf_normal = 0.5 * (1.0 + math.erf(z))
        survival = 1.0 - cdf_normal

        if survival > 1e-15:
            phi = -math.log10(survival)
            return (round(max(0.0, phi), 6), round(cdf_normal, 8), survival)

        erfc_survival = 0.5 * math.erfc(z)
        if erfc_survival > 0.0:
            phi = -math.log10(erfc_survival)
            return (round(max(0.0, phi), 6), 1.0, erfc_survival)

        asymptotic_phi = -math.log10(0.5) + (
            (z * z) + math.log(max(1.0, z * math.sqrt(math.pi)))
        ) / math.log(10.0)
        return (round(max(0.0, asymptotic_phi), 6), 1.0, 0.0)

    @staticmethod
    def _extract_node_state_hash(state_dict: Dict[str, Any]) -> str:
        """Extract or compute a deterministic state hash from a node state dictionary."""
        for key in ("state_hash", "sha256", "log_sha256", "digest", "hash"):
            if key in state_dict and state_dict[key] is not None:
                return str(state_dict[key])
        return _canonical_json_sha256(state_dict)

    @classmethod
    def _detect_byzantine_divergence(
        cls,
        node_states: Optional[Dict[str, Dict[str, Any]]],
    ) -> Tuple[bool, List[str], Optional[str], Dict[str, str]]:
        """Detect Byzantine state-hash divergence across `node_states`."""
        if not node_states:
            return (False, [], None, {})

        node_hashes: Dict[str, str] = {}
        hash_counts: Dict[str, int] = {}
        explicit_byzantine: Set[str] = set()

        for node_id, raw_state in sorted(node_states.items()):
            state_map = dict(raw_state) if isinstance(raw_state, dict) else {"value": raw_state}
            if state_map.get("byzantine") is True or state_map.get("corrupted") is True:
                explicit_byzantine.add(str(node_id))
            digest = cls._extract_node_state_hash(state_map)
            node_hashes[str(node_id)] = digest
            hash_counts[digest] = hash_counts.get(digest, 0) + 1

        quorum_hash = sorted(
            hash_counts.keys(),
            key=lambda h: (-hash_counts[h], h),
        )[0]

        byzantine_nodes: List[str] = []
        for node_id, digest in sorted(node_hashes.items()):
            if digest != quorum_hash or node_id in explicit_byzantine:
                byzantine_nodes.append(node_id)

        divergence = len(hash_counts) > 1 or bool(byzantine_nodes)
        return (divergence, byzantine_nodes, quorum_hash, node_hashes)

    @classmethod
    def evaluate_cluster_health(
        cls,
        heartbeat_intervals_ms: Sequence[float],
        *,
        elapsed_since_last_ms: float,
        phi_threshold: float = 8.0,
        node_states: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compute Phi-Accrual suspicion level, Byzantine divergence, and healing actions."""
        if phi_threshold <= 0.0:
            raise ValueError("phi_threshold must be > 0.")

        mean_ms, std_ms = cls._compute_mean_and_std(heartbeat_intervals_ms)
        phi, cdf_normal, survival = cls._compute_phi_from_normal_cdf(
            elapsed_ms=float(elapsed_since_last_ms),
            mean_ms=mean_ms,
            std_ms=std_ms,
        )

        suspect_threshold = max(1.0, phi_threshold * 0.25)
        if phi >= phi_threshold:
            status = "CONVICTION_FAILOVER"
        elif phi >= suspect_threshold:
            status = "SUSPECT"
        else:
            status = "HEALTHY"

        divergence, byzantine_nodes, quorum_hash, node_hashes = cls._detect_byzantine_divergence(
            node_states
        )

        healing_actions: List[str] = []
        if divergence:
            healing_actions.append("quarantine_byzantine_node")
        if status == "CONVICTION_FAILOVER":
            healing_actions.append("trigger_raft_election")
            healing_actions.append("rebalance_shards")
        elif divergence:
            healing_actions.append("rebalance_shards")

        return {
            "ok": True,
            "phi": phi,
            "phi_threshold": float(phi_threshold),
            "suspect_threshold": round(suspect_threshold, 4),
            "status": status,
            "node_status": status,
            "mean_interval_ms": round(mean_ms, 4),
            "std_interval_ms": round(std_ms, 4),
            "elapsed_since_last_ms": float(elapsed_since_last_ms),
            "cdf_normal": cdf_normal,
            "survival_probability": survival,
            "byzantine_divergence_detected": divergence,
            "byzantine_nodes": byzantine_nodes,
            "quorum_state_hash": quorum_hash,
            "node_state_hashes": node_hashes,
            "healing_actions": healing_actions,
            "self_healing_actions": list(healing_actions),
            "actions": list(healing_actions),
            "evaluated_at_epoch_ms": int(time.time() * 1000),
        }


__all__ = [
    "DeterministicPaxosSynod",
    "DeterministicRaftCluster",
    "PhiAccrualSelfHealingSupervisor",
    "RaftNodeState",
]
