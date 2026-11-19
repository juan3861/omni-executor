"""Canonical Contracts — CognitiveEnvelope v1 + 6 MSEA Factory Contracts + Astra R01/R04/R12/R16."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EpistemicTag(str, Enum):
    """Operational epistemic classification (Radical Truth + Astra R06)."""

    PROVADO = "PROVADO"
    INFERIDO = "INFERIDO"
    HIPOTESE = "HIPOTESE"
    NAO_VERIFICADO = "NAO_VERIFICADO"
    BLOQUEADO = "BLOQUEADO"


class TrustLevel(str, Enum):
    """Information trust boundary (Astra R16 defense against indirect prompt injection)."""

    TRUSTED_SYSTEM = "trusted_system"
    USER_AUTHORIZED = "user_authorized"
    UNTRUSTED_DATA = "untrusted_data"


class ExecutionRealm(str, Enum):
    """Strict separation between simulation, digital execution, and physical world (Astra R12)."""

    SIMULATED = "simulated"
    EXECUTED_DIGITAL = "executed_digital"
    REQUIRES_PHYSICAL_ACTUATION = "requires_physical_actuation"


class UntrustedDataEscalationError(PermissionError):
    """Raised when UNTRUSTED_DATA attempts to authorize a mutative or external action."""


class ProblemFramingError(ValueError):
    """Raised when a MissionContract fails R01 invariant/contradiction checks."""


@dataclass
class CognitiveEnvelope:
    """Canonical inter-organ message contract (AetherMind Apotheosis V1 CognitiveEnvelope v1)."""

    source: str
    target: str
    task_id: str
    payload: Dict[str, Any]
    confidence: float = 1.0
    epistemic_tag: EpistemicTag = EpistemicTag.NAO_VERIFICADO
    trust_level: TrustLevel = TrustLevel.USER_AUTHORIZED
    provenance: List[str] = field(default_factory=list)
    policy_context: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    causation_id: Optional[str] = None
    timestamp_ns: int = field(default_factory=time.time_ns)
    schema_version: str = "cognitive_envelope/v1"

    def __post_init__(self) -> None:
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError(f"Invalid confidence {self.confidence}; expected [0.0, 1.0]")
        self.epistemic_tag = EpistemicTag(self.epistemic_tag)
        self.trust_level = TrustLevel(self.trust_level)

    def assert_can_authorize_mutation(self) -> None:
        """R16 enforcement: retrieved external data can never authorize mutations."""
        if self.trust_level == TrustLevel.UNTRUSTED_DATA:
            raise UntrustedDataEscalationError(
                f"R16 violation: envelope {self.event_id} carries UNTRUSTED_DATA and cannot authorize mutation"
            )

    def canonical_bytes(self) -> bytes:
        data = asdict(self)
        data["epistemic_tag"] = self.epistemic_tag.value
        data["trust_level"] = self.trust_level.value
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["epistemic_tag"] = self.epistemic_tag.value
        d["trust_level"] = self.trust_level.value
        return d


# ---------------------------------------------------------------------------
# The 6 Canonical MSEA Autonomous Software Factory Contracts (M0 -> M3)
# ---------------------------------------------------------------------------

@dataclass
class MissionContract:
    """M0 Input: Formalized engineering objective, constraints, invariants, and acceptance criteria."""

    mission_id: str
    objective: str
    domain: str
    functional_requirements: List[str]
    constraints: Dict[str, Any] = field(default_factory=dict)
    invariants: List[str] = field(default_factory=list)
    unverified_assumptions: List[str] = field(default_factory=list)
    acceptance_criteria: List[str] = field(default_factory=list)
    max_tokens_budget: int = 250_000
    allow_network: bool = True


@dataclass
class WorkforcePlan:
    """M0 Output: Decomposition into disjoint write-scope lanes and specialist assignments."""

    mission_id: str
    lanes: List[Dict[str, Any]]
    write_scopes: Dict[str, List[str]]
    verification_lane_id: str


@dataclass
class CandidateInventory:
    """M1 Output: Discovered local/external components with provenance and licenses."""

    mission_id: str
    candidates: List[Dict[str, Any]]
    ucip_summary: str = ""


@dataclass
class EvaluationRecord:
    """M2 Output: Empirical A/B, license, security, and topology evaluation score."""

    candidate_id: str
    license_spdx: str
    passed_security: bool
    passed_topology: bool
    empirical_score: Optional[float]  # None = NOT_SCORED (never fake 80!)
    notes: List[str] = field(default_factory=list)


@dataclass
class BuildArtifact:
    """M3 Output: Concrete artifact with real content SHA-256 and realm tag."""

    artifact_id: str
    mission_id: str
    paths: List[str]
    content_sha256: Dict[str, str]
    realm: ExecutionRealm = ExecutionRealm.EXECUTED_DIGITAL


@dataclass
class VerificationReceipt:
    """Independent Judge Output (Actor != Judge)."""

    receipt_id: str
    mission_id: str
    judge_id: str
    passed: bool
    exit_code: int
    epistemic_tag: EpistemicTag
    evidence_paths: List[str]
    artifacts_sha256: Dict[str, str]
    limitations: List[str] = field(default_factory=list)
    timestamp_ns: int = field(default_factory=time.time_ns)


# ---------------------------------------------------------------------------
# Astra R01: Problem Framing & Counter-Proposal Gate
# ---------------------------------------------------------------------------

@dataclass
class CounterProposal:
    reason: str
    detected_conflicts: List[str]
    recommended_alternative: str
    validation_micro_experiment: str


@dataclass
class FramingVerdict:
    approved_for_execution: bool
    contradictions: List[str]
    symptom_only_warnings: List[str]
    counter_proposal: Optional[CounterProposal] = None


class ProblemFramingGate:
    """Audits MissionContract BEFORE execution to catch contradictions and symptom-chasing (R01)."""

    def evaluate(self, mission: MissionContract) -> FramingVerdict:
        contradictions: List[str] = []
        warnings: List[str] = []
        c = mission.constraints

        if not mission.objective or not mission.objective.strip():
            contradictions.append("Empty mission objective")

        if mission.allow_network is False and c.get("require_live_external_api") is True:
            contradictions.append(
                "Contradiction: allow_network=False conflicts with require_live_external_api=True"
            )

        if c.get("zero_disk_writes") is True and c.get("require_persistent_sqlite_db") is True:
            contradictions.append(
                "Contradiction: zero_disk_writes=True conflicts with require_persistent_sqlite_db=True"
            )

        if mission.max_tokens_budget <= 0:
            contradictions.append(f"Invalid non-positive max_tokens_budget={mission.max_tokens_budget}")

        min_lat = c.get("max_latency_ms")
        if isinstance(min_lat, (int, float)) and min_lat < 1 and c.get("require_cloud_llm_roundtrip") is True:
            contradictions.append(
                f"Physical contradiction: max_latency_ms={min_lat}ms impossible with cloud LLM roundtrip"
            )

        if c.get("forbidden_WriteScopes_overlap") is True:
            pass  # Checked in WorkforcePlan

        obj_lower = mission.objective.lower()
        if any(tok in obj_lower for tok in ("apenas esconda o erro", "suppress all exceptions", "ignore test failures")):
            warnings.append("Symptom-only anti-pattern detected: suppressing errors instead of fixing root cause")

        if not mission.acceptance_criteria:
            warnings.append("No explicit acceptance_criteria provided; verification must synthesize measurable checks")

        if contradictions or warnings:
            if contradictions or any("Symptom-only" in w for w in warnings):
                proposal = CounterProposal(
                    reason="Mission contains contradictory constraints or symptom-masking directives.",
                    detected_conflicts=contradictions + warnings,
                    recommended_alternative=(
                        "Resolve constraint conflict (e.g., use local CPU-safe engine/cache when network is disabled, "
                        "and fix root failure instead of masking exceptions)."
                    ),
                    validation_micro_experiment="Run isolated reproduction test on root cause before full build.",
                )
                return FramingVerdict(
                    approved_for_execution=False,
                    contradictions=contradictions,
                    symptom_only_warnings=warnings,
                    counter_proposal=proposal,
                )

        return FramingVerdict(
            approved_for_execution=True,
            contradictions=[],
            symptom_only_warnings=warnings,
            counter_proposal=None,
        )

    @staticmethod
    def validate_workforce_disjoint_scopes(plan: WorkforcePlan) -> None:
        """Enforce oh-my-hermes /dag-ulw law: parallel lanes MUST NOT share write scopes."""
        seen: Dict[str, str] = {}
        for lane_id, paths in plan.write_scopes.items():
            for p in paths:
                norm = p.replace("\\", "/").strip("/").lower()
                if norm in seen and seen[norm] != lane_id:
                    raise ProblemFramingError(
                        f"Write-scope collision on '{p}' between parallel lanes '{seen[norm]}' and '{lane_id}'"
                    )
                seen[norm] = lane_id


# ---------------------------------------------------------------------------
# Astra R04: Pre-Registered Falsifiable Hypothesis Record
# ---------------------------------------------------------------------------

@dataclass
class HypothesisRecord:
    """Scientific hypothesis requiring a pre-registered falsification condition BEFORE testing."""

    hypothesis_id: str
    statement: str
    predicted_observation: str
    falsification_criterion: str
    experiment_command: str
    created_at_ns: int = field(default_factory=time.time_ns)
    status: str = "PRE_REGISTERED"  # PRE_REGISTERED -> SUPPORTED | FALSIFIED | INCONCLUSIVE
    observed_output: Optional[str] = None
    evaluated_at_ns: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.falsification_criterion or len(self.falsification_criterion.strip()) < 5:
            raise ValueError("R04 violation: falsification_criterion must be explicitly defined BEFORE running experiment")

    def evaluate_outcome(self, *, observed_output: str, falsified: bool, inconclusive: bool = False) -> str:
        if self.status != "PRE_REGISTERED":
            raise RuntimeError("R04 violation: cannot retroactively rewrite an already evaluated hypothesis")
        self.observed_output = observed_output
        self.evaluated_at_ns = time.time_ns()
        if inconclusive:
            self.status = "INCONCLUSIVE"
        elif falsified:
            self.status = "FALSIFIED"
        else:
            self.status = "SUPPORTED"
        return self.status


def default_repo_root() -> "Path":
    """Resolve the repository root portably across Windows/Linux/macOS."""
    from pathlib import Path

    return Path(__file__).resolve().parents[3]


def default_temp_dir(subdir: Optional[str] = None) -> "Path":
    """Resolve a portable writable temp directory (honors AM_UA_TEMP_DIR and F:\\AetherMind_Temp when present)."""
    import os
    import tempfile
    from pathlib import Path

    env_dir = os.environ.get("AM_UA_TEMP_DIR", "").strip()
    if env_dir:
        base = Path(env_dir)
    elif os.name == "nt" and Path("F:/").exists():
        base = Path(r"F:\AetherMind_Temp")
    else:
        base = Path(tempfile.gettempdir()) / "omni_executor_tmp"
    return (base / subdir) if subdir else base
