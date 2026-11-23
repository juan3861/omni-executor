"""SpecSearch Self-Evolution Loop & Native Zero-Dep ACE Context Playbook (v12.0).

Inspired by OpenJarvis:
  - `learning/spec_search/*` (Diagnose -> Plan -> RiskTier -> Apply -> BenchmarkGate -> Rollback)
  - `learning/agents/ace_optimizer.py` (ACE Generator / Reflector / Curator scored playbook)

100% Python stdlib (`dependencies = []`) and strictly governed by `ConstitutionSealGuard`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
import shutil
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from am_ua.governance.seal_guard import ConstitutionSealGuard


class EditRiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ACERule:
    """Single scored strategy rule in the ACE textual playbook."""

    rule_id: str
    text: str
    helpful: int = 1
    harmful: int = 0
    domain: str = "general"
    updated_at: float = field(default_factory=time.time)

    @property
    def net_score(self) -> int:
        return self.helpful - self.harmful

    def format_line(self) -> str:
        return f"[{self.rule_id}] helpful={self.helpful} harmful={self.harmful} ({self.domain}) :: {self.text}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "text": self.text,
            "helpful": self.helpful,
            "harmful": self.harmful,
            "domain": self.domain,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ACERule":
        return cls(
            rule_id=str(data.get("rule_id", "str-00001")),
            text=str(data.get("text", "")),
            helpful=int(data.get("helpful", 1)),
            harmful=int(data.get("harmful", 0)),
            domain=str(data.get("domain", "general")),
            updated_at=float(data.get("updated_at", time.time())),
        )


class ACEContextPlaybook:
    """Native zero-dep Agentic Context Engineering (Generator/Reflector/Curator) playbook."""

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = Path(path) if path else None
        self.rules: List[ACERule] = []
        if self.path and self.path.is_file():
            self.load(self.path)

    def _next_id(self) -> str:
        existing = {r.rule_id for r in self.rules}
        idx = len(self.rules) + 1
        while f"str-{idx:05d}" in existing:
            idx += 1
        return f"str-{idx:05d}"

    def add_or_reinforce(self, text: str, *, domain: str = "general", helpful: bool = True) -> ACERule:
        norm = " ".join((text or "").strip().split())
        for rule in self.rules:
            if rule.text.lower() == norm.lower():
                if helpful:
                    rule.helpful += 1
                else:
                    rule.harmful += 1
                rule.updated_at = time.time()
                if self.path:
                    self.save(self.path)
                return rule
        rule = ACERule(
            rule_id=self._next_id(),
            text=norm,
            helpful=1 if helpful else 0,
            harmful=0 if helpful else 1,
            domain=domain,
        )
        self.rules.append(rule)
        if self.path:
            self.save(self.path)
        return rule

    def record_outcome(self, rule_id: str, *, helpful: bool) -> bool:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                if helpful:
                    rule.helpful += 1
                else:
                    rule.harmful += 1
                rule.updated_at = time.time()
                if self.path:
                    self.save(self.path)
                return True
        return False

    def curate_from_trace(self, trace: Dict[str, Any]) -> List[ACERule]:
        """Reflector/Curator pass: extract actionable non-redundant lessons from a run trace."""
        added: List[ACERule] = []
        status = str(trace.get("agent_status") or trace.get("status") or "").upper()
        patch_bytes = int(trace.get("patch_bytes") or 0)
        turns = int(trace.get("turns") or 0)
        domain = str(trace.get("repo") or trace.get("domain") or "code")

        if status == "BUDGET_EXHAUSTED" and patch_bytes == 0:
            added.append(
                self.add_or_reinforce(
                    "Apply a minimal targeted edit within the first 6 turns after reproducing the failing test instead of repeating read-only searches.",
                    domain=domain,
                )
            )
        elif status in ("VERIFIED", "VERIFIED_AFTER_BUDGET") and patch_bytes > 0 and turns <= 20:
            added.append(
                self.add_or_reinforce(
                    f"Run the exact failing nodeid early and keep patches concise (~{patch_bytes}B) without running mutating auto-formatters on legacy files.",
                    domain=domain,
                )
            )
        error_note = str(trace.get("error") or "")
        if "ModuleNotFoundError" in error_note or "minversion" in error_note:
            added.append(
                self.add_or_reinforce(
                    "Always invoke the explicit isolated venv Python interpreter from the verify command rather than bare global python/pip.",
                    domain=domain,
                )
            )
        return added

    def prune_harmful(self, *, min_net_score: int = 0) -> int:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.net_score >= min_net_score]
        removed = before - len(self.rules)
        if removed and self.path:
            self.save(self.path)
        return removed

    def render_context(self, *, top_k: int = 8, domain: Optional[str] = None) -> str:
        candidates = [r for r in self.rules if r.net_score >= 0 and (domain is None or r.domain in (domain, "general"))]
        candidates.sort(key=lambda r: (r.net_score, r.helpful, r.updated_at), reverse=True)
        selected = candidates[: max(0, top_k)]
        if not selected:
            return ""
        header = "[ACE LEARNED PLAYBOOK — APPLY WHEN RELEVANT]"
        return "\n".join([header, *(r.format_line() for r in selected)])

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": "omni_ace_playbook/v1", "rules": [r.to_dict() for r in self.rules]}
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def load(self, path: Path | str) -> None:
        p = Path(path)
        if not p.is_file():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.rules = [ACERule.from_dict(r) for r in data.get("rules", [])]
        except (OSError, json.JSONDecodeError):
            self.rules = []


def classify_edit_risk(target_path: str, diff_text: str = "") -> EditRiskTier:
    """Classify proposed self-evolution edit risk tier."""
    rel = (target_path or "").replace("\\", "/").lower()
    if any(k in rel for k in ("constitution/", "seal_guard", "agent_shield", "security/", "eval/")):
        return EditRiskTier.HIGH
    if any(k in rel for k in ("agent_loop", "llm_client", "durable_engine")) or len(diff_text.splitlines()) > 120:
        return EditRiskTier.MEDIUM
    return EditRiskTier.LOW


@dataclass(frozen=True)
class BenchmarkSnapshot:
    """Point-in-time benchmark score snapshot with optional per-cluster breakdown."""

    overall_score: float
    cluster_scores: Dict[str, float] = field(default_factory=dict)
    version: str = "v1"


@dataclass(frozen=True)
class GateResult:
    accepted: bool
    before: BenchmarkSnapshot
    after: BenchmarkSnapshot
    delta: float
    regressed_clusters: List[str] = field(default_factory=list)
    reason: str = ""


class BenchmarkRegressionGate:
    """Accepts a self-evolution edit only if overall score improves and no cluster regresses."""

    def __init__(self, *, min_improvement: float = 0.0, max_regression: float = 0.05) -> None:
        self.min_improvement = float(min_improvement)
        self.max_regression = float(max_regression)

    def evaluate(self, *, before: BenchmarkSnapshot, after: BenchmarkSnapshot) -> GateResult:
        delta = round(after.overall_score - before.overall_score, 6)
        regressed: List[str] = []
        for cluster, prev_val in before.cluster_scores.items():
            if cluster in after.cluster_scores:
                drop = prev_val - after.cluster_scores[cluster]
                if drop > self.max_regression + 1e-9:
                    regressed.append(f"{cluster} (-{drop:.3f})")
        if regressed:
            return GateResult(
                accepted=False,
                before=before,
                after=after,
                delta=delta,
                regressed_clusters=regressed,
                reason=f"Cluster regression exceeded {self.max_regression:.3f}: {', '.join(regressed)}",
            )
        if delta < self.min_improvement - 1e-9:
            return GateResult(
                accepted=False,
                before=before,
                after=after,
                delta=delta,
                reason=f"Delta {delta:+.4f} below min_improvement {self.min_improvement:+.4f}",
            )
        return GateResult(accepted=True, before=before, after=after, delta=delta, reason="accepted")


class SpecSearchOrchestrator:
    """Closed Diagnose -> RiskCheck -> Checkpoint -> Apply -> BenchmarkGate -> Rollback loop."""

    def __init__(
        self,
        *,
        seal_guard: Optional[ConstitutionSealGuard] = None,
        gate: Optional[BenchmarkRegressionGate] = None,
    ) -> None:
        self.seal_guard = seal_guard
        self.gate = gate or BenchmarkRegressionGate(min_improvement=0.0, max_regression=0.05)

    def run_cycle(
        self,
        *,
        target_file: Path | str,
        traces: Sequence[Dict[str, Any]],
        before_snapshot: BenchmarkSnapshot,
        apply_fn: Callable[[Path, List[ACERule]], None],
        scorer_fn: Callable[[], BenchmarkSnapshot],
        playbook: Optional[ACEContextPlaybook] = None,
        checkpoint_dir: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        target = Path(target_file).resolve()
        if self.seal_guard is not None:
            self.seal_guard.assert_write_allowed(target, actor="spec_search_orchestrator")

        risk = classify_edit_risk(str(target))
        if risk == EditRiskTier.HIGH:
            return {
                "accepted": False,
                "rolled_back": False,
                "risk_tier": risk.value,
                "reason": f"Blocked HIGH-risk self-evolution target: {target.name}",
            }

        pb = playbook or ACEContextPlaybook()
        curated: List[ACERule] = []
        for tr in traces:
            curated.extend(pb.curate_from_trace(tr))

        ckpt_path: Optional[Path] = None
        existed_before = target.is_file()
        before_sha = hashlib.sha256(target.read_bytes()).hexdigest() if existed_before else ""
        if existed_before:
            cdir = Path(checkpoint_dir) if checkpoint_dir else target.parent / ".spec_search_ckpt"
            cdir.mkdir(parents=True, exist_ok=True)
            ckpt_path = cdir / f"{target.name}.{int(time.time() * 1000)}.bak"
            shutil.copy2(target, ckpt_path)

        apply_fn(target, curated)
        after_snapshot = scorer_fn()
        gate_res = self.gate.evaluate(before=before_snapshot, after=after_snapshot)

        rolled_back = False
        if not gate_res.accepted:
            if existed_before and ckpt_path and ckpt_path.is_file():
                shutil.copy2(ckpt_path, target)
            elif not existed_before and target.is_file():
                target.unlink()
            rolled_back = True

        return {
            "accepted": gate_res.accepted,
            "rolled_back": rolled_back,
            "risk_tier": risk.value,
            "before_sha256": before_sha,
            "curated_rules": [r.to_dict() for r in curated],
            "delta": gate_res.delta,
            "regressed_clusters": gate_res.regressed_clusters,
            "reason": gate_res.reason,
        }
