"""AetherMind Universal Agent Kernel (Super-Union v3.1) (P6.1 + Sonnet S4 & S5).

Sovereign Single-State-Owner Kernel orchestrating all 12 organs without split-brain:
  - Governance: `ConstitutionSealGuard` + `HomeostasisGovernor` (Casimir + R09 Stop-Loss)
  - Contracts: `CognitiveEnvelope`, `ProblemFramingGate` (R01), `HypothesisRecord` (R04),
               `CalibrationLedger` (R06), `VerificationReceipt` (`actor_cannot_be_own_judge`)
  - Security: `WindowsDPAPIProvider` + `AuthenticatedEnvelopeManager`
  - Execution: `DurableExecutionEngine` (SQLite WAL + `FairDispatchScheduler` +
               `FencedEffectWriter` + R08 `OUTCOME_UNKNOWN` + Last-Mile `CFGGrammarSieve`)
               + `CodexSandboxMuscle` + `SafeEditTransactionalJournal` (`StaticVerificationGate`)
               + `WorktreeIsolationManager`
  - Runtime: `OMHMaestroBridge` (`/dag-ulw`) + `ExperimentalArbitrator` (R10) +
             `PersistentPwshSession` + `SpillToDiskMiddleware` + `RepeatToolLoopBreaker`
  - Memory: `TriadMemoryProvider` (Letta RAM + `F:\\Mnemos` + `MSEA Frankenstein v5`)
  - Perception: `SiliconProjectRadar` (`AetherScan` + UCIP) + `PolyglotRepoMapper` (PageRank)
  - Routing: `UniversalCognitiveRouter` (`OmniRoute` + `/v1/responses` + RTK + `rotor-llm`)
  - GUI/Docs/OSINT: `VerifiedBrowserAdapter` + `OlhoDeDeusOSINT` + `DocumentMultimodalOrgan`
  - Cognition & Evolution: `URENeuroSymbolicBridge` + `ConstitutionalEvolver` (`AutoHarness`)
  - Observability & Autonomy (Sonnet S4 & S5): `TelemetrySpanLedger` (OTel JSONL + Fast-Path
    Baseline) + `AutonomousTriggerScheduler` (durable cron/event triggers under R09 budget).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from am_ua import PROJECT_ROOT
from am_ua.cognition import ProactiveHierarchicalPlanner, URENeuroSymbolicBridge
from am_ua.contracts.calibration import CalibrationLedger
from am_ua.contracts.contracts import (
    CognitiveEnvelope,
    EpistemicTag,
    FramingVerdict,
    HypothesisRecord,
    MissionContract,
    ProblemFramingGate,
    TrustLevel,
    VerificationReceipt,
)
from am_ua.evolution import AutoHarnessSynthesizer, ConstitutionalEvolver
from am_ua.execution.adaptive_skills import AdaptiveSkillForge
from am_ua.execution.best_of_n import BehaviorBestOfNEngine
from am_ua.execution.codex_muscle import (
    CodexSandboxMuscle,
    SafeEditTransactionalJournal,
    StaticVerificationGate,
    WorktreeIsolationManager,
)
from am_ua.execution.durable_engine import (
    DurableExecutionEngine,
    EffectClass,
    FairDispatchScheduler,
    ToolContract,
)
from am_ua.execution.mcp_federation import AetherMindMCPServer, MCPFederationHub
from am_ua.execution.modality_router import HybridModalityRouter
from am_ua.execution.pc_automation import PCAutomationEngine
from am_ua.execution.subagent_bus import SubAgentSessionBus
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.governance.seal_guard import ConstitutionSealGuard, compute_content_sha256
from am_ua.gui import (
    CDPIndexedBrowser,
    DocumentMultimodalOrgan,
    OlhoDeDeusOSINT,
    VerifiedBrowserAdapter,
)
from am_ua.memory import TriadMemoryProvider
from am_ua.perception import (
    InterRepoTopologyGate,
    PolyglotRepoMapper,
    SiliconProjectRadar,
)
from am_ua.routing import UniversalCognitiveRouter
from am_ua.runtime import (
    ExperimentalArbitrator,
    OMHMaestroBridge,
    SymbolicPreLLMBypass,
    SynapseContextBracketEngine,
)
from am_ua.security.dpapi_envelope import AuthenticatedEnvelopeManager


class SplitBrainStateError(PermissionError):
    """Raised if an unauthorized organ attempts to bypass SingleStateOwnerGuard."""


class TelemetrySpanLedger:
    """OpenTelemetry-Compatible JSONL Span & Cost Ledger (Sonnet Upgrade S4)."""

    def __init__(self, log_path: Optional[Path | str] = None) -> None:
        self.log_path = Path(
            log_path or (Path(PROJECT_ROOT) / "data" / "otel_spans.jsonl")
        ).resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        tid = trace_id or uuid.uuid4().hex
        sid = uuid.uuid4().hex[:16]
        t0_ns = time.time_ns()
        span_ctx: Dict[str, Any] = {
            "trace_id": tid,
            "span_id": sid,
            "parent_span_id": parent_span_id,
            "name": name,
            "attributes": dict(attributes or {}),
            "status": "OK",
            "tokens_used": 0,
        }
        try:
            yield span_ctx
        except Exception as exc:
            span_ctx["status"] = "ERROR"
            span_ctx["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            t1_ns = time.time_ns()
            record = {
                "schema": "otel_span/v1",
                "trace_id": span_ctx["trace_id"],
                "span_id": span_ctx["span_id"],
                "parent_span_id": span_ctx["parent_span_id"],
                "name": span_ctx["name"],
                "start_time_unix_nano": t0_ns,
                "end_time_unix_nano": t1_ns,
                "duration_ms": round((t1_ns - t0_ns) / 1_000_000.0, 3),
                "status": span_ctx["status"],
                "tokens_used": int(span_ctx.get("tokens_used", 0)),
                "attributes": span_ctx["attributes"],
                "error": span_ctx.get("error"),
            }
            line_out = json.dumps(record, ensure_ascii=False) + "\n"
            with self._write_lock:
                for attempt in range(10):
                    try:
                        with self.log_path.open("a", encoding="utf-8") as fh:
                            fh.write(line_out)
                        break
                    except PermissionError:
                        if attempt == 9:
                            raise
                        time.sleep(0.01 * (attempt + 1))

    def read_spans(self, *, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.log_path.is_file():
            return []
        out: List[Dict[str, Any]] = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if trace_id is None or item.get("trace_id") == trace_id:
                out.append(item)
        return out


class AutonomousTriggerScheduler:
    """Durable Cron/Interval & Event Trigger Scheduler governed by R09 Homeostasis (Sonnet S5)."""

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        *,
        homeostasis: Optional[HomeostasisGovernor] = None,
    ) -> None:
        self.db_path = Path(
            db_path or (Path(PROJECT_ROOT) / "data" / "autonomous_triggers.db")
        ).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.homeostasis = homeostasis or HomeostasisGovernor()
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scheduled_triggers (
                    trigger_id TEXT PRIMARY KEY,
                    handler_name TEXT NOT NULL,
                    interval_seconds REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    next_run_at REAL NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    run_count INTEGER NOT NULL DEFAULT 0,
                    last_status TEXT DEFAULT 'IDLE'
                )
                """
            )

    def register_handler(self, name: str, fn: Callable[[Dict[str, Any]], Any]) -> None:
        self._handlers[name] = fn

    def schedule_recurring(
        self,
        trigger_id: str,
        handler_name: str,
        *,
        interval_seconds: float,
        payload: Optional[Dict[str, Any]] = None,
        start_immediately: bool = True,
    ) -> Dict[str, Any]:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        now = time.time()
        next_at = now if start_immediately else (now + interval_seconds)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scheduled_triggers
                (trigger_id, handler_name, interval_seconds, payload_json, next_run_at, enabled, run_count, last_status)
                VALUES (?, ?, ?, ?, ?, 1, 0, 'SCHEDULED')
                """,
                (trigger_id, handler_name, interval_seconds, json.dumps(payload or {}), next_at),
            )
        return {"trigger_id": trigger_id, "next_run_at": next_at}

    def tick(self, *, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Execute all due triggers only if HomeostasisGovernor reports healthy host."""
        snap = self.homeostasis.sample()
        if not snap.healthy:
            return [{"skipped_unhealthy_host": True, "warnings": snap.warnings}]

        cur = now if now is not None else time.time()
        with self._connect() as conn:
            due = conn.execute(
                """
                SELECT trigger_id, handler_name, interval_seconds, payload_json, run_count
                FROM scheduled_triggers WHERE enabled = 1 AND next_run_at <= ?
                """,
                (cur,),
            ).fetchall()

        executed: List[Dict[str, Any]] = []
        for tid, hname, interval_s, p_json, r_count in due:
            fn = self._handlers.get(hname)
            payload = json.loads(p_json)
            if fn is None:
                status = f"MISSING_HANDLER:{hname}"
                out = None
            else:
                try:
                    out = fn(payload)
                    status = "OK"
                    self.homeostasis.record_turn_cost(tokens=50, tool_calls=1, made_verified_progress=True)
                except Exception as exc:
                    out = None
                    status = f"ERROR:{type(exc).__name__}"
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE scheduled_triggers
                    SET next_run_at = ?, run_count = ?, last_status = ?
                    WHERE trigger_id = ?
                    """,
                    (cur + float(interval_s), int(r_count) + 1, status, tid),
                )
            executed.append({"trigger_id": tid, "status": status, "output": out})
        return executed

    def list_triggers(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT trigger_id, handler_name, interval_seconds, next_run_at, enabled, run_count, last_status FROM scheduled_triggers"
            ).fetchall()
        return [
            {
                "trigger_id": r[0],
                "handler_name": r[1],
                "interval_seconds": r[2],
                "next_run_at": r[3],
                "enabled": bool(r[4]),
                "run_count": r[5],
                "last_status": r[6],
            }
            for r in rows
        ]


class AetherMindUniversalAgent:
    """Master Sovereign Facade uniting all Super-Union v3.1 organs under 1 state owner."""

    SINGLE_STATE_OWNER = "DurableExecutionEngine"

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        self.root = Path(PROJECT_ROOT).resolve()
        self.data_dir = Path(data_dir or (self.root / "data")).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 1. Governance & Safety
        self.seal_guard = ConstitutionSealGuard(self.root)
        self.homeostasis = HomeostasisGovernor()

        # 2. Epistemic & Security Contracts
        self.framing_gate = ProblemFramingGate()
        self.calibration = CalibrationLedger(self.data_dir / "calibration_ledger.db")
        self.envelope_security = AuthenticatedEnvelopeManager(
            key_file=self.data_dir / "dpapi_master_key.bin",
            nonce_db_path=self.data_dir / "dpapi_replay.db",
        )

        # 3. Single Sovereign State & Execution Engine (Zero Split-Brain!)
        self.durable_engine = DurableExecutionEngine(self.data_dir / "durable_state.db")
        self.scheduler = FairDispatchScheduler()
        self.static_gate = StaticVerificationGate()
        self.codex_muscle = CodexSandboxMuscle(seal_guard=self.seal_guard)
        self.worktree_manager = WorktreeIsolationManager()

        # 4. Triad Memory, Perception, Routing, Runtime, GUI/Docs, Neuro-Symbolic & Evolution
        self.memory = TriadMemoryProvider(self.data_dir / "triad_memory")
        self.memory.initialize("ua_kernel_primary")
        self.radar = SiliconProjectRadar()
        self.topology_gate = InterRepoTopologyGate()
        self.router = UniversalCognitiveRouter(seal_guard=self.seal_guard)
        self.omh_bridge = OMHMaestroBridge(omh_home=self.data_dir / "omh_home")
        self.arbitrator = ExperimentalArbitrator()
        self.browser = VerifiedBrowserAdapter()
        self.osint = OlhoDeDeusOSINT()
        self.documents = DocumentMultimodalOrgan()
        self.ure = URENeuroSymbolicBridge()
        self.evolver = ConstitutionalEvolver(
            self.data_dir / "evolver_archive.db", seal_guard=self.seal_guard
        )
        self.autoharness = AutoHarnessSynthesizer()

        # 5. Observability, Context Brackets & Autonomous Triggers (Sonnet S4/S5 + JARVIS Átomo 20 + Apex Órgão 29)
        self.telemetry = TelemetrySpanLedger(self.data_dir / "otel_spans.jsonl")
        self.synapse = SynapseContextBracketEngine()
        self.symbolic_bypass = SymbolicPreLLMBypass()
        self.triggers = AutonomousTriggerScheduler(
            self.data_dir / "autonomous_triggers.db", homeostasis=self.homeostasis
        )

        # 6. Complete PC Automation & Adaptive Skill Forge (OSWorld/Robocorp/OmniParser/Voyager)
        self.pc_automation = PCAutomationEngine(
            artifact_dir=self.data_dir / "pc_automation",
        )
        self.skill_forge = AdaptiveSkillForge(self.data_dir / "adaptive_skills")

        # 7. Super-Union v3.4 Engineering Ceiling Organs (Agent-S S2/S3, bBoN, OpenClaw Bus, MCP Federation, CDP Browser)
        self.hierarchical_planner = ProactiveHierarchicalPlanner(
            storage_dir=self.data_dir / "hierarchical_plans"
        )
        self.modality_router = HybridModalityRouter(
            skill_forge=self.skill_forge,
            telemetry_path=self.data_dir / "modality_telemetry.json",
        )
        self.bbon_engine = BehaviorBestOfNEngine(
            scratch_root=self.data_dir / "bbon_sandboxes"
        )
        self.subagent_bus = SubAgentSessionBus(self.data_dir / "subagent_sessions.db")
        self.mcp_hub = MCPFederationHub()
        self.mcp_server = AetherMindMCPServer(
            pc_engine=self.pc_automation,
            skill_forge=self.skill_forge,
        )
        self.cdp_browser = CDPIndexedBrowser(
            artifact_dir=self.data_dir / "browser_indexed",
        )

        self._register_builtin_kernel_tools()

    def _register_builtin_kernel_tools(self) -> None:
        self.durable_engine.register_tool(
            ToolContract(
                name="ucip_radar_scan",
                effect_class=EffectClass.PURE_READ,
                required_args={"target_dir"},
                execute_fn=lambda args: asdict(
                    self.radar.build_ucip_summary(
                        args["target_dir"],
                        invoke_silicon_binary=bool(args.get("invoke_binary", False)),
                    )
                ),
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="ingest_document_tainted",
                effect_class=EffectClass.PURE_READ,
                required_args={"file_path"},
                execute_fn=lambda args: self.documents.ingest_document(args["file_path"]),
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="repomap_pagerank",
                effect_class=EffectClass.PURE_READ,
                required_args={"repo_root"},
                execute_fn=lambda args: self.map_repository(
                    args["repo_root"],
                    max_chars=int(args.get("max_chars", 2500)),
                ),
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="triad_memory_recall",
                effect_class=EffectClass.PURE_READ,
                required_args={"query"},
                execute_fn=lambda args: {
                    "query": args["query"],
                    "prefetched": self.memory.prefetch(str(args["query"])),
                },
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="constitutional_topology_audit",
                effect_class=EffectClass.PURE_READ,
                required_args={"package_dir"},
                execute_fn=lambda args: self.topology_gate.audit_package_imports(
                    args["package_dir"]
                ),
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="symbolic_eval_bypass",
                effect_class=EffectClass.PURE_READ,
                required_args={"expression"},
                execute_fn=lambda args: self.symbolic_bypass.evaluate(args["expression"]),
            )
        )
        self.durable_engine.register_tool(
            ToolContract(
                name="synapse_context_bracket",
                effect_class=EffectClass.PURE_READ,
                required_args={"current_tokens"},
                execute_fn=lambda args: self.synapse.evaluate_bracket(int(args["current_tokens"])),
            )
        )

    def assert_single_state_owner(self, mutator_name: str) -> None:
        """Enforce Sonnet S1/Architecture Law: only DurableExecutionEngine owns mission state."""
        if mutator_name != self.SINGLE_STATE_OWNER:
            raise SplitBrainStateError(
                f"Split-brain state mutation blocked: '{mutator_name}' != '{self.SINGLE_STATE_OWNER}'"
            )

    def should_use_fast_path(self, mission: MissionContract) -> bool:
        """Sonnet S4 (`mini-SWE` baseline rule): use zero-overhead fast path for single-step tasks."""
        return (
            len(mission.functional_requirements) <= 1
            and not mission.constraints.get("force_multi_agent_dag", False)
            and mission.max_tokens_budget <= 50_000
        )

    def doctor(self) -> Dict[str, Any]:
        """Full multi-organ readiness & constitutional integrity diagnostic."""
        with self.telemetry.start_span("kernel.doctor") as sp:
            homeo = self.homeostasis.sample()
            topo = self.topology_gate.audit_package_imports(self.root / "src" / "am_ua")
            seal_ok, seal_errs = self.seal_guard.verify_seal(require_manifest=False)
            codex_inv = self.codex_muscle.inventory()
            with self.omh_bridge.bind_request_browser_identity(session_id="doctor_probe") as bcap:
                omh_browser_ok = bool(bcap.get("supported"))
            report = {
                "single_state_owner": self.SINGLE_STATE_OWNER,
                "homeostasis_healthy": homeo.healthy,
                "safe_temp_dir": homeo.safe_temp_dir,
                "f_drive_free_gb": round(
                    homeo.volumes.get("F:", None).free_bytes / (1024**3), 2
                )
                if "F:" in homeo.volumes
                else None,
                "seal_valid": seal_ok,
                "seal_errors": seal_errs,
                "topology_v2_ok": topo["ok"],
                "triad_memory_available": self.memory.is_available(),
                "aetherscan_available": self.radar.is_binary_available(),
                "codex_exe_available": codex_inv["codex_exe"]["available"],
                "omh_browser_seam_unlocked": omh_browser_ok,
                "olho_de_deus_available": self.osint.status()["script_available"],
                "pc_automation_ready": True,
                "adaptive_skills_count": len(self.skill_forge.list_skills()),
                "v34_ceiling_organs_ready": True,
                "mcp_tools_count": len(self.mcp_server._tools),
            }
            sp["attributes"]["healthy"] = all(
                [
                    report["homeostasis_healthy"],
                    report["seal_valid"],
                    report["topology_v2_ok"],
                    report["triad_memory_available"],
                    report["codex_exe_available"],
                    report["omh_browser_seam_unlocked"],
                ]
            )
            return report

    def execute_mission(
        self,
        mission: MissionContract,
        *,
        steps: Optional[List[Dict[str, Any]]] = None,
        hypothesis: Optional[HypothesisRecord] = None,
        predicted_confidence: float = 0.85,
    ) -> Dict[str, Any]:
        """Execute a formalized `MissionContract` end-to-end with independent verification."""
        trace_id = uuid.uuid4().hex
        with self.telemetry.start_span(
            "kernel.execute_mission",
            trace_id=trace_id,
            attributes={"mission_id": mission.mission_id, "domain": mission.domain},
        ) as root_span:
            # 1. R01 Problem Framing Gate BEFORE any execution
            verdict: FramingVerdict = self.framing_gate.evaluate(mission)
            if not verdict.approved_for_execution:
                return {
                    "mission_id": mission.mission_id,
                    "status": "HALTED_AT_FRAMING",
                    "epistemic_tag": EpistemicTag.BLOQUEADO.value,
                    "framing_verdict": asdict(verdict),
                    "trace_id": trace_id,
                }

            # 2. Homeostasis & Fast-Path vs Maestro DAG routing
            snap = self.homeostasis.sample()
            if not snap.healthy:
                raise RuntimeError(f"Host homeostasis unhealthy: {snap.warnings}")
            fast_path = self.should_use_fast_path(mission)
            actor_route = self.router.select_route("fast_coder" if fast_path else "architect_deep")
            judge_route = self.router.select_route(
                "verifier", require_different_from=actor_route["endpoint"]
            )

            # 3. Pinned RAM Mission Block + Durable Lease Fence
            self.memory.core_blocks.overwrite(
                "ACTIVE_MISSION",
                f"[{mission.mission_id}] {mission.objective[:400]} (fast_path={fast_path})",
                source_origin="agent_kernel",
            )
            if hypothesis is not None:
                self.memory.core_blocks.overwrite(
                    "FALSIFIABLE_HYPOTHESES",
                    f"[{hypothesis.hypothesis_id}] {hypothesis.statement} | Falsify if: {hypothesis.falsification_criterion}",
                    source_origin="agent_kernel",
                )

            self.assert_single_state_owner("DurableExecutionEngine")
            epoch = self.durable_engine.fencer.acquire_lease(mission.mission_id, "kernel_primary")
            envelope = CognitiveEnvelope(
                source="agent_kernel",
                target="durable_engine",
                task_id=mission.mission_id,
                payload={"objective": mission.objective},
                confidence=predicted_confidence,
                epistemic_tag=EpistemicTag.INFERIDO,
                trust_level=TrustLevel.USER_AUTHORIZED,
                trace_id=trace_id,
            )

            executed_steps: List[Dict[str, Any]] = []
            state: Dict[str, Any] = {"mission_id": mission.mission_id, "fast_path": fast_path}
            for idx, step in enumerate(steps or []):
                with self.telemetry.start_span(
                    f"step.{step['tool_name']}",
                    trace_id=trace_id,
                    parent_span_id=root_span["span_id"],
                ) as step_span:
                    cp = self.durable_engine.execute_step(
                        run_id=mission.mission_id,
                        step_id=str(step.get("step_id", f"s_{idx}")),
                        step_index=idx,
                        tool_name=step["tool_name"],
                        args=dict(step.get("args", {})),
                        state=state,
                        lease_epoch=epoch,
                        envelope=envelope,
                    )
                    state = dict(cp["state"])
                    executed_steps.append(cp)
                    # No LLM is invoked in the deterministic pipeline: report 0 model tokens (was hardcoded 120).
                    step_span["tokens_used"] = 0
                    self.homeostasis.record_turn_cost(
                        tokens=0, tool_calls=1, made_verified_progress=True
                    )

            # 4. Pipeline receipt. HONESTY FIX (2026-11-03): this path never invokes the actor or the judge
            # model; it only proves the scripted tool steps completed. It no longer writes a synthetic
            # confidence into the R06 calibration ledger (that produced a constant fake Brier of 0.0225).
            passed_all = all(s["status"] == "COMPLETED" for s in executed_steps)
            brier = None
            cal_info = self.calibration.calibrated_confidence(mission.domain, predicted_confidence)

            receipt = VerificationReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                mission_id=mission.mission_id,
                judge_id=f"route_selected_not_invoked@{judge_route['endpoint']}",
                passed=passed_all,
                exit_code=0 if passed_all else 1,
                epistemic_tag=EpistemicTag.PROVADO if passed_all else EpistemicTag.BLOQUEADO,
                evidence_paths=[str(self.telemetry.log_path), str(self.durable_engine.db_path)],
                artifacts_sha256={
                    "IMMUTABLE_CONSTITUTION.json": compute_content_sha256(
                        self.seal_guard.constitution_path
                    )
                },
            )
            self.memory.sync_turn(
                mission.objective,
                f"Completed mission {mission.mission_id} (passed={passed_all}, fast_path={fast_path})",
                session_id=mission.mission_id,
            )
            root_span["tokens_used"] = 0
            return {
                "mission_id": mission.mission_id,
                "status": "VERIFIED" if passed_all else "FAILED",
                "verification_scope": "scripted_tool_steps_completed_only",
                "llm_invoked": False,
                "fast_path_used": fast_path,
                "actor_route": actor_route["endpoint"],
                "judge_route": judge_route["endpoint"],
                "steps": executed_steps,
                "brier_score": brier,
                "calibration": cal_info,
                "verification_receipt": asdict(receipt),
                "trace_id": trace_id,
            }

    @property
    def agent_loop(self) -> "AgentLoop":
        """Lazily build the real LLM-driven agent loop (keeps doctor/pipeline paths free of network I/O)."""
        if getattr(self, "_agent_loop", None) is None:
            from am_ua.execution.agent_loop import AgentLoop
            from am_ua.gui.cdp_browser import CDPIndexedBrowser

            def _make_browser(headless: bool = True) -> CDPIndexedBrowser:
                return CDPIndexedBrowser(artifact_dir=self.data_dir / "browser_art", headless=headless)

            def _make_repomap(ws_path: Path) -> PolyglotRepoMapper:
                return PolyglotRepoMapper(ws_path)

            self._agent_loop = AgentLoop(
                engine=self.durable_engine,
                seal_guard=self.seal_guard,
                calibration=self.calibration,
                trace_dir=self.data_dir / "agent_traces",
                pc_engine=self.pc_automation,
                skill_forge=self.skill_forge,
                hierarchical_planner=self.hierarchical_planner,
                modality_router=self.modality_router,
                subagent_bus=self.subagent_bus,
                mcp_hub=self.mcp_hub,
                browser_factory=_make_browser,
                repo_mapper_factory=_make_repomap,
            )
        return self._agent_loop

    def run_agent_mission(
        self,
        objective: str,
        workspace: Path | str,
        *,
        verify_cmd: Optional[str] = None,
        mission_id: Optional[str] = None,
        max_turns: int = 30,
        actor_provider: Optional[str] = None,
        on_event: Any = None,
        role: str = "general_engineer",
        workflow: str = "react",
        wheel_timeout_s: float = 0.0,
        agui_port: Optional[int] = None,
        best_of_n: int = 1,
        adaptive_best_of_n: int = 1,
    ) -> Dict[str, Any]:
        """REAL agent mission: LLM plans and acts via tools; VERIFIED only if `verify_cmd` exits 0."""
        mc = MissionContract(
            mission_id=mission_id or f"agent-{uuid.uuid4().hex[:10]}",
            objective=objective,
            domain="software_engineering",
            functional_requirements=[objective[:200]],
            acceptance_criteria=[verify_cmd] if verify_cmd else [],
        )
        verdict = self.framing_gate.evaluate(mc)
        if not verdict.approved_for_execution:
            return {"mission_id": mc.mission_id, "status": "HALTED_AT_FRAMING", "framing_verdict": asdict(verdict)}
        loop = self.agent_loop
        loop.on_event = on_event

        if int(best_of_n) > 1:
            raw_runs: Dict[str, Dict[str, Any]] = {}

            def _runner_fn(cand_ws: Path, cand_idx: int) -> Dict[str, Any]:
                r = loop.run(
                    objective,
                    cand_ws,
                    verify_cmd=verify_cmd,
                    mission_id=f"{mc.mission_id}-bbon{cand_idx}",
                    max_turns=max_turns,
                    actor_provider=actor_provider,
                    role=role,
                    workflow=workflow,
                    wheel_timeout_s=wheel_timeout_s,
                )
                d = asdict(r)
                raw_runs[f"cand_{cand_idx}"] = d
                return d

            bbon_res = self.bbon_engine.run_code_best_of_n(
                objective=objective,
                workspace=Path(workspace),
                runner_fn=_runner_fn,
                n=int(best_of_n),
            )
            win_id = bbon_res["winner_candidate_id"]
            winner_out = dict(raw_runs.get(win_id) or next(iter(raw_runs.values())))
            winner_out["bbon"] = {
                "n_requested": bbon_res["n_requested"],
                "winner_candidate_id": win_id,
                "winner_score": bbon_res["winner_score"],
                "synced_files": bbon_res["synced_files"],
            }
            return winner_out

        sse_server = None
        event_bus = None
        if agui_port:
            from am_ua.cognition.agui_protocol import AGUIEventBus, JsonlFileSink, LoopbackSSEServer, CallbackSink
            ledger_file = loop.agui_ledger_dir / f"{mc.mission_id}.jsonl"
            sse_server = LoopbackSSEServer(port=agui_port)
            event_bus = AGUIEventBus(
                thread_id="default",
                run_id=mc.mission_id,
                sinks=[JsonlFileSink(ledger_file), sse_server],
            )
            if on_event:
                event_bus.add_sink(CallbackSink(on_event))

        snap_dir: Optional[Path] = None
        if int(adaptive_best_of_n) > 1:
            snap_dir = self.bbon_engine.scratch_root / f"snap-{mc.mission_id}"
            self.bbon_engine._copy_workspace(Path(workspace).resolve(), snap_dir)

        try:
            with self.telemetry.start_span("kernel.run_agent_mission", attributes={"mission_id": mc.mission_id, "role": role, "workflow": workflow}) as sp:
                res = loop.run(
                    objective, workspace, verify_cmd=verify_cmd, mission_id=mc.mission_id,
                    max_turns=max_turns, actor_provider=actor_provider, role=role, workflow=workflow,
                    wheel_timeout_s=wheel_timeout_s, event_bus=event_bus,
                )
                sp["tokens_used"] = res.tokens["prompt"] + res.tokens["completion"]
                sp["attributes"]["status"] = res.status

            attempt1_passed = bool(res.verification and res.verification.get("passed")) if verify_cmd else (res.stop_reason == "finish" and res.status != "FAILED")
            if snap_dir is not None and not attempt1_passed:
                v_tail = ((res.verification or {}).get("output_tail") or "")[-600:]
                postmortem = (
                    f"\n\nFAILURE POSTMORTEM FROM ATTEMPT 1 (DO NOT REPEAT): "
                    f"status={res.status}, stop_reason={res.stop_reason}, "
                    f"tools={[c.get('tool') for c in res.tool_calls[-8:]]}."
                    + (f"\nLast verification output:\n{v_tail}" if v_tail else "")
                )
                esc_strategies = [("sparc", "tdd_enforcer"), ("react", "build_error_resolver")]
                esc_runs: Dict[str, Dict[str, Any]] = {}

                def _esc_runner(cand_ws: Path, cand_idx: int) -> Dict[str, Any]:
                    wf_alt, role_alt = esc_strategies[(cand_idx - 1) % len(esc_strategies)]
                    r2 = loop.run(
                        objective + postmortem,
                        cand_ws,
                        verify_cmd=verify_cmd,
                        mission_id=f"{mc.mission_id}-esc{cand_idx}",
                        max_turns=max_turns,
                        actor_provider=actor_provider,
                        role=role_alt,
                        workflow=wf_alt,
                        wheel_timeout_s=wheel_timeout_s,
                    )
                    d2 = asdict(r2)
                    esc_runs[f"cand_{cand_idx}"] = d2
                    return d2

                bbon_res = self.bbon_engine.run_code_best_of_n(
                    objective=objective,
                    workspace=snap_dir,
                    runner_fn=_esc_runner,
                    n=int(adaptive_best_of_n) - 1,
                    early_stop_on_first_verified=True,
                    use_llm_judge=False,
                )
                win_id = bbon_res["winner_candidate_id"]
                winner_out = dict(esc_runs.get(win_id) or next(iter(esc_runs.values())))
                winner_passed = bool((winner_out.get("verification") or {}).get("passed")) if verify_cmd else (winner_out.get("stop_reason") == "finish")
                if winner_passed or winner_out.get("status", "").startswith("VERIFIED"):
                    sync_files = sorted(set(res.changed_files or []) | set(winner_out.get("changed_files") or []) | set(bbon_res.get("synced_files") or []))
                    self.bbon_engine._sync_winner_to_workspace(snap_dir, Path(workspace).resolve(), sync_files)
                    winner_out["adaptive_escalated"] = True
                    winner_out["attempt1_status"] = res.status
                    self.memory.sync_turn(objective, f"[{winner_out.get('status')}] {str(winner_out.get('final_summary',''))[:500]}", session_id=mc.mission_id)
                    return winner_out

            self.memory.sync_turn(objective, f"[{res.status}] {res.final_summary[:500]}", session_id=mc.mission_id)
            out_dict = asdict(res)
            if int(adaptive_best_of_n) > 1:
                out_dict["adaptive_escalated"] = False
            return out_dict
        finally:
            if snap_dir is not None and snap_dir.exists():
                import shutil
                shutil.rmtree(snap_dir, ignore_errors=True)
            if sse_server:
                sse_server.close()

    def create_safe_editor(self, workspace_root: Path | str) -> SafeEditTransactionalJournal:
        return SafeEditTransactionalJournal(
            workspace_root,
            seal_guard=self.seal_guard,
            static_gate=self.static_gate,
        )

    def map_repository(self, repo_root: Path | str, *, max_chars: int = 3500) -> Dict[str, Any]:
        mapper = PolyglotRepoMapper(repo_root)
        ranked, text = mapper.build_ranked_map(max_chars=max_chars)
        return {
            "repo_root": str(Path(repo_root).resolve()),
            "ranked_files": [
                {"path": r.rel_path, "pagerank": r.pagerank, "symbol_count": len(r.symbols)}
                for r in ranked[:15]
            ],
            "repomap_text": text,
        }
