"""Real cognitive agent loop (am_ua.execution.agent_loop — v8.0).

Part of the Execution Organ (OMNI_TOPOLOGY_V2 compliant).
Unites:
  - Multi-provider native tool-calling loop (OpenAI, Anthropic, Gemini, Ollama, Groq, OpenRouter)
    with explicit prompt caching, reasoning effort, and transparent JSON-text fallback
  - Parallel `ThreadPoolExecutor` dispatch for contiguous `PURE_READ` tool batches
  - Dynamic first-class MCP tool mounting (`mcp__<server>__<tool>`)
  - DurableExecutionEngine checkpoints + lease fences + Last-Mile security gate
  - Independent LLM judge on separate provider + calibrated Brier score
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import difflib
import hashlib
import inspect
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from am_ua.cognition.agui_protocol import (
    AGUIEvent,
    AGUIEventBus,
    AGUIEventType,
    CallbackSink,
    JsonlFileSink,
    StderrPrettySink,
)
from am_ua.cognition.hierarchical_planner import ProactiveHierarchicalPlanner
from am_ua.cognition.llm_client import LLMClient, LLMUnavailableError, ToolCall, extract_json_object
from am_ua.cognition.personas import PersonaManager
from am_ua.cognition.reasoning_bank import ReasoningBank
from am_ua.contracts.contracts import CognitiveEnvelope, EpistemicTag, TrustLevel, default_temp_dir
from am_ua.execution.adaptive_skills import AdaptiveSkillForge
from am_ua.execution.durable_engine import DurableExecutionEngine, EffectClass, ToolContract
from am_ua.execution.hook_engine import DeterministicHookEngine, ToolGuardrailTripwireError
from am_ua.execution.human_wheel import HumanWheelGate, WheelOutcome
from am_ua.execution.mcp_federation import MCPFederationHub
from am_ua.execution.modality_router import HybridModalityRouter
from am_ua.execution.output_compressor import ToolOutputCompressor
from am_ua.execution.pc_automation import PCAutomationEngine
from am_ua.execution.subagent_bus import SubAgentSessionBus
from am_ua.execution.tool_schemas import build_native_tool_schemas, discover_mcp_tool_schemas
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.homeostasis import HomeostasisGovernor, ResourceExhaustedError
from am_ua.governance.seal_guard import ConstitutionSealGuard, ConstitutionalViolationError
from am_ua.execution.loop_prompts_and_scopes import (
    DANGEROUS_CMD_RE,
    JUDGE_PROMPT,
    MAX_OBS_CHARS,
    ROLE_TOOL_SCOPES,
    SECRET_ENV_RE,
    SKIP_DIRS,
    SPARC_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    TOOL_FAMILIES,
    RepeatToolLoopBreaker,
    RepeatToolLoopError,
    clip,
    rank_tools_for_objective,
    scrubbed_env,
)


def _llm_supports_native_tools(llm: Any) -> bool:
    """Return True if `llm.chat` accepts a `tools` keyword argument (safe with mock FakeLLMs)."""
    chat_fn = getattr(llm, "chat", None)
    if chat_fn is None:
        return False
    try:
        params = inspect.signature(chat_fn).parameters
        return "tools" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        return False


def _msg_char_len(msg: Dict[str, Any]) -> int:
    content = msg.get("content")
    n = len(content) if isinstance(content, str) else len(json.dumps(content, default=str)) if content else 0
    if msg.get("tool_calls"):
        n += len(json.dumps(msg["tool_calls"], default=str))
    return n


@dataclass
class AgentRunResult:
    mission_id: str
    objective: str
    workspace: str
    status: str
    epistemic_tag: str
    final_summary: str
    actor_confidence: Optional[float]
    actor_providers: List[str]
    turns: int
    tool_calls: List[Dict[str, Any]]
    verification: Optional[Dict[str, Any]]
    judge: Optional[Dict[str, Any]]
    changed_files: List[str]
    diff: str
    tokens: Dict[str, int]
    llm_calls: int
    elapsed_s: float
    stop_reason: str
    brier_score: Optional[float] = None
    trace_path: Optional[str] = None
    role: str = "general_engineer"
    workflow: str = "react"
    event_ledger_path: Optional[str] = None
    pre_critic: Optional[Dict[str, Any]] = None
    structured_output: Optional[Any] = None


from am_ua.execution.loop_policies import (
    AGENT_STATE_TRANSITIONS as _LP_AGENT_STATE_TRANSITIONS,
    PLAN_MODE_FORBIDDEN_TOOLS as _LP_PLAN_MODE_FORBIDDEN_TOOLS,
    assert_tool_allowed_in_mode as _lp_assert_tool_allowed_in_mode,
    evaluate_pre_critic as _lp_evaluate_pre_critic,
    export_event_stream as _lp_export_event_stream,
    replay_event_stream as _lp_replay_event_stream,
    run_self_review_diff_gate as _lp_run_self_review_diff_gate,
    sync_todo_anchor as _lp_sync_todo_anchor,
    transition_state as _lp_transition_state,
    validate_output_schema as _lp_validate_output_schema,
)


class AgentLoop:
    AGENT_STATE_TRANSITIONS: Dict[str, frozenset[str]] = _LP_AGENT_STATE_TRANSITIONS
    PLAN_MODE_FORBIDDEN_TOOLS: frozenset[str] = _LP_PLAN_MODE_FORBIDDEN_TOOLS

    @classmethod
    def transition_state(cls, current: str, target: str) -> str:
        """Enforce finite-statechart transition invariants (XState-style)."""
        return _lp_transition_state(current, target)

    @classmethod
    def assert_tool_allowed_in_mode(cls, tool_name: str, mode: str = "act") -> None:
        """Cline/Roo-style strict Plan vs Act execution gate at kernel level."""
        _lp_assert_tool_allowed_in_mode(tool_name, mode)

    sync_todo_anchor = staticmethod(_lp_sync_todo_anchor)
    export_event_stream = staticmethod(_lp_export_event_stream)
    replay_event_stream = staticmethod(_lp_replay_event_stream)
    run_self_review_diff_gate = staticmethod(_lp_run_self_review_diff_gate)

    TOOL_EFFECTS = {
        "list_dir": EffectClass.PURE_READ,
        "read_file": EffectClass.PURE_READ,
        "search": EffectClass.PURE_READ,
        "write_file": EffectClass.COMPENSATABLE_MUTATION,
        "replace_in_file": EffectClass.COMPENSATABLE_MUTATION,
        "run": EffectClass.COMPENSATABLE_MUTATION,
        "task_tracker": EffectClass.IDEMPOTENT_WRITE,
        "pc_observe": EffectClass.PURE_READ,
        "pc_ground_vlm": EffectClass.PURE_READ,
        "pc_act": EffectClass.COMPENSATABLE_MUTATION,
        "pc_window": EffectClass.COMPENSATABLE_MUTATION,
        "pc_clipboard": EffectClass.IDEMPOTENT_WRITE,
        "pc_process": EffectClass.PURE_READ,
        "skill_forge": EffectClass.IDEMPOTENT_WRITE,
        "skill_run": EffectClass.COMPENSATABLE_MUTATION,
        "spawn_agent": EffectClass.COMPENSATABLE_MUTATION,
        "spawn_team": EffectClass.COMPENSATABLE_MUTATION,
        "send_agent": EffectClass.IDEMPOTENT_WRITE,
        "await_agents": EffectClass.PURE_READ,
        "mcp_call": EffectClass.COMPENSATABLE_MUTATION,
        "browser_observe": EffectClass.PURE_READ,
        "browser_act": EffectClass.COMPENSATABLE_MUTATION,
        "browser_extract": EffectClass.PURE_READ,
        "repo_map": EffectClass.PURE_READ,
        "cpg_impact": EffectClass.PURE_READ,
        "knowledge_query": EffectClass.PURE_READ,
        "web_fetch": EffectClass.PURE_READ,
        "spill_query": EffectClass.PURE_READ,
        "code_sandbox": EffectClass.PURE_READ,
        "deterministic_preflight": EffectClass.PURE_READ,
        "deterministic_exec": EffectClass.COMPENSATABLE_MUTATION,
        "run_playbook": EffectClass.COMPENSATABLE_MUTATION,
        "checkpoint": EffectClass.PURE_READ,
        "restore_checkpoint": EffectClass.COMPENSATABLE_MUTATION,
    }

    PARALLEL_READ_TOOLS: frozenset[str] = frozenset({
        "list_dir",
        "read_file",
        "search",
        "repo_map",
        "cpg_impact",
        "knowledge_query",
        "web_fetch",
        "spill_query",
        "deterministic_preflight",
        "checkpoint",
    })

    def __init__(
        self,
        *,
        engine: DurableExecutionEngine,
        seal_guard: ConstitutionSealGuard,
        llm: Optional[LLMClient] = None,
        calibration: Any = None,
        trace_dir: Optional[Path] = None,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        persona_mgr: Optional[PersonaManager] = None,
        reasoning_bank: Optional[ReasoningBank] = None,
        event_bus: Optional[AGUIEventBus] = None,
        wheel_gate: Optional[HumanWheelGate] = None,
        wheel_timeout_s: float = 0.0,
        agui_ledger_dir: Optional[Path] = None,
        pc_engine: Optional[PCAutomationEngine] = None,
        skill_forge: Optional[AdaptiveSkillForge] = None,
        hierarchical_planner: Optional[ProactiveHierarchicalPlanner] = None,
        modality_router: Optional[HybridModalityRouter] = None,
        subagent_bus: Optional[SubAgentSessionBus] = None,
        mcp_hub: Optional[MCPFederationHub] = None,
        browser_factory: Optional[Callable[[bool], Any]] = None,
        hook_engine: Optional[DeterministicHookEngine] = None,
        repo_mapper_factory: Optional[Callable[[Path], Any]] = None,
        knowledge_factory: Optional[Callable[[Path], Any]] = None,
        memory_provider: Optional[Any] = None,
    ) -> None:
        self.engine = engine
        self.seal_guard = seal_guard
        self.llm = llm or LLMClient()
        self.calibration = calibration
        self.trace_dir = trace_dir
        self.on_event = on_event
        self.persona_mgr = persona_mgr or PersonaManager()
        self.reasoning_bank = reasoning_bank or ReasoningBank(traces_dir=trace_dir)
        self.event_bus = event_bus
        self.wheel_gate = wheel_gate or HumanWheelGate()
        self.wheel_timeout_s = max(0.0, float(wheel_timeout_s))
        self.agui_ledger_dir = Path(agui_ledger_dir or (Path(__file__).resolve().parents[3] / "data" / "agui_events")).resolve()
        self.pc_engine = pc_engine or PCAutomationEngine()
        self.skill_forge = skill_forge or AdaptiveSkillForge()
        self.hierarchical_planner = hierarchical_planner or ProactiveHierarchicalPlanner(llm=self.llm)
        self.modality_router = modality_router or HybridModalityRouter(skill_forge=self.skill_forge)
        self.browser_factory = browser_factory
        self.hook_engine = hook_engine or DeterministicHookEngine()
        self.repo_mapper_factory = repo_mapper_factory
        self.knowledge_factory = knowledge_factory
        self.memory_provider = memory_provider
        self.subagent_bus = subagent_bus or SubAgentSessionBus()
        self.mcp_hub = mcp_hub or MCPFederationHub()
        self._active: Optional[WorkspaceTools] = None
        self._register_tools()

    @staticmethod
    def auto_select_role(objective: str, requested_role: str) -> str:
        """Select optimal ECC/engineering persona when `role='auto'`."""
        r = (requested_role or "general_engineer").strip().lower()
        if r != "auto":
            return requested_role
        low = (objective or "").lower()
        if any(k in low for k in ("security", "secret", "shield", "vulnerability", "injection", "audit")):
            return "security_auditor"
        if any(k in low for k in ("syntaxerror", "importerror", "build error", "compile", "type error")):
            return "build_error_resolver"
        if any(k in low for k in ("test", "pytest", "bug", "fix", "edge case", "regression")):
            return "tdd_enforcer"
        return "general_engineer"

    @staticmethod
    def _extract_sparc_phase(thought: str) -> str:
        s = str(thought).strip()
        m = re.search(r"SPARC\s*Phase:\s*([SPARC])", s, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        m2 = re.search(r"\b([SPARC])\s*[-:—\)]", s, re.IGNORECASE)
        if m2:
            return m2.group(1).upper()
        names = {
            "specification": "S",
            "pseudocode": "P",
            "architecture": "A",
            "refinement": "R",
            "completion": "C",
        }
        for name, p in names.items():
            if re.search(rf"\b{name}\b", s, re.IGNORECASE):
                return p
        return "?"

    rank_tools_for_objective = staticmethod(rank_tools_for_objective)

    @staticmethod
    def _compose_system_prompt(
        base_prompt: str,
        objective: str,
        *,
        role: str = "general_engineer",
        native_tools: bool = False,
    ) -> str:
        """Progressive tool-surface pruning (`HostOnly` role scopes + family relevance) + surgical discipline."""
        low = (objective or "").lower()
        need_browser = any(k in low for k in ("browser", "http://", "https://", "file://", ".html", "cdp", "playwright", "click", "url", "dom", "webpage", "website", "site"))
        need_desktop = any(k in low for k in ("desktop", "window", "gui", "screen", "ocr", "hotkey", "clipboard", "process", "port", "mouse", "dialog", "app"))
        need_swarm_mcp = len(low) > 450 or any(k in low for k in ("mcp", "swarm", "subagent", "spawn", "skill", "cli", "parallel", "pipeline", "audit"))
        role_scope = ROLE_TOOL_SCOPES.get((role or "general_engineer").strip().lower())

        kept: List[str] = []
        in_tools = False
        for ln in base_prompt.splitlines():
            if ln.strip() == "Tools:":
                in_tools = True
                if not native_tools:
                    kept.append(ln)
                continue
            if ln.strip() == "Rules:":
                in_tools = False
                kept.append(ln)
                continue
            if native_tools:
                if in_tools:
                    continue
                if ln.startswith('{"thought":') or "EXACTLY ONE JSON object" in ln:
                    continue
                kept.append(ln)
                continue
            if in_tools and ln.startswith("- "):
                tname = ln[2:].split(" ", 1)[0].strip()
                if role_scope is not None and tname not in role_scope:
                    if not ((need_browser and tname.startswith("browser_")) or (need_desktop and tname.startswith("pc_"))):
                        continue
                if tname.startswith("browser_") or tname == "web_fetch":
                    if not need_browser:
                        continue
                elif tname.startswith("pc_"):
                    if not need_desktop:
                        continue
                elif tname in ("spawn_agent", "send_agent", "await_agents", "mcp_call", "skill_forge", "skill_run"):
                    if not need_swarm_mcp:
                        continue
            kept.append(ln)

        out = "\n".join(kept)
        if native_tools:
            out += (
                "\n11. NATIVE PARALLEL TOOL CALLING: Invoke tools directly via native tool calls (emit multiple "
                "parallel read_file/search/list_dir calls in one turn to inspect files concurrently). Prefer surgical "
                "replace_in_file over write_file; never emit literal \\\\n instead of real newlines; run ad-hoc checks "
                "via `python -c`; call `finish` only after verification passes."
            )
        else:
            out += (
                "\n10. SPEED & BATCHING: You may execute up to 6 independent tool calls in ONE turn via "
                '{"thought": "...", "actions": [{"tool": "...", "args": {...}}, ...]} (e.g. multiple read_file, '
                "replace_in_file, or browser_act steps). Always prefer surgical replace_in_file over full write_file; "
                "for multi-file symbol renames across Python files, prefer deterministic_exec "
                '{"action": "libcst_safe_codemod", "params": {"file_path": ..., "symbol_old": ..., "symbol_new": ...}} '
                'or {"action": "structural_search_replace", ...}; never emit literal \\\\n instead of real newlines in Python edits; '
                "run ad-hoc checks via `python -c` instead of creating scratch files in workspace; on command failure, "
                "diagnose root cause before editing again."
            )
        return out

    @staticmethod
    def _build_turn0_inventory(ws: WorkspaceTools, before: Dict[str, Tuple[str, Optional[str]]]) -> str:
        """Pre-seed workspace file tree (+ RepoMap on small repos) so Turn 1 skips blind list_dir."""
        rels = sorted(
            r for r in before
            if not r.startswith(("tests_hidden/", ".am_"))
            and "__pycache__" not in r
            and not r.endswith(("durable.db", "durable.db-shm", "durable.db-wal"))
        )
        if not rels:
            return ""
        items = []
        for r in rels[:35]:
            txt = (before.get(r) or ("", None))[1]
            sz = f"{len(txt)}ch" if txt is not None else "bin"
            items.append(f"{r} ({sz})")
        block = f"WORKSPACE FILES ({len(rels)}): " + ", ".join(items)
        if len(rels) > 35:
            block += f", ... (+{len(rels) - 35} more)"

        names = {Path(r).name.lower(): r for r in rels}
        hints: List[str] = []
        if "uv.lock" in names:
            hints.append("uv.lock detected -> prefer 'uv run' / 'uv pip'")
        elif "poetry.lock" in names:
            hints.append("poetry.lock detected -> prefer 'poetry run'")
        elif "pipfile" in names:
            hints.append("Pipfile detected -> prefer 'pipenv run'")
        elif "pyproject.toml" in names:
            hints.append("pyproject.toml detected -> prefer 'python -m pytest'")
        if "pnpm-lock.yaml" in names:
            hints.append("pnpm-lock.yaml detected -> prefer 'pnpm'")
        elif "yarn.lock" in names:
            hints.append("yarn.lock detected -> prefer 'yarn'")
        elif "package-lock.json" in names:
            hints.append("package-lock.json detected -> prefer 'npm'")
        if any(k in names for k in ("deno.json", "deno.jsonc", "deno.lock")):
            hints.append("Deno markers detected -> prefer 'deno'")
        if "cargo.toml" in names:
            hints.append("Cargo.toml detected -> prefer 'cargo test' / 'cargo check'")
        if "go.mod" in names:
            hints.append("go.mod detected -> prefer 'go test ./...'")
        if hints:
            block += "\nTOOLCHAIN HINTS: " + "; ".join(hints)

        if len(rels) <= 15 and ws._repo_mapper_factory is not None:
            try:
                rm_res = ws.repo_map({"max_chars": 1000})
                rm_txt = str(rm_res.get("map") or "").strip()
                if rm_txt:
                    block += f"\nREPOMAP:\n{rm_txt[:1000]}"
            except Exception:
                pass
        return block + "\n\n"

    # Tools are registered once on the single state owner; they dispatch to the active workspace.
    def _register_tools(self) -> None:
        for name, effect in self.TOOL_EFFECTS.items():
            tool_name = f"ws.{name}"
            if tool_name in self.engine.tools:
                continue

            def make(n: str) -> Callable[[Dict[str, Any]], Any]:
                def fn(args: Dict[str, Any]) -> Any:
                    if self._active is None:
                        raise RuntimeError("no active workspace")
                    return getattr(self._active, n)(args)
                return fn

            req = {
                "read_file": {"file"},
                "search": {"pattern"},
                "write_file": {"path", "content"},
                "replace_in_file": {"path"},
                "run": {"command"},
                "skill_forge": {"name", "code"},
            }.get(name, set())
            self.engine.register_tool(ToolContract(name=tool_name, effect_class=effect, execute_fn=make(name), required_args=req))

    def _emit(self, event: Dict[str, Any]) -> None:
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    def _prepare_args(self, tool: str, args: Dict[str, Any], ws: WorkspaceTools) -> Dict[str, Any]:
        args = dict(args)
        if tool in ("write_file", "replace_in_file"):
            rel = str(args.pop("file", args.get("path", "")))
            args["path"] = str(ws.resolve(rel))  # absolute -> LastMileSecurityGate checks the real target
            if "old_str" in args and "old" not in args:
                args["old"] = args.pop("old_str")
            if "new_str" in args and "new" not in args:
                args["new"] = args.pop("new_str")
            if "contents" in args and "content" not in args:
                args["content"] = args.pop("contents")
        elif tool == "read_file":
            if "path" in args and "file" not in args:
                args["file"] = args.pop("path")
        return args

    def run(
        self,
        objective: str,
        workspace: Path | str,
        *,
        verify_cmd: Optional[str] = None,
        mission_id: Optional[str] = None,
        max_turns: int = 30,
        max_tokens: int = 400_000,
        max_wall_s: float = 1800.0,
        actor_provider: Optional[str] = None,
        domain: str = "software_engineering",
        use_judge: bool = True,
        role: str = "general_engineer",
        workflow: str = "react",
        wheel_timeout_s: Optional[float] = None,
        event_bus: Optional[AGUIEventBus] = None,
        output_schema: Optional[Dict[str, Any]] = None,
        enable_zero_token_offload: bool = True,
        execution_mode: str = "act",
        sync_todo_anchor: bool = False,
        enable_self_review_gate: bool = True,
        enable_dlp_supervisor: bool = True,
        auto_compile_skill: bool = False,
        auto_compile_playbook: bool = False,
        use_native_tools: bool = True,
        reasoning_effort: Optional[str] = None,
        parallel_read_workers: int = 6,
        enable_memory_prefetch: bool = True,
        ace_context_rules: Optional[str] = None,
    ) -> AgentRunResult:
        from am_ua.cognition.stage_router import ComplexityQueryAnalyzer, StageSkillHandbook
        from am_ua.execution.wasm_sandbox import WasmSandboxRunner
        from am_ua.perception.efficiency_telemetry import EfficiencyTracker

        mission_id = mission_id or f"agent-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
        complexity_res = ComplexityQueryAnalyzer.analyze(objective or "")
        stage_handbook = StageSkillHandbook()
        efficiency_tracker = EfficiencyTracker()
        _wasm_sandbox = WasmSandboxRunner()
        _ = (_wasm_sandbox, stage_handbook, efficiency_tracker)
        low_obj = (objective or "").lower()
        s2_kw = ("architect", "refactor", "migrate", "security", "formal", "z3", "proof", "distributed", "kernel", "optimize", "compiler")
        s2_hits = sum(1 for k in s2_kw if k in low_obj)
        cog_score = round(max(complexity_res.score, min(1.0, min(0.45, s2_hits * 0.18) + min(0.25, len(low_obj) / 600.0))), 3)
        cog_sys = "SYSTEM_2" if cog_score >= 0.45 else "SYSTEM_1"
        event_stream_buf: List[Dict[str, Any]] = [
            {
                "kind": "system",
                "event": "cognitive_route",
                "system": cog_sys,
                "complexity_score": cog_score,
                "complexity_tier": complexity_res.tier,
                "suggested_max_tokens": complexity_res.suggested_max_tokens,
                "query_class": complexity_res.query_class,
                "execution_mode": execution_mode,
            }
        ]
        ws = WorkspaceTools(
            Path(workspace),
            self.seal_guard,
            pc_engine=self.pc_engine,
            skill_forge=self.skill_forge,
            llm_client=self.llm,
            subagent_bus=self.subagent_bus,
            mcp_hub=self.mcp_hub,
            browser_factory=self.browser_factory,
            repo_mapper_factory=self.repo_mapper_factory,
            knowledge_factory=self.knowledge_factory,
        )
        self._active = ws
        if sync_todo_anchor:
            self.sync_todo_anchor(ws.ws, objective, [{"id": "m1", "title": objective[:120], "status": "in_progress"}])
        effective_wheel_timeout = self.wheel_timeout_s if wheel_timeout_s is None else max(0.0, float(wheel_timeout_s))
        homeo = HomeostasisGovernor(max_tokens_budget=max_tokens, max_wall_seconds=max_wall_s, max_stagnant_turns=6)
        breaker = RepeatToolLoopBreaker(window_size=12, max_identical_calls=3)
        epoch = self.engine.fencer.acquire_lease(mission_id, "agent_loop")
        envelope = CognitiveEnvelope(source="agent_loop", target="durable_engine", task_id=mission_id,
                                     payload={"objective": objective[:500]}, trust_level=TrustLevel.USER_AUTHORIZED)
        before = ws.snapshot()
        t_start = time.perf_counter()
        calls0, pt0, ct0 = self.llm.calls, self.llm.total_prompt_tokens, self.llm.total_completion_tokens

        if enable_zero_token_offload:
            from am_ua.execution.playbook_compiler import TraceToPlaybookCompiler, TurnZeroPlaybookRouter

            pb_match = TurnZeroPlaybookRouter.match_intent(
                objective,
                verify_cmd=verify_cmd,
                compiler=TraceToPlaybookCompiler(),
            )
            if pb_match is not None:
                pb_res = ws.run_playbook({"playbook": pb_match["playbook"], "variables": pb_match["variables"]})
                if pb_res.get("ok"):
                    ver_ok = True
                    v_check: Optional[Dict[str, Any]] = None
                    if verify_cmd:
                        v_out = ws.run({"command": verify_cmd, "timeout_s": 600})
                        ver_ok = v_out.get("exit_code") == 0
                        v_check = {"command": verify_cmd, "exit_code": v_out.get("exit_code"), "passed": ver_ok, "output_tail": str(v_out.get("output", ""))[-2000:]}
                    if ver_ok:
                        after_pb = ws.snapshot()
                        changed_pb = sorted(k for k in set(before) | set(after_pb) if before.get(k, ("", None))[0] != after_pb.get(k, ("", None))[0])
                        diff_pb = self._diff(before, after_pb, changed_pb)
                        ws.close()
                        self._active = None
                        return AgentRunResult(
                            mission_id=mission_id,
                            objective=objective,
                            workspace=str(ws.ws),
                            status="VERIFIED",
                            epistemic_tag=EpistemicTag.PROVADO.value,
                            final_summary=f"Turn-0 deterministic playbook '{pb_match['playbook']}' completed without LLM calls.",
                            actor_confidence=float(pb_match.get("confidence", 0.95)),
                            actor_providers=["turn0_playbook_router"],
                            turns=0,
                            tool_calls=[{"turn": 0, "tool": f"playbook:{pb_match['playbook']}", "args": pb_match["variables"], "ok": True}],
                            verification=v_check or {"passed": True, "playbook": pb_match["playbook"], "details": pb_res},
                            judge=None,
                            changed_files=changed_pb,
                            diff=clip(diff_pb, 20000),
                            tokens={"prompt": 0, "completion": 0},
                            llm_calls=0,
                            elapsed_s=round(time.perf_counter() - t_start, 3),
                            stop_reason=f"deterministic_playbook:{pb_match['playbook']}",
                            role=role,
                            workflow=workflow,
                            structured_output=pb_res,
                        )

            from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

            rail = DeterministicTaskOffloader.match_zero_token_rail(objective, verify_cmd=verify_cmd)
            if rail is not None:
                rail_res = DeterministicTaskOffloader.execute_rail(
                    rail, ws.ws, verify_cmd=verify_cmd, run_fn=ws.run
                )
                ws.close()
                self._active = None
                return AgentRunResult(
                    mission_id=mission_id,
                    objective=objective,
                    workspace=str(ws.ws),
                    status="VERIFIED" if rail_res.get("ok") else "FAILED",
                    epistemic_tag=EpistemicTag.PROVADO.value if rail_res.get("ok") else EpistemicTag.NAO_VERIFICADO.value,
                    final_summary=str(rail_res.get("summary") or rail),
                    actor_confidence=1.0 if rail_res.get("ok") else 0.0,
                    actor_providers=["deterministic_offloader"],
                    turns=0,
                    tool_calls=[{"turn": 0, "tool": f"rail:{rail}", "args": {}, "ok": bool(rail_res.get("ok"))}],
                    verification={"passed": bool(rail_res.get("ok")), "rail": rail, "details": rail_res.get("details")},
                    judge=None,
                    changed_files=[],
                    diff="",
                    tokens={"prompt": 0, "completion": 0},
                    llm_calls=0,
                    elapsed_s=round(time.perf_counter() - t_start, 3),
                    stop_reason=f"deterministic_rail:{rail}",
                    role=role,
                    workflow=workflow,
                    structured_output=rail_res,
                )

        # AG-UI EventBus setup
        bus = event_bus or self.event_bus
        created_local_bus = False
        ledger_path_str: Optional[str] = None
        if bus is None:
            created_local_bus = True
            self.agui_ledger_dir.mkdir(parents=True, exist_ok=True)
            ledger_file = self.agui_ledger_dir / f"{mission_id}.jsonl"
            ledger_path_str = str(ledger_file)
            bus = AGUIEventBus(
                thread_id="default",
                run_id=mission_id,
                sinks=[JsonlFileSink(ledger_file)],
            )
            if self.on_event:
                bus.add_sink(CallbackSink(self.on_event))

        bus.emit(
            AGUIEventType.RUN_STARTED,
            objective=objective,
            role=role,
            workflow=workflow,
            workspace=str(ws.ws),
            max_turns=max_turns,
            verify_cmd=verify_cmd,
        )

        # v8.0 Dynamic MCP tool mounting + Native Tool Calling schema construction
        mcp_schemas, mcp_routing = (
            discover_mcp_tool_schemas(self.mcp_hub) if self.mcp_hub.list_servers() else ([], {})
        )
        native_tools_active = bool(use_native_tools and _llm_supports_native_tools(self.llm))

        # SPARC vs ReAct base prompt selection, tool-surface pruning & Persona contract injection
        role = self.auto_select_role(objective, role)
        base_prompt = SPARC_SYSTEM_PROMPT if (workflow or "").lower() == "sparc" else SYSTEM_PROMPT
        base_prompt = self._compose_system_prompt(base_prompt, objective, role=role, native_tools=native_tools_active)
        system_prompt = self.persona_mgr.inject_persona(base_prompt, role)
        event_stream_buf.append({
            "kind": "system",
            "event": "kv_cache_static_prefix",
            "kv_prefix_sha256": hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()[:16],
        })

        native_tools: Optional[List[Dict[str, Any]]] = None
        if native_tools_active:
            native_tools = build_native_tool_schemas(
                objective=objective,
                role=role,
                execution_mode=execution_mode,
                mcp_schemas=mcp_schemas,
            )
            if mcp_routing:
                bus.emit(
                    AGUIEventType.CUSTOM,
                    name="MCP_TOOLS_MOUNTED",
                    count=len(mcp_routing),
                    tools=sorted(mcp_routing.keys()),
                )

        # ReasoningBank trajectory grounding + TriadMemoryProvider semantic/hybrid prefetch
        task = ""
        if self.reasoning_bank:
            exemplar = self.reasoning_bank.format_trajectory_exemplar(objective)
            if exemplar:
                task += f"{exemplar}\n"
        if enable_memory_prefetch and self.memory_provider is not None and hasattr(self.memory_provider, "prefetch"):
            try:
                triad_ctx = str(self.memory_provider.prefetch(objective, session_id=mission_id) or "").strip()
                if triad_ctx:
                    task += f"{triad_ctx}\n"
            except Exception:
                pass

        if mcp_routing and not native_tools_active:
            mounted_list = ", ".join(sorted(mcp_routing.keys())[:20])
            task += f"MOUNTED_MCP_TOOLS (invoke directly as tool names): {mounted_list}\n"

        if ace_context_rules and ace_context_rules.strip():
            task += f"{ace_context_rules.strip()}\n\n"

        if (workflow or "").lower() == "hierarchical":
            obj_low = objective.lower()
            complex_markers = (
                "browser", "playwright", "cdp", "desktop", "window", "gui",
                "screenshot", "click", "and then", "after that", "pipeline",
                "migrate", "refactor", "multi-file", "end-to-end",
            )
            is_fast_path = len(objective) < 500 and not any(m in obj_low for m in complex_markers)
            if is_fast_path:
                task += (
                    "FAST-PATH DIRECT EXECUTION: Focused single-scope task detected. "
                    "Inspect the relevant file(s) directly, apply the minimal fix, run the verification command, and call finish.\n\n"
                )
                bus.emit(
                    AGUIEventType.CUSTOM,
                    name="HIERARCHICAL_PLAN_CREATED",
                    fast_path=True,
                    subgoals=[],
                )
            else:
                h_plan = self.hierarchical_planner.decompose(objective, mission_id=mission_id, verify_cmd=verify_cmd)
                dag_lines = ["PROACTIVE HIERARCHICAL PLAN (Agent-S S2 Manager DAG):"]
                for sg in h_plan.subgoals:
                    dec = self.modality_router.select_modality(sg.description, suggested_modality=sg.suggested_modality)
                    dag_lines.append(
                        f"  - [{sg.subgoal_id}] {sg.title} (deps={sg.depends_on}, modality={dec.primary_modality}, tools={dec.recommended_tools[:3]}): {sg.description}"
                    )
                task += "\n".join(dag_lines) + "\n\n"
                bus.emit(
                    AGUIEventType.CUSTOM,
                    name="HIERARCHICAL_PLAN_CREATED",
                    fast_path=False,
                    subgoals=[asdict(sg) for sg in h_plan.subgoals],
                )

        task += self._build_turn0_inventory(ws, before)
        if re.search(r"\b(traceback|error|fail|bug|exception|fix|corrija|erro)\b", objective, re.I):
            try:
                from am_ua.execution.apex_fault_localizer import AgentlessThreePhaseLocalizer

                loc = AgentlessThreePhaseLocalizer.localize(ws.ws, query_or_traceback=objective, top_k_files=2, window=8)
                top_files = [f.get("file") for f in (loc.get("phase1_ranked_files") or [])[:2] if f.get("file")]
                if top_files:
                    task += f"ZERO_TOKEN_FAULT_LOCALIZER_HINTS: suspicious_files={top_files}\n"
            except Exception:
                pass
        task += f"OBJECTIVE:\n{objective}\n\nWORKSPACE: {ws.ws}\n"
        task += f"ACCEPTANCE COMMAND (must exit 0): {verify_cmd}\n" if verify_cmd else "No acceptance command was provided; verify your work yourself.\n"
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}, {"role": "user", "content": task}]

        from am_ua.execution.openhands_organs import OpenHandsStuckDetector
        from am_ua.execution.token_latency_savers import SimHashSemanticCache, grammar_json_repair, prompt_token_pruner

        tool_log: List[Dict[str, Any]] = []
        stuck_events_log: List[Dict[str, Any]] = []
        stuck_detector = OpenHandsStuckDetector()
        read_cache = SimHashSemanticCache(max_hamming_distance=0)
        providers_used: List[str] = []
        summary, confidence, stop_reason = "", None, "max_turns"
        parse_failures, turn = 0, 0
        human_requests_count = 0
        pre_verification: Optional[Dict[str, Any]] = None
        structured_output: Optional[Any] = None
        active_role = role
        compressor = ToolOutputCompressor()
        effective_reasoning = reasoning_effort or ("medium" if cog_sys == "SYSTEM_2" else None)

        def _finalize_tool_result(
            sub_idx: int,
            tool: str,
            args: Dict[str, Any],
            tc_id: str,
            call_args: Optional[Dict[str, Any]],
            ok: bool,
            obs: Any,
            total_batch_len: int,
        ) -> Tuple[bool, str]:
            bus.emit(
                AGUIEventType.TOOL_CALL_END,
                toolCallId=tc_id,
                toolName=tool,
            )
            bus.emit(
                AGUIEventType.TOOL_CALL_RESULT,
                toolCallId=tc_id,
                ok=ok,
                result=clip(json.dumps(obs, ensure_ascii=False, default=str), 1500),
            )
            if ok and tool in ("write_file", "replace_in_file") and call_args:
                rel_path = str(call_args.get("path", ""))
                try:
                    rel_path = Path(rel_path).relative_to(ws.ws).as_posix()
                except ValueError:
                    pass
                bus.emit(
                    AGUIEventType.STATE_DELTA,
                    deltas=[{"op": "replace", "path": f"/files/{rel_path}"}],
                )
            elif ok and tool == "task_tracker" and isinstance(obs, dict):
                bus.emit(
                    AGUIEventType.STATE_DELTA,
                    deltas=[{"op": "replace", "path": "/tasks", "value": obs.get("tasks", [])}],
                )
            tool_log.append(
                {
                    "turn": turn,
                    "tool": tool,
                    "args": {k: (v if len(str(v)) < 300 else str(v)[:300] + "...") for k, v in args.items()},
                    "ok": ok,
                }
            )
            stuck_events_log.append({"tool": tool, "args": args, "is_error": not ok, "observation": str(obs)[:250]})
            compressed = compressor.compress_tool_payload(tool, obs)
            if len(compressed) > 1200:
                compressed = prompt_token_pruner(compressed).get("pruned_text", compressed)
            prefix = f"[{sub_idx}:{tool}] " if total_batch_len > 1 else ""
            return ok, prefix + compressed

        for turn in range(1, max_turns + 1):
            messages = self._condense(messages)
            try:
                if event_bus is not None and hasattr(self.llm, "chat_stream"):
                    if native_tools_active and native_tools:
                        resp = self.llm.chat_stream(
                            messages,
                            max_tokens=4096,
                            temperature=0.2,
                            json_mode=False,
                            prefer=actor_provider,
                            tools=native_tools,
                            tool_choice="auto",
                            enable_prompt_cache=True,
                            reasoning_effort=effective_reasoning,
                            on_delta=lambda d: bus.emit(
                                AGUIEventType.TEXT_MESSAGE_CONTENT,
                                messageId=f"msg-{turn}",
                                delta=d,
                            ),
                        )
                    else:
                        resp = self.llm.chat_stream(
                            messages,
                            max_tokens=4096,
                            temperature=0.2,
                            json_mode=True,
                            prefer=actor_provider,
                            on_delta=lambda d: bus.emit(
                                AGUIEventType.TEXT_MESSAGE_CONTENT,
                                messageId=f"msg-{turn}",
                                delta=d,
                            ),
                        )
                else:
                    if native_tools_active and native_tools:
                        resp = self.llm.chat(
                            messages,
                            max_tokens=4096,
                            temperature=0.2,
                            json_mode=False,
                            prefer=actor_provider,
                            tools=native_tools,
                            tool_choice="auto",
                            enable_prompt_cache=True,
                            reasoning_effort=effective_reasoning,
                        )
                    else:
                        resp = self.llm.chat(messages, max_tokens=4096, temperature=0.2, json_mode=True, prefer=actor_provider)
            except LLMUnavailableError as exc:
                stop_reason = f"llm_unavailable: {str(exc)[:300]}"
                break
            if resp.provider not in providers_used:
                providers_used.append(resp.provider)

            resp_tool_calls: List[ToolCall] = list(getattr(resp, "tool_calls", None) or [])
            used_native_tool_turn = bool(resp_tool_calls)
            batch: List[Tuple[str, Dict[str, Any], Optional[str]]] = []
            thought_text = ""

            if used_native_tool_turn:
                tc_wire = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": tc.raw_arguments or json.dumps(tc.arguments, ensure_ascii=False),
                        },
                    }
                    for tc in resp_tool_calls[:8]
                ]
                messages.append({"role": "assistant", "content": resp.text or "", "tool_calls": tc_wire})
                for tc in resp_tool_calls[:8]:
                    batch.append((tc.name, tc.arguments if isinstance(tc.arguments, dict) else {}, tc.id))
                thought_text = str(getattr(resp, "thinking_text", "") or resp.text or "")
            else:
                messages.append({"role": "assistant", "content": resp.text})
                try:
                    try:
                        action = extract_json_object(resp.text)
                    except ValueError:
                        healed = grammar_json_repair(resp.text)
                        if not healed.get("ok") or not isinstance(healed.get("parsed"), dict):
                            raise
                        action = healed["parsed"]
                    if isinstance(action.get("actions"), list) and action["actions"]:
                        for item in action["actions"][:6]:
                            if not isinstance(item, dict):
                                raise ValueError("each entry in 'actions' must be an object")
                            t_name = str(item.get("tool", "")).strip()
                            if not t_name:
                                raise ValueError("missing non-empty 'tool' name in actions item")
                            t_args = item.get("args") or {}
                            if not isinstance(t_args, dict):
                                raise ValueError("args in actions item must be an object")
                            batch.append((t_name, t_args, None))
                    else:
                        tool = str(action.get("tool", "")).strip()
                        if not tool:
                            raise ValueError("missing non-empty 'tool' name")
                        args = action.get("args") or {}
                        if not isinstance(args, dict):
                            raise ValueError("args must be an object")
                        batch.append((tool, args, None))
                    thought_text = str(action.get("thought", ""))
                except ValueError as exc:
                    parse_failures += 1
                    messages.append({"role": "user", "content": f"PROTOCOL ERROR: {exc}. Reply with a tool call or exactly one JSON object."})
                    if parse_failures >= 4:
                        stop_reason = "protocol_failures"
                        break
                    continue

            first_tool = batch[0][0]
            step_name = f"SPARC:{self._extract_sparc_phase(thought_text)}" if (workflow or "").lower() == "sparc" else f"turn:{turn}"
            bus.emit(
                AGUIEventType.STEP_STARTED,
                turn=turn,
                stepName=step_name,
                thought=thought_text[:300],
            )
            self._emit({"turn": turn, "tool": first_tool if len(batch) == 1 else f"batch[{len(batch)}]", "provider": resp.provider, "thought": thought_text[:200]})

            turn_obs_chunks: List[str] = []
            native_tool_results: Dict[str, Tuple[str, str]] = {}
            turn_progress = False
            turn_tools_executed = 0
            should_break_loop = False
            reject_finish_msg: Optional[str] = None

            # Partition batch into contiguous segments so PURE_READ runs >= 2 execute concurrently
            segments: List[Tuple[bool, List[Tuple[int, str, Dict[str, Any], Optional[str]]]]] = []
            for sub_idx, (t_name, t_args, t_cid) in enumerate(batch, 1):
                is_par = t_name in self.PARALLEL_READ_TOOLS
                if segments and segments[-1][0] == is_par and is_par:
                    segments[-1][1].append((sub_idx, t_name, t_args, t_cid))
                else:
                    segments.append((is_par, [(sub_idx, t_name, t_args, t_cid)]))

            for is_par_seg, seg_items in segments:
                if should_break_loop or reject_finish_msg is not None:
                    break

                # ---- Parallel PURE_READ segment execution ----
                if is_par_seg and len(seg_items) >= 2 and parallel_read_workers > 1:
                    prepared_jobs: List[Dict[str, Any]] = []
                    for sub_idx, tool, args, native_cid in seg_items:
                        tc_id = native_cid or f"tc-{turn}-{sub_idx}-{tool}"
                        bus.emit(AGUIEventType.TOOL_CALL_START, toolCallId=tc_id, toolName=tool, args_preview=str(args)[:150])
                        bus.emit(AGUIEventType.TOOL_CALL_ARGS, toolCallId=tc_id, args=args)
                        event_stream_buf.append({"kind": "action", "turn": turn, "tool": tool, "args": args})
                        job: Dict[str, Any] = {
                            "sub_idx": sub_idx,
                            "tool": tool,
                            "args": args,
                            "tc_id": tc_id,
                            "native_cid": native_cid,
                            "call_args": None,
                            "cache_key": None,
                            "ok": True,
                            "obs": None,
                            "step_id": None,
                        }
                        try:
                            self.assert_tool_allowed_in_mode(tool, execution_mode)
                            breaker.record_and_check(tool, args)
                            call_args = self._prepare_args(tool, args, ws)
                            job["call_args"] = call_args
                            pre_dec = self.hook_engine.run_pre(tool, call_args, ws.ws)
                            if not pre_dec.allowed:
                                job["ok"], job["obs"] = False, {"error": pre_dec.reason, "blocked_by_hook": True}
                            else:
                                if tool in ("read_file", "search", "repo_map"):
                                    ck = json.dumps([tool, call_args], sort_keys=True, default=str)
                                    job["cache_key"] = ck
                                    hit = read_cache.lookup(ck)
                                    if hit.get("cache_hit") and isinstance(hit.get("response"), dict):
                                        cached_obs = dict(hit["response"])
                                        cached_obs["simhash_cache_hit"] = True
                                        job["obs"] = cached_obs
                                if job["obs"] is None:
                                    job["step_id"] = (
                                        f"t{turn}-{sub_idx}-"
                                        f"{hashlib.sha256(json.dumps([tool, call_args], sort_keys=True, default=str).encode()).hexdigest()[:10]}"
                                    )
                        except RepeatToolLoopError as exc:
                            job["ok"], job["obs"] = False, {"error": f"{exc}. Change strategy."}
                        except ToolGuardrailTripwireError:
                            raise
                        except Exception as exc:
                            job["ok"], job["obs"] = False, {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}
                        prepared_jobs.append(job)

                    runnable = [j for j in prepared_jobs if j["obs"] is None and j["step_id"] is not None]
                    if runnable:
                        def _exec_read_job(j: Dict[str, Any]) -> Tuple[bool, Any]:
                            try:
                                cp = self.engine.execute_step(
                                    run_id=mission_id,
                                    step_id=j["step_id"],
                                    step_index=turn * 10 + j["sub_idx"],
                                    tool_name=f"ws.{j['tool']}",
                                    args=j["call_args"],
                                    state={"mission_id": mission_id},
                                    lease_epoch=epoch,
                                    envelope=envelope,
                                )
                                return True, cp["output"]
                            except Exception as exc:
                                return False, {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}

                        max_w = min(max(1, int(parallel_read_workers)), len(runnable))
                        with ThreadPoolExecutor(max_workers=max_w) as pool:
                            futures = [pool.submit(_exec_read_job, j) for j in runnable]
                            for j, fut in zip(runnable, futures):
                                j["ok"], j["obs"] = fut.result()

                    for j in prepared_jobs:
                        tool = j["tool"]
                        call_args = j["call_args"]
                        ok, obs = j["ok"], j["obs"]
                        if j["cache_key"] is not None and isinstance(obs, dict) and not obs.get("error") and not obs.get("simhash_cache_hit"):
                            read_cache.put(j["cache_key"], dict(obs))
                        if isinstance(obs, dict) and call_args is not None:
                            try:
                                post_notes = self.hook_engine.run_post(tool, call_args, obs, ws.ws)
                                if post_notes:
                                    obs["hook_annotations"] = post_notes
                                guard_dec = self.hook_engine.run_output_guardrails(tool, call_args, obs, ws.ws)
                                if guard_dec.redacted_obs is not None:
                                    obs = guard_dec.redacted_obs
                                if guard_dec.behavior == "reject_content":
                                    ok = False
                                    if not isinstance(obs, dict) or "error" not in obs:
                                        obs = {"error": f"Output guardrail rejected tool output: {guard_dec.reason}"}
                            except ToolGuardrailTripwireError:
                                raise
                        ok, chunk = _finalize_tool_result(
                            j["sub_idx"], tool, j["args"], j["tc_id"], call_args, ok, obs, len(batch)
                        )
                        turn_tools_executed += 1
                        if ok:
                            turn_progress = True
                        turn_obs_chunks.append(chunk)
                        if j["native_cid"]:
                            native_tool_results[j["native_cid"]] = (tool, chunk)
                    continue

                # ---- Sequential segment execution ----
                for sub_idx, tool, args, native_cid in seg_items:
                    if tool == "finish":
                        if verify_cmd and turn < max_turns:
                            v_pre = ws.run({"command": verify_cmd, "timeout_s": 600})
                            if v_pre["exit_code"] != 0:
                                from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

                                diag = DeterministicTaskOffloader.parse_pytest_output(v_pre["output"])
                                diag_note = (
                                    f"\nSTRUCTURED_DIAGNOSIS: {json.dumps(diag, ensure_ascii=False)}"
                                    if diag.get("failures")
                                    else ""
                                )
                                reject_finish_msg = (
                                    f"FINISH REJECTED: acceptance command '{verify_cmd}' failed "
                                    f"(exit_code={v_pre['exit_code']}). Fix the failure before calling finish:\n"
                                    f"{v_pre['output'][-2000:]}{diag_note}"
                                )
                                if native_cid:
                                    native_tool_results[native_cid] = (tool, reject_finish_msg)
                                break
                            pre_verification = {
                                "command": verify_cmd,
                                "exit_code": v_pre["exit_code"],
                                "passed": True,
                                "output_tail": v_pre["output"][-2500:],
                            }
                        summary = str(args.get("summary", ""))
                        if enable_self_review_gate and turn < max_turns and execution_mode.strip().lower() != "plan":
                            cur_snap = ws.snapshot()
                            mutated_py = [
                                p for p in cur_snap
                                if p.endswith(".py") and (p not in before or cur_snap[p] != before[p])
                            ]
                            if mutated_py:
                                sr_gate = self.run_self_review_diff_gate(ws.ws, mutated_py_files=mutated_py)
                                if not sr_gate["ok"]:
                                    reject_finish_msg = (
                                        f"FINISH REJECTED (Self-Review Diff Gate): syntax_ok={sr_gate['syntax_ok']}, "
                                        f"shield_grade={sr_gate['shield_grade']}, "
                                        f"syntax_errors={sr_gate['syntax_errors'][:3]}, "
                                        f"edge_bugs={sr_gate.get('edge_bugs', [])[:3]}. Fix before calling finish."
                                    )
                                    if native_cid:
                                        native_tool_results[native_cid] = (tool, reject_finish_msg)
                                    break
                        if output_schema is not None:
                            candidate_out = args.get("output")
                            if candidate_out is None and summary.strip().startswith(("{", "[")):
                                try:
                                    candidate_out = json.loads(summary)
                                except Exception:
                                    candidate_out = None
                            schema_err = self._validate_output_schema(candidate_out, output_schema)
                            if schema_err and turn < max_turns:
                                reject_finish_msg = (
                                    f"FINISH REJECTED (ModelRetry): output_schema validation failed: {schema_err}. "
                                    "Include a valid JSON object under args['output'] matching the required schema."
                                )
                                if native_cid:
                                    native_tool_results[native_cid] = (tool, reject_finish_msg)
                                break
                            if not schema_err:
                                structured_output = candidate_out
                        try:
                            c = float(args.get("confidence"))
                            confidence = c if 0.0 <= c <= 1.0 else None
                        except (TypeError, ValueError):
                            confidence = None
                        stop_reason = "finish"
                        should_break_loop = True
                        break

                    if tool == "handoff_agent":
                        target_role = str(args.get("target_role", "")).strip()
                        reason = str(args.get("reason", "specialist handoff")).strip()
                        context_note = str(args.get("context_note", "")).strip()
                        if target_role not in ROLE_TOOL_SCOPES:
                            ok, obs = False, {"error": f"Unknown target_role '{target_role}'. Valid: {sorted(ROLE_TOOL_SCOPES)}"}
                        else:
                            prev_role = active_role
                            active_role = target_role
                            new_base = SPARC_SYSTEM_PROMPT if (workflow or "").lower() == "sparc" else SYSTEM_PROMPT
                            new_base = self._compose_system_prompt(new_base, objective, role=active_role, native_tools=native_tools_active)
                            messages[0]["content"] = self.persona_mgr.inject_persona(new_base, active_role)
                            if native_tools_active:
                                native_tools = build_native_tool_schemas(
                                    objective=objective,
                                    role=active_role,
                                    execution_mode=execution_mode,
                                    mcp_schemas=mcp_schemas,
                                )
                            bus.emit(
                                AGUIEventType.CUSTOM,
                                name="AGENT_HANDOFF",
                                from_role=prev_role,
                                to_role=active_role,
                                reason=reason,
                                turn=turn,
                            )
                            ok = True
                            obs = {
                                "ok": True,
                                "handoff": {"from_role": prev_role, "to_role": active_role, "reason": reason},
                                "note": f"[HANDOFF_CONTEXT] Switched from {prev_role} to {active_role}: {context_note or reason}",
                            }
                        turn_tools_executed += 1
                        if ok:
                            turn_progress = True
                        tool_log.append({"turn": turn, "tool": tool, "args": args, "ok": ok})
                        chunk = clip(json.dumps(obs, ensure_ascii=False, default=str))
                        turn_obs_chunks.append(chunk)
                        if native_cid:
                            native_tool_results[native_cid] = (tool, chunk)
                        continue

                    # --- Take the Wheel: Human Intervention Gate ---
                    if tool == "request_human":
                        human_requests_count += 1
                        if human_requests_count > 3:
                            ok, obs = False, {"error": "Maximum of 3 human intervention requests exceeded for this mission. Continue autonomously."}
                        else:
                            reason = str(args.get("reason", "Human intervention required"))
                            instructions = str(args.get("instructions", "Please inspect workspace and resolve blocker"))
                            bus.emit(
                                AGUIEventType.CUSTOM,
                                name="HUMAN_INTERVENTION_REQUEST",
                                reason=reason,
                                instructions=instructions,
                                turn=turn,
                            )
                            outcome = self.wheel_gate.pause_for_human(
                                mission_id=mission_id,
                                reason=reason,
                                instructions=instructions,
                                turn=turn,
                                timeout_s=effective_wheel_timeout,
                            )
                            if outcome.action == "ABORTED":
                                stop_reason = f"human_abort: {outcome.note}"
                                bus.emit(
                                    AGUIEventType.CUSTOM,
                                    name="HUMAN_INTERVENTION_ABORTED",
                                    note=outcome.note,
                                    paused_seconds=outcome.paused_seconds,
                                )
                                tool_log.append({"turn": turn, "tool": tool, "args": args, "ok": False, "aborted": True})
                                should_break_loop = True
                                break
                            elif outcome.action == "RESUMED":
                                homeo.credit_paused_time(outcome.paused_seconds)
                                bus.emit(
                                    AGUIEventType.CUSTOM,
                                    name="HUMAN_INTERVENTION_RESUMED",
                                    note=outcome.note,
                                    paused_seconds=outcome.paused_seconds,
                                )
                                ok, obs = True, {"status": "RESUMED", "human_note": outcome.note, "paused_seconds": outcome.paused_seconds}
                            else:
                                ok, obs = True, {"status": outcome.action, "note": outcome.note, "paused_seconds": outcome.paused_seconds}

                        turn_tools_executed += 1
                        if ok:
                            turn_progress = True
                        tool_log.append({"turn": turn, "tool": tool, "args": args, "ok": ok})
                        chunk = clip(json.dumps(obs, ensure_ascii=False, default=str))
                        turn_obs_chunks.append(chunk)
                        if native_cid:
                            native_tool_results[native_cid] = (tool, chunk)
                        continue

                    tc_id = native_cid or f"tc-{turn}-{sub_idx}-{tool}"
                    bus.emit(
                        AGUIEventType.TOOL_CALL_START,
                        toolCallId=tc_id,
                        toolName=tool,
                        args_preview=str(args)[:150],
                    )
                    bus.emit(
                        AGUIEventType.TOOL_CALL_ARGS,
                        toolCallId=tc_id,
                        args=args,
                    )

                    ok, obs = True, None
                    call_args = None
                    event_stream_buf.append({"kind": "action", "turn": turn, "tool": tool, "args": args})

                    # v8.0 Dynamic first-class MCP tool dispatch (`mcp__<server>__<tool>`)
                    if tool in mcp_routing:
                        srv_name, orig_tool = mcp_routing[tool]
                        try:
                            self.assert_tool_allowed_in_mode("mcp_call", execution_mode)
                            breaker.record_and_check(tool, args)
                            call_args = {"action": "call", "server": srv_name, "tool": orig_tool, "arguments": dict(args)}
                            pre_dec = self.hook_engine.run_pre(tool, call_args, ws.ws)
                            if not pre_dec.allowed:
                                ok, obs = False, {"error": pre_dec.reason, "blocked_by_hook": True}
                            else:
                                step_id = f"t{turn}-{sub_idx}-{hashlib.sha256(json.dumps([tool, call_args], sort_keys=True, default=str).encode()).hexdigest()[:10]}"
                                cp = self.engine.execute_step(
                                    run_id=mission_id,
                                    step_id=step_id,
                                    step_index=turn * 10 + sub_idx,
                                    tool_name="ws.mcp_call",
                                    args=call_args,
                                    state={"mission_id": mission_id},
                                    lease_epoch=epoch,
                                    envelope=envelope,
                                )
                                obs = cp["output"]
                                read_cache._entries.clear()
                                if isinstance(obs, dict):
                                    if obs.get("ok") is False:
                                        ok = False
                                    post_notes = self.hook_engine.run_post(tool, call_args, obs, ws.ws)
                                    if post_notes:
                                        obs["hook_annotations"] = post_notes
                                    self._attach_visual_som_recovery(self.llm, tool, args, obs)
                                    guard_dec = self.hook_engine.run_output_guardrails(tool, call_args, obs, ws.ws)
                                    if guard_dec.redacted_obs is not None:
                                        obs = guard_dec.redacted_obs
                                    if guard_dec.behavior == "reject_content":
                                        ok = False
                                        if not isinstance(obs, dict) or "error" not in obs:
                                            obs = {"error": f"Output guardrail rejected tool output: {guard_dec.reason}"}
                        except RepeatToolLoopError as exc:
                            ok, obs = False, {"error": f"{exc}. Change strategy."}
                        except ToolGuardrailTripwireError:
                            raise
                        except Exception as exc:
                            ok, obs = False, {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}
                    elif tool not in self.TOOL_EFFECTS:
                        ok, obs = False, {"error": f"unknown tool '{tool}'"}
                    else:
                        try:
                            self.assert_tool_allowed_in_mode(tool, execution_mode)
                            breaker.record_and_check(tool, args)
                            call_args = self._prepare_args(tool, args, ws)
                            pre_dec = self.hook_engine.run_pre(tool, call_args, ws.ws)
                            if not pre_dec.allowed:
                                ok, obs = False, {"error": pre_dec.reason, "blocked_by_hook": True}
                            else:
                                cache_key: Optional[str] = None
                                if tool in ("read_file", "search", "repo_map"):
                                    cache_key = json.dumps([tool, call_args], sort_keys=True, default=str)
                                    hit = read_cache.lookup(cache_key)
                                    if hit.get("cache_hit") and isinstance(hit.get("response"), dict):
                                        obs = dict(hit["response"])
                                        obs["simhash_cache_hit"] = True
                                if obs is None:
                                    step_id = f"t{turn}-{sub_idx}-{hashlib.sha256(json.dumps([tool, call_args], sort_keys=True, default=str).encode()).hexdigest()[:10]}"
                                    cp = self.engine.execute_step(run_id=mission_id, step_id=step_id, step_index=turn * 10 + sub_idx, tool_name=f"ws.{tool}",
                                                                  args=call_args, state={"mission_id": mission_id}, lease_epoch=epoch, envelope=envelope)
                                    obs = cp["output"]
                                    if cache_key is not None and isinstance(obs, dict) and not obs.get("error"):
                                        read_cache.put(cache_key, dict(obs))
                                    elif self.TOOL_EFFECTS.get(tool) != EffectClass.PURE_READ:
                                        read_cache._entries.clear()
                                if isinstance(obs, dict):
                                    if ok and tool in ("write_file", "replace_in_file") and call_args:
                                        edited_p = Path(str(call_args.get("path", "")))
                                        if edited_p.suffix.lower() == ".py" and edited_p.is_file():
                                            from am_ua.execution.deterministic_offloader import DeterministicTaskOffloader

                                            fix_res = DeterministicTaskOffloader.code_autofix_and_lint(
                                                ws.ws, target=str(edited_p), apply_fix=False
                                            )
                                            obs["auto_lint"] = {
                                                "ok": fix_res.get("ok"),
                                                "backend": fix_res.get("backend"),
                                            }
                                    post_notes = self.hook_engine.run_post(tool, call_args, obs, ws.ws)
                                    if post_notes:
                                        obs["hook_annotations"] = post_notes
                                    self._attach_visual_som_recovery(self.llm, tool, args, obs)
                                    guard_dec = self.hook_engine.run_output_guardrails(tool, call_args, obs, ws.ws)
                                    if guard_dec.redacted_obs is not None:
                                        obs = guard_dec.redacted_obs
                                    if guard_dec.behavior == "reject_content":
                                        ok = False
                                        if not isinstance(obs, dict) or "error" not in obs:
                                            obs = {"error": f"Output guardrail rejected tool output: {guard_dec.reason}"}
                                if tool == "run" and isinstance(obs, dict) and obs.get("exit_code") not in (0, None):
                                    ok = True  # a failing command is still valid information
                        except RepeatToolLoopError as exc:
                            ok, obs = False, {"error": f"{exc}. Change strategy."}
                        except ToolGuardrailTripwireError:
                            raise
                        except Exception as exc:  # gate violations, bad args, IO errors -> feed back to the model
                            ok, obs = False, {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}

                    ok, chunk = _finalize_tool_result(sub_idx, tool, args, tc_id, call_args, ok, obs, len(batch))
                    turn_tools_executed += 1
                    if ok:
                        turn_progress = True
                    turn_obs_chunks.append(chunk)
                    if native_cid:
                        native_tool_results[native_cid] = (tool, chunk)

            if should_break_loop:
                break
            stuck_verdict = stuck_detector.analyze(stuck_events_log)
            stuck_note = (
                f"[STUCK_DETECTOR_NUDGE ({stuck_verdict.loop_type}): {stuck_verdict.recovery_nudge}]"
                if (stuck_verdict.is_stuck and stuck_verdict.recovery_nudge)
                else ""
            )
            edit_nudge = self._build_anti_stagnation_edit_nudge(
                turn=turn,
                max_turns=max_turns,
                tool_log=tool_log,
                verify_cmd=verify_cmd,
                execution_mode=execution_mode,
            )
            if edit_nudge:
                stuck_note = f"{stuck_note}\n{edit_nudge}".strip() if stuck_note else edit_nudge

            if used_native_tool_turn:
                for t_name, _t_args, t_cid in batch:
                    if not t_cid:
                        continue
                    r_name, r_content = native_tool_results.get(
                        t_cid, (t_name, "Skipped due to earlier control/finish rejection in same turn.")
                    )
                    messages.append({"role": "tool", "tool_call_id": t_cid, "name": r_name, "content": r_content})
                if stuck_note:
                    messages.append({"role": "user", "content": stuck_note})
                made_prog = False if reject_finish_msg is not None else turn_progress
                try:
                    homeo.record_turn_cost(tokens=resp.total_tokens, tool_calls=max(1, turn_tools_executed), made_verified_progress=made_prog)
                except ResourceExhaustedError as exc:
                    stop_reason = f"budget: {exc}"
                    break
                continue

            if stuck_note:
                turn_obs_chunks.append(stuck_note)
            if reject_finish_msg is not None:
                obs_head = ("\n".join(turn_obs_chunks) + "\n\n") if turn_obs_chunks else ""
                messages.append({"role": "user", "content": obs_head + reject_finish_msg})
                try:
                    homeo.record_turn_cost(tokens=resp.total_tokens, tool_calls=max(1, turn_tools_executed), made_verified_progress=False)
                except ResourceExhaustedError as exc:
                    stop_reason = f"budget: {exc}"
                    break
                continue

            messages.append({"role": "user", "content": "OBSERVATION:\n" + "\n".join(turn_obs_chunks)})
            try:
                homeo.record_turn_cost(tokens=resp.total_tokens, tool_calls=max(1, turn_tools_executed), made_verified_progress=turn_progress)
            except ResourceExhaustedError as exc:
                stop_reason = f"budget: {exc}"
                break

        # ---------------- verification (executable oracle first, judge second)
        verification = pre_verification
        if verify_cmd:
            if verification is None:
                v = ws.run({"command": verify_cmd, "timeout_s": 600})
                verification = {"command": verify_cmd, "exit_code": v["exit_code"], "passed": v["exit_code"] == 0, "output_tail": v["output"][-2500:]}
            bus.emit(
                AGUIEventType.CUSTOM,
                name="VERIFICATION",
                exit_code=verification["exit_code"],
                passed=verification["passed"],
            )

        after = ws.snapshot()
        changed = sorted(k for k in set(before) | set(after) if before.get(k, ("", None))[0] != after.get(k, ("", None))[0])
        diff = self._diff(before, after, changed)

        judge = None
        if use_judge and stop_reason == "finish":
            judge = self._judge(objective, summary, diff, verification, exclude=providers_used)

        if stop_reason != "finish":
            status = "BUDGET_EXHAUSTED" if stop_reason.startswith(("budget", "max_turns")) else "ABORTED"
        elif verification is not None:
            status = "VERIFIED" if verification["passed"] else "FAILED"
        else:
            status = "COMPLETED_UNVERIFIED"
        if verification is not None and status in ("BUDGET_EXHAUSTED", "ABORTED") and verification["passed"]:
            status = "VERIFIED_AFTER_BUDGET"
        tag = EpistemicTag.PROVADO if status.startswith("VERIFIED") else (
            EpistemicTag.INFERIDO if status == "COMPLETED_UNVERIFIED" else EpistemicTag.BLOQUEADO)

        brier = None
        if self.calibration is not None and verification is not None and confidence is not None:
            brier = self.calibration.record(domain=domain, task_id=mission_id, predicted_conf=confidence, actual_pass=verification["passed"])

        if status.startswith("VERIFIED") or status == "COMPLETED_UNVERIFIED":
            bus.emit(
                AGUIEventType.RUN_FINISHED,
                status=status,
                epistemic_tag=tag.value,
                brier_score=brier,
                changed_files=changed,
            )
        else:
            bus.emit(
                AGUIEventType.RUN_ERROR,
                status=status,
                stop_reason=stop_reason,
            )

        pre_critic = self.evaluate_pre_critic(
            objective=objective,
            stop_reason=stop_reason,
            changed_files=changed,
            diff=diff,
            verification=verification,
            tool_calls=tool_log,
        )
        if enable_dlp_supervisor and summary:
            from am_ua.execution.hook_engine import ParallelPolicySupervisor

            sup_verdict = ParallelPolicySupervisor(block_on_pii=False).audit_parallel(summary)
            if sup_verdict.pii_hits:
                summary = sup_verdict.redacted_text
        if sync_todo_anchor:
            final_task_st = "done" if status.startswith("VERIFIED") or status == "COMPLETED_UNVERIFIED" else "failed"
            self.sync_todo_anchor(ws.ws, objective, [{"id": "m1", "title": objective[:120], "status": final_task_st}])
        if (auto_compile_skill or auto_compile_playbook) and status in ("VERIFIED", "COMPLETED_UNVERIFIED"):
            good_steps = [
                {"tool": t["tool"], "args": t.get("args", {}), "ok": True}
                for t in tool_log
                if t.get("ok") and t.get("tool") not in ("finish", "request_human")
            ]
            if good_steps:
                if auto_compile_skill:
                    try:
                        skill_slug = re.sub(r"[^a-z0-9_]+", "_", mission_id.lower()).strip("_")[:48]
                        ws._skill_forge.compile_trajectory_to_skill(
                            name=f"sop_{skill_slug}",
                            description=f"Auto-compiled SOP from verified mission: {objective[:120]}",
                            trajectory_steps=good_steps[:12],
                        )
                    except Exception:
                        pass
                if auto_compile_playbook:
                    try:
                        from am_ua.execution.playbook_compiler import TraceToPlaybookCompiler

                        pb_slug = re.sub(r"[^a-z0-9_]+", "_", mission_id.lower()).strip("_")[:48]
                        TraceToPlaybookCompiler().compile_trace(
                            name=f"compiled_{pb_slug}",
                            objective=objective,
                            tool_calls=good_steps[:12],
                            verification=verification,
                        )
                    except Exception:
                        pass
        for t_rec in tool_log:
            event_stream_buf.append({"kind": "observation", "turn": t_rec.get("turn"), "tool": t_rec.get("tool"), "ok": t_rec.get("ok")})
        result = AgentRunResult(
            mission_id=mission_id, objective=objective, workspace=str(ws.ws), status=status, epistemic_tag=tag.value,
            final_summary=summary, actor_confidence=confidence, actor_providers=providers_used, turns=turn,
            tool_calls=tool_log, verification=verification, judge=judge, changed_files=changed, diff=clip(diff, 20000),
            tokens={"prompt": self.llm.total_prompt_tokens - pt0, "completion": self.llm.total_completion_tokens - ct0},
            llm_calls=self.llm.calls - calls0, elapsed_s=round(time.perf_counter() - t_start, 2), stop_reason=stop_reason,
            brier_score=None if brier is None else round(brier, 5),
            role=active_role, workflow=workflow,
            event_ledger_path=ledger_path_str,
            pre_critic=pre_critic,
            structured_output=structured_output,
        )
        if self.trace_dir is not None:
            self.trace_dir.mkdir(parents=True, exist_ok=True)
            tp = self.trace_dir / f"{mission_id}.json"
            tp.write_text(json.dumps({**asdict(result), "messages": messages}, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
            self.export_event_stream(event_stream_buf, self.trace_dir / f"{mission_id}_events.jsonl")
            result.trace_path = str(tp)
        if self.reasoning_bank is not None:
            self.reasoning_bank.record_run(asdict(result))
        if enable_memory_prefetch and self.memory_provider is not None and hasattr(self.memory_provider, "sync_turn"):
            try:
                if status.startswith("VERIFIED") or status == "COMPLETED_UNVERIFIED":
                    self.memory_provider.sync_turn(objective, f"[{status}] {summary[:400]}", session_id=mission_id)
            except Exception:
                pass
        if created_local_bus:
            bus.close()
        ws.close()
        self._active = None
        return result

    # ------------------------------------------------------------------ helpers
    _validate_output_schema = staticmethod(_lp_validate_output_schema)
    evaluate_pre_critic = staticmethod(_lp_evaluate_pre_critic)

    @staticmethod
    def _attach_visual_som_recovery(llm: Any, tool: str, args: Dict[str, Any], obs: Dict[str, Any]) -> None:
        if tool not in ("browser_act", "pc_act"):
            return
        rec = obs.get("receipt") if isinstance(obs.get("receipt"), dict) else {}
        unchanged = (rec.get("visual_state_changed") is False) or (obs.get("ok") is False)
        img_p = (
            rec.get("visual_screenshot_path")
            or obs.get("som_screenshot_path")
            or rec.get("annotated_screenshot_path")
        )
        if unchanged and img_p and hasattr(llm, "chat_multimodal") and Path(str(img_p)).is_file():
            try:
                vlm_resp = llm.chat_multimodal(
                    f"UI action '{tool}' ({args}) did not verify a visual state change. Inspect this Set-of-Mark screenshot and suggest next locator/idx or diagnosis.",
                    str(img_p),
                    max_tokens=300,
                    json_mode=False,
                )
                obs["vlm_som_recovery_hint"] = str(getattr(vlm_resp, "text", ""))[:500]
            except Exception:
                pass

    @staticmethod
    def _build_anti_stagnation_edit_nudge(
        *,
        turn: int,
        max_turns: int,
        tool_log: Sequence[Dict[str, Any]],
        verify_cmd: Optional[str],
        execution_mode: str = "act",
    ) -> str:
        """Emit a mid-budget edit nudge if no `replace_in_file` has succeeded by half-budget."""
        if not verify_cmd or execution_mode.strip().lower() == "plan" or max_turns < 8:
            return ""
        half = max(6, max_turns // 2)
        checkpoints = (half, max(half + 1, max_turns - 3))
        if turn not in checkpoints:
            return ""
        if any(bool(e.get("ok")) and e.get("tool") == "replace_in_file" for e in tool_log):
            return ""
        return (
            f"[ANTI_STAGNATION_EDIT_NUDGE: Turn {turn}/{max_turns} reached with 0 source edits via "
            f"replace_in_file. Stop read-only exploration/scratch scripts now: apply the minimal targeted "
            f"fix to the repository source file with replace_in_file and run verify_cmd.]"
        )

    @staticmethod
    def _condense(messages: List[Dict[str, Any]], max_chars: int = 45_000) -> List[Dict[str, Any]]:
        """Cache-friendly half-window tombstone condensation preserving atomic assistant/tool_calls groups."""
        total = sum(_msg_char_len(m) for m in messages)
        if total <= max_chars or len(messages) <= 8:
            return messages

        head = list(messages[:2])
        tail_start = max(2, len(messages) - 6)
        # Never slice tail starting inside a role='tool' response group (breaks OpenAI/Anthropic API contracts)
        while tail_start > 2 and messages[tail_start].get("role") == "tool":
            tail_start -= 1
        tail = list(messages[tail_start:])
        middle = list(messages[2:tail_start])

        while middle and (sum(_msg_char_len(m) for m in head + middle + tail) > max_chars):
            c0 = str(middle[0].get("content") or "")
            if len(middle) == 1 and c0.startswith("[CONDENSATION_TOMBSTONE"):
                break
            starts_with_tombstone = c0.startswith("[CONDENSATION_TOMBSTONE")
            min_evict = 2 if (starts_with_tombstone and len(middle) >= 2) else 1
            half = max(min_evict, len(middle) // 2)
            # Keep assistant+tool_calls pairs atomic when evicting from middle
            while half < len(middle) and middle[half].get("role") == "tool":
                half += 1
            evicted = middle[:half]
            middle = middle[half:]
            markers: List[str] = []
            compacted_chars = 0
            covered = 0
            for m in evicted:
                c = str(m.get("content") or "")
                compacted_chars += _msg_char_len(m)
                m_prev = re.match(r"\[CONDENSATION_TOMBSTONE covered_messages=(\d+)", c)
                covered += int(m_prev.group(1)) if m_prev else 1
                for ln in c.splitlines():
                    if ln.startswith("[PINNED STATE:"):
                        inner = ln[len("[PINNED STATE:"):].rstrip("]").strip()
                        if inner and inner not in markers:
                            markers.append(inner[:140])
                    elif any(k in ln for k in ('"written":', '"replaced_in":', '"replaced":', '"exit_code":', '"checkpoint":', '"error":')):
                        s_ln = ln.strip()[:140]
                        if s_ln not in markers:
                            markers.append(s_ln)
            pin_note = f"[PINNED STATE: {' | '.join(markers[:5])}]" if markers else "[PINNED STATE: none]"
            tombstone = {
                "role": "user",
                "content": f"[CONDENSATION_TOMBSTONE covered_messages={covered} chars_compacted={compacted_chars}]\n{pin_note}",
            }
            middle = [tombstone] + middle
            if len(middle) == 1:
                break

        return head + middle + tail

    @staticmethod
    def _diff(before: Dict[str, Tuple[str, Optional[str]]], after: Dict[str, Tuple[str, Optional[str]]], changed: List[str]) -> str:
        chunks: List[str] = []
        for rel in changed[:40]:
            a = (before.get(rel) or ("", ""))[1]
            b = (after.get(rel) or ("", ""))[1]
            if a is None or b is None:
                chunks.append(f"--- {rel} (binary changed)")
                continue
            chunks.extend(difflib.unified_diff(a.splitlines(), b.splitlines(), f"a/{rel}", f"b/{rel}", lineterm="", n=2))
        return "\n".join(chunks)

    def _judge(self, objective: str, summary: str, diff: str, verification: Optional[Dict[str, Any]], *, exclude: List[str]) -> Dict[str, Any]:
        content = (f"OBJECTIVE:\n{objective}\n\nAGENT SUMMARY (untrusted claim):\n{summary}\n\nDIFF:\n{clip(diff, 14000) or '(no file changes)'}\n\n"
                   f"ACCEPTANCE CHECK: {json.dumps(verification) if verification else 'none provided'}")
        msgs = [{"role": "system", "content": JUDGE_PROMPT}, {"role": "user", "content": content}]
        independent = any(p not in exclude for p in self.llm.available())
        try:
            r = self.llm.chat(msgs, max_tokens=1500, temperature=0.0, json_mode=True, exclude=exclude if independent else None)
            obj = extract_json_object(r.text)
            verdict = str(obj.get("verdict", "UNSURE")).upper()
            return {"provider": r.provider, "model": r.model, "independent_provider": r.provider not in exclude,
                    "verdict": verdict if verdict in ("PASS", "FAIL", "UNSURE") else "UNSURE",
                    "confidence": obj.get("confidence"), "reasons": obj.get("reasons", [])[:6]}
        except Exception:
            try:
                r = self.llm.chat(msgs, max_tokens=1500, temperature=0.0, json_mode=True, exclude=None)
                obj = extract_json_object(r.text)
                verdict = str(obj.get("verdict", "UNSURE")).upper()
                return {"provider": r.provider, "model": r.model, "independent_provider": False,
                        "verdict": verdict if verdict in ("PASS", "FAIL", "UNSURE") else "UNSURE",
                        "confidence": obj.get("confidence"), "reasons": obj.get("reasons", [])[:6]}
            except Exception as exc:
                return {"verdict": "UNAVAILABLE", "error": f"{type(exc).__name__}: {str(exc)[:200]}", "independent_provider": False}

    def resolve_via_best_of_n_worktrees(
        self,
        workspace: Path | str,
        candidates: Sequence[Dict[str, Any]],
        verify_fn: Callable[[Path], Tuple[bool, str]],
        *,
        objective: str = "Best-of-N candidate verification",
        apply_winner: bool = True,
    ) -> Dict[str, Any]:
        """Execute multi-hypothesis candidate mutations in isolated worktrees via BehaviorBestOfNEngine."""
        from am_ua.execution.best_of_n import BehaviorBestOfNEngine

        cand_list = list(candidates)
        if not cand_list:
            return {"ok": False, "error": "candidates must be non-empty"}

        def _runner(cand_ws: Path, idx: int) -> Dict[str, Any]:
            spec = cand_list[max(0, min(len(cand_list) - 1, idx - 1))]
            changed: List[str] = []
            for rel, content in (spec.get("files") or {}).items():
                dst = (cand_ws / str(rel)).resolve()
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(str(content), encoding="utf-8", newline="\n")
                changed.append(str(rel))
            passed, note = verify_fn(cand_ws)
            return {
                "status": "VERIFIED" if passed else "FAILED",
                "verification": {"passed": bool(passed), "note": note},
                "turns": 1,
                "changed_files": changed,
                "diff": "\n".join(changed),
                "final_summary": note,
            }

        bo_res = BehaviorBestOfNEngine(llm=self.llm).run_code_best_of_n(
            objective=objective,
            workspace=workspace,
            runner_fn=_runner,
            n=len(cand_list),
            use_llm_judge=False,
            parallel=len(cand_list) > 1,
            post_sync_verify_fn=(lambda ws_p: bool(verify_fn(ws_p)[0])) if apply_winner else None,
        )
        return {
            "ok": bool(bo_res.get("winner_candidate_id")) and bool(bo_res.get("winner_passed_oracle")) and not bool(bo_res.get("rolled_back")),
            "best_of_n": bo_res,
        }

    def run_live_best_of_n(
        self,
        objective: str,
        workspace: Path | str,
        *,
        verify_cmd: str,
        n: int = 3,
        max_turns: int = 25,
        early_stop_on_first_verified: bool = True,
        use_judge: bool = False,
        ace_context_rules: Optional[str] = None,
        post_sync_verify_fn: Optional[Callable[[Path], bool]] = None,
    ) -> Dict[str, Any]:
        """Run up to `n` diverse live AgentLoop trajectories in isolated sandboxes with PYTHONPATH isolation and post-mortem escalation."""
        import os
        from am_ua.execution.best_of_n import BehaviorBestOfNEngine

        strategies: Tuple[Tuple[str, str], ...] = (
            ("react", "general_engineer"),
            ("sparc", "tdd_enforcer"),
            ("hierarchical", "build_error_resolver"),
            ("react", "tdd_enforcer"),
            ("sparc", "general_engineer"),
        )
        avail_provs = list(self.llm.available()) if self.llm and hasattr(self.llm, "available") else []
        prov_schedule: List[Optional[str]] = []
        for p in ("groq", "gemini", "openrouter", "cerebras", "nvidia"):
            if p in avail_provs:
                prov_schedule.append(p)
        for p in avail_provs:
            if p not in prov_schedule:
                prov_schedule.append(p)
        prior_notes: List[str] = []
        run_records: List[AgentRunResult] = []
        target_ws = Path(workspace).resolve()

        def _live_runner(cand_ws: Path, idx: int) -> AgentRunResult:
            wf, rl = strategies[(idx - 1) % len(strategies)]
            pref_prov = prov_schedule[(idx - 1) % len(prov_schedule)] if prov_schedule else None
            cand_obj = objective
            if prior_notes:
                cand_obj += (
                    "\n\n[PRIOR ATTEMPT POST-MORTEM — DO NOT REPEAT FAILED APPROACH]\n"
                    + "\n".join(prior_notes[-2:])
                )
            old_pypath = os.environ.get("PYTHONPATH")
            py_parts = [str(cand_ws / "src"), str(cand_ws)] if (cand_ws / "src").is_dir() else [str(cand_ws)]
            if old_pypath:
                py_parts.append(old_pypath)
            os.environ["PYTHONPATH"] = os.pathsep.join(py_parts)
            try:
                cand_engine = DurableExecutionEngine(cand_ws.parent / f"{cand_ws.name}_durable.db")
                cand_loop = AgentLoop(
                    engine=cand_engine,
                    seal_guard=self.seal_guard,
                    llm=self.llm,
                    pc_engine=self.pc_engine,
                    skill_forge=self.skill_forge,
                )
                res = cand_loop.run(
                    objective=cand_obj,
                    workspace=cand_ws,
                    verify_cmd=verify_cmd,
                    max_turns=max_turns,
                    actor_provider=pref_prov,
                    workflow=wf,
                    role=rl,
                    use_judge=use_judge,
                    ace_context_rules=ace_context_rules,
                )
            finally:
                if old_pypath is None:
                    os.environ.pop("PYTHONPATH", None)
                else:
                    os.environ["PYTHONPATH"] = old_pypath

            run_records.append(res)
            passed = bool(res.verification and res.verification.get("passed"))
            if not passed:
                prior_notes.append(
                    f"- Attempt {idx} ({wf}/{rl}) ended with status={res.status} turns={res.turns} changed={res.changed_files}: {str(res.final_summary)[:220]}"
                )
            return res

        bo_res = BehaviorBestOfNEngine(llm=self.llm).run_code_best_of_n(
            objective=objective,
            workspace=target_ws,
            runner_fn=_live_runner,
            n=n,
            early_stop_on_first_verified=early_stop_on_first_verified,
            use_llm_judge=False,
            parallel=not early_stop_on_first_verified,
            post_sync_verify_fn=post_sync_verify_fn,
        )
        agg_prompt = sum(int(r.tokens.get("prompt", 0)) for r in run_records)
        agg_comp = sum(int(r.tokens.get("completion", 0)) for r in run_records)
        agg_turns = sum(int(r.turns) for r in run_records)
        agg_calls = sum(int(r.llm_calls) for r in run_records)
        provs: List[str] = []
        for r in run_records:
            for p in r.actor_providers:
                if p not in provs:
                    provs.append(p)
        return {
            "ok": bool(bo_res.get("winner_passed_oracle")) and not bool(bo_res.get("rolled_back")),
            "best_of_n": bo_res,
            "attempts_run": len(run_records),
            "turns_total": agg_turns,
            "llm_calls_total": agg_calls,
            "tokens_total": {"prompt": agg_prompt, "completion": agg_comp},
            "providers": provs,
            "last_status": run_records[-1].status if run_records else "NONE",
        }
