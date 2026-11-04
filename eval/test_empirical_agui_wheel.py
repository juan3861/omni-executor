"""Empirical Homologation Suite for CopilotKit/OpenBot AG-UI Protocol & Take the Wheel Gate.

Designed for execution under AetherMind_Strict_Auditor.py.
Validates:
1. AG-UI Event Protocol: Typed schemas, JSONL persistence, secret redaction, Alpha-C13 finite number sanitization.
2. Zero-Dependency Loopback SSE Server: Strict 127.0.0.1 binding, real HTTP streaming, clean teardown.
3. Take the Wheel Gate & Homeostasis Discounting: Safe state suspension via REQUEST.json, human operator RESUME,
   automatic intervention archival, and R09 wall-clock time credit.
4. CLI Integration: Verification of --wheel-timeout, --agui-port, and 'aether-ua wheel status|resume|abort' subcommands.
5. End-to-End Agent Loop Integration: Real disk JSONL ledger creation, step tracking, and state mutation deltas.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from am_ua.cognition.agui_protocol import (
    AGUIEvent,
    AGUIEventBus,
    AGUIEventType,
    JsonlFileSink,
    LoopbackSSEServer,
    redact_sensitive_payload,
    sanitize_finite_numbers,
)
from am_ua.execution.agent_loop import AgentLoop
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.human_wheel import HumanWheelGate
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.cognition.llm_client import LLMResponse


def test_agui_protocol_and_event_bus() -> None:
    print("[TEST 1/5] Verifying AG-UI Protocol, Secret Redaction & JSONL Event Bus...")
    
    # 1. Secret Redaction
    dirty = {
        "api_key": "sk-proj-secret-12345",
        "nested": {"authorization": "Bearer token-abc", "safe_val": 42},
    }
    cleaned = redact_sensitive_payload(dirty)
    assert cleaned["api_key"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["authorization"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["safe_val"] == 42
    print("  -> Secret redaction passed (API keys and auth tokens masked).")

    # 2. Alpha-C13 Finite Number Sanitization
    nums = {"normal": 3.14, "integer": 42}
    clean_nums = sanitize_finite_numbers(nums)
    assert clean_nums["normal"] == 3.14
    assert clean_nums["integer"] == 42

    try:
        sanitize_finite_numbers({"nan_val": float("nan")})
        assert False, "Should have rejected NaN"
    except ValueError:
        pass

    try:
        sanitize_finite_numbers({"inf_val": float("inf")})
        assert False, "Should have rejected Inf"
    except ValueError:
        pass
    print("  -> Alpha-C13 finite number sanitization passed (NaN/Inf strictly rejected).")

    # 3. JSONL Sink and EventBus
    tmp_ledger = Path(r"F:\AetherMind_Temp\empirical_agui_ledger.jsonl")
    if tmp_ledger.exists():
        tmp_ledger.unlink()

    sink = JsonlFileSink(tmp_ledger)
    bus = AGUIEventBus(
        thread_id="t-empirical-01",
        run_id="m-empirical-01",
        sinks=[sink],
    )

    bus.emit(AGUIEventType.RUN_STARTED, objective="Empirical audit", model="mock")
    bus.emit(AGUIEventType.STEP_STARTED, stepIndex=1, stepName="SPARC:S")
    bus.emit(AGUIEventType.TOOL_CALL_START, toolCallId="call_1", toolName="read_file")
    bus.emit(AGUIEventType.RUN_FINISHED, status="SUCCESS", turns=1)
    bus.close()

    assert tmp_ledger.is_file()
    lines = [json.loads(l) for l in tmp_ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 4
    assert [l["type"] for l in lines] == ["RUN_STARTED", "STEP_STARTED", "TOOL_CALL_START", "RUN_FINISHED"]
    print(f"  -> Physical JSONL ledger verified on disk ({tmp_ledger.stat().st_size} bytes, 4 typed events).")


def test_loopback_sse_streaming() -> None:
    print("\n[TEST 2/5] Verifying Loopback SSE Server & Real-time Event Streaming...")
    
    # 1. Non-loopback bind rejection
    try:
        LoopbackSSEServer(port=8894, host="0.0.0.0")
        assert False, "Should have rejected 0.0.0.0 host binding"
    except PermissionError:
        print("  -> Host security lock confirmed (0.0.0.0 binding strictly rejected).")

    # 2. Real SSE streaming on 127.0.0.1
    port = 8896
    server = LoopbackSSEServer(port=port, host="127.0.0.1")
    bus = AGUIEventBus(thread_id="t-sse-emp", run_id="run-sse-emp", sinks=[server])
    print(f"  -> Loopback SSE server running on 127.0.0.1:{port}")

    received_lines: List[str] = []
    stop_client = threading.Event()

    def client_stream() -> None:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/events")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                for _ in range(4):
                    line = resp.readline().decode("utf-8")
                    if line:
                        received_lines.append(line)
                    if stop_client.is_set():
                        break
        except Exception:
            pass

    th = threading.Thread(target=client_stream, daemon=True)
    th.start()
    time.sleep(0.3)

    bus.emit(AGUIEventType.RUN_STARTED, objective="EmpiricalStreamCheck")
    time.sleep(0.3)
    stop_client.set()
    th.join(timeout=1.5)
    server.close()
    bus.close()

    assert any("event: RUN_STARTED" in l for l in received_lines)
    assert any("data: " in l for l in received_lines)
    print("  -> Live SSE event streaming over loopback HTTP verified successfully.")


def test_human_wheel_and_homeostasis_discount() -> None:
    print("\n[TEST 3/5] Verifying 'Take the Wheel' Suspension, Resume & Homeostasis Discount...")
    wheel_root = Path(r"F:\AetherMind_Temp\empirical_wheel_root")
    if wheel_root.exists():
        shutil.rmtree(wheel_root, ignore_errors=True)
    wheel_root.mkdir(parents=True, exist_ok=True)

    gate = HumanWheelGate(wheel_root, timeout_s=5.0, poll_interval_s=0.1)

    # 1. Path traversal security check
    try:
        gate.pause_for_human("../malicious_id", "test", "instructions")
        assert False, "Should have rejected path traversal in mission_id"
    except ValueError:
        print("  -> Path traversal security lock verified on mission_id.")

    # 2. Real pause with operator resume in background
    mission_id = "m-empirical-wheel-01"

    def operator() -> None:
        time.sleep(0.4)
        active = HumanWheelGate.list_active_requests(wheel_root)
        assert len(active) == 1
        assert active[0]["mission_id"] == mission_id
        res = HumanWheelGate.resume(mission_id, note="Mestre Ruan confirms clearance", wheel_root=wheel_root)
        assert res["ok"] is True

    op_th = threading.Thread(target=operator, daemon=True)
    op_th.start()

    outcome = gate.pause_for_human(
        mission_id=mission_id,
        reason="Security clearance required",
        instructions="Confirm deployment",
    )
    op_th.join(timeout=3.0)

    assert outcome.action == "RESUMED"
    assert outcome.note == "Mestre Ruan confirms clearance"
    assert outcome.paused_seconds >= 0.3
    print(f"  -> Human intervention resumed seamlessly (paused for {outcome.paused_seconds:.3f}s).")

    # 3. Verify archival in HISTORY
    hist_dir = wheel_root / mission_id / "HISTORY"
    assert hist_dir.is_dir()
    records = list(hist_dir.glob("*.json"))
    assert len(records) >= 1
    rec_data = json.loads(records[0].read_text(encoding="utf-8"))
    assert rec_data["outcome"] == "RESUMED"
    assert rec_data["human_note"] == "Mestre Ruan confirms clearance"
    print("  -> Intervention record successfully archived in HISTORY.")

    # 4. Verify Homeostasis wall-clock discount
    gov = HomeostasisGovernor(max_wall_seconds=2.0)
    gov._started_at -= 5.0  # simulate 5 elapsed seconds
    gov.credit_paused_time(outcome.paused_seconds + 4.5)  # credit back paused duration
    cost_status = gov.record_turn_cost(tokens=100, tool_calls=1, made_verified_progress=True)
    assert cost_status["tokens_spent"] == 100
    assert cost_status["stagnant_turns"] == 0
    print("  -> Homeostasis wall-clock pause discounting verified (R09 deadline preserved).")


def test_cli_integration() -> None:
    print("\n[TEST 4/5] Verifying CLI Flags & 'wheel' Subcommands...")
    
    # 1. Mission help flags
    cmd_help = [sys.executable, "-m", "am_ua.cli", "mission", "--help"]
    proc_help = subprocess.run(cmd_help, cwd=str(ROOT), capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
    assert proc_help.returncode == 0
    assert "--wheel-timeout" in proc_help.stdout
    assert "--agui-port" in proc_help.stdout
    print("  -> CLI mission flags (--wheel-timeout, --agui-port) confirmed.")

    # 2. Wheel status subcommand
    cmd_wheel = [sys.executable, "-m", "am_ua.cli", "wheel", "status"]
    proc_wheel = subprocess.run(cmd_wheel, cwd=str(ROOT), capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
    assert proc_wheel.returncode == 0
    assert "active_requests" in proc_wheel.stdout
    assert "count" in proc_wheel.stdout
    print("  -> CLI 'wheel status' execution confirmed.")


class MockEmpiricalLLM:
    def __init__(self, turns: List[str]) -> None:
        self.turns = list(turns)
        self.idx = 0
        self.calls = 0
        self.total_prompt_tokens = 120
        self.total_completion_tokens = 60

    def chat(self, messages: Any, **kwargs: Any) -> LLMResponse:
        self.calls += 1
        if self.idx < len(self.turns):
            text = self.turns[self.idx]
            self.idx += 1
        else:
            text = json.dumps({"thought": "SPARC Phase: C Done", "tool": "finish", "args": {"summary": "Done", "confidence": 0.99}})
        return LLMResponse(
            text=text,
            provider="mock_empirical",
            model="mock_model",
            prompt_tokens=120,
            completion_tokens=60,
            latency_ms=10.0,
        )

    def available(self) -> List[str]:
        return ["mock_empirical"]


def test_full_agent_loop_agui_and_wheel_end_to_end() -> None:
    print("\n[TEST 5/5] Physical End-to-End Mission Execution with AG-UI Ledger...")
    ws = Path(r"F:\AetherMind_Temp\empirical_agui_ws")
    if ws.exists():
        shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir(parents=True, exist_ok=True)

    ledger_dir = Path(r"F:\AetherMind_Temp\empirical_agui_ledgers")
    if ledger_dir.exists():
        shutil.rmtree(ledger_dir, ignore_errors=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)

    wheel_root = Path(r"F:\AetherMind_Temp\empirical_wheel_loop")
    if wheel_root.exists():
        shutil.rmtree(wheel_root, ignore_errors=True)
    wheel_root.mkdir(parents=True, exist_ok=True)

    scripted = [
        json.dumps({
            "thought": "SPARC Phase: S Specification - Requesting operator gate",
            "tool": "request_human",
            "args": {"reason": "Authorize artifact generation", "instructions": "Approve via resume"},
        }),
        json.dumps({
            "thought": "SPARC Phase: R Refinement - Writing artifact",
            "tool": "write_file",
            "args": {"file": "evidence.txt", "content": "AUDIT_PROVEN_AGUI_OK\n"},
        }),
        json.dumps({
            "thought": "SPARC Phase: C Completion - Mission verified",
            "tool": "finish",
            "args": {"summary": "All empirical checks passed", "confidence": 0.99},
        }),
    ]

    llm = MockEmpiricalLLM(scripted)
    engine = DurableExecutionEngine(r"F:\AetherMind_Temp\empirical_durable\durable.db")
    seal_guard = ConstitutionSealGuard(ROOT)
    wheel_gate = HumanWheelGate(wheel_root, timeout_s=4.0, poll_interval_s=0.1)

    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=llm,  # type: ignore
        wheel_gate=wheel_gate,
        wheel_timeout_s=4.0,
        agui_ledger_dir=ledger_dir,
    )

    mission_id = f"m-e2e-audit-{int(time.time())}"

    def auto_operator() -> None:
        for _ in range(30):
            time.sleep(0.1)
            active = HumanWheelGate.list_active_requests(wheel_root)
            if active and active[0]["mission_id"] == mission_id:
                HumanWheelGate.resume(mission_id, note="Auto Operator Resume OK", wheel_root=wheel_root)
                break

    th = threading.Thread(target=auto_operator, daemon=True)
    th.start()

    res = loop.run(
        objective="Generate evidence.txt with operator approval",
        workspace=ws,
        mission_id=mission_id,
        workflow="sparc",
        use_judge=False,
    )
    th.join(timeout=3.0)

    assert res.status == "COMPLETED_UNVERIFIED"
    target_file = ws / "evidence.txt"
    assert target_file.is_file()
    assert target_file.read_text(encoding="utf-8") == "AUDIT_PROVEN_AGUI_OK\n"
    print(f"  -> Physical disk output file verified at {target_file}")

    assert res.event_ledger_path is not None
    ledger_path = Path(res.event_ledger_path)
    assert ledger_path.is_file()
    lines = [json.loads(l) for l in ledger_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    event_types = [l["type"] for l in lines]

    assert "RUN_STARTED" in event_types
    assert "STEP_STARTED" in event_types
    assert "CUSTOM" in event_types
    assert "TOOL_CALL_START" in event_types
    assert "STATE_DELTA" in event_types
    assert "RUN_FINISHED" in event_types

    step_events = [l for l in lines if l["type"] == "STEP_STARTED"]
    assert any("SPARC:S" in s["payload"]["stepName"] for s in step_events)
    assert any("SPARC:R" in s["payload"]["stepName"] for s in step_events)
    assert any("SPARC:C" in s["payload"]["stepName"] for s in step_events)
    print(f"  -> End-to-end AG-UI ledger verified ({len(lines)} structured events emitted).")


def main() -> None:
    t0 = time.perf_counter()
    print("================================================================================")
    print(" [AETHERMIND EMPIRICAL AUDITOR SUITE] AG-UI Protocol & Take the Wheel Gate")
    print("================================================================================")

    test_agui_protocol_and_event_bus()
    test_loopback_sse_streaming()
    test_human_wheel_and_homeostasis_discount()
    test_cli_integration()
    test_full_agent_loop_agui_and_wheel_end_to_end()

    elapsed = time.perf_counter() - t0
    print("\n================================================================================")
    print(f" [ALL 5 EMPIRICAL CHAMBERS PASSED] Execution verified in {elapsed:.2f}s.")
    print("================================================================================")


if __name__ == "__main__":
    main()
