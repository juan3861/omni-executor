"""Comprehensive Test Suite for AG-UI Protocol & Take the Wheel (am_ua.cognition.agui_protocol & am_ua.execution.human_wheel).

Validates:
1. AGUIEvent Schema, immutability, SSE formatting, and Alpha-C13 finite number enforcement.
2. Redaction of sensitive tokens/keys in event payloads.
3. Sink isolation (faulty sinks do not crash the EventBus).
4. Zero-dependency LoopbackSSEServer on 127.0.0.1 (rejection of non-loopback binds).
5. HumanWheelGate path traversal rejection, atomic REQUEST.json handshake, and history archiving.
6. Homeostasis credit_paused_time behavior under simulated human pauses.
7. End-to-end AgentLoop execution with AG-UI streaming and HumanWheel resumption.
8. CLI `wheel` status/resume/abort integration.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest

from am_ua.cognition.agui_protocol import (
    AGUIEvent,
    AGUIEventBus,
    AGUIEventType,
    BaseAGUISink,
    CallbackSink,
    JsonlFileSink,
    LoopbackSSEServer,
    redact_sensitive_payload,
    sanitize_finite_numbers,
)
from am_ua.cognition.llm_client import LLMResponse
from am_ua.execution.agent_loop import AgentLoop, AgentRunResult
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.human_wheel import HumanWheelGate, WheelOutcome
from am_ua.governance.homeostasis import HomeostasisGovernor
from am_ua.governance.seal_guard import ConstitutionSealGuard


def test_agui_event_schema_and_immutability() -> None:
    ev = AGUIEvent(
        type=AGUIEventType.RUN_STARTED,
        thread_id="t-1",
        run_id="run-1",
        seq=1,
        timestamp_ms=1000,
        payload={"goal": "Refactor codebase", "tokens": 42},
    )
    assert ev.type == AGUIEventType.RUN_STARTED
    assert ev.thread_id == "t-1"
    assert ev.seq == 1
    assert ev.payload["goal"] == "Refactor codebase"

    # Frozen immutability
    with pytest.raises(Exception):
        ev.seq = 2  # type: ignore

    # Alpha-C13: Rejection of NaN / Inf in payloads
    with pytest.raises(ValueError, match="Non-finite float rejected"):
        AGUIEvent(
            type=AGUIEventType.RUN_FINISHED,
            thread_id="t-1",
            run_id="run-1",
            seq=2,
            timestamp_ms=1010,
            payload={"brier_score": float("nan")},
        )

    with pytest.raises(ValueError, match="Non-finite float rejected"):
        AGUIEvent(
            type=AGUIEventType.RUN_FINISHED,
            thread_id="t-1",
            run_id="run-1",
            seq=3,
            timestamp_ms=1020,
            payload={"nested": {"loss": float("inf")}},
        )

    # SSE formatting
    sse = ev.encode_sse()
    assert sse.startswith("event: RUN_STARTED\n")
    assert "data: " in sse
    assert sse.endswith("\n\n")

    # JSON encoding
    parsed = json.loads(ev.encode_json())
    assert parsed["type"] == "RUN_STARTED"
    assert parsed["threadId"] == "t-1"
    assert parsed["payload"]["tokens"] == 42


def test_agui_secret_redaction_and_sink_isolation(tmp_path: Path) -> None:
    # 1. Redaction
    raw = {
        "api_key": "sk-secret123456",
        "auth_token": "bearer-token-abc",
        "nested": {"PASSWORD": "supersecretpassword", "safe_param": "hello"},
    }
    redacted = redact_sensitive_payload(raw)
    assert redacted["api_key"] == "[REDACTED_SECRET]"
    assert redacted["auth_token"] == "[REDACTED_SECRET]"
    assert redacted["nested"]["PASSWORD"] == "[REDACTED_SECRET]"
    assert redacted["nested"]["safe_param"] == "hello"

    # 2. Sink isolation: Faulty sink must not crash EventBus
    class CrashingSink(BaseAGUISink):
        def write_event(self, event: AGUIEvent) -> None:
            raise RuntimeError("Sink exploded!")

    valid_events: List[AGUIEvent] = []

    class CapturingSink(BaseAGUISink):
        def write_event(self, event: AGUIEvent) -> None:
            valid_events.append(event)

    bus = AGUIEventBus(
        thread_id="t-2",
        run_id="run-2",
        sinks=[CrashingSink(), CapturingSink()],
    )

    ev = bus.emit(AGUIEventType.STEP_STARTED, stepName="SPARC:S", secret_token="my-token")
    assert bus.sink_errors == 1
    assert len(valid_events) == 1
    assert valid_events[0].payload["secret_token"] == "[REDACTED_SECRET]"
    bus.close()


def test_loopback_sse_server_security_and_streaming() -> None:
    # Non-loopback host must be rejected fail-closed
    with pytest.raises(PermissionError, match="strictly to local loopback"):
        LoopbackSSEServer(port=8891, host="0.0.0.0")

    # Start on available port
    server = LoopbackSSEServer(port=8892, host="127.0.0.1")
    bus = AGUIEventBus(thread_id="t-sse", run_id="run-sse", sinks=[server])

    received_lines: List[str] = []
    stop_client = threading.Event()

    def client_worker() -> None:
        req = urllib.request.Request("http://127.0.0.1:8892/events")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            for _ in range(3):
                line = resp.readline().decode("utf-8")
                if line:
                    received_lines.append(line)
                if stop_client.is_set():
                    break

    client_th = threading.Thread(target=client_worker, daemon=True)
    client_th.start()
    time.sleep(0.3)

    bus.emit(AGUIEventType.RUN_STARTED, goal="Test streaming")
    time.sleep(0.3)
    stop_client.set()
    client_th.join(timeout=1.0)
    server.close()
    bus.close()

    assert any("event: RUN_STARTED" in l for l in received_lines)
    assert any("data: " in l for l in received_lines)


def test_human_wheel_gate_lifecycle() -> None:
    test_root = Path(r"F:\AetherMind_Temp\pytest_wheel_test")
    if test_root.exists():
        shutil.rmtree(test_root, ignore_errors=True)
    test_root.mkdir(parents=True, exist_ok=True)

    gate = HumanWheelGate(test_root, timeout_s=0.0)

    # 1. Path traversal check in mission_id
    with pytest.raises(ValueError, match="Invalid mission_id"):
        gate.pause_for_human("../evil_path", "test", "instructions")
    with pytest.raises(ValueError, match="Invalid mission_id"):
        gate.pause_for_human("mission/with/slashes", "test", "instructions")

    # 2. Timeout_s = 0 returns immediately with CONTINUE_AUTONOMOUS
    res = gate.pause_for_human("m-auto", "Reason", "Instructions")
    assert res.action == "CONTINUE_AUTONOMOUS"
    assert res.paused_seconds == 0.0

    # 3. Real pause with background human RESUME
    gate_with_timeout = HumanWheelGate(test_root, timeout_s=4.0, poll_interval_s=0.1)

    def operator_resume() -> None:
        time.sleep(0.4)
        active = HumanWheelGate.list_active_requests(test_root)
        assert len(active) == 1
        assert active[0]["mission_id"] == "m-paused-1"
        assert active[0]["reason"] == "Solve CAPTCHA"
        HumanWheelGate.resume("m-paused-1", note="CAPTCHA solved by Mestre", wheel_root=test_root)

    th_resume = threading.Thread(target=operator_resume, daemon=True)
    th_resume.start()

    outcome = gate_with_timeout.pause_for_human(
        "m-paused-1",
        reason="Solve CAPTCHA",
        instructions="Please complete the Cloudflare check on screen",
    )
    th_resume.join(timeout=2.0)

    assert outcome.action == "RESUMED"
    assert "CAPTCHA solved by Mestre" in outcome.note
    assert outcome.paused_seconds >= 0.3
    # Active request must be cleaned up, archived in HISTORY
    hist_dir = test_root / "m-paused-1" / "HISTORY"
    assert hist_dir.exists()
    assert len(list(hist_dir.glob("*.json"))) >= 1

    # 4. Real pause with background human ABORT
    def operator_abort() -> None:
        time.sleep(0.3)
        HumanWheelGate.abort("m-paused-2", note="Operation forbidden", wheel_root=test_root)

    th_abort = threading.Thread(target=operator_abort, daemon=True)
    th_abort.start()

    outcome_abort = gate_with_timeout.pause_for_human(
        "m-paused-2",
        reason="Confirm high-risk rm -rf",
        instructions="Do you authorize wiping /data?",
    )
    th_abort.join(timeout=2.0)
    assert outcome_abort.action == "ABORTED"
    assert "Operation forbidden" in outcome_abort.note

    # 5. Real pause TIMEOUT
    fast_timeout_gate = HumanWheelGate(test_root, timeout_s=0.3, poll_interval_s=0.05)
    outcome_timeout = fast_timeout_gate.pause_for_human(
        "m-paused-timeout",
        reason="No operator present",
        instructions="Wait for answer",
    )
    assert outcome_timeout.action == "TIMEOUT"
    assert outcome_timeout.paused_seconds >= 0.25


def test_homeostasis_credit_paused_time() -> None:
    gov = HomeostasisGovernor(max_wall_seconds=2.0)
    # Simulate 5 seconds having elapsed by manipulating started_at
    gov._started_at -= 5.0
    # Now elapsed is > 5s -> exceeds 2.0s
    with pytest.raises(Exception, match="R09 Wall-clock deadline exceeded"):
        gov.record_turn_cost(tokens=100, tool_calls=1, made_verified_progress=True)

    # Now credit 5.5 seconds of paused human time
    gov.credit_paused_time(5.5)
    # Now elapsed is -0.5s -> within 2.0s, does not throw!
    res = gov.record_turn_cost(tokens=50, tool_calls=1, made_verified_progress=True)
    assert res["tokens_spent"] == 150
    assert res["stagnant_turns"] == 0


class MockAGUILLM:
    """Mock LLM returning sequential scripted responses for testing."""
    def __init__(self, turns_data: List[str]) -> None:
        self.turns_data = list(turns_data)
        self.current = 0
        self.calls = 0
        self.total_prompt_tokens = 100
        self.total_completion_tokens = 50

    def chat(self, messages: Any, **kwargs: Any) -> LLMResponse:
        self.calls += 1
        if self.current < len(self.turns_data):
            text = self.turns_data[self.current]
            self.current += 1
        else:
            text = json.dumps({"thought": "SPARC Phase: C Done", "tool": "finish", "args": {"summary": "Done", "confidence": 0.95}})
        return LLMResponse(
            text=text,
            provider="mock_llm",
            model="mock-model",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=10.0,
        )

    def available(self) -> List[str]:
        return ["mock_llm"]


def test_agent_loop_agui_and_human_wheel_integration() -> None:
    ws_dir = Path(r"F:\AetherMind_Temp\pytest_agui_loop_ws")
    if ws_dir.exists():
        shutil.rmtree(ws_dir, ignore_errors=True)
    ws_dir.mkdir(parents=True, exist_ok=True)

    wheel_root = Path(r"F:\AetherMind_Temp\pytest_wheel_loop")
    if wheel_root.exists():
        shutil.rmtree(wheel_root, ignore_errors=True)
    wheel_root.mkdir(parents=True, exist_ok=True)

    ledger_dir = Path(r"F:\AetherMind_Temp\pytest_agui_ledgers")
    if ledger_dir.exists():
        shutil.rmtree(ledger_dir, ignore_errors=True)
    ledger_dir.mkdir(parents=True, exist_ok=True)

    # Scripted LLM turns:
    # Turn 1: SPARC S: Request human assistance
    # Turn 2: SPARC R: Write file
    # Turn 3: SPARC C: Finish
    scripted_turns = [
        json.dumps({
            "thought": "SPARC Phase: S Specification - Blocked by human confirmation",
            "tool": "request_human",
            "args": {"reason": "Approval required for init", "instructions": "Resume please"},
        }),
        json.dumps({
            "thought": "SPARC Phase: R Refinement - Writing output file",
            "tool": "write_file",
            "args": {"file": "result.txt", "content": "AGENT_OUTPUT_OK\n"},
        }),
        json.dumps({
            "thought": "SPARC Phase: C Completion - All done",
            "tool": "finish",
            "args": {"summary": "Completed successfully with human intervention", "confidence": 0.98},
        }),
    ]

    mock_llm = MockAGUILLM(scripted_turns)
    engine = DurableExecutionEngine(r"F:\AetherMind_Temp\pytest_durable\durable.db")
    seal_guard = ConstitutionSealGuard(r"F:\AetherMind_Universal_Agent")
    wheel_gate = HumanWheelGate(wheel_root, timeout_s=4.0, poll_interval_s=0.1)

    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=mock_llm,  # type: ignore
        wheel_gate=wheel_gate,
        wheel_timeout_s=4.0,
        agui_ledger_dir=ledger_dir,
    )

    mission_id = f"m-agui-test-{int(time.time())}"

    # Background thread to resume mission when request_human occurs
    def background_human_operator() -> None:
        for _ in range(30):
            time.sleep(0.1)
            active = HumanWheelGate.list_active_requests(wheel_root)
            if active and active[0]["mission_id"] == mission_id:
                HumanWheelGate.resume(mission_id, note="Human approves init", wheel_root=wheel_root)
                break

    op_th = threading.Thread(target=background_human_operator, daemon=True)
    op_th.start()

    res = loop.run(
        objective="Create result.txt after human check",
        workspace=ws_dir,
        mission_id=mission_id,
        workflow="sparc",
        use_judge=False,
    )
    op_th.join(timeout=3.0)

    assert res.status == "COMPLETED_UNVERIFIED"
    assert (ws_dir / "result.txt").is_file()
    assert (ws_dir / "result.txt").read_text(encoding="utf-8") == "AGENT_OUTPUT_OK\n"
    assert res.event_ledger_path is not None

    # Verify JSONL event ledger on disk
    ledger_path = Path(res.event_ledger_path)
    assert ledger_path.is_file()
    lines = [json.loads(l) for l in ledger_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    event_types = [l["type"] for l in lines]

    assert "RUN_STARTED" in event_types
    assert "STEP_STARTED" in event_types
    assert "CUSTOM" in event_types  # HUMAN_INTERVENTION_REQUEST
    assert "TOOL_CALL_START" in event_types
    assert "STATE_DELTA" in event_types  # from write_file
    assert "RUN_FINISHED" in event_types

    # Check SPARC step naming in events
    step_events = [l for l in lines if l["type"] == "STEP_STARTED"]
    assert any("SPARC:S" in s["payload"]["stepName"] for s in step_events)
    assert any("SPARC:R" in s["payload"]["stepName"] for s in step_events)
    assert any("SPARC:C" in s["payload"]["stepName"] for s in step_events)


def test_cli_wheel_subcommands() -> None:
    from am_ua.cli import main

    test_root = Path(r"F:\AetherMind_Temp\pytest_cli_wheel")
    if test_root.exists():
        shutil.rmtree(test_root, ignore_errors=True)
    test_root.mkdir(parents=True, exist_ok=True)

    # 1. Status with no active requests
    rc = main(["wheel", "status"])
    assert rc == 0

    # 2. Resume without mission_id -> error
    rc_err = main(["wheel", "resume"])
    assert rc_err == 1

    # 3. Create simulated active request
    HumanWheelGate(test_root)._mission_dir("m-cli-1")
    req_file = test_root / "m-cli-1" / "REQUEST.json"
    req_file.write_text(json.dumps({"mission_id": "m-cli-1", "reason": "CLI check"}), encoding="utf-8")

    # Resume via CLI with custom root patched
    import am_ua.execution.human_wheel as hw
    orig_root = hw.HumanWheelGate.DEFAULT_WHEEL_ROOT
    try:
        hw.HumanWheelGate.DEFAULT_WHEEL_ROOT = test_root
        rc_resume = main(["wheel", "resume", "m-cli-1", "--note", "Mestre via CLI"])
        assert rc_resume == 0
        assert (test_root / "m-cli-1" / "RESUME.json").is_file()
    finally:
        hw.HumanWheelGate.DEFAULT_WHEEL_ROOT = orig_root
