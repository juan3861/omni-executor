"""AG-UI Protocol — Agent-User Interaction Protocol Implementation (am_ua.cognition.agui_protocol).

Pure Python implementation of the AG-UI event streaming standard.
Provides structured, typed events for agent lifecycle, SPARC phase transitions,
tool execution, state deltas, and human intervention requests without external dependencies.
Compliant with OMNI_TOPOLOGY_V2 layer contracts.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Dict, List, Optional, Set

SECRET_ENV_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.IGNORECASE)


class AGUIEventType(str, Enum):
    """Standardized AG-UI Event Types."""
    RUN_STARTED = "RUN_STARTED"
    RUN_FINISHED = "RUN_FINISHED"
    RUN_ERROR = "RUN_ERROR"
    STEP_STARTED = "STEP_STARTED"
    STEP_FINISHED = "STEP_FINISHED"
    TEXT_MESSAGE_CONTENT = "TEXT_MESSAGE_CONTENT"
    TOOL_CALL_START = "TOOL_CALL_START"
    TOOL_CALL_ARGS = "TOOL_CALL_ARGS"
    TOOL_CALL_END = "TOOL_CALL_END"
    TOOL_CALL_RESULT = "TOOL_CALL_RESULT"
    STATE_SNAPSHOT = "STATE_SNAPSHOT"
    STATE_DELTA = "STATE_DELTA"
    CUSTOM = "CUSTOM"


def sanitize_finite_numbers(val: Any) -> Any:
    """Recursively validates that all numbers in the payload are finite (Alpha-C13 invariant)."""
    if isinstance(val, (int, bool)):
        return val
    if isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError(f"Non-finite float rejected in AG-UI event payload: {val}")
        return val
    if isinstance(val, dict):
        return {str(k): sanitize_finite_numbers(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [sanitize_finite_numbers(x) for x in val]
    return val


def redact_sensitive_payload(val: Any) -> Any:
    """Masks secret values in tool args or payloads."""
    if isinstance(val, dict):
        redacted = {}
        for k, v in val.items():
            if SECRET_ENV_RE.search(str(k)):
                redacted[k] = "[REDACTED_SECRET]"
            else:
                redacted[k] = redact_sensitive_payload(v)
        return redacted
    if isinstance(val, list):
        return [redact_sensitive_payload(x) for x in val]
    return val


@dataclass(frozen=True)
class AGUIEvent:
    """Immutable, typed AG-UI Protocol event."""
    type: AGUIEventType
    thread_id: str
    run_id: str
    seq: int
    timestamp_ms: int
    payload: Dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.type, AGUIEventType):
            raise TypeError(f"Invalid AGUIEventType: {self.type}")
        if not isinstance(self.seq, int) or self.seq < 1:
            raise ValueError(f"Sequence number must be a positive integer, got: {self.seq}")
        if not isinstance(self.timestamp_ms, int) or self.timestamp_ms < 0:
            raise ValueError(f"timestamp_ms must be non-negative integer, got: {self.timestamp_ms}")
        sanitize_finite_numbers(self.payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "threadId": self.thread_id,
            "runId": self.run_id,
            "seq": self.seq,
            "timestampMs": self.timestamp_ms,
            "payload": self.payload,
        }

    def encode_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    def encode_sse(self) -> str:
        """Formats the event as a standard Server-Sent Event (SSE)."""
        data = self.encode_json()
        return f"event: {self.type.value}\ndata: {data}\n\n"


class BaseAGUISink:
    """Base interface for AG-UI event consumers."""
    def write_event(self, event: AGUIEvent) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class JsonlFileSink(BaseAGUISink):
    """Appends AG-UI events to a durable JSONL ledger with fsync."""
    def __init__(self, output_path: Path | str) -> None:
        self.output_path = Path(output_path).resolve()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file = open(self.output_path, "a", encoding="utf-8")

    def write_event(self, event: AGUIEvent) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.write(event.encode_json() + "\n")
                self._file.flush()
                try:
                    os.fsync(self._file.fileno())
                except OSError:
                    pass

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.close()


class StderrPrettySink(BaseAGUISink):
    """Outputs human-readable, formatted progress events to stderr."""
    def write_event(self, event: AGUIEvent) -> None:
        t = event.type
        p = event.payload
        msg = ""
        if t == AGUIEventType.RUN_STARTED:
            msg = f"[AG-UI RUN_STARTED] id={event.run_id} role={p.get('role')} workflow={p.get('workflow')}"
        elif t == AGUIEventType.STEP_STARTED:
            step_name = p.get("stepName", "")
            turn = p.get("turn", "")
            msg = f"[AG-UI STEP] Turn {turn} -> {step_name}"
        elif t == AGUIEventType.TOOL_CALL_START:
            msg = f"  -> Tool Call: {p.get('toolName')} ({event.payload.get('args_preview', '')})"
        elif t == AGUIEventType.TOOL_CALL_RESULT:
            ok_str = "OK" if p.get("ok") else "FAIL"
            msg = f"  <- Tool Result [{ok_str}]: {str(p.get('result', ''))[:120]}"
        elif t == AGUIEventType.STATE_DELTA:
            paths = [d.get("path", "") for d in p.get("deltas", [])]
            msg = f"  * State Delta: modified {paths}"
        elif t == AGUIEventType.CUSTOM:
            c_name = p.get("name", "CUSTOM")
            msg = f"[AG-UI CUSTOM:{c_name}] {json.dumps(p, default=str)}"
        elif t == AGUIEventType.RUN_FINISHED:
            status = p.get("status", "")
            brier = p.get("brier_score")
            msg = f"[AG-UI RUN_FINISHED] status={status} brier={brier}"
        elif t == AGUIEventType.RUN_ERROR:
            msg = f"[AG-UI RUN_ERROR] stop_reason={p.get('stop_reason')} error={p.get('error')}"

        if msg:
            print(msg, file=sys.stderr, flush=True)


class CallbackSink(BaseAGUISink):
    """Adapts an arbitrary callback function (like legacy on_event) into an AG-UI sink."""
    def __init__(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.callback = callback

    def write_event(self, event: AGUIEvent) -> None:
        try:
            self.callback(event.to_dict())
        except Exception:
            pass


class LoopbackSSEServer(BaseAGUISink):
    """Zero-dependency local-only HTTP server streaming AG-UI events via SSE on 127.0.0.1."""

    def __init__(self, port: int = 8765, host: str = "127.0.0.1") -> None:
        if host not in ("127.0.0.1", "localhost"):
            raise PermissionError("AG-UI LoopbackSSEServer bound strictly to local loopback (127.0.0.1)")
        self.host = host
        self.port = port
        self.clients: Set[Queue[Optional[str]]] = set()
        self._lock = threading.Lock()

        server_self = self

        class SSEHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path in ("/events", "/"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()

                    q: Queue[Optional[str]] = Queue(maxsize=1000)
                    with server_self._lock:
                        server_self.clients.add(q)

                    try:
                        while True:
                            item = q.get()
                            if item is None:
                                break
                            self.wfile.write(item.encode("utf-8"))
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        with server_self._lock:
                            server_self.clients.discard(q)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer((self.host, self.port), SSEHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def write_event(self, event: AGUIEvent) -> None:
        sse_text = event.encode_sse()
        with self._lock:
            for q in list(self.clients):
                try:
                    q.put_nowait(sse_text)
                except Exception:
                    pass

    def close(self) -> None:
        with self._lock:
            for q in self.clients:
                try:
                    q.put_nowait(None)
                except Exception:
                    pass
            self.clients.clear()
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


class AGUIEventBus:
    """Orchestrates sequence numbering, timestamping, redaction, and fan-out to sinks."""

    def __init__(
        self,
        thread_id: str,
        run_id: str,
        sinks: Optional[List[BaseAGUISink]] = None,
    ) -> None:
        self.thread_id = thread_id
        self.run_id = run_id
        self.sinks = list(sinks or [])
        self._seq = 0
        self._lock = threading.Lock()
        self.sink_errors = 0

    def add_sink(self, sink: BaseAGUISink) -> None:
        with self._lock:
            self.sinks.append(sink)

    def emit(self, event_type: AGUIEventType | str, **payload: Any) -> AGUIEvent:
        if isinstance(event_type, str):
            event_type = AGUIEventType(event_type)

        redacted_payload = redact_sensitive_payload(payload)

        with self._lock:
            self._seq += 1
            seq = self._seq
            ts = int(time.time() * 1000)

            event = AGUIEvent(
                type=event_type,
                thread_id=self.thread_id,
                run_id=self.run_id,
                seq=seq,
                timestamp_ms=ts,
                payload=redacted_payload,
            )

            for sink in self.sinks:
                try:
                    sink.write_event(event)
                except Exception:
                    self.sink_errors += 1

        return event

    def close(self) -> None:
        with self._lock:
            for sink in self.sinks:
                try:
                    sink.close()
                except Exception:
                    pass
