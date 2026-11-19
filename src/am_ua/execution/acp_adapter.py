"""Agent Client Protocol (ACP) stdio JSON-RPC 2.0 server (`am_ua.execution.acp_adapter`).

Exposes OmniExecutor Agent sessions over stdin/stdout for IDE/editor clients
supporting `initialize`, `session/new`, `session/prompt`, and `session/cancel`.
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TextIO


@dataclass
class ACPSession:
    session_id: str
    workspace: str
    role: str = "general_engineer"
    workflow: str = "react"
    cancelled: bool = False
    history: list[Dict[str, Any]] = field(default_factory=list)


class OmniACPServer:
    """Line-delimited JSON-RPC 2.0 Agent Client Protocol (ACP) adapter."""

    def __init__(
        self,
        *,
        agent: Any = None,
        prompt_handler: Optional[Callable[[ACPSession, str], Dict[str, Any]]] = None,
        default_workspace: str = ".",
    ) -> None:
        self.agent = agent
        self.prompt_handler = prompt_handler
        self.default_workspace = str(Path(default_workspace).resolve())
        self.sessions: Dict[str, ACPSession] = {}
        self.initialized = False

    def handle_request(
        self,
        req: Dict[str, Any],
        *,
        notify_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Optional[Dict[str, Any]]:
        req_id = req.get("id")
        method = str(req.get("method") or "")
        params = req.get("params") or {}

        try:
            if method == "initialize":
                self.initialized = True
                result = {
                    "protocolVersion": "2026-01-01",
                    "agentInfo": {"name": "omni-executor", "version": "4.4.0"},
                    "capabilities": {
                        "sessions": True,
                        "streaming": True,
                        "cancel": True,
                        "structuredOutput": True,
                    },
                }
            elif method == "session/new":
                sid = str(params.get("sessionId") or f"acp-{uuid.uuid4().hex[:10]}")
                ws = str(params.get("workspace") or self.default_workspace)
                role = str(params.get("role") or "general_engineer")
                workflow = str(params.get("workflow") or "react")
                self.sessions[sid] = ACPSession(
                    session_id=sid,
                    workspace=ws,
                    role=role,
                    workflow=workflow,
                )
                result = {"sessionId": sid, "workspace": ws, "role": role, "workflow": workflow}
            elif method == "session/prompt":
                sid = str(params.get("sessionId") or "")
                session = self.sessions.get(sid)
                if session is None:
                    return self._error(req_id, -32004, f"Unknown ACP session: {sid!r}")
                session.cancelled = False
                prompt_text = str(params.get("prompt") or params.get("text") or "").strip()
                if not prompt_text:
                    return self._error(req_id, -32602, "Missing required 'prompt' text")
                if notify_fn is not None:
                    notify_fn(
                        {
                            "jsonrpc": "2.0",
                            "method": "session/update",
                            "params": {"sessionId": sid, "status": "running"},
                        }
                    )
                if self.prompt_handler is not None:
                    run_out = self.prompt_handler(session, prompt_text)
                elif self.agent is not None:
                    run_out = self.agent.run_agent_mission(
                        prompt_text,
                        workspace=session.workspace,
                        role=session.role,
                        workflow=session.workflow,
                        output_schema=params.get("output_schema"),
                    )
                else:
                    run_out = {"status": "NO_AGENT_ATTACHED", "final_summary": prompt_text}
                session.history.append({"prompt": prompt_text, "result": run_out})
                result = {
                    "sessionId": sid,
                    "stopReason": "cancelled" if session.cancelled else str(run_out.get("stop_reason") or "end_turn"),
                    "result": run_out,
                }
            elif method == "session/cancel":
                sid = str(params.get("sessionId") or "")
                session = self.sessions.get(sid)
                if session is None:
                    return self._error(req_id, -32004, f"Unknown ACP session: {sid!r}")
                session.cancelled = True
                if self.agent is not None and hasattr(self.agent, "agent_loop"):
                    self.agent.agent_loop.request_cancel()
                result = {"sessionId": sid, "cancelled": True}
            else:
                return self._error(req_id, -32601, f"Method not found: {method!r}")

            if req_id is None:
                return None
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except Exception as exc:
            if req_id is None:
                return None
            return self._error(req_id, -32000, f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def serve_stdio(
        self,
        in_stream: Optional[TextIO] = None,
        out_stream: Optional[TextIO] = None,
    ) -> None:
        stdin = in_stream or sys.stdin
        stdout = out_stream or sys.stdout

        def _notify(payload: Dict[str, Any]) -> None:
            stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
            stdout.flush()

        for line in stdin:
            raw = line.strip()
            if not raw:
                continue
            try:
                req = json.loads(raw)
            except json.JSONDecodeError as exc:
                _notify(self._error(None, -32700, f"Parse error: {exc}"))
                continue
            resp = self.handle_request(req, notify_fn=_notify)
            if resp is not None:
                _notify(resp)
