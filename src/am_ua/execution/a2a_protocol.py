"""Agent2Agent (A2A) Interoperability Protocol (`am_ua.execution.a2a_protocol`).

Implements standard Agent2Agent discovery (`/.well-known/agent.json` AgentCard) and
asynchronous task negotiation (`tasks/send`, `tasks/get`, `tasks/cancel`) with opaque
artifact exchange so OmniExecutor can discover and collaborate with external specialist
agents without exposing internal system prompts or private memory.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class A2ASkillDescriptor:
    id: str
    name: str
    description: str
    tags: Tuple[str, ...] = ()


@dataclass
class AgentCard:
    """Standard A2A AgentCard published at `/.well-known/agent.json`."""

    name: str = "omni-executor"
    version: str = "5.0.0"
    description: str = "Autonomous coding, deterministic verification, and multi-agent execution harness."
    url: str = "http://127.0.0.1:8788"
    protocol_version: str = "0.2.0"
    capabilities: Dict[str, bool] = field(
        default_factory=lambda: {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
            "opaqueArtifacts": True,
        }
    )
    skills: List[Dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": "deterministic_rails", "name": "27 Deterministic Rails", "description": "Zero-token AST, Z3, Hypothesis, DuckDB, fastmft, and ledger verification."},
            {"id": "code_engineering", "name": "Autonomous Software Engineering", "description": "Verified code edits with git worktree bBoN and self-review diff gate."},
        ]
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class A2ATaskRecord:
    task_id: str
    state: str  # "submitted" | "working" | "completed" | "failed" | "canceled"
    skill_id: str
    created_at: float
    updated_at: float
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OmniA2AServer:
    """Lightweight JSON-RPC 2.0 + HTTP server for Agent2Agent (A2A) interoperability."""

    def __init__(
        self,
        *,
        card: Optional[AgentCard] = None,
        task_handler: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        self.card = card or AgentCard()
        self.task_handler = task_handler
        self.tasks: Dict[str, A2ATaskRecord] = {}
        self._lock = threading.Lock()

    def get_agent_card(self) -> Dict[str, Any]:
        return self.card.to_dict()

    def handle_rpc(self, req: Dict[str, Any]) -> Dict[str, Any]:
        req_id = req.get("id")
        method = str(req.get("method") or "")
        params = dict(req.get("params") or {})

        if method == "agent/card":
            return {"jsonrpc": "2.0", "id": req_id, "result": self.get_agent_card()}

        if method == "tasks/send":
            tid = str(params.get("id") or f"a2a-{uuid.uuid4().hex[:10]}")
            skill_id = str(params.get("skillId") or "code_engineering")
            payload = dict(params.get("input") or params.get("message") or {})
            now = time.time()
            rec = A2ATaskRecord(
                task_id=tid,
                state="working",
                skill_id=skill_id,
                created_at=now,
                updated_at=now,
            )
            with self._lock:
                self.tasks[tid] = rec
            try:
                if self.task_handler is not None:
                    out = self.task_handler(skill_id, payload)
                else:
                    out = {"ok": True, "echo_skill": skill_id, "status": "completed"}
                rec.state = "completed" if out.get("ok", True) else "failed"
                # Exchange only opaque artifacts; never expose internal prompts or raw memory
                rec.artifacts = [{"name": "result.json", "mimeType": "application/json", "data": out}]
                rec.updated_at = time.time()
            except Exception as exc:
                rec.state = "failed"
                rec.error = str(exc)[:300]
                rec.updated_at = time.time()
            return {"jsonrpc": "2.0", "id": req_id, "result": rec.to_dict()}

        if method == "tasks/get":
            tid = str(params.get("id") or "")
            with self._lock:
                rec = self.tasks.get(tid)
            if rec is None:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32004, "message": f"Unknown task: {tid}"}}
            return {"jsonrpc": "2.0", "id": req_id, "result": rec.to_dict()}

        if method == "tasks/cancel":
            tid = str(params.get("id") or "")
            with self._lock:
                rec = self.tasks.get(tid)
                if rec is None:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32004, "message": f"Unknown task: {tid}"}}
                rec.state = "canceled"
                rec.updated_at = time.time()
            return {"jsonrpc": "2.0", "id": req_id, "result": rec.to_dict()}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    def serve_http(self, *, host: str = "127.0.0.1", port: int = 8788, auth_token: Optional[str] = None) -> None:
        """Serve `GET /.well-known/agent.json` and `POST /a2a` over ThreadingHTTPServer."""
        server_ref = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_json(self, status: int, body: Dict[str, Any]) -> None:
                raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path.rstrip("/") == "/.well-known/agent.json":
                    self._send_json(200, server_ref.get_agent_card())
                    return
                self._send_json(404, {"error": "Not found"})

            def do_POST(self) -> None:
                if auth_token:
                    hdr = self.headers.get("Authorization", "")
                    if not hmac.compare_digest(hdr, f"Bearer {auth_token}"):
                        self._send_json(401, {"error": "Unauthorized"})
                        return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(min(length, 2_000_000))
                try:
                    req = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception as exc:
                    self._send_json(400, {"error": f"Invalid JSON: {exc}"})
                    return
                resp = server_ref.handle_rpc(req)
                self._send_json(200, resp)

        httpd = ThreadingHTTPServer((host, int(port)), _Handler)
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()


class A2AClient:
    """Minimal zero-dependency A2A client for discovering AgentCards and sending tasks."""

    def __init__(self, base_url: str, *, auth_token: Optional[str] = None, timeout_s: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout_s = float(timeout_s)

    def fetch_agent_card(self) -> Dict[str, Any]:
        req = urllib.request.Request(f"{self.base_url}/.well-known/agent.json", method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def send_task(self, skill_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tasks/send",
            "params": {"skillId": skill_id, "input": payload},
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        req = urllib.request.Request(f"{self.base_url}/a2a", data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
