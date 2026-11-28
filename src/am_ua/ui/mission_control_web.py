"""Localhost Web Mission Control Dashboard for OmniExecutor (v9.0 — Fase 4).

Zero-dependency stdlib HTTP + SSE dashboard bound strictly to loopback (`127.0.0.1`)
that streams live AG-UI events, displays deterministic token savings (`220` rails +
parametric playbooks), lets the operator toggle `on_demand` (free/uncapped) vs `fixed`
USD budgets on `HomeostasisGovernor`, and dispatches Take-the-Wheel signals.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from queue import Queue
import threading
import time
from typing import Any, Dict, List, Optional, Set

from am_ua.cognition.agui_protocol import AGUIEvent, AGUIEventBus, BaseAGUISink
from am_ua.execution.parametric_playbooks import DEFAULT_PLAYBOOK_ENGINE
from am_ua.governance.homeostasis import HomeostasisGovernor

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OmniExecutor Mission Control</title>
<style>
:root { color-scheme: dark; --bg: #0b1020; --card: #121a30; --accent: #38bdf8; --ok: #22c55e; --warn: #f59e0b; --text: #e2e8f0; --muted: #94a3b8; }
body { font-family: system-ui, -apple-system, sans-serif; margin: 0; background: var(--bg); color: var(--text); }
header { padding: 14px 22px; background: #0f172a; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 16px; padding: 18px; }
.card { background: var(--card); border: 1px solid #1e293b; border-radius: 10px; padding: 16px; }
h2 { margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--accent); }
.metric { font-size: 24px; font-weight: 700; margin: 4px 0; }
.muted { color: var(--muted); font-size: 12px; }
button, select, input { background: #1e293b; color: var(--text); border: 1px solid #334155; border-radius: 6px; padding: 6px 10px; font-size: 13px; }
button { cursor: pointer; background: #0284c7; border-color: #0284c7; font-weight: 600; }
button.warn { background: #b45309; border-color: #b45309; }
pre { background: #070b15; padding: 10px; border-radius: 6px; max-height: 280px; overflow: auto; font-size: 12px; margin: 0; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: 11px; background: #1e293b; }
</style>
</head>
<body>
<header>
  <div><strong>OmniExecutor Mission Control</strong> <span class="pill" id="modeBadge">on_demand</span></div>
  <div class="muted" id="connStatus">SSE connecting...</div>
</header>
<div class="grid">
  <div class="card">
    <h2>Budget & Homeostasis</h2>
    <div class="metric" id="costSpent">$0.0000</div>
    <div class="muted" id="budgetDetail">Mode: On-Demand (Free Tier / No Cap)</div>
    <div style="margin-top:10px; display:flex; gap:6px; flex-wrap:wrap;">
      <select id="budgetMode"><option value="on_demand">On-Demand (Free / Uncapped)</option><option value="fixed">Fixed Cap (USD)</option></select>
      <input id="maxUsd" type="number" step="0.10" min="0" value="1.00" style="width:80px;" />
      <button onclick="applyBudget()">Apply</button>
    </div>
  </div>
  <div class="card">
    <h2>Deterministic Engine</h2>
    <div class="metric" id="tokensSaved">0 tokens saved</div>
    <div class="muted" id="playbooksInfo">Playbooks active</div>
  </div>
  <div class="card">
    <h2>Take the Wheel &amp; Approval Cards</h2>
    <div class="muted" id="wheelState">Status: Autonomous</div>
    <div style="margin-top:10px; display:flex; gap:6px;">
      <input id="wheelNote" type="text" placeholder="Operator note..." style="flex:1;" />
      <button onclick="sendWheel('resume')">Resume</button>
      <button class="warn" onclick="sendWheel('abort')">Abort</button>
    </div>
    <div class="muted" id="approvalsCount" style="margin-top:8px;">Pending Approvals: 0</div>
  </div>
  <div class="card">
    <h2>Blind Vault, Schedules &amp; Receipts</h2>
    <div class="muted" id="vaultCount">Vault Aliases: 0 (Host-Only DPAPI)</div>
    <div class="muted" id="schedulesCount">Active Schedules: 0</div>
    <div class="muted" id="receiptsCount">Task Receipts: 0</div>
    <div class="muted" id="memoryFirewallCount">Poison Blocked: 0</div>
  </div>
</div>
<div style="padding: 0 18px 18px;">
  <div class="card">
    <h2>Live AG-UI Telemetry Stream</h2>
    <pre id="eventsLog"></pre>
  </div>
</div>
<script>
async function refreshState() {
  const r = await fetch('/api/state');
  const st = await r.json();
  document.getElementById('costSpent').textContent = '$' + Number(st.cost_usd_spent || 0).toFixed(4);
  document.getElementById('modeBadge').textContent = st.budget_mode;
  document.getElementById('budgetDetail').textContent = st.budget_mode === 'fixed'
    ? ('Fixed Ceiling: $' + Number(st.max_cost_usd || 0).toFixed(2))
    : 'Mode: On-Demand (Free Tier Default / Uncapped)';
  document.getElementById('tokensSaved').textContent = (st.deterministic_tokens_saved || 0) + ' tokens saved';
  document.getElementById('playbooksInfo').textContent = st.playbooks_count + ' parametric playbooks ready';
  document.getElementById('wheelState').textContent = 'Wheel: ' + (st.wheel_status || 'autonomous');
  document.getElementById('approvalsCount').textContent = 'Pending Approvals: ' + (st.pending_approvals_count || 0);
  document.getElementById('vaultCount').textContent = 'Vault Aliases: ' + (st.vault_entries_count || 0) + ' (Host-Only)';
  document.getElementById('schedulesCount').textContent = 'Active Schedules: ' + (st.schedules_count || 0);
  document.getElementById('receiptsCount').textContent = 'Task Receipts: ' + (st.receipts_count || 0);
  document.getElementById('memoryFirewallCount').textContent = 'Poison Blocked: ' + (st.memory_poison_blocked || 0);
}
async function applyBudget() {
  const mode = document.getElementById('budgetMode').value;
  const maxUsd = parseFloat(document.getElementById('maxUsd').value || '0');
  await fetch('/api/budget', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode, max_cost_usd: mode === 'fixed' ? maxUsd : null}) });
  await refreshState();
}
async function sendWheel(action) {
  const note = document.getElementById('wheelNote').value;
  await fetch('/api/wheel', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action, note}) });
  await refreshState();
}
const es = new EventSource('/api/events');
es.onopen = () => { document.getElementById('connStatus').textContent = 'SSE live'; };
es.onmessage = (ev) => {
  const pre = document.getElementById('eventsLog');
  pre.textContent = (ev.data + '\\n' + pre.textContent).slice(0, 8000);
};
refreshState();
</script>
</body>
</html>
"""


class _DashboardSSESink(BaseAGUISink):
    def __init__(self, server: "MissionControlServer") -> None:
        self._server = server

    def write_event(self, event: AGUIEvent) -> None:
        self._server.publish_event(event.to_dict())


class MissionControlServer:
    """Zero-dependency loopback HTTP + SSE Mission Control Dashboard."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        governor: Optional[HomeostasisGovernor] = None,
        event_bus: Optional[AGUIEventBus] = None,
        vault: Optional[Any] = None,
        schedule_store: Optional[Any] = None,
        memory_provider: Optional[Any] = None,
    ) -> None:
        if host not in ("127.0.0.1", "localhost"):
            raise PermissionError("MissionControlServer strictly binds to loopback (127.0.0.1)")
        self.host = host
        self.port = int(port)
        self.governor = governor or HomeostasisGovernor()
        self.event_bus = event_bus
        self.vault = vault
        self.schedule_store = schedule_store
        self.memory_provider = memory_provider
        self._lock = threading.Lock()
        self._clients: Set[Queue[Optional[str]]] = set()
        self._recent_events: List[Dict[str, Any]] = []
        self._state: Dict[str, Any] = {
            "deterministic_tokens_saved": 0,
            "wheel_status": "autonomous",
            "wheel_note": "",
            "workers": [],
            "som_screenshots": [],
            "pending_approvals": [],
            "approval_decisions": [],
            "receipts": [],
        }
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        if self.event_bus is not None:
            self.event_bus.add_sink(_DashboardSSESink(self))

    def snapshot_state(self) -> Dict[str, Any]:
        with self._lock:
            playbooks = DEFAULT_PLAYBOOK_ENGINE.list_playbooks()
            vault_count = len(self.vault.list_entries()) if self.vault is not None else 0
            sched_count = len(self.schedule_store.list_schedules()) if self.schedule_store is not None else 0
            rcpt_count = len(self.schedule_store.list_receipts()) if self.schedule_store is not None else len(self._state["receipts"])
            poison_blocked = (
                int(self.memory_provider.firewall.stats().get("blocked_poison_attempts", 0))
                if (self.memory_provider is not None and hasattr(self.memory_provider, "firewall"))
                else 0
            )
            return {
                "ok": True,
                "budget_mode": self.governor.budget_mode,
                "max_cost_usd": self.governor.max_cost_usd,
                "cost_usd_spent": round(self.governor.cost_usd_spent, 6),
                "playbooks_count": len(playbooks),
                "recent_events_count": len(self._recent_events),
                "pending_approvals_count": len(self._state["pending_approvals"]),
                "vault_entries_count": vault_count,
                "schedules_count": sched_count,
                "receipts_count": rcpt_count,
                "memory_poison_blocked": poison_blocked,
                **self._state,
            }

    def publish_event(self, payload: Dict[str, Any]) -> None:
        encoded = f"data: {json.dumps(payload, default=str)}\n\n"
        with self._lock:
            self._recent_events.append(payload)
            if len(self._recent_events) > 200:
                self._recent_events = self._recent_events[-200:]
            for q in list(self._clients):
                try:
                    q.put_nowait(encoded)
                except Exception:
                    pass

    def record_deterministic_savings(self, tokens: int) -> None:
        with self._lock:
            self._state["deterministic_tokens_saved"] += max(0, int(tokens))

    def enqueue_approval_card(self, card: Dict[str, Any]) -> None:
        with self._lock:
            self._state["pending_approvals"].append(dict(card))
        self.publish_event({"event": "approval_queued", "card": card, "timestamp": time.time()})

    def record_receipt(self, receipt: Dict[str, Any]) -> None:
        with self._lock:
            self._state["receipts"].append(dict(receipt))
            if len(self._state["receipts"]) > 200:
                self._state["receipts"] = self._state["receipts"][-200:]

    def start(self) -> int:
        if self._httpd is not None:
            return int(self._httpd.server_address[1])
        srv_self = self

        class _Handler(BaseHTTPRequestHandler):
            def _send_json(self, code: int, obj: Dict[str, Any]) -> None:
                body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/":
                    raw = _DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path == "/api/health":
                    self._send_json(200, {"ok": True, "service": "omni-mission-control"})
                    return
                if self.path == "/api/state":
                    self._send_json(200, srv_self.snapshot_state())
                    return
                if self.path == "/api/approvals":
                    with srv_self._lock:
                        self._send_json(200, {
                            "ok": True,
                            "pending": list(srv_self._state["pending_approvals"]),
                            "decisions": list(srv_self._state["approval_decisions"][-25:]),
                        })
                    return
                if self.path == "/api/vault":
                    entries = srv_self.vault.list_entries() if srv_self.vault is not None else []
                    self._send_json(200, {"ok": True, "entries": entries, "count": len(entries)})
                    return
                if self.path == "/api/schedules":
                    scheds = srv_self.schedule_store.list_schedules() if srv_self.schedule_store is not None else []
                    self._send_json(200, {"ok": True, "schedules": scheds, "count": len(scheds)})
                    return
                if self.path == "/api/receipts":
                    rcpts = srv_self.schedule_store.list_receipts() if srv_self.schedule_store is not None else list(srv_self._state["receipts"])
                    self._send_json(200, {"ok": True, "receipts": rcpts, "count": len(rcpts)})
                    return
                if self.path == "/api/memory":
                    mem = srv_self.memory_provider.list_memories() if (srv_self.memory_provider is not None and hasattr(srv_self.memory_provider, "list_memories")) else {"ok": True, "atoms": [], "procedural_notes": [], "firewall_stats": {}}
                    self._send_json(200, mem)
                    return
                if self.path == "/api/events":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    q: Queue[Optional[str]] = Queue(maxsize=500)
                    with srv_self._lock:
                        srv_self._clients.add(q)
                        history = list(srv_self._recent_events[-20:])
                    try:
                        for item in history:
                            self.wfile.write(f"data: {json.dumps(item, default=str)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                        while True:
                            msg = q.get()
                            if msg is None:
                                break
                            self.wfile.write(msg.encode("utf-8"))
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    finally:
                        with srv_self._lock:
                            srv_self._clients.discard(q)
                    return
                self._send_json(404, {"ok": False, "error": f"Unknown path: {self.path}"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(min(length, 65536)) if length > 0 else b"{}"
                try:
                    data = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._send_json(400, {"ok": False, "error": "Invalid JSON body"})
                    return
                if self.path == "/api/budget":
                    try:
                        res = srv_self.governor.set_budget_mode(
                            str(data.get("mode", "on_demand")),
                            max_cost_usd=data.get("max_cost_usd"),
                        )
                        srv_self.publish_event({"event": "budget_updated", **res, "timestamp": time.time()})
                        self._send_json(200, {"ok": True, **res})
                    except ValueError as exc:
                        self._send_json(400, {"ok": False, "error": str(exc)})
                    return
                if self.path == "/api/wheel":
                    act = str(data.get("action", "resume")).strip().lower()
                    note = str(data.get("note", "")).strip()
                    with srv_self._lock:
                        srv_self._state["wheel_status"] = act
                        srv_self._state["wheel_note"] = note
                    srv_self.publish_event({"event": "wheel_signal", "action": act, "note": note, "timestamp": time.time()})
                    self._send_json(200, {"ok": True, "wheel_status": act, "note": note})
                    return
                if self.path == "/api/approvals":
                    cid = str(data.get("card_id", "")).strip()
                    decision = str(data.get("decision", "approve")).strip().lower()
                    with srv_self._lock:
                        kept: List[Dict[str, Any]] = []
                        matched = None
                        for c in srv_self._state["pending_approvals"]:
                            if c.get("card_id") == cid and matched is None:
                                matched = c
                            else:
                                kept.append(c)
                        srv_self._state["pending_approvals"] = kept
                        rec = {"card_id": cid, "decision": decision, "matched": matched is not None, "ts": time.time()}
                        srv_self._state["approval_decisions"].append(rec)
                    srv_self.publish_event({"event": "approval_decision", **rec})
                    self._send_json(200, {"ok": True, **rec})
                    return
                if self.path == "/api/vault":
                    if srv_self.vault is None:
                        self._send_json(400, {"ok": False, "error": "BlindSecretVault not attached"})
                        return
                    act = str(data.get("action", "list")).strip().lower()
                    if act == "revoke":
                        ok = srv_self.vault.revoke_secret(str(data.get("alias", "")))
                        self._send_json(200, {"ok": ok, "action": "revoke"})
                        return
                    if act == "add":
                        meta = srv_self.vault.store_secret(
                            str(data.get("alias", "")),
                            str(data.get("secret", "")),
                            allowed_domains=list(data.get("allowed_domains") or []),
                            kind=str(data.get("kind", "password")),
                            notes=str(data.get("notes", "")),
                        )
                        self._send_json(200, {"ok": True, "entry": meta.to_dict()})
                        return
                    self._send_json(200, {"ok": True, "entries": srv_self.vault.list_entries()})
                    return
                if self.path == "/api/schedules":
                    if srv_self.schedule_store is None:
                        self._send_json(400, {"ok": False, "error": "RecurringScheduleStore not attached"})
                        return
                    act = str(data.get("action", "create")).strip().lower()
                    if act in ("pause", "resume"):
                        st = "paused" if act == "pause" else "active"
                        ok = srv_self.schedule_store.set_status(str(data.get("schedule_id", "")), st)
                        self._send_json(200, {"ok": ok, "status": st})
                        return
                    sch = srv_self.schedule_store.create_schedule(
                        name=str(data.get("name", "Scheduled Task")),
                        objective=str(data.get("objective", "")),
                        workspace=str(data.get("workspace", ".")),
                        expression=str(data.get("expression", "daily")),
                        provider=str(data.get("provider", "groq")),
                    )
                    self._send_json(200, {"ok": True, "schedule": sch})
                    return
                if self.path == "/api/memory":
                    if srv_self.memory_provider is None or not hasattr(srv_self.memory_provider, "delete_memory"):
                        self._send_json(400, {"ok": False, "error": "Memory provider CRUD not attached"})
                        return
                    act = str(data.get("action", "delete")).strip().lower()
                    if act == "delete":
                        out = srv_self.memory_provider.delete_memory(str(data.get("id", "")))
                        self._send_json(200, out)
                        return
                    self._send_json(400, {"ok": False, "error": f"Unsupported memory action: {act!r}"})
                    return
                self._send_json(404, {"ok": False, "error": f"Unknown endpoint: {self.path}"})

            def log_message(self, _format: str, *_args: Any) -> None:
                return None

        self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def close(self) -> None:
        with self._lock:
            for q in list(self._clients):
                try:
                    q.put_nowait(None)
                except Exception:
                    pass
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
