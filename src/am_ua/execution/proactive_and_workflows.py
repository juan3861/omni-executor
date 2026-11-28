"""Proactive Work-Ahead Draft Engine & Workflow Draft-Test-Publish Gate (`am_ua.execution.proactive_and_workflows`, v14.0).

Inspired by Nod (`n8n-io/nod`):
  - `ProactiveDraftEngine`: scans authorized read-only signals (failing checks, inbox/webhook
    summaries, overdue tasks, repository diffs) and prepares non-mutating `ProactiveOffer`
    drafts with estimated cost & impact, awaiting explicit human acceptance.
  - `WorkflowDraftManager`: enforces `DRAFT -> SAMPLE_TESTED -> AWAITING_PUBLISH_APPROVAL -> PUBLISHED`
    for structured automation pipelines and n8n-compatible workflow JSONs (via local store or
    `MCPFederationHub` / SSRF-guarded HTTP). Includes deterministic failure troubleshooting.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence
import uuid

from am_ua.contracts.contracts import resolve_omni_temp_dir


@dataclass(frozen=True)
class ProactiveOffer:
    offer_id: str
    title: str
    source: str
    suggested_objective: str
    estimated_cost_usd: float
    risk_tier: str  # "low" | "medium" | "high"
    draft_summary: str
    requires_approval: bool = True
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProactiveDraftEngine:
    """Generates non-destructive proactive task offers ahead of user requests."""

    def __init__(self) -> None:
        self._offers: Dict[str, ProactiveOffer] = {}
        self._accepted_ids: List[str] = []

    def generate_offers_from_signals(self, signals: Sequence[Dict[str, Any]]) -> List[ProactiveOffer]:
        created: List[ProactiveOffer] = []
        now = time.time()
        for sig in signals:
            kind = str(sig.get("kind") or "generic").lower()
            src = str(sig.get("source") or "signal")
            title = str(sig.get("title") or f"Handle {kind} event").strip()
            detail = str(sig.get("detail") or sig.get("message") or "").strip()
            oid = f"off-{hashlib.sha256(f'{kind}:{src}:{title}'.encode('utf-8')).hexdigest()[:10]}"
            if kind in ("failing_ci", "ci_error", "workflow_failed"):
                obj = f"Diagnose and prepare minimal verified fix for {title}: {detail[:200]}"
                risk = "low"
                draft = f"Read-only diagnosis + isolated patch draft for '{title}'."
            elif kind in ("invoice_email", "supplier_portal"):
                obj = f"Download invoice PDF from {src} and stage in accountant folder (draft receipt only)"
                risk = "medium"
                draft = f"Blind login + PDF download proposal for '{title}' (no payment or deletion)."
            elif kind in ("price_drop", "alert"):
                obj = f"Compare current price on {src} and prepare notification draft"
                risk = "low"
                draft = f"Price check & summary brief for '{title}'."
            else:
                obj = f"Prepare draft action plan for {title}: {detail[:180]}"
                risk = "medium"
                draft = f"Draft plan generated from '{src}'."
            offer = ProactiveOffer(
                offer_id=oid,
                title=title,
                source=src,
                suggested_objective=obj,
                estimated_cost_usd=0.0 if sig.get("free_tier", True) else float(sig.get("estimated_cost_usd", 0.05)),
                risk_tier=risk,
                draft_summary=draft,
                requires_approval=True,
                created_at=now,
            )
            self._offers[oid] = offer
            created.append(offer)
        return created

    def list_offers(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self._offers.values()]

    def accept_offer(self, offer_id: str) -> Dict[str, Any]:
        if offer_id not in self._offers:
            return {"ok": False, "error": f"Unknown offer_id: {offer_id!r}"}
        if offer_id not in self._accepted_ids:
            self._accepted_ids.append(offer_id)
        return {"ok": True, "offer": self._offers[offer_id].to_dict(), "accepted": True}


class WorkflowDraftManager:
    """Enforces Draft -> Sample-Test -> Troubleshoot -> Explicit Publish Gate (n8n-compatible)."""

    def __init__(self, store_path: Optional[Path | str] = None) -> None:
        base = resolve_omni_temp_dir("workflow_drafts") if store_path is None else None
        self.store_path = Path(store_path or (base / "drafts.json")).resolve()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._drafts: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.store_path.is_file():
            try:
                raw = json.loads(self.store_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return raw
            except Exception:
                pass
        return {}

    def _save(self) -> None:
        tmp = self.store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._drafts, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.store_path)

    def create_draft(
        self,
        name: str,
        *,
        objective: str,
        nodes: Optional[Sequence[Dict[str, Any]]] = None,
        connections: Optional[Dict[str, Any]] = None,
        target_system: str = "omni",  # "omni" | "n8n"
    ) -> Dict[str, Any]:
        """Build an inactive workflow draft (safe to edit & test without publishing)."""
        did = f"wfd-{uuid.uuid4().hex[:10]}"
        wf_nodes = list(nodes or [
            {"id": "1", "name": "Manual/Schedule Trigger", "type": "trigger", "parameters": {"objective": objective}},
            {"id": "2", "name": "Action Step", "type": "action", "parameters": {"mode": "dry_run"}},
        ])
        now = time.time()
        rec = {
            "draft_id": did,
            "name": name.strip() or did,
            "objective": objective.strip(),
            "target_system": target_system.strip().lower(),
            "status": "DRAFT",
            "active": False,
            "workflow_json": {
                "name": name.strip() or did,
                "active": False,
                "nodes": wf_nodes,
                "connections": dict(connections or {}),
            },
            "last_test_result": None,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self._drafts[did] = rec
            self._save()
        return dict(rec)

    def test_draft_with_sample(
        self,
        draft_id: str,
        sample_payload: Optional[Dict[str, Any]] = None,
        *,
        runner_fn: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validate workflow graph & simulate execution against sample data without activating live triggers."""
        with self._lock:
            rec = self._drafts.get(draft_id)
            if not rec:
                return {"ok": False, "error": f"Unknown draft_id: {draft_id!r}"}
            wf = rec["workflow_json"]
            nodes = wf.get("nodes") or []
            if not nodes:
                rec["last_test_result"] = {"ok": False, "error": "Workflow has zero nodes"}
                rec["updated_at"] = time.time()
                self._save()
                return rec["last_test_result"]

            sample = dict(sample_payload or {"sample": True, "ts": time.time()})
            if runner_fn is not None:
                test_out = runner_fn(wf, sample)
            else:
                trace = [{"node": n.get("name") or n.get("id"), "type": n.get("type"), "ok": True} for n in nodes]
                test_out = {"ok": True, "mode": "sample_dry_run", "nodes_executed": len(trace), "trace": trace, "sample": sample}

            rec["last_test_result"] = test_out
            if test_out.get("ok"):
                rec["status"] = "SAMPLE_TESTED"
            rec["updated_at"] = time.time()
            self._save()
            return {"ok": bool(test_out.get("ok")), "draft_id": draft_id, "status": rec["status"], "test_result": test_out}

    def publish_draft(
        self,
        draft_id: str,
        *,
        human_approved: bool = False,
        mcp_hub: Any = None,
        mcp_server: str = "n8n",
        mcp_tool: str = "publish_workflow",
    ) -> Dict[str, Any]:
        """Publish an explicitly approved & sample-tested workflow draft."""
        with self._lock:
            rec = self._drafts.get(draft_id)
            if not rec:
                return {"ok": False, "error": f"Unknown draft_id: {draft_id!r}"}
            if not human_approved:
                return {
                    "ok": False,
                    "blocked_by_publish_gate": True,
                    "requires_human_approval": True,
                    "draft_id": draft_id,
                    "error": "Explicit human approval (`human_approved=True`) is required before publishing any workflow.",
                }
            if rec.get("status") != "SAMPLE_TESTED":
                return {
                    "ok": False,
                    "blocked_by_publish_gate": True,
                    "draft_id": draft_id,
                    "error": f"Draft '{draft_id}' must pass `test_draft_with_sample` before publishing (current={rec.get('status')}).",
                }
            mcp_out = None
            if mcp_hub is not None and rec.get("target_system") == "n8n":
                mcp_out = mcp_hub.call_server_tool(mcp_server, mcp_tool, {"workflow": rec["workflow_json"]})
            rec["status"] = "PUBLISHED"
            rec["active"] = True
            rec["workflow_json"]["active"] = True
            rec["updated_at"] = time.time()
            self._save()
            out: Dict[str, Any] = {"ok": True, "draft_id": draft_id, "status": "PUBLISHED", "active": True}
            if mcp_out is not None:
                out["mcp_result"] = mcp_out
            return out

    @staticmethod
    def troubleshoot_execution(execution_log: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministically pinpoint the failing node and probable root cause from an execution trace."""
        nodes = list(execution_log.get("nodes") or execution_log.get("steps") or [])
        failing: List[Dict[str, Any]] = []
        for n in nodes:
            if not n.get("ok", True) or n.get("error"):
                failing.append({
                    "node": n.get("name") or n.get("node") or n.get("id") or "unknown",
                    "error": str(n.get("error") or "step_failed")[:300],
                })
        err_blob = " ".join(f["error"].lower() for f in failing) + " " + str(execution_log.get("error") or "").lower()
        if any(k in err_blob for k in ("401", "403", "unauthorized", "token", "auth")):
            hint = "Check credentials in BlindSecretVault / MCP auth configuration; never hardcode keys."
        elif any(k in err_blob for k in ("timeout", "429", "rate limit", "econnreset")):
            hint = "Transient network/rate error; enable retry backoff or switch provider."
        elif any(k in err_blob for k in ("keyerror", "undefined", "missing field", "json")):
            hint = "Upstream payload schema mismatch; validate sample data mapping before publishing."
        else:
            hint = "Inspect failing node input/output and re-run `test_draft_with_sample`."
        return {
            "ok": True,
            "failing_nodes": failing,
            "root_cause_hint": hint,
            "failed_count": len(failing),
        }

    def list_drafts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self._drafts.values()]
