"""Server-Side Intent-vs-Action Permission Checker & Trust Boundary (`am_ua.security.intent_authority`, v14.0).

Inspired by Nod (`n8n-io/nod`):
  - Only explicit user messages, user-created schedules, or explicit human approvals carry
    authority (`AuthorityScope`).
  - Untrusted external inputs (web pages, downloaded documents, external emails, tool
    outputs containing `TaintLabel.EXTERNAL`) NEVER grant authority or elevate permissions.
  - Every high-impact external/mutative action (send, post, pay, delete, publish, PR create,
    fill_secret, outbound network command) is verified deterministically against the trusted
    `AuthorityScope`; out-of-scope or externally-tainted actions pause for explicit human
    approval via an `ApprovalRequestCard`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import re
import time
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set


_SENSITIVE_INTENT_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "payment": frozenset({
        "pay", "purchase", "buy", "checkout", "refund", "transfer", "billing",
        "pagar", "compra", "pagamento", "pix", "cartao", "card",
    }),
    "delete": frozenset({
        "delete", "remove", "cancel", "terminate", "drop", "purge", "uninstall",
        "apagar", "deletar", "remover", "cancelar", "excluir",
    }),
    "send": frozenset({
        "send", "email", "mail", "message", "reply", "notify", "slack", "telegram", "whatsapp",
        "enviar", "responder", "mandar", "notificar",
    }),
    "publish": frozenset({
        "publish", "deploy", "release", "submit", "post", "create pr", "open pr", "push",
        "publicar", "postar", "submeter",
    }),
    "login": frozenset({
        "login", "sign in", "signin", "authenticate", "log in", "entrar", "autenticar", "vault",
    }),
}

_PAYMENT_TARGET_RE = re.compile(
    r"\b(pay|purchase|buy|checkout|transfer|charge|wire|pix|credit\s*card|cvv|pagar|comprar|pagamento)\b",
    re.IGNORECASE,
)
_DELETE_TARGET_RE = re.compile(
    r"\b(delete|remove|cancel\s+subscription|terminate|drop\s+table|purge|rm\s+-rf|apagar|cancelar|excluir)\b",
    re.IGNORECASE,
)
_SEND_TARGET_RE = re.compile(
    r"\b(send|email|reply|post|tweet|publish|submit|webhook|slack|telegram|whatsapp|enviar|publicar)\b",
    re.IGNORECASE,
)
_PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+system|new\s+priority\s+instruction|"
    r"exfiltrate|forward\s+all\s+secrets|transfer\s+funds\s+to|always\s+approve)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ApprovalRequestCard:
    """Human-readable approval card surfaced in CLI, Web Mission Control, and AG-UI SSE."""

    card_id: str
    mission_id: str
    category: str
    tool_name: str
    target_summary: str
    reason: str
    tainted_by_external: bool
    user_objective_excerpt: str
    created_at: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PermissionCheckDecision:
    """Result of evaluating a proposed tool call against the trusted `AuthorityScope`."""

    allowed: bool
    requires_approval: bool
    category: str
    reason: str
    tainted_by_external: bool = False
    approval_card: Optional[ApprovalRequestCard] = None

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        if self.approval_card is not None:
            out["approval_card"] = self.approval_card.to_dict()
        return out


@dataclass
class AuthorityScope:
    """Immutable-by-origin permissions extracted exclusively from trusted user input."""

    mission_id: str
    user_objective: str
    source: str = "user_chat"  # "user_chat" | "trusted_schedule" | "manual_approval"
    allowed_categories: Set[str] = field(default_factory=set)
    approved_signatures: Set[str] = field(default_factory=set)

    @classmethod
    def from_user_objective(
        cls,
        objective: str,
        *,
        mission_id: str = "mission",
        source: str = "user_chat",
    ) -> "AuthorityScope":
        low = (objective or "").lower()
        allowed: Set[str] = set()
        for cat, kws in _SENSITIVE_INTENT_CATEGORIES.items():
            if any(k in low for k in kws):
                allowed.add(cat)
        return cls(
            mission_id=mission_id,
            user_objective=str(objective or ""),
            source=source,
            allowed_categories=allowed,
        )

    def grant_signature(self, sig: str) -> None:
        if sig:
            self.approved_signatures.add(sig)


class IntentAuthorityChecker:
    """Deterministic trust-boundary checker ensuring external content never steers sensitive actions."""

    def __init__(self, scope: AuthorityScope) -> None:
        self.scope = scope
        self.external_taint_seen: bool = False
        self.external_sources: List[str] = []
        self.decisions_log: List[Dict[str, Any]] = []

    def mark_external_exposure(self, source: str, raw_text: str = "") -> Dict[str, Any]:
        """Record that untrusted external content entered the context window."""
        self.external_taint_seen = True
        src = str(source or "external")[:120]
        if src not in self.external_sources:
            self.external_sources.append(src)
        inj_hit = bool(raw_text and _PROMPT_INJECTION_RE.search(raw_text))
        return {
            "external_taint_seen": True,
            "source": src,
            "prompt_injection_pattern_detected": inj_hit,
        }

    @staticmethod
    def _action_signature(tool_name: str, args: Dict[str, Any]) -> str:
        raw = f"{tool_name}::{args.get('action', '')}::{args.get('target', args.get('url', args.get('command', args.get('recipient_id', ''))))}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _classify_sensitive_action(self, tool_name: str, args: Dict[str, Any]) -> Optional[tuple[str, str]]:
        """Return `(category, target_summary)` if the action is externally sensitive/irreversible."""
        t = (tool_name or "").strip().lower()
        act = str(args.get("action") or "").strip().lower()
        target_blob = " ".join(
            str(args.get(k) or "")
            for k in ("target", "url", "command", "recipient_id", "content", "vault_alias", "title", "playbook")
        ).strip()

        if t == "browser_act":
            if act == "fill_secret":
                return "login", f"fill_secret alias={args.get('vault_alias') or target_blob[:80]}"
            if act in ("click", "submit", "press"):
                if _PAYMENT_TARGET_RE.search(target_blob):
                    return "payment", target_blob[:120]
                if _DELETE_TARGET_RE.search(target_blob):
                    return "delete", target_blob[:120]
                if _SEND_TARGET_RE.search(target_blob) or act == "submit":
                    return "send", target_blob[:120]
        if t == "pc_act" and str(args.get("action_type") or "").lower() in ("click", "type", "hotkey", "press"):
            if _PAYMENT_TARGET_RE.search(target_blob):
                return "payment", target_blob[:120]
            if _DELETE_TARGET_RE.search(target_blob):
                return "delete", target_blob[:120]
            if _SEND_TARGET_RE.search(target_blob) and self.external_taint_seen:
                return "send", target_blob[:120]
        if t == "send_agent":
            return None  # internal swarm coordination stays inside AgentLoop
        if t in ("publish_workflow", "pr_create", "email_send", "channel_send"):
            return ("publish" if "publish" in t or "pr" in t else "send"), target_blob[:120]
        if t == "run":
            cmd = str(args.get("command") or "")
            if _PAYMENT_TARGET_RE.search(cmd):
                return "payment", cmd[:120]
            if _DELETE_TARGET_RE.search(cmd) and self.external_taint_seen:
                return "delete", cmd[:120]
            if re.search(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|git\s+push|gh\s+pr\s+create)\b", cmd, re.I):
                if self.external_taint_seen or "push" in cmd.lower() or "gh pr create" in cmd.lower():
                    return "publish", cmd[:120]
        if t == "mcp_call":
            mcp_t = str(args.get("tool") or "").lower()
            if any(k in mcp_t for k in ("send", "post", "email", "pay", "delete", "publish", "activate")):
                return "publish" if ("publish" in mcp_t or "activate" in mcp_t) else "send", f"{args.get('server')}/{mcp_t}"
        return None

    def check_action(self, tool_name: str, args: Dict[str, Any]) -> PermissionCheckDecision:
        """Verify whether `tool_name(args)` is strictly covered by trusted user intent."""
        classified = self._classify_sensitive_action(tool_name, args)
        if classified is None:
            return PermissionCheckDecision(
                allowed=True,
                requires_approval=False,
                category="safe_or_workspace",
                reason="Within normal workspace boundary",
                tainted_by_external=self.external_taint_seen,
            )

        category, target_summary = classified
        sig = self._action_signature(tool_name, args)
        if sig in self.scope.approved_signatures:
            dec = PermissionCheckDecision(
                allowed=True,
                requires_approval=False,
                category=category,
                reason="Explicitly approved by human operator",
                tainted_by_external=self.external_taint_seen,
            )
            self.decisions_log.append(dec.to_dict())
            return dec

        # Payments ALWAYS require explicit manual approval / override regardless of objective text
        in_scope = category in self.scope.allowed_categories
        if category == "payment":
            blocked = True
            reason = "Financial/payment actions always require explicit human approval before execution."
        elif self.external_taint_seen and not in_scope:
            blocked = True
            reason = (
                f"Action category '{category}' was not requested in user intent and session ingested "
                f"untrusted external content ({', '.join(self.external_sources[-3:])})."
            )
        elif not in_scope:
            blocked = True
            reason = f"Action category '{category}' exceeds trusted user objective scope."
        elif self.external_taint_seen and category in ("delete", "send", "publish"):
            # Under external taint, verify target matches something anchored in the trusted prompt if specific recipient/target
            target_tokens = [w for w in re.findall(r"[a-z0-9@._-]{4,}", target_summary.lower()) if w not in ("click", "submit", "post")]
            obj_low = self.scope.user_objective.lower()
            if target_tokens and not any(tok in obj_low for tok in target_tokens):
                blocked = True
                reason = (
                    f"External content cannot steer '{category}' toward an unmentioned target ({target_summary[:60]})."
                )
            else:
                blocked = False
                reason = f"Authorized by user intent ({category})"
        else:
            blocked = False
            reason = f"Authorized by user intent ({category})"

        card: Optional[ApprovalRequestCard] = None
        if blocked:
            card = ApprovalRequestCard(
                card_id=f"apr-{sig[:10]}",
                mission_id=self.scope.mission_id,
                category=category,
                tool_name=tool_name,
                target_summary=target_summary or tool_name,
                reason=reason,
                tainted_by_external=self.external_taint_seen,
                user_objective_excerpt=self.scope.user_objective[:180],
                created_at=time.time(),
            )

        dec = PermissionCheckDecision(
            allowed=not blocked,
            requires_approval=blocked,
            category=category,
            reason=reason,
            tainted_by_external=self.external_taint_seen,
            approval_card=card,
        )
        self.decisions_log.append(dec.to_dict())
        return dec
