"""Blind Secret Vault & Domain-Pinned Form-Filling Isolation (`am_ua.security.blind_vault`, v14.0).

Inspired by Nod (`n8n-io/nod`):
  - Secrets (logins, passwords, payment cards, service tokens) are encrypted at rest via
    `WindowsDPAPIProvider` (Win32 DPAPI on Windows, PBKDF2/HMAC `0o600` on POSIX).
  - Plaintext secrets NEVER enter LLM prompts, tool observations, AG-UI event streams, or
    workspace files.
  - Only host-side sinks (such as `CDPIndexedBrowser.fill_secret`) may call
    `resolve_for_domain(alias, target_url)`, which strictly checks `allowed_domains`
    against the active URL host before decrypting and records a redacted audit trail.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from am_ua.contracts.contracts import resolve_omni_temp_dir
from am_ua.governance.seal_guard import ConstitutionalViolationError
from am_ua.security.dpapi_envelope import WindowsDPAPIProvider

_VALID_KINDS = frozenset({"login", "username", "password", "card", "token", "generic"})


@dataclass(frozen=True)
class BlindVaultMetadata:
    """Public metadata for a stored secret (never carries plaintext)."""

    alias: str
    kind: str
    allowed_domains: List[str]
    masked_preview: str
    notes: str
    created_at: float
    updated_at: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BlindSecretVault:
    """Host-only encrypted credential vault with strict domain pinning."""

    _ENTROPY = b"OmniExecutor_BlindSecretVault_v14"

    def __init__(self, vault_path: Optional[Path | str] = None) -> None:
        base = resolve_omni_temp_dir("blind_vault") if vault_path is None else None
        self.vault_path = Path(vault_path or (base / "vault.json")).resolve()
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.vault_path.is_file():
            try:
                raw = json.loads(self.vault_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw.setdefault("entries", {})
                    raw.setdefault("usage_log", [])
                    return raw
            except Exception:
                pass
        return {"version": 1, "entries": {}, "usage_log": []}

    def _save(self) -> None:
        tmp = self.vault_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.vault_path)
        if os.name != "nt":
            try:
                os.chmod(self.vault_path, 0o600)
            except OSError:
                pass

    @staticmethod
    def _normalize_alias(alias: str) -> str:
        clean = (alias or "").strip()
        if not clean or len(clean) > 64 or any(c.isspace() for c in clean):
            raise ValueError(f"Invalid vault alias: {alias!r}")
        return clean

    @staticmethod
    def _normalize_domains(domains: Optional[Sequence[str]]) -> List[str]:
        out: List[str] = []
        for d in domains or []:
            s = str(d).strip().lower()
            if s.startswith(("http://", "https://")):
                s = (urlparse(s).hostname or "").lower()
            if s and s not in out:
                out.append(s)
        return out

    @staticmethod
    def _domain_matches(target_url: str, allowed_domains: Sequence[str]) -> bool:
        if not allowed_domains:
            return False
        parsed = urlparse((target_url or "").strip())
        if parsed.scheme.lower() == "file":
            return "file" in allowed_domains or "localhost" in allowed_domains or "local" in allowed_domains
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        for allowed in allowed_domains:
            pat = allowed.lower().strip()
            if pat == "*":
                continue  # refuse wildcard-all for security; require explicit host or suffix
            if pat.startswith("*."):
                suffix = pat[1:]
                if host == pat[2:] or host.endswith(suffix):
                    return True
            elif host == pat or host.endswith(f".{pat}"):
                return True
        return False

    @staticmethod
    def _mask_secret(value: str, kind: str) -> str:
        if kind == "card" and len(value) >= 4:
            return f"****-****-****-{value[-4:]}"
        if kind in ("login", "username") and "@" in value:
            local, dom = value.split("@", 1)
            head = local[:2] if len(local) >= 2 else "*"
            return f"{head}***@{dom}"
        return "********"

    def store_secret(
        self,
        alias: str,
        secret_value: str,
        *,
        allowed_domains: Sequence[str],
        kind: str = "password",
        notes: str = "",
    ) -> BlindVaultMetadata:
        """Encrypt and store a secret bound strictly to `allowed_domains`."""
        clean_alias = self._normalize_alias(alias)
        val = str(secret_value)
        if not val:
            raise ValueError("secret_value must be non-empty")
        norm_kind = (kind or "generic").strip().lower()
        if norm_kind not in _VALID_KINDS:
            raise ValueError(f"Unsupported secret kind: {kind!r}")
        doms = self._normalize_domains(allowed_domains)
        if not doms:
            raise ValueError("allowed_domains must contain at least one explicit domain (e.g. 'portal.example.com' or 'localhost')")

        blob = WindowsDPAPIProvider.protect(val.encode("utf-8"), entropy=self._ENTROPY)
        b64 = base64.b64encode(blob).decode("ascii")
        now = time.time()
        with self._lock:
            prev = self._data["entries"].get(clean_alias) or {}
            created_at = float(prev.get("created_at") or now)
            entry = {
                "alias": clean_alias,
                "kind": norm_kind,
                "allowed_domains": doms,
                "masked_preview": self._mask_secret(val, norm_kind),
                "notes": str(notes or "")[:200],
                "sha256_prefix": hashlib.sha256(val.encode("utf-8")).hexdigest()[:10],
                "ciphertext_b64": b64,
                "created_at": created_at,
                "updated_at": now,
            }
            self._data["entries"][clean_alias] = entry
            self._save()
            return BlindVaultMetadata(
                alias=clean_alias,
                kind=norm_kind,
                allowed_domains=doms,
                masked_preview=entry["masked_preview"],
                notes=entry["notes"],
                created_at=created_at,
                updated_at=now,
            )

    def list_entries(self) -> List[Dict[str, Any]]:
        """List stored aliases with masked previews only (never returns plaintext)."""
        with self._lock:
            out: List[Dict[str, Any]] = []
            for alias in sorted(self._data["entries"]):
                e = self._data["entries"][alias]
                out.append({
                    "alias": e["alias"],
                    "kind": e["kind"],
                    "allowed_domains": list(e["allowed_domains"]),
                    "masked_preview": e["masked_preview"],
                    "notes": e.get("notes", ""),
                    "created_at": e.get("created_at"),
                    "updated_at": e.get("updated_at"),
                })
            return out

    def revoke_secret(self, alias: str) -> bool:
        """Delete a secret entry permanently by alias."""
        clean_alias = self._normalize_alias(alias)
        with self._lock:
            if clean_alias in self._data["entries"]:
                del self._data["entries"][clean_alias]
                self._data["usage_log"].append({
                    "ts": time.time(),
                    "alias": clean_alias,
                    "event": "revoked",
                })
                self._save()
                return True
            return False

    def resolve_for_domain(
        self,
        alias: str,
        target_url: str,
        *,
        purpose: str = "browser_fill",
        mission_id: str = "",
    ) -> str:
        """Host-only secret resolution for an explicitly pinned URL domain.

        Raises `ConstitutionalViolationError` if `target_url` does not match the
        secret's `allowed_domains`, blocking cross-site / prompt-injection exfiltration.
        """
        clean_alias = self._normalize_alias(alias)
        with self._lock:
            entry = self._data["entries"].get(clean_alias)
            if not entry:
                raise KeyError(f"Unknown vault alias: {clean_alias!r}")
            doms = list(entry.get("allowed_domains") or [])
            if not self._domain_matches(target_url, doms):
                self._data["usage_log"].append({
                    "ts": time.time(),
                    "alias": clean_alias,
                    "event": "blocked_domain_mismatch",
                    "target_host": urlparse(target_url).hostname or urlparse(target_url).scheme,
                    "purpose": purpose,
                    "mission_id": mission_id,
                })
                self._save()
                raise ConstitutionalViolationError(
                    f"BlindSecretVault blocked secret '{clean_alias}' on unauthorized URL '{target_url}' (allowed={doms})"
                )
            blob = base64.b64decode(str(entry["ciphertext_b64"]).encode("ascii"))
            plaintext = WindowsDPAPIProvider.unprotect(blob, entropy=self._ENTROPY).decode("utf-8")
            self._data["usage_log"].append({
                "ts": time.time(),
                "alias": clean_alias,
                "kind": entry.get("kind"),
                "event": "filled_blind",
                "target_host": urlparse(target_url).hostname or urlparse(target_url).scheme,
                "purpose": purpose,
                "mission_id": mission_id,
            })
            if len(self._data["usage_log"]) > 500:
                self._data["usage_log"] = self._data["usage_log"][-500:]
            self._save()
            return plaintext

    def get_usage_log(self, *, mission_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            logs = list(self._data.get("usage_log") or [])
            if mission_id:
                logs = [item for item in logs if item.get("mission_id") == mission_id]
            return logs[-max(1, int(limit)):]
