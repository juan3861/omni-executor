"""Runtime Information-Flow Control (Taint Tracking), SSRF Validator & Mount Allowlist Guard (v12.0).

Zero-dependency stdlib implementation inspired by OpenJarvis security/taint.py,
security/ssrf.py, and sandbox/mount_security.py, integrated into OmniExecutor's
security organ (`OMNI_TOPOLOGY_V2`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import fnmatch
import ipaddress
import os
from pathlib import Path
import re
import socket
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse


class TaintLabel(str, Enum):
    """Information-flow sensitivity labels attached to runtime tool data."""

    PII = "pii"
    SECRET = "secret"
    USER_PRIVATE = "user_private"
    EXTERNAL = "external"


@dataclass(frozen=True)
class TaintSet:
    """Immutable set of taint labels propagated across tool chains."""

    labels: FrozenSet[TaintLabel] = field(default_factory=frozenset)

    def union(self, other: "TaintSet") -> "TaintSet":
        return TaintSet(labels=self.labels | other.labels)

    def has(self, label: TaintLabel) -> bool:
        return label in self.labels

    def __bool__(self) -> bool:
        return bool(self.labels)

    def to_list(self) -> List[str]:
        return sorted(lbl.value for lbl in self.labels)

    @classmethod
    def from_labels(cls, *labels: TaintLabel) -> "TaintSet":
        return cls(labels=frozenset(labels))


# Sink policy: labels forbidden from flowing into each sink class
SINK_POLICY: Dict[str, Set[TaintLabel]] = {
    "web_search": {TaintLabel.PII, TaintLabel.SECRET},
    "http_request": {TaintLabel.PII, TaintLabel.SECRET},
    "browser_navigate": {TaintLabel.SECRET},
    "browser_type": {TaintLabel.SECRET},
    "channel_send": {TaintLabel.SECRET},
    "ws.write_file": {TaintLabel.SECRET},
    "file_write": {TaintLabel.SECRET},
    "ws.run": {TaintLabel.SECRET},
    "code_interpreter": {TaintLabel.SECRET},
}

_PII_PATTERNS = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),  # CPF
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),  # credit card
)

_PEM_HEADER_RE = re.compile(r"-{5}BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{5}")

_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|pk|api)[_-][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _PEM_HEADER_RE,
    re.compile(r"(?:bearer|api[_-]?key|password|secret|token)\s*[=:]\s*[A-Za-z0-9._/+=-]{12,}", re.IGNORECASE),
)

_SENSITIVE_PATH_PARTS = frozenset({
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    "secrets",
    "credentials",
})


def detect_taint(text: str, *, source_external: bool = False) -> TaintSet:
    """Detect PII, SECRET, or EXTERNAL taint labels in arbitrary tool text."""
    labels: Set[TaintLabel] = set()
    if source_external:
        labels.add(TaintLabel.EXTERNAL)
    if text:
        for pat in _SECRET_PATTERNS:
            if pat.search(text):
                labels.add(TaintLabel.SECRET)
                break
        for pat in _PII_PATTERNS:
            if pat.search(text):
                labels.add(TaintLabel.PII)
                break
    return TaintSet(labels=frozenset(labels))


def check_taint(tool_name: str, taint: TaintSet) -> Optional[str]:
    """Return a violation string if *taint* violates SINK_POLICY for *tool_name*, else None."""
    forbidden = SINK_POLICY.get(tool_name)
    if not forbidden or not taint:
        return None
    violations = taint.labels & forbidden
    if not violations:
        return None
    labels_str = ", ".join(sorted(v.value for v in violations))
    return f"Taint policy violation on sink '{tool_name}': forbidden labels [{labels_str}]"


class RuntimeTaintTracker:
    """Session-scoped information-flow taint tracker for WorkspaceTools / AgentLoop."""

    def __init__(self, *, enforce: bool = False) -> None:
        self.enforce = enforce
        self.session_taint: TaintSet = TaintSet()
        self.events: List[Dict[str, Any]] = []

    def observe_source(self, source_name: str, content: str, *, external: bool = False) -> TaintSet:
        """Scan content read from a tool/file and merge detected taint into session state."""
        detected = detect_taint(content, source_external=external)
        if detected:
            self.session_taint = self.session_taint.union(detected)
            self.events.append({
                "kind": "source",
                "source": source_name,
                "labels": detected.to_list(),
            })
        return detected

    def check_sink(self, sink_name: str, payload: str, *, inherit_session: bool = False) -> Dict[str, Any]:
        """Evaluate whether *payload* (and optionally session taint) may flow to *sink_name*."""
        payload_taint = detect_taint(payload)
        effective = payload_taint.union(self.session_taint) if inherit_session else payload_taint
        violation = check_taint(sink_name, effective)
        rec = {
            "ok": violation is None,
            "blocked": bool(violation is not None and self.enforce),
            "sink": sink_name,
            "labels": effective.to_list(),
            "violation": violation,
        }
        if violation is not None:
            self.events.append({"kind": "sink_violation", **rec})
        return rec

    def summary(self) -> Dict[str, Any]:
        return {
            "enforce": self.enforce,
            "session_labels": self.session_taint.to_list(),
            "event_count": len(self.events),
            "violations": [e for e in self.events if e.get("kind") == "sink_violation"],
        }


class SSRFValidator:
    """Strict outbound URL validator preventing SSRF against loopback, RFC1918, and cloud metadata."""

    BLOCKED_HOSTNAMES = frozenset({
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.goog",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
    })
    ALLOWED_SCHEMES = frozenset({"http", "https"})

    @classmethod
    def _is_forbidden_ip(cls, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        if ip.is_loopback:
            return f"loopback IP blocked: {ip}"
        if ip.is_private:
            return f"private/RFC1918 IP blocked: {ip}"
        if ip.is_link_local:
            return f"link-local/metadata IP blocked: {ip}"
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return f"non-routable IP blocked: {ip}"
        return None

    @classmethod
    def validate_url(cls, url: str, *, resolve_dns: bool = False) -> Tuple[bool, str]:
        """Validate *url* for SSRF safety. Returns (allowed, reason)."""
        parsed = urlparse((url or "").strip())
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            return False, f"disallowed URL scheme: '{parsed.scheme}'"
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return False, "missing hostname"
        if host in cls.BLOCKED_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
            return False, f"blocked internal hostname: '{host}'"
        ip_err = cls._is_forbidden_ip(host)
        if ip_err:
            return False, ip_err
        if resolve_dns:
            try:
                infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
                for info in infos:
                    addr = info[4][0]
                    err = cls._is_forbidden_ip(addr)
                    if err:
                        return False, f"DNS resolved to forbidden target ({err})"
            except OSError:
                return False, f"DNS resolution failed for '{host}'"
        return True, "ok"


@dataclass(frozen=True)
class AllowedRoot:
    path: Path
    read_only: bool = True


class MountAllowlistGuard:
    """Validate host paths before mounting into containers or sandboxes."""

    def __init__(
        self,
        allowed_roots: Sequence[AllowedRoot],
        *,
        blocked_globs: Sequence[str] = ("*.pem", "*.key", ".env", ".env.*", "*id_rsa*"),
    ) -> None:
        self.allowed_roots = [AllowedRoot(Path(r.path).resolve(), r.read_only) for r in allowed_roots]
        self.blocked_globs = tuple(blocked_globs)

    def validate_mount(self, host_path: Path | str, *, write: bool = False) -> Tuple[bool, str]:
        raw = Path(host_path)
        if raw.is_symlink():
            return False, f"symlink mount rejected: {raw}"
        resolved = raw.resolve()
        parts_lower = {p.lower() for p in resolved.parts}
        if parts_lower & _SENSITIVE_PATH_PARTS:
            return False, f"sensitive directory mount blocked: {resolved}"
        name_lower = resolved.name.lower()
        for pat in self.blocked_globs:
            if fnmatch.fnmatch(name_lower, pat):
                return False, f"sensitive file pattern '{pat}' blocked: {resolved}"

        for root in self.allowed_roots:
            if resolved == root.path or root.path in resolved.parents:
                if write and root.read_only:
                    return False, f"write mount requested on read-only root: {root.path}"
                return True, "ok"
        return False, f"path outside mount allowlist: {resolved}"
