"""Windows DPAPI Secret Protection, Anti-Replay Envelopes & Runtime Taint/SSRF/Mount Guard."""

from .dpapi_envelope import (
    AuthenticatedEnvelopeManager,
    EnvelopeTamperedError,
    ReplayAttackError,
    WindowsDPAPIProvider,
)
from .runtime_taint import (
    AllowedRoot,
    MountAllowlistGuard,
    RuntimeTaintTracker,
    SSRFValidator,
    TaintLabel,
    TaintSet,
    check_taint,
    detect_taint,
)

__all__ = [
    "AuthenticatedEnvelopeManager",
    "EnvelopeTamperedError",
    "ReplayAttackError",
    "WindowsDPAPIProvider",
    "AllowedRoot",
    "MountAllowlistGuard",
    "RuntimeTaintTracker",
    "SSRFValidator",
    "TaintLabel",
    "TaintSet",
    "check_taint",
    "detect_taint",
]
