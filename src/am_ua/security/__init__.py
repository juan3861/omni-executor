"""Windows DPAPI Secret Protection & Anti-Replay Signed Envelopes."""

from .dpapi_envelope import (
    AuthenticatedEnvelopeManager,
    EnvelopeTamperedError,
    ReplayAttackError,
    WindowsDPAPIProvider,
)

__all__ = [
    "AuthenticatedEnvelopeManager",
    "EnvelopeTamperedError",
    "ReplayAttackError",
    "WindowsDPAPIProvider",
]
