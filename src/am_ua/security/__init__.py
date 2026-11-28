"""Windows DPAPI Secret Protection, Anti-Replay Envelopes & Runtime Taint/SSRF/Mount Guard."""

from .blind_vault import BlindSecretVault, BlindVaultMetadata
from .dpapi_envelope import (
    AuthenticatedEnvelopeManager,
    EnvelopeTamperedError,
    ReplayAttackError,
    WindowsDPAPIProvider,
)
from .intent_authority import (
    ApprovalRequestCard,
    AuthorityScope,
    IntentAuthorityChecker,
    PermissionCheckDecision,
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
    "ApprovalRequestCard",
    "AuthorityScope",
    "AuthenticatedEnvelopeManager",
    "BlindSecretVault",
    "BlindVaultMetadata",
    "EnvelopeTamperedError",
    "IntentAuthorityChecker",
    "PermissionCheckDecision",
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
