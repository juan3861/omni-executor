"""Cognition & LLM Client Organ (P5.2 + Real Cognitive Layer)."""

from .llm_client import (
    LLMClient,
    LLMResponse,
    LLMUnavailableError,
    ProviderSpec,
    build_provider_chain,
    extract_json_object,
)
from .personas import PersonaContract, PersonaManager
from .reasoning_bank import ReasoningBank
from .ure_bridge import URENeuroSymbolicBridge

__all__ = [
    "URENeuroSymbolicBridge",
    "LLMClient",
    "LLMResponse",
    "LLMUnavailableError",
    "ProviderSpec",
    "build_provider_chain",
    "extract_json_object",
    "PersonaContract",
    "PersonaManager",
    "ReasoningBank",
]
