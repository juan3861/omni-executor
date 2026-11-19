"""Cognition & LLM Client Organ (P5.2 + Real Cognitive Layer + AG-UI Protocol)."""

from .agui_protocol import (
    AGUIEvent,
    AGUIEventBus,
    AGUIEventType,
    BaseAGUISink,
    CallbackSink,
    JsonlFileSink,
    LoopbackSSEServer,
    StderrPrettySink,
)
from .hierarchical_planner import (
    HierarchicalPlan,
    ProactiveHierarchicalPlanner,
    Subgoal,
)
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

try:
    from .ure_bridge import URENeuroSymbolicBridge
except ImportError:  # optional external URE engine (clean CI / minimal pip install)
    URENeuroSymbolicBridge = None  # type: ignore[misc, assignment]

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
    "AGUIEventType",
    "AGUIEvent",
    "AGUIEventBus",
    "BaseAGUISink",
    "JsonlFileSink",
    "StderrPrettySink",
    "CallbackSink",
    "LoopbackSSEServer",
    "Subgoal",
    "HierarchicalPlan",
    "ProactiveHierarchicalPlanner",
]
