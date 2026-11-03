"""Universal Cognitive Router (`OmniRoute` + `/v1/responses` + RTK + `rotor-llm` Adapter) (P4.4)."""

from .omni_router import ResponsesWireTranslator, UniversalCognitiveRouter

__all__ = ["ResponsesWireTranslator", "UniversalCognitiveRouter"]
