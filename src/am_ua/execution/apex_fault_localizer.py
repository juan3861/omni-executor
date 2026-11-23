"""APEX Fault Localization, Guard Synthesis & Windowed ACI (`am_ua.execution.apex_fault_localizer`)."""

from __future__ import annotations

from am_ua.execution.autocoderover_ast_guard import AutoCodeRoverASTGuardSynthesizer
from am_ua.execution.fault_agentless_repair import AgentlessThreePhaseLocalizer
from am_ua.execution.fault_localization_core import (
    OchiaiSBFLFaultLocalizer,
    _extract_run_lines,
    _is_test_passed,
    _normalize_line_item,
    _split_location,
)
from am_ua.execution.swe_agent_window_aci import SWEAgentWindowedACI

__all__ = [
    "OchiaiSBFLFaultLocalizer",
    "AgentlessThreePhaseLocalizer",
    "AutoCodeRoverASTGuardSynthesizer",
    "SWEAgentWindowedACI",
]
