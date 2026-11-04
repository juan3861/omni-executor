"""Tests for SPARC Methodology & Elite Personas Assimilation (tests/test_sparc_and_personas.py).

Verifies:
1. PersonaManager loads all 5 elite engineering personas from Markdown-as-Code contracts.
2. PersonaManager aliases and fallbacks work reliably.
3. ReasoningBank indexes traces, computes similarity, and formats few-shot exemplars.
4. AgentLoop incorporates role-based persona contracts and SPARC workflow prompts.
"""

import json
from pathlib import Path
import pytest

from am_ua.cognition.personas import PersonaManager, PersonaContract
from am_ua.cognition.reasoning_bank import ReasoningBank, tokenize, jaccard_similarity
from am_ua.cognition.llm_client import LLMResponse
from am_ua.execution.agent_loop import AgentLoop, SYSTEM_PROMPT, SPARC_SYSTEM_PROMPT
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.governance.seal_guard import ConstitutionSealGuard


@pytest.fixture
def persona_mgr():
    return PersonaManager()


def test_persona_manager_discovers_all_elite_roles(persona_mgr):
    roles = persona_mgr.list_roles()
    expected = [
        "general_engineer",
        "performance_sre",
        "security_reverse_engineer",
        "strict_auditor",
        "systems_architect",
    ]
    for exp in expected:
        assert exp in roles, f"Expected role '{exp}' not discovered in personas"


def test_persona_contract_content(persona_mgr):
    auditor = persona_mgr.get_persona("strict_auditor")
    assert auditor.name == "Strict Empirical Auditor"
    assert auditor.role == "strict_auditor"
    assert "⚖️" in auditor.emoji
    assert "refutation" in auditor.body.lower() or "adversarial" in auditor.body.lower()

    injection = auditor.format_system_injection()
    assert "=== ACTIVE SPECIALIZED PERSONA: Strict Empirical Auditor" in injection
    assert "=== END PERSONA CONTRACT ===" in injection


def test_persona_aliases_and_fallback(persona_mgr):
    # Aliases
    p_arch = persona_mgr.get_persona("architect")
    assert p_arch.role == "systems_architect"

    p_aud = persona_mgr.get_persona("auditor")
    assert p_aud.role == "strict_auditor"

    p_sre = persona_mgr.get_persona("perf")
    assert p_sre.role == "performance_sre"

    # Fallback to general_engineer
    p_fallback = persona_mgr.get_persona("unknown_fantasy_role")
    assert p_fallback.role == "general_engineer"


def test_reasoning_bank_indexing_and_retrieval(tmp_path):
    traces_dir = tmp_path / "traces"
    traces_dir.mkdir()

    bank = ReasoningBank(traces_dir=traces_dir)
    assert bank.refresh_index() == 0

    # Add a mock successful run trace
    trace_data = {
        "mission_id": "test-trace-001",
        "objective": "Fix quadratic equation solver discriminant zero division",
        "status": "PASSED",
        "brier_score": 0.0,
        "verification": {"passed": True, "exit_code": 0},
        "final_summary": "Handled zero division by checking a == 0 first.",
        "tool_calls": [
            {"turn": 1, "tool": "read_file", "args": {"file": "solver.py"}},
            {"turn": 2, "tool": "replace_in_file", "args": {"file": "solver.py", "old": "x", "new": "y"}},
        ],
    }
    bank.record_run(trace_data)

    assert bank.refresh_index() == 1

    # Search with a similar query
    match = bank.find_best_trajectory("Resolve zero division in quadratic equation solver", min_similarity=0.2)
    assert match is not None
    assert match["mission_id"] == "test-trace-001"

    # Format exemplar
    exemplar = bank.format_trajectory_exemplar("Resolve zero division in quadratic equation solver", min_similarity=0.2)
    assert exemplar is not None
    assert "=== REASONING BANK: SIMILAR PAST SUCCESSFUL TRAJECTORY" in exemplar
    assert "read_file" in exemplar
    assert "replace_in_file" in exemplar


def test_tokenization_and_jaccard():
    tokens1 = tokenize("Fix the broken quadratic solver in python")
    tokens2 = tokenize("Fix quadratic equation solver zero division")
    sim = jaccard_similarity(tokens1, tokens2)
    assert sim > 0.25
    assert "the" not in tokens1
    assert "quadratic" in tokens1
    assert "solver" in tokens1


class MockLLMForLoop:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.total_prompt_tokens = 100
        self.total_completion_tokens = 50

    def chat(self, messages, **kwargs):
        self.calls += 1
        resp = self.responses.pop(0) if self.responses else '{"tool": "finish", "args": {"summary": "done", "confidence": 0.95}}'
        return LLMResponse(
            text=resp,
            provider="mock_provider",
            model="mock_model",
            prompt_tokens=50,
            completion_tokens=25,
            latency_ms=10.0,
        )

    def available(self):
        return ["mock_provider"]


def test_agent_loop_sparc_and_persona_injection(tmp_path):
    root = Path("F:/AetherMind_Universal_Agent")
    engine = DurableExecutionEngine(tmp_path / "durable_state.json")
    seal_guard = ConstitutionSealGuard(root)

    # Mock response finishes immediately
    mock_llm = MockLLMForLoop([
        '{"thought": "SPARC Phase S: read solver", "tool": "read_file", "args": {"file": "sample.py"}}',
        '{"thought": "SPARC Phase C: verified", "tool": "finish", "args": {"summary": "Audited sample.py", "confidence": 0.98}}',
    ])

    loop = AgentLoop(
        engine=engine,
        seal_guard=seal_guard,
        llm=mock_llm,
        trace_dir=tmp_path / "traces",
    )

    # Workspace must be in constitutionally allowed root (e.g. F:/AetherMind_Temp)
    ws_dir = Path("F:/AetherMind_Temp") / f"sparc_test_{tmp_path.name}"
    ws_dir.mkdir(parents=True, exist_ok=True)
    try:
        sample_file = ws_dir / "sample.py"
        sample_file.write_text("print('hello world')\n", encoding="utf-8")

        result = loop.run(
            objective="Audit sample.py for edge cases",
            workspace=ws_dir,
            role="strict_auditor",
            workflow="sparc",
            use_judge=False,
        )

        assert result.status == "COMPLETED_UNVERIFIED"
        assert result.role == "strict_auditor"
        assert result.workflow == "sparc"
        assert result.turns == 2
    finally:
        import shutil
        shutil.rmtree(ws_dir, ignore_errors=True)
