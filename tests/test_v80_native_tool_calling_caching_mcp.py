"""Empirical verification suite for OmniExecutor v8.0 (Fase 1):
  - Native Tool Calling (`tools`, `tool_calls`) across OpenAI-compat, Anthropic, Gemini Native, Ollama
  - Explicit Prompt Caching (`cache_control` breakpoints + cache read/write cost telemetry) & Thinking budgets
  - True SSE Streaming assembling fragmented `delta.tool_calls` (OpenAI + Anthropic)
  - Parallel `ThreadPoolExecutor` dispatch for contiguous `PURE_READ` batches inside `AgentLoop`
  - Dynamic first-class MCP tool mounting (`mcp__<server>__<tool>`) inside `AgentLoop`
  - Atomic `_condense` preservation of `assistant(tool_calls)` + `role=tool` message pairs
  - Modular `WorkspaceTools` extraction, `[project.scripts]` entry points, and `OMNI_TOPOLOGY_V2` compliance.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading
import time
import tomllib
from typing import Any, Dict, List, Optional, Tuple

import pytest

from am_ua.cognition.llm_client import (
    DEFAULT_ORDER,
    LLMClient,
    LLMResponse,
    ProviderSpec,
    ToolCall,
    _DEFAULTS,
    estimate_cost_usd,
)
from am_ua.execution.agent_loop import AgentLoop, WorkspaceTools as LoopWorkspaceTools
from am_ua.execution.durable_engine import DurableExecutionEngine
from am_ua.execution.mcp_federation import MCPFederationHub
from am_ua.execution.tool_schemas import (
    TOOL_JSON_SCHEMAS,
    build_native_tool_schemas,
    discover_mcp_tool_schemas,
)
from am_ua.execution.workspace_tools import WorkspaceTools
from am_ua.governance.seal_guard import ConstitutionSealGuard
from am_ua.perception.polyglot_repomap import InterRepoTopologyGate


def _start_mock_server(handler_cls: type[BaseHTTPRequestHandler]) -> Tuple[HTTPServer, str, threading.Thread]:
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}", t


def test_v80_anthropic_protocol_wire_prompt_caching_thinking_and_tool_use(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: Dict[str, Any] = {}

    class AnthropicHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            captured["path"] = self.path
            captured["headers"] = {k.lower(): v for k, v in self.headers.items()}
            captured["body"] = json.loads(raw)
            resp = {
                "id": "msg_test_01",
                "model": "claude-sonnet-4-5-20250929",
                "content": [
                    {"type": "thinking", "thinking": "Inspecting file a.py first."},
                    {"type": "text", "text": "Reading a.py now."},
                    {
                        "type": "tool_use",
                        "id": "toolu_01abc",
                        "name": "read_file",
                        "input": {"file": "a.py", "start_line": 1, "end_line": 50},
                    },
                ],
                "usage": {
                    "input_tokens": 200,
                    "cache_read_input_tokens": 1800,
                    "cache_creation_input_tokens": 400,
                    "output_tokens": 120,
                },
            }
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv, base_url, _ = _start_mock_server(AnthropicHandler)
    try:
        monkeypatch.setenv("TEST_ANTHROPIC_KEY", "test-key-v80")
        spec = ProviderSpec(
            "anthropic",
            f"{base_url}/v1",
            "TEST_ANTHROPIC_KEY",
            "claude-sonnet-4-5-20250929",
            protocol="anthropic",
        )
        client = LLMClient(providers=[spec])
        tools = build_native_tool_schemas(objective="fix bug in a.py", role="general_engineer")
        messages = [
            {"role": "system", "content": "You are a disciplined engineer."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Inspect the screenshot and a.py"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
                ],
            },
            {"role": "assistant", "content": "Checking."},
            {"role": "user", "content": "Continue."},
        ]
        res = client.chat(
            messages,
            max_tokens=2048,
            temperature=0.2,
            tools=tools,
            tool_choice="auto",
            enable_prompt_cache=True,
            reasoning_effort="medium",
        )

        assert captured["path"] == "/v1/messages"
        assert captured["headers"]["x-api-key"] == "test-key-v80"
        assert captured["headers"]["anthropic-version"] == "2023-06-01"
        assert "prompt-caching" in captured["headers"]["anthropic-beta"]

        body = captured["body"]
        assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
        assert body["tools"][-1]["cache_control"] == {"type": "ephemeral"}
        assert "input_schema" in body["tools"][0]
        assert body["thinking"] == {"type": "enabled", "budget_tokens": 4096}
        assert body["max_tokens"] > 4096
        assert "temperature" not in body  # Anthropic forbids temperature with extended thinking
        # Verify multimodal image translation
        first_user_blocks = body["messages"][0]["content"]
        assert any(b.get("type") == "image" and b["source"]["type"] == "base64" for b in first_user_blocks)

        assert len(res.tool_calls) == 1
        assert res.tool_calls[0].id == "toolu_01abc"
        assert res.tool_calls[0].name == "read_file"
        assert res.tool_calls[0].arguments["file"] == "a.py"
        assert "Inspecting file" in res.thinking_text
        assert res.cache_read_tokens == 1800
        assert res.cache_write_tokens == 400
        assert res.prompt_tokens == 2400
        assert res.cost_usd > 0.0
        # Verify cache read discount makes cached call cheaper than uncached equivalent
        uncached_cost = estimate_cost_usd("claude-sonnet-4-5-20250929", 2400, 120)
        assert res.cost_usd < uncached_cost
    finally:
        srv.shutdown()
        srv.server_close()


def test_v80_gemini_native_protocol_wire_function_calls_and_schema_sanitization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: Dict[str, Any] = {}

    class GeminiHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            captured["path"] = self.path
            captured["headers"] = {k.lower(): v for k, v in self.headers.items()}
            captured["body"] = json.loads(raw)
            resp = {
                "modelVersion": "gemini-2.5-flash",
                "candidates": [
                    {
                        "content": {
                            "role": "model",
                            "parts": [
                                {"thought": True, "text": "Searching pattern first."},
                                {"functionCall": {"name": "search", "args": {"pattern": "def main"}}},
                            ],
                        }
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 900,
                    "candidatesTokenCount": 40,
                    "cachedContentTokenCount": 600,
                },
            }
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv, base_url, _ = _start_mock_server(GeminiHandler)
    try:
        monkeypatch.setenv("TEST_GEMINI_KEY", "gem-key-v80")
        spec = ProviderSpec(
            "gemini",
            f"{base_url}/v1beta",
            "TEST_GEMINI_KEY",
            "gemini-2.5-flash",
            protocol="gemini_native",
        )
        client = LLMClient(providers=[spec])
        tools = [TOOL_JSON_SCHEMAS["search"], TOOL_JSON_SCHEMAS["finish"]]
        res = client.chat(
            [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Find main."},
            ],
            tools=tools,
            tool_choice="auto",
            reasoning_effort="low",
        )

        assert captured["path"] == "/v1beta/models/gemini-2.5-flash:generateContent"
        assert "key=" not in captured["path"]  # Key must travel via header, never query string
        assert captured["headers"]["x-goog-api-key"] == "gem-key-v80"
        body = captured["body"]
        assert body["systemInstruction"]["parts"][0]["text"] == "Be concise."
        decls = body["tools"][0]["functionDeclarations"]
        assert len(decls) == 2
        assert "additionalProperties" not in json.dumps(decls)
        assert body["generationConfig"]["thinkingConfig"]["thinkingBudget"] == 1024

        assert len(res.tool_calls) == 1
        assert res.tool_calls[0].name == "search"
        assert res.tool_calls[0].arguments == {"pattern": "def main"}
        assert res.cache_read_tokens == 600
        assert "Searching pattern" in res.thinking_text
    finally:
        srv.shutdown()
        srv.server_close()


def test_v80_openai_and_anthropic_sse_stream_assembles_tool_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    class StreamHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            if self.path.endswith("/messages"):
                events = [
                    {"type": "message_start", "message": {"model": "claude-sonnet-4-5-20250929", "usage": {"input_tokens": 100, "cache_read_input_tokens": 500}}},
                    {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}},
                    {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Step 1"}},
                    {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_stream_1", "name": "list_dir", "input": {}}},
                    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '{"path": '}},
                    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '"src"}'}},
                    {"type": "message_delta", "usage": {"output_tokens": 25}},
                ]
                for ev in events:
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode("utf-8"))
            else:
                events = [
                    {"model": "gpt-5-mini", "choices": [{"delta": {"content": "Checking..."}}]},
                    {"model": "gpt-5-mini", "choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_s1", "function": {"name": "read_file", "arguments": '{"file":'}}]}}]},
                    {"model": "gpt-5-mini", "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"a.py"}'}}]}}]},
                    {"model": "gpt-5-mini", "choices": [{"delta": {}}], "usage": {"prompt_tokens": 300, "completion_tokens": 30}},
                ]
                for ev in events:
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")

    srv, base_url, _ = _start_mock_server(StreamHandler)
    try:
        deltas: List[str] = []
        oai_client = LLMClient(providers=[ProviderSpec("openai", f"{base_url}/v1", None, "gpt-5-mini", local=True)])
        r_oai = oai_client.chat_stream(
            [{"role": "user", "content": "read a.py"}],
            tools=[TOOL_JSON_SCHEMAS["read_file"]],
            on_delta=deltas.append,
        )
        assert "".join(deltas) == "Checking..."
        assert len(r_oai.tool_calls) == 1
        assert r_oai.tool_calls[0].id == "call_s1"
        assert r_oai.tool_calls[0].name == "read_file"
        assert r_oai.tool_calls[0].arguments == {"file": "a.py"}
        assert r_oai.prompt_tokens == 300 and r_oai.completion_tokens == 30

        thinks: List[str] = []
        monkeypatch.setenv("TEST_ANTH_STREAM_KEY", "k-stream")
        anth_client = LLMClient(
            providers=[ProviderSpec("anthropic", f"{base_url}/v1", "TEST_ANTH_STREAM_KEY", "claude-sonnet-4-5-20250929", protocol="anthropic")]
        )
        r_anth = anth_client.chat_stream(
            [{"role": "user", "content": "list src"}],
            tools=[TOOL_JSON_SCHEMAS["list_dir"]],
            on_thinking_delta=thinks.append,
        )
        assert "".join(thinks) == "Step 1"
        assert len(r_anth.tool_calls) == 1
        assert r_anth.tool_calls[0].id == "toolu_stream_1"
        assert r_anth.tool_calls[0].name == "list_dir"
        assert r_anth.tool_calls[0].arguments == {"path": "src"}
        assert r_anth.cache_read_tokens == 500
    finally:
        srv.shutdown()
        srv.server_close()


def test_v80_agent_loop_native_tool_calling_and_parallel_pure_read_speedup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "repo"
    ws.mkdir()
    for name in ("a.py", "b.py", "c.py", "d.py"):
        (ws / name).write_text(f"VALUE_{name[0].upper()} = 1\n", encoding="utf-8")

    seen_threads: set[int] = set()
    active_count = 0
    peak_concurrency = 0
    starts: List[float] = []
    ends: List[float] = []
    conc_lock = threading.Lock()
    orig_read_file = WorkspaceTools.read_file

    def slow_read_file(self: WorkspaceTools, args: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal active_count, peak_concurrency
        with conc_lock:
            seen_threads.add(threading.get_ident())
            active_count += 1
            peak_concurrency = max(peak_concurrency, active_count)
            starts.append(time.perf_counter())
        try:
            time.sleep(0.18)
            return orig_read_file(self, args)
        finally:
            with conc_lock:
                ends.append(time.perf_counter())
                active_count -= 1

    monkeypatch.setattr(WorkspaceTools, "read_file", slow_read_file)

    captured_calls: List[Dict[str, Any]] = []

    class NativeToolFakeLLM:
        calls = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["native_mock"]

        def chat(
            self,
            messages: List[Dict[str, Any]],
            *,
            max_tokens: int = 2048,
            temperature: Optional[float] = 0.2,
            json_mode: bool = False,
            prefer: Optional[str] = None,
            exclude: Optional[Any] = None,
            tools: Optional[List[Dict[str, Any]]] = None,
            tool_choice: Optional[Any] = None,
            enable_prompt_cache: bool = True,
            reasoning_effort: Optional[str] = None,
        ) -> LLMResponse:
            self.calls += 1
            captured_calls.append({"messages": list(messages), "tools": tools, "tool_choice": tool_choice})
            self.total_prompt_tokens += 200
            self.total_completion_tokens += 40
            if self.calls == 1:
                return LLMResponse(
                    text="",
                    provider="native_mock",
                    model="mock-v8",
                    prompt_tokens=200,
                    completion_tokens=40,
                    latency_ms=5.0,
                    tool_calls=[
                        ToolCall(id="tc_a", name="read_file", arguments={"file": "a.py"}),
                        ToolCall(id="tc_b", name="read_file", arguments={"file": "b.py"}),
                        ToolCall(id="tc_c", name="read_file", arguments={"file": "c.py"}),
                        ToolCall(id="tc_d", name="read_file", arguments={"file": "d.py"}),
                    ],
                )
            return LLMResponse(
                text="",
                provider="native_mock",
                model="mock-v8",
                prompt_tokens=200,
                completion_tokens=30,
                latency_ms=5.0,
                tool_calls=[
                    ToolCall(id="tc_fin", name="finish", arguments={"summary": "Read all 4 files in parallel.", "confidence": 0.99})
                ],
            )

    engine = DurableExecutionEngine(tmp_path / "durable.db")
    seal = ConstitutionSealGuard()
    loop = AgentLoop(engine=engine, seal_guard=seal, llm=NativeToolFakeLLM())  # type: ignore[arg-type]

    t0 = time.perf_counter()
    res = loop.run(
        "Read a.py, b.py, c.py, and d.py to inspect values",
        ws,
        use_judge=False,
        enable_zero_token_offload=False,
        parallel_read_workers=4,
    )
    elapsed = time.perf_counter() - t0

    assert res.status == "COMPLETED_UNVERIFIED"
    assert res.stop_reason == "finish"
    assert len(res.tool_calls) == 4
    # 4 x 0.18s in parallel must overlap concurrently (peak >= 2, batch span < 0.50s vs 0.72s sequential)
    read_batch_span = max(ends) - min(starts)
    assert peak_concurrency >= 2, f"Expected concurrent execution, got peak_concurrency={peak_concurrency}"
    assert read_batch_span < 0.50, f"Expected parallel PURE_READ span (<0.50s vs 0.72s seq), got {read_batch_span:.3f}s"
    assert len(seen_threads) >= 2

    # Turn 1 received native tools schema; Turn 2 received properly paired assistant tool_calls + 4 tool messages
    assert captured_calls[0]["tools"] is not None
    assert any(t["function"]["name"] == "read_file" for t in captured_calls[0]["tools"])
    turn2_msgs = captured_calls[1]["messages"]
    tool_msgs = [m for m in turn2_msgs if m.get("role") == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["tc_a", "tc_b", "tc_c", "tc_d"]

    # Verify _condense preserves atomic assistant(tool_calls) + role=tool grouping
    big_msgs: List[Dict[str, Any]] = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
    ]
    for i in range(6):
        big_msgs.append({"role": "assistant", "content": "x" * 10000, "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]})
        big_msgs.append({"role": "tool", "tool_call_id": f"c{i}", "name": "read_file", "content": "y" * 10000})
    condensed = AgentLoop._condense(big_msgs, max_chars=25_000)
    for idx, m in enumerate(condensed):
        if m.get("role") == "tool":
            assert idx > 0
            prev = condensed[idx - 1]
            assert prev.get("role") in ("assistant", "tool")


def test_v80_dynamic_mcp_tool_mounting_inside_agent_loop(tmp_path: Path) -> None:
    ws = tmp_path / "mcp_ws"
    ws.mkdir()
    (ws / "readme.txt").write_text("hello\n", encoding="utf-8")

    class StubMCPHub(MCPFederationHub):
        def __init__(self) -> None:
            super().__init__()
            self.invocations: List[Tuple[str, str, Dict[str, Any]]] = []
            self._servers["calc_srv"] = {"command": ["stub"], "cwd": None, "env": None}

        def list_server_tools(self, server_name: str, *, timeout_s: float = 15.0) -> Dict[str, Any]:
            return {
                "ok": True,
                "server": server_name,
                "tools": [
                    {
                        "name": "add_numbers",
                        "description": "Add two integers.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                            "required": ["a", "b"],
                        },
                    }
                ],
            }

        def call_server_tool(
            self,
            server_name: str,
            tool_name: str,
            arguments: Optional[Dict[str, Any]] = None,
            *,
            timeout_s: float = 30.0,
        ) -> Dict[str, Any]:
            args = dict(arguments or {})
            self.invocations.append((server_name, tool_name, args))
            return {"ok": True, "server": server_name, "tool": tool_name, "result": {"sum": int(args["a"]) + int(args["b"])}}

    hub = StubMCPHub()
    schemas, routing = discover_mcp_tool_schemas(hub)
    assert "mcp__calc_srv__add_numbers" in routing
    assert routing["mcp__calc_srv__add_numbers"] == ("calc_srv", "add_numbers")
    assert schemas[0]["function"]["name"] == "mcp__calc_srv__add_numbers"

    seen_tools_in_llm: List[str] = []
    seen_tool_result: List[str] = []

    class MCPFakeLLM:
        calls = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0

        def available(self) -> List[str]:
            return ["mcp_mock"]

        def chat(
            self,
            messages: List[Dict[str, Any]],
            *,
            max_tokens: int = 2048,
            temperature: Optional[float] = 0.2,
            json_mode: bool = False,
            prefer: Optional[str] = None,
            exclude: Optional[Any] = None,
            tools: Optional[List[Dict[str, Any]]] = None,
            tool_choice: Optional[Any] = None,
            enable_prompt_cache: bool = True,
            reasoning_effort: Optional[str] = None,
        ) -> LLMResponse:
            self.calls += 1
            if tools:
                seen_tools_in_llm.extend(t["function"]["name"] for t in tools)
            if self.calls == 1:
                return LLMResponse(
                    text="",
                    provider="mcp_mock",
                    model="mock-v8",
                    prompt_tokens=100,
                    completion_tokens=20,
                    latency_ms=2.0,
                    tool_calls=[
                        ToolCall(
                            id="tc_mcp_1",
                            name="mcp__calc_srv__add_numbers",
                            arguments={"a": 19, "b": 23},
                        )
                    ],
                )
            for m in messages:
                if m.get("role") == "tool" and m.get("tool_call_id") == "tc_mcp_1":
                    seen_tool_result.append(str(m.get("content", "")))
            return LLMResponse(
                text="",
                provider="mcp_mock",
                model="mock-v8",
                prompt_tokens=100,
                completion_tokens=20,
                latency_ms=2.0,
                tool_calls=[ToolCall(id="tc_fin", name="finish", arguments={"summary": "Sum is 42.", "confidence": 1.0})],
            )

    engine = DurableExecutionEngine(tmp_path / "durable_mcp.db")
    loop = AgentLoop(engine=engine, seal_guard=ConstitutionSealGuard(), llm=MCPFakeLLM(), mcp_hub=hub)  # type: ignore[arg-type]
    res = loop.run("Compute 19 + 23 using MCP calculator", ws, use_judge=False, enable_zero_token_offload=False)

    assert res.stop_reason == "finish"
    assert "mcp__calc_srv__add_numbers" in seen_tools_in_llm
    assert hub.invocations == [("calc_srv", "add_numbers", {"a": 19, "b": 23})]
    assert any("42" in txt for txt in seen_tool_result)


def test_v80_workspace_tools_modular_reexport_and_provider_registry() -> None:
    assert LoopWorkspaceTools is WorkspaceTools
    for prov in ("anthropic", "gemini", "ollama", "openai", "groq", "openrouter"):
        assert prov in _DEFAULTS
        assert prov in DEFAULT_ORDER
    assert _DEFAULTS["anthropic"]["protocol"] == "anthropic"
    assert _DEFAULTS["gemini"]["protocol"] == "gemini_native"
    assert _DEFAULTS["ollama"]["local"] is True


def test_v80_pyproject_console_scripts_and_topology_gate() -> None:
    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == "8.0.0"
    assert data["project"]["dependencies"] == []
    assert data["project"]["scripts"]["omni-executor"] == "am_ua.cli:main"
    assert data["project"]["scripts"]["omni"] == "am_ua.cli:main"
    topo = InterRepoTopologyGate().audit_package_imports(root / "src" / "am_ua")
    assert topo["ok"] is True, f"Topology violations: {topo['violations']}"
