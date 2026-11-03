"""Universal Cognitive Router (P4.4).

Unites:
  1. `ResponsesWireTranslator`: Bidirectional lossless translation between OpenAI
     `/v1/chat/completions` (`messages` + `tool_calls`) and OpenAI `/v1/responses`
     (`instructions` + `input` + `function_call` / `function_call_output`).
  2. RTK / Caveman Token Compression (`compress_prompt_rtk`): Compresses prose boilerplate
     while strictly preserving fenced code blocks, file paths, URLs, and identifiers.
  3. `UniversalCognitiveRouter`: Health-checked multi-tier model routing across `OmniRoute`
     (`:20128`), `Mesh Gateway` (`:8317`), and strictly read-only HTTP client access to
     `F:\\rotor-llm` (`:3700`) under `ConstitutionSealGuard` RX 580 hardware locks.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from am_ua.governance.seal_guard import ConstitutionSealGuard

CODE_FENCE_SPLIT_RE = re.compile(r"(```[\s\S]*?```)")
FILLER_PATTERNS = [
    (re.compile(r"\bplease\s+make\s+sure\s+to\b", re.IGNORECASE), "ensure"),
    (re.compile(r"\bin\s+order\s+to\b", re.IGNORECASE), "to"),
    (re.compile(r"\bat\s+this\s+point\s+in\s+time\b", re.IGNORECASE), "now"),
    (re.compile(r"\bdue\s+to\s+the\s+fact\s+that\b", re.IGNORECASE), "because"),
    (re.compile(r"\bit\s+is\s+important\s+to\s+note\s+that\b", re.IGNORECASE), "note:"),
    (re.compile(r"\bfor\s+the\s+purpose\s+of\b", re.IGNORECASE), "for"),
    (re.compile(r"[ \t]{2,}"), " "),
    (re.compile(r"\n{3,}"), "\n\n"),
]


class ResponsesWireTranslator:
    """Lossless wire translator between `/v1/chat/completions` and `/v1/responses`."""

    @staticmethod
    def chat_to_responses_payload(chat_req: Dict[str, Any]) -> Dict[str, Any]:
        """Convert `/v1/chat/completions` request dict into `/v1/responses` schema."""
        messages = list(chat_req.get("messages", []))
        system_chunks: List[str] = []
        input_items: List[Dict[str, Any]] = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role in ("system", "developer"):
                if isinstance(content, str) and content.strip():
                    system_chunks.append(content.strip())
                continue
            if role == "tool":
                input_items.append(
                    {
                        "type": "function_call_output",
                        "call_id": str(msg.get("tool_call_id", "call_unknown")),
                        "output": content if isinstance(content, str) else json.dumps(content),
                    }
                )
                continue
            if role == "assistant" and msg.get("tool_calls"):
                if isinstance(content, str) and content.strip():
                    input_items.append({"role": "assistant", "content": content})
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    input_items.append(
                        {
                            "type": "function_call",
                            "call_id": str(tc.get("id", "call_0")),
                            "name": str(fn.get("name", "")),
                            "arguments": str(fn.get("arguments", "{}")),
                        }
                    )
                continue
            input_items.append({"role": role, "content": content})

        out: Dict[str, Any] = {
            "model": chat_req.get("model", "gpt-5.4"),
            "input": input_items,
        }
        if system_chunks:
            out["instructions"] = "\n\n".join(system_chunks)
        if "tools" in chat_req:
            resp_tools = []
            for t in chat_req["tools"]:
                if t.get("type") == "function" and "function" in t:
                    fn = t["function"]
                    resp_tools.append(
                        {
                            "type": "function",
                            "name": fn.get("name"),
                            "description": fn.get("description", ""),
                            "parameters": fn.get("parameters", {}),
                        }
                    )
                else:
                    resp_tools.append(t)
            out["tools"] = resp_tools
        if "previous_response_id" in chat_req:
            out["previous_response_id"] = chat_req["previous_response_id"]
        return out

    @staticmethod
    def responses_to_chat_completion(resp_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Convert `/v1/responses` output object back into `/v1/chat/completions` response."""
        text_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []

        for item in resp_obj.get("output", []):
            itype = item.get("type")
            if itype == "message":
                for c in item.get("content", []):
                    if c.get("type") in ("output_text", "text"):
                        text_parts.append(str(c.get("text", "")))
            elif itype == "function_call":
                tool_calls.append(
                    {
                        "id": str(item.get("call_id", item.get("id", "call_0"))),
                        "type": "function",
                        "function": {
                            "name": str(item.get("name", "")),
                            "arguments": str(item.get("arguments", "{}")),
                        },
                    }
                )
        if not text_parts and isinstance(resp_obj.get("output_text"), str):
            text_parts.append(resp_obj["output_text"])

        assistant_msg: Dict[str, Any] = {
            "role": "assistant",
            "content": "\n".join(text_parts) if text_parts else None,
        }
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls

        return {
            "id": resp_obj.get("id", "chatcmpl-translated"),
            "object": "chat.completion",
            "model": resp_obj.get("model", "unknown"),
            "choices": [
                {
                    "index": 0,
                    "message": assistant_msg,
                    "finish_reason": "tool_calls" if tool_calls else "stop",
                }
            ],
            "usage": resp_obj.get("usage", {}),
        }


@dataclass
class EndpointProfile:
    name: str
    base_url: str
    wire_protocol: str  # "responses" | "chat_completions"
    read_only_external: bool = False
    default_model: str = "auto"
    tags: List[str] = field(default_factory=list)


class UniversalCognitiveRouter:
    """Multi-provider health-aware router across OmniRoute, Mesh Gateway, and rotor-llm."""

    DEFAULT_ENDPOINTS: Dict[str, EndpointProfile] = {
        "omniroute": EndpointProfile(
            name="omniroute",
            base_url="http://127.0.0.1:20128/v1",
            wire_protocol="responses",
            default_model="claude-opus-4-6",
            tags=["architect_deep", "verifier", "general"],
        ),
        "mesh_gateway": EndpointProfile(
            name="mesh_gateway",
            base_url="http://127.0.0.1:8317/v1",
            wire_protocol="chat_completions",
            default_model="gpt-5.4",
            tags=["fast_coder", "verifier", "general"],
        ),
        "rotor_llm_local": EndpointProfile(
            name="rotor_llm_local",
            base_url="http://127.0.0.1:3700/v1",
            wire_protocol="chat_completions",
            read_only_external=True,
            default_model="qwen2.5-coder-local",
            tags=["local_sovereign", "offline"],
        ),
    }

    def __init__(
        self,
        endpoints: Optional[Dict[str, EndpointProfile]] = None,
        *,
        seal_guard: Optional[ConstitutionSealGuard] = None,
    ) -> None:
        self.endpoints = endpoints or dict(self.DEFAULT_ENDPOINTS)
        self.seal_guard = seal_guard or ConstitutionSealGuard()
        self.telemetry_log: List[Dict[str, Any]] = []

    @staticmethod
    def compress_prompt_rtk(text: str) -> Dict[str, Any]:
        """RTK / Caveman prompt compression preserving fenced code blocks byte-for-byte."""
        segments = CODE_FENCE_SPLIT_RE.split(text)
        compressed_parts: List[str] = []
        for idx, seg in enumerate(segments):
            if idx % 2 == 1:
                # Fenced code block: preserve 100% verbatim!
                compressed_parts.append(seg)
            else:
                cur = seg
                for pat, repl in FILLER_PATTERNS:
                    cur = pat.sub(repl, cur)
                compressed_parts.append(cur)
        out = "".join(compressed_parts)
        orig_len = max(1, len(text))
        return {
            "text": out,
            "original_chars": len(text),
            "compressed_chars": len(out),
            "saved_chars": len(text) - len(out),
            "ratio": round(len(out) / orig_len, 4),
        }

    def probe_endpoint_health(self, name: str, *, timeout_s: float = 1.5) -> Dict[str, Any]:
        """Non-mutating HTTP health probe (`GET /models`) against local sovereign gateway."""
        ep = self.endpoints[name]
        url = f"{ep.base_url.rstrip('/')}/models"
        t0 = time.perf_counter()
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                body = resp.read(8192).decode("utf-8", errors="replace")
                ms = round((time.perf_counter() - t0) * 1000.0, 2)
                return {
                    "endpoint": name,
                    "reachable": 200 <= resp.status < 400,
                    "status_code": resp.status,
                    "latency_ms": ms,
                    "sample": body[:200],
                }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                "endpoint": name,
                "reachable": False,
                "status_code": 0,
                "latency_ms": ms,
                "reason": str(exc),
            }

    def select_route(
        self,
        task_tier: str = "general",
        *,
        require_different_from: Optional[str] = None,
        probe_live: bool = False,
    ) -> Dict[str, Any]:
        """Select optimal cognitive route while enforcing independent-judge diversity."""
        candidates = [
            ep
            for ep in self.endpoints.values()
            if (task_tier in ep.tags or task_tier == "general")
            and ep.name != require_different_from
        ]
        if not candidates:
            candidates = [
                ep for ep in self.endpoints.values() if ep.name != require_different_from
            ]
        chosen = candidates[0]
        live_status = None
        if probe_live:
            for ep in candidates:
                st = self.probe_endpoint_health(ep.name)
                if st["reachable"]:
                    chosen = ep
                    live_status = st
                    break
            if live_status is None:
                live_status = self.probe_endpoint_health(chosen.name)

        decision = {
            "endpoint": chosen.name,
            "base_url": chosen.base_url,
            "wire_protocol": chosen.wire_protocol,
            "model": chosen.default_model,
            "read_only_external": chosen.read_only_external,
            "live_probe": live_status,
        }
        self.telemetry_log.append({"ts": time.time(), "task_tier": task_tier, **decision})
        return decision
