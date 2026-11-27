"""Real multi-provider LLM client v8.0 (OpenAI-compat, Anthropic, Gemini Native, Ollama).

Supports:
  - Ordered provider chain with automatic failover (429/5xx/timeout/network) and per-session circuit breaker
  - Native Tool Calling (`tools`, `tool_choice`, structured `ToolCall` outputs) across OpenAI, Anthropic,
    Gemini Native, and Ollama/OpenRouter/Groq — with automatic fallback if a model rejects `tools`
  - Explicit Prompt Caching (`cache_control` breakpoints on Anthropic + cache hit/write telemetry across all providers)
  - Reasoning/Thinking budgets (`reasoning_effort`: low/medium/high -> OpenAI reasoning_effort, Anthropic thinking, Gemini thinkingConfig)
  - True SSE Streaming (`chat_stream`) assembling both text deltas and incremental streamed `tool_calls`
  - Multimodal vision inputs (`image_url` data URIs translated natively per provider)
  - Honest token and USD cost accounting from provider `usage` payloads; keys read only from env at call time.

Provider order / models are configurable via env:
  AM_UA_PROVIDERS="groq,openrouter,openai,anthropic,gemini,ollama"
  AM_UA_GROQ_MODEL=...  AM_UA_ANTHROPIC_MODEL=...  AM_UA_OPENAI_MODEL=... etc.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse


class LLMUnavailableError(RuntimeError):
    """Raised when every provider in the chain failed."""


@dataclass(frozen=True)
class ToolCall:
    """Normalized structured tool invocation returned natively by an LLM provider."""

    id: str
    name: str
    arguments: Dict[str, Any]
    raw_arguments: str = ""


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    base_url: str
    key_env: Optional[str]
    model: str
    local: bool = False
    fallback_models: Tuple[str, ...] = ()
    protocol: str = "openai_compat"

    def api_keys(self) -> List[str]:
        """Return ordered deduplicated key pool from `<KEY_ENV>S`, `<KEY_ENV>`, or `GOOGLE_API_KEY`."""
        if not self.key_env:
            return []
        candidates: List[str] = []
        for env_name in (f"{self.key_env}S", self.key_env):
            raw = os.environ.get(env_name, "")
            if raw:
                for part in raw.split(","):
                    k = part.strip()
                    if k and k not in candidates:
                        candidates.append(k)
        if not candidates and self.name == "gemini":
            for env_name in ("GOOGLE_API_KEYS", "GOOGLE_API_KEY"):
                raw = os.environ.get(env_name, "")
                if raw:
                    for part in raw.split(","):
                        k = part.strip()
                        if k and k not in candidates:
                            candidates.append(k)
        return candidates

    def api_key(self) -> Optional[str]:
        keys = self.api_keys()
        return keys[0] if keys else None

    def is_configured(self) -> bool:
        return self.local or bool(self.api_keys())


MODEL_PRICING_PER_1M: Dict[str, Tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5": (1.25, 10.00),
    "o3-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-haiku-4-5": (0.80, 4.00),
    "claude-haiku-4": (0.80, 4.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-3-flash": (0.20, 0.80),
    "gemini-3-pro": (1.50, 12.00),
    "deepseek-chat": (0.27, 1.10),
    "deepseek-reasoner": (0.55, 2.19),
    "llama-3.3-70b": (0.59, 0.79),
    "gpt-oss-120b": (0.15, 0.60),
    "gpt-oss-20b": (0.075, 0.30),
    "qwen-2.5-72b": (0.40, 1.20),
}

_THINKING_BUDGETS: Dict[str, int] = {
    "low": 1024,
    "medium": 4096,
    "high": 8192,
}


def estimate_cost_usd(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    *,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """Estimate USD inference cost from model name and token counts (incl. cache reads/writes)."""
    m = (model or "").lower().strip()
    in_rate, out_rate = (0.0, 0.0)
    # Match longest prefix first so gpt-4o-mini beats gpt-4o and gpt-5-mini beats gpt-5
    for key in sorted(MODEL_PRICING_PER_1M.keys(), key=len, reverse=True):
        if key in m:
            in_rate, out_rate = MODEL_PRICING_PER_1M[key]
            break
    if in_rate == 0.0 and out_rate == 0.0:
        return 0.0
    pt = max(0, int(prompt_tokens or 0))
    cached_r = max(0, min(int(cache_read_tokens or 0), pt))
    cached_w = max(0, min(int(cache_write_tokens or 0), max(0, pt - cached_r)))
    uncached_prompt = max(0, pt - cached_r - cached_w)
    cache_read_mult = 0.10 if "claude" in m else 0.25
    cost = (
        (uncached_prompt * in_rate)
        + (cached_r * in_rate * cache_read_mult)
        + (cached_w * in_rate * 1.25)
        + (max(0, int(completion_tokens or 0)) * out_rate)
    ) / 1_000_000.0
    return round(cost, 8)


def check_cache_health(
    established_prefix_tokens: int,
    current_cached_tokens: Optional[int],
    *,
    compacted: bool = False,
) -> Dict[str, Any]:
    """Classify prompt-cache stability across turns."""
    if current_cached_tokens is None:
        return {
            "status": "unreported",
            "established_prefix_tokens": int(established_prefix_tokens),
            "current_cached_tokens": None,
            "retention_ratio": None,
        }
    est = max(0, int(established_prefix_tokens))
    cur = max(0, int(current_cached_tokens))
    ratio = round(cur / est, 4) if est > 0 else 1.0
    if compacted:
        status = "compacted"
    elif est >= 1024 and cur < int(est * 0.5):
        status = "unexpected_collapse"
    else:
        status = "healthy"
    return {
        "status": status,
        "established_prefix_tokens": est,
        "current_cached_tokens": cur,
        "retention_ratio": ratio,
    }


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    attempts: List[Dict[str, Any]] = field(default_factory=list)
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    cache_write_tokens: int = 0
    tool_calls: List[ToolCall] = field(default_factory=list)
    thinking_text: str = ""
    ttft_ms: float = 0.0
    itl_ms: List[float] = field(default_factory=list)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "omniroute": {
        "base_url": "http://127.0.0.1:20128/v1",
        "key_env": None,
        "model": "auto",
        "local": True,
        "protocol": "openai_compat",
    },
    # 2026-11-04: `llama-3.3-70b-versatile` returns 404 model_not_found on Groq; gpt-oss-120b verified live.
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
        "model": "openai/gpt-oss-120b",
        "fallback_models": ("qwen/qwen3.8-27b", "openai/gpt-oss-20b"),
        "protocol": "openai_compat",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "fallback_models": (
            "google/gemma-4-31b-it:free",
            "nvidia/nemotron-3.5-super-vl:free",
            "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        ),
        "protocol": "openai_compat",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "model": "gpt-5-mini",
        "protocol": "openai_compat",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "key_env": "ANTHROPIC_API_KEY",
        "model": "claude-sonnet-4-5-20250929",
        "fallback_models": ("claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"),
        "protocol": "anthropic",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "key_env": "GEMINI_API_KEY",
        "model": "gemini-2.5-flash",
        "fallback_models": ("gemini-2.5-pro",),
        "protocol": "gemini_native",
    },
    "ollama": {
        "base_url": "http://127.0.0.1:11434/v1",
        "key_env": None,
        "model": "qwen2.5-coder:14b",
        "local": True,
        "protocol": "ollama",
    },
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "key_env": "CEREBRAS_API_KEY",
        "model": "gpt-oss-120b",
        "fallback_models": ("qwen-3.8-27b",),
        "protocol": "openai_compat",
    },
    "nvidia": {
        "base_url": "https://integrate.api.nvidia.com/v1",
        "key_env": "NVIDIA_API_KEY",
        "model": "nvidia/nemotron-3-ultra-550b-a55b",
        "fallback_models": (
            "nvidia/nemotron-3.5-super-vl-120b-a12b",
            "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",
        ),
        "protocol": "openai_compat",
    },
    "sambanova": {
        "base_url": "https://api.sambanova.ai/v1",
        "key_env": "SAMBANOVA_API_KEY",
        "model": "Meta-Llama-3.3-70B-Instruct",
        "fallback_models": ("DeepSeek-V3-0324",),
        "protocol": "openai_compat",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "key_env": "TOGETHER_API_KEY",
        "model": "Qwen/Qwen2.5-Coder-32B-Instruct",
        "fallback_models": ("meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",),
        "protocol": "openai_compat",
    },
}

DEFAULT_ORDER = (
    "omniroute",
    "groq",
    "openrouter",
    "openai",
    "anthropic",
    "gemini",
    "cerebras",
    "sambanova",
    "nvidia",
    "together",
    "ollama",
)


def load_local_env(env_path: Optional[Path | str] = None, *, force: bool = False) -> int:
    """Safely load key pools from external vault file (`OMNI_ENV_FILE`, `~/.omni/omni_keys.env`, or `F:\\AetherMind_Temp\\secrets\\omni_keys.env`)."""
    from am_ua.contracts.contracts import resolve_omni_temp_dir

    candidates: List[Path] = []
    if env_path is not None:
        candidates.append(Path(env_path))
    else:
        explicit = os.environ.get("OMNI_ENV_FILE", "").strip()
        if explicit:
            candidates.append(Path(explicit))
        candidates.append(Path.home() / ".omni" / "omni_keys.env")
        candidates.append(resolve_omni_temp_dir("secrets") / "omni_keys.env")

    loaded = 0
    for fp in candidates:
        if not fp.is_file():
            continue
        for raw in fp.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and (force or k not in os.environ):
                os.environ[k] = v
                loaded += 1
        if loaded > 0:
            break
    return loaded


def _tcp_alive(url: str, timeout_s: float = 0.25) -> bool:
    p = urlparse(url)
    try:
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 80), timeout=timeout_s):
            return True
    except OSError:
        return False


def build_provider_chain(
    order: Optional[Sequence[str]] = None,
    *,
    autoload_env: Optional[bool] = None,
) -> List[ProviderSpec]:
    should_autoload = (
        autoload_env
        if autoload_env is not None
        else (bool(os.environ.get("OMNI_ENV_FILE")) or "PYTEST_CURRENT_TEST" not in os.environ)
    )
    if should_autoload:
        load_local_env()
    names = list(
        order
        or [
            n.strip()
            for n in os.environ.get("AM_UA_PROVIDERS", ",".join(DEFAULT_ORDER)).split(",")
            if n.strip()
        ]
    )
    chain: List[ProviderSpec] = []
    for n in names:
        d = _DEFAULTS.get(n)
        if d is None:
            continue
        model = os.environ.get(f"AM_UA_{n.upper()}_MODEL", d["model"])
        base_url = os.environ.get(f"AM_UA_{n.upper()}_BASE_URL", d["base_url"])
        fb = tuple(d.get("fallback_models", ()))
        spec = ProviderSpec(
            n,
            base_url,
            d["key_env"],
            model,
            bool(d.get("local", False)),
            fallback_models=fb,
            protocol=str(d.get("protocol", "openai_compat")),
        )
        if spec.local and not _tcp_alive(spec.base_url):
            continue  # offline local endpoint: skip silently, never pretend it exists
        if spec.is_configured():
            chain.append(spec)
    return chain


def _safe_parse_tool_args(raw: Any) -> Tuple[Dict[str, Any], str]:
    """Parse tool arguments safely from dict or JSON string without crashing on partial JSON."""
    if isinstance(raw, dict):
        return raw, json.dumps(raw, ensure_ascii=False)
    s = str(raw or "").strip()
    if not s:
        return {}, ""
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return parsed, s
    except json.JSONDecodeError:
        try:
            parsed = extract_json_object(s)
            return parsed, s
        except ValueError:
            pass
    return {"_raw": s}, s


def _parse_data_uri(uri: str) -> Optional[Tuple[str, str]]:
    """Extract (mime_type, base64_data) from a `data:<mime>;base64,<data>` URI."""
    if not isinstance(uri, str) or not uri.startswith("data:") or ";base64," not in uri:
        return None
    header, b64 = uri.split(";base64,", 1)
    mime = header[5:].strip() or "image/png"
    return mime, b64


def _sanitize_gemini_schema(schema: Any) -> Any:
    """Recursively strip JSON Schema keys unsupported by Gemini functionDeclarations."""
    if isinstance(schema, list):
        return [_sanitize_gemini_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    drop = {"additionalProperties", "$schema", "default", "title"}
    out: Dict[str, Any] = {}
    for k, v in schema.items():
        if k in drop:
            continue
        out[k] = _sanitize_gemini_schema(v)
    return out


class LLMClient:
    RETRYABLE_HTTP = {408, 409, 425, 429, 500, 502, 503, 504, 529}

    def __init__(
        self,
        providers: Optional[List[ProviderSpec]] = None,
        *,
        timeout_s: float = 90.0,
        breaker_threshold: int = 3,
        breaker_cooldown_s: float = 25.0,
    ) -> None:
        self.providers = providers if providers is not None else build_provider_chain()
        self.timeout_s = timeout_s
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown_s = float(breaker_cooldown_s)
        self._failures: Dict[str, int] = {}
        self._cooldown_until: Dict[str, float] = {}
        self._dead: set[str] = set()
        self._key_cursor: Dict[str, int] = {}
        self._bad_keys: set[Tuple[str, str]] = set()
        self._lock = threading.Lock()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.total_cost_usd = 0.0
        self.calls = 0

    # ------------------------------------------------------------------ helpers
    def _is_circuit_open(self, name: str) -> bool:
        if name in self._dead:
            return True
        if self._failures.get(name, 0) < self.breaker_threshold:
            return False
        until = self._cooldown_until.get(name, 0.0)
        if time.monotonic() >= until:
            # Half-open recovery after transient cooldown
            with self._lock:
                self._failures[name] = max(0, self.breaker_threshold - 1)
                self._cooldown_until.pop(name, None)
            return False
        return True

    def available(self) -> List[str]:
        return [p.name for p in self.providers if not self._is_circuit_open(p.name)]

    # -------------------------------------------------------- protocol builders
    @staticmethod
    def _payload(
        spec: ProviderSpec,
        messages: Sequence[Dict[str, Any]],
        max_tokens: int,
        temperature: Optional[float],
        json_mode: bool,
        *,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        enable_prompt_cache: bool = True,
        reasoning_effort: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build provider-native request payload for OpenAI-compat, Anthropic, Gemini, or Ollama."""
        proto = (spec.protocol or "openai_compat").lower()
        if proto == "anthropic":
            return LLMClient._payload_anthropic(
                spec,
                messages,
                max_tokens,
                temperature,
                tools=tools,
                tool_choice=tool_choice,
                enable_prompt_cache=enable_prompt_cache,
                reasoning_effort=reasoning_effort,
            )
        if proto == "gemini_native":
            return LLMClient._payload_gemini(
                spec,
                messages,
                max_tokens,
                temperature,
                json_mode,
                tools=tools,
                tool_choice=tool_choice,
                reasoning_effort=reasoning_effort,
            )
        return LLMClient._payload_openai(
            spec,
            messages,
            max_tokens,
            temperature,
            json_mode,
            tools=tools,
            tool_choice=tool_choice,
            reasoning_effort=reasoning_effort,
        )

    @staticmethod
    def _payload_openai(
        spec: ProviderSpec,
        messages: Sequence[Dict[str, Any]],
        max_tokens: int,
        temperature: Optional[float],
        json_mode: bool,
        *,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        reasoning_effort: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"model": spec.model, "messages": list(messages)}
        reasoning_family = spec.name == "openai" and (
            spec.model.startswith("gpt-5") or spec.model.startswith("o")
        )
        if reasoning_family:
            body["max_completion_tokens"] = max_tokens
            if reasoning_effort in _THINKING_BUDGETS:
                body["reasoning_effort"] = reasoning_effort
        else:
            body["max_tokens"] = max_tokens
            if temperature is not None:
                body["temperature"] = temperature
        if tools:
            body["tools"] = list(tools)
            if tool_choice is not None:
                body["tool_choice"] = tool_choice
            else:
                body["tool_choice"] = "auto"
        elif json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    @staticmethod
    def _payload_anthropic(
        spec: ProviderSpec,
        messages: Sequence[Dict[str, Any]],
        max_tokens: int,
        temperature: Optional[float],
        *,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        enable_prompt_cache: bool = True,
        reasoning_effort: Optional[str] = None,
    ) -> Dict[str, Any]:
        system_blocks: List[Dict[str, Any]] = []
        anth_messages: List[Dict[str, Any]] = []

        for msg in messages:
            role = str(msg.get("role", "user"))
            content = msg.get("content", "")
            if role == "system":
                txt = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                if txt:
                    blk: Dict[str, Any] = {"type": "text", "text": txt}
                    if enable_prompt_cache:
                        blk["cache_control"] = {"type": "ephemeral"}
                    system_blocks.append(blk)
                continue

            if role == "tool":
                tool_blk = {
                    "type": "tool_result",
                    "tool_use_id": str(msg.get("tool_call_id") or "call_0"),
                    "content": content if isinstance(content, str) else json.dumps(content, ensure_ascii=False),
                }
                if anth_messages and anth_messages[-1]["role"] == "user" and isinstance(anth_messages[-1]["content"], list):
                    anth_messages[-1]["content"].append(tool_blk)
                else:
                    anth_messages.append({"role": "user", "content": [tool_blk]})
                continue

            blocks: List[Dict[str, Any]] = []
            if isinstance(content, str):
                if content:
                    blocks.append({"type": "text", "text": content})
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    ptype = part.get("type")
                    if ptype == "text" and part.get("text"):
                        blocks.append({"type": "text", "text": str(part["text"])})
                    elif ptype == "image_url":
                        url = (part.get("image_url") or {}).get("url", "")
                        parsed = _parse_data_uri(url)
                        if parsed:
                            mime, b64 = parsed
                            blocks.append(
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": mime,
                                        "data": b64,
                                    },
                                }
                            )

            if role == "assistant" and isinstance(msg.get("tool_calls"), list):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function") or {}
                    targs, _ = _safe_parse_tool_args(fn.get("arguments"))
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": str(tc.get("id") or f"toolu_{uuid.uuid4().hex[:10]}"),
                            "name": str(fn.get("name", "")),
                            "input": targs,
                        }
                    )

            if not blocks:
                blocks.append({"type": "text", "text": " "})
            anth_role = "assistant" if role == "assistant" else "user"
            if anth_messages and anth_messages[-1]["role"] == anth_role:
                anth_messages[-1]["content"].extend(blocks)
            else:
                anth_messages.append({"role": anth_role, "content": blocks})

        # Place an ephemeral cache breakpoint on the latest stable user turn when multi-turn
        if enable_prompt_cache and len(anth_messages) >= 2:
            target_idx = len(anth_messages) - 1
            if anth_messages[target_idx]["content"]:
                last_blk = dict(anth_messages[target_idx]["content"][-1])
                last_blk["cache_control"] = {"type": "ephemeral"}
                anth_messages[target_idx]["content"][-1] = last_blk

        body: Dict[str, Any] = {
            "model": spec.model,
            "max_tokens": max_tokens,
            "messages": anth_messages,
        }
        if system_blocks:
            body["system"] = system_blocks

        if reasoning_effort in _THINKING_BUDGETS:
            budget = _THINKING_BUDGETS[reasoning_effort]
            body["thinking"] = {"type": "enabled", "budget_tokens": budget}
            if body["max_tokens"] <= budget:
                body["max_tokens"] = budget + 2048
        elif temperature is not None:
            body["temperature"] = temperature

        if tools:
            anth_tools: List[Dict[str, Any]] = []
            for t in tools:
                fn = t.get("function") if t.get("type") == "function" else t
                if not isinstance(fn, dict) or not fn.get("name"):
                    continue
                anth_tools.append(
                    {
                        "name": str(fn["name"]),
                        "description": str(fn.get("description", "")),
                        "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
                    }
                )
            if anth_tools:
                if enable_prompt_cache:
                    anth_tools[-1]["cache_control"] = {"type": "ephemeral"}
                body["tools"] = anth_tools
                if tool_choice == "required":
                    body["tool_choice"] = {"type": "any"}
                elif tool_choice == "auto" or tool_choice is None:
                    body["tool_choice"] = {"type": "auto"}
                elif isinstance(tool_choice, dict) and tool_choice.get("function", {}).get("name"):
                    body["tool_choice"] = {
                        "type": "tool",
                        "name": str(tool_choice["function"]["name"]),
                    }
        return body

    @staticmethod
    def _payload_gemini(
        spec: ProviderSpec,
        messages: Sequence[Dict[str, Any]],
        max_tokens: int,
        temperature: Optional[float],
        json_mode: bool,
        *,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        reasoning_effort: Optional[str] = None,
    ) -> Dict[str, Any]:
        sys_parts: List[Dict[str, Any]] = []
        contents: List[Dict[str, Any]] = []

        for msg in messages:
            role = str(msg.get("role", "user"))
            content = msg.get("content", "")
            if role == "system":
                txt = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                if txt:
                    sys_parts.append({"text": txt})
                continue
            if role == "tool":
                resp_data, _ = _safe_parse_tool_args(content)
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "name": str(msg.get("name") or "tool"),
                                    "response": resp_data,
                                }
                            }
                        ],
                    }
                )
                continue

            parts: List[Dict[str, Any]] = []
            if isinstance(content, str):
                if content:
                    parts.append({"text": content})
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text" and part.get("text"):
                        parts.append({"text": str(part["text"])})
                    elif part.get("type") == "image_url":
                        parsed = _parse_data_uri((part.get("image_url") or {}).get("url", ""))
                        if parsed:
                            mime, b64 = parsed
                            parts.append({"inlineData": {"mimeType": mime, "data": b64}})

            if role == "assistant" and isinstance(msg.get("tool_calls"), list):
                for tc in msg["tool_calls"]:
                    fn = tc.get("function") or {}
                    targs, _ = _safe_parse_tool_args(fn.get("arguments"))
                    parts.append({"functionCall": {"name": str(fn.get("name", "")), "args": targs}})

            if not parts:
                parts.append({"text": " "})
            g_role = "model" if role == "assistant" else "user"
            contents.append({"role": g_role, "parts": parts})

        gen_cfg: Dict[str, Any] = {"maxOutputTokens": max_tokens}
        if temperature is not None:
            gen_cfg["temperature"] = temperature
        if json_mode and not tools:
            gen_cfg["responseMimeType"] = "application/json"
        if reasoning_effort in _THINKING_BUDGETS:
            gen_cfg["thinkingConfig"] = {"thinkingBudget": _THINKING_BUDGETS[reasoning_effort]}

        body: Dict[str, Any] = {"contents": contents, "generationConfig": gen_cfg}
        if sys_parts:
            body["systemInstruction"] = {"parts": sys_parts}

        if tools:
            decls: List[Dict[str, Any]] = []
            for t in tools:
                fn = t.get("function") if t.get("type") == "function" else t
                if not isinstance(fn, dict) or not fn.get("name"):
                    continue
                decls.append(
                    {
                        "name": str(fn["name"]),
                        "description": str(fn.get("description", "")),
                        "parameters": _sanitize_gemini_schema(
                            fn.get("parameters") or {"type": "object", "properties": {}}
                        ),
                    }
                )
            if decls:
                body["tools"] = [{"functionDeclarations": decls}]
                mode = "AUTO"
                if tool_choice == "required":
                    mode = "ANY"
                elif tool_choice == "none":
                    mode = "NONE"
                body["toolConfig"] = {"functionCallingConfig": {"mode": mode}}
        return body

    def _select_key(self, spec: ProviderSpec) -> Optional[str]:
        keys = spec.api_keys()
        if not keys:
            return None
        with self._lock:
            n = len(keys)
            start = self._key_cursor.get(spec.name, 0) % n
            for offset in range(n):
                idx = (start + offset) % n
                cand = keys[idx]
                if (spec.name, cand) not in self._bad_keys:
                    return cand
        return None

    def _rotate_key(self, spec: ProviderSpec, failed_key: Optional[str], *, mark_bad: bool = False) -> bool:
        keys = spec.api_keys()
        if len(keys) <= 1 and not mark_bad:
            return False
        with self._lock:
            if mark_bad and failed_key:
                self._bad_keys.add((spec.name, failed_key))
            if not keys:
                return False
            self._key_cursor[spec.name] = (self._key_cursor.get(spec.name, 0) + 1) % len(keys)
            return any((spec.name, k) not in self._bad_keys for k in keys)

    def _endpoint_and_headers(
        self,
        spec: ProviderSpec,
        *,
        stream: bool = False,
        enable_prompt_cache: bool = True,
        api_key_override: Optional[str] = None,
    ) -> Tuple[str, Dict[str, str]]:
        proto = (spec.protocol or "openai_compat").lower()
        key = api_key_override if api_key_override is not None else self._select_key(spec)
        if key is None:
            key = spec.api_key()
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "omni-executor/8.0",
        }
        if stream:
            headers["Accept"] = "text/event-stream"
        if proto == "anthropic":
            url = spec.base_url.rstrip("/") + "/messages"
            headers["anthropic-version"] = "2023-06-01"
            if enable_prompt_cache:
                headers["anthropic-beta"] = "prompt-caching-2024-07-31"
            if key:
                headers["x-api-key"] = key
            return url, headers
        if proto == "gemini_native":
            action = "streamGenerateContent?alt=sse" if stream else "generateContent"
            url = f"{spec.base_url.rstrip('/')}/models/{spec.model}:{action}"
            if key:
                headers["x-goog-api-key"] = key
            return url, headers
        # OpenAI-compatible (OpenAI, Groq, OpenRouter, OmniRoute, Ollama)
        url = spec.base_url.rstrip("/") + "/chat/completions"
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return url, headers

    def _post(
        self,
        spec: ProviderSpec,
        body: Dict[str, Any],
        *,
        enable_prompt_cache: bool = True,
        api_key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        url, headers = self._endpoint_and_headers(
            spec,
            stream=False,
            enable_prompt_cache=enable_prompt_cache,
            api_key_override=api_key_override,
        )
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def _parse_response(
        spec: ProviderSpec,
        data: Dict[str, Any],
        cand_model: str,
    ) -> Tuple[str, str, int, int, int, int, List[ToolCall], str]:
        """Parse provider response into (text, actual_model, pt, ct, cache_r, cache_w, tool_calls, thinking)."""
        proto = (spec.protocol or "openai_compat").lower()
        if proto == "anthropic":
            text_parts: List[str] = []
            think_parts: List[str] = []
            tcalls: List[ToolCall] = []
            for blk in data.get("content") or []:
                if not isinstance(blk, dict):
                    continue
                btype = blk.get("type")
                if btype == "text":
                    text_parts.append(str(blk.get("text") or ""))
                elif btype == "thinking":
                    think_parts.append(str(blk.get("thinking") or ""))
                elif btype == "tool_use":
                    args_dict, raw_args = _safe_parse_tool_args(blk.get("input"))
                    tcalls.append(
                        ToolCall(
                            id=str(blk.get("id") or f"toolu_{uuid.uuid4().hex[:8]}"),
                            name=str(blk.get("name") or ""),
                            arguments=args_dict,
                            raw_arguments=raw_args,
                        )
                    )
            usage = data.get("usage") or {}
            base_in = int(usage.get("input_tokens") or 0)
            cache_r = int(usage.get("cache_read_input_tokens") or 0)
            cache_w = int(usage.get("cache_creation_input_tokens") or 0)
            pt = base_in + cache_r + cache_w
            ct = int(usage.get("output_tokens") or 0)
            actual_model = str(data.get("model") or cand_model)
            return "".join(text_parts), actual_model, pt, ct, cache_r, cache_w, tcalls, "".join(think_parts)

        if proto == "gemini_native":
            text_parts = []
            think_parts = []
            tcalls = []
            cand = (data.get("candidates") or [{}])[0]
            for part in (cand.get("content") or {}).get("parts") or []:
                if not isinstance(part, dict):
                    continue
                if part.get("thought") and isinstance(part.get("text"), str):
                    think_parts.append(part["text"])
                elif isinstance(part.get("text"), str):
                    text_parts.append(part["text"])
                elif isinstance(part.get("functionCall"), dict):
                    fc = part["functionCall"]
                    args_dict, raw_args = _safe_parse_tool_args(fc.get("args"))
                    tcalls.append(
                        ToolCall(
                            id=f"gem_{uuid.uuid4().hex[:8]}",
                            name=str(fc.get("name") or ""),
                            arguments=args_dict,
                            raw_arguments=raw_args,
                        )
                    )
            um = data.get("usageMetadata") or {}
            pt = int(um.get("promptTokenCount") or 0)
            ct = int(um.get("candidatesTokenCount") or 0)
            cache_r = int(um.get("cachedContentTokenCount") or 0)
            actual_model = str(data.get("modelVersion") or cand_model)
            return "".join(text_parts), actual_model, pt, ct, cache_r, 0, tcalls, "".join(think_parts)

        # OpenAI-compatible
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text = msg.get("content") or ""
        thinking = msg.get("reasoning_content") or msg.get("reasoning") or ""
        tcalls = []
        for idx, tc in enumerate(msg.get("tool_calls") or []):
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") or {}
            name = str(fn.get("name") or "").strip()
            if not name:
                continue
            args_dict, raw_args = _safe_parse_tool_args(fn.get("arguments"))
            tcalls.append(
                ToolCall(
                    id=str(tc.get("id") or f"call_{idx}_{uuid.uuid4().hex[:6]}"),
                    name=name,
                    arguments=args_dict,
                    raw_arguments=raw_args,
                )
            )
        usage = data.get("usage") or {}
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        pt_details = usage.get("prompt_tokens_details") or {}
        cache_r = int(
            pt_details.get("cached_tokens")
            or usage.get("cache_read_input_tokens")
            or 0
        )
        cache_w = int(usage.get("cache_creation_input_tokens") or 0)
        actual_model = str(data.get("model") or cand_model)
        return text, actual_model, pt, ct, cache_r, cache_w, tcalls, str(thinking)

    # --------------------------------------------------------------------- API
    def chat(
        self,
        messages: Sequence[Dict[str, Any]],
        *,
        max_tokens: int = 2048,
        temperature: Optional[float] = 0.2,
        json_mode: bool = False,
        prefer: Optional[str] = None,
        exclude: Optional[Sequence[str]] = None,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        enable_prompt_cache: bool = True,
        reasoning_effort: Optional[str] = None,
    ) -> LLMResponse:
        chain = [p for p in self.providers if p.name not in set(exclude or ())]
        if prefer:
            chain.sort(key=lambda p: 0 if p.name == prefer else 1)
        attempts: List[Dict[str, Any]] = []
        # If every non-dead provider is momentarily in short cooldown, wait briefly instead of failing fast
        live = [p for p in chain if p.name not in self._dead]
        if live and all(self._is_circuit_open(p.name) for p in live):
            soonest = min(self._cooldown_until.get(p.name, 0.0) for p in live)
            wait_s = max(0.0, soonest - time.monotonic())
            if 0.0 < wait_s <= self.breaker_cooldown_s + 1.0:
                time.sleep(min(wait_s + 0.2, 26.0))
        for spec in chain:
            if self._is_circuit_open(spec.name):
                attempts.append({"provider": spec.name, "skipped": "circuit_open"})
                continue
            models_to_try = [spec.model] + [m for m in spec.fallback_models if m != spec.model]
            for cand_model in models_to_try:
                cand_spec = ProviderSpec(
                    spec.name,
                    spec.base_url,
                    spec.key_env,
                    cand_model,
                    spec.local,
                    spec.fallback_models,
                    spec.protocol,
                )
                # Try native tools first when requested; on 400 fallback gracefully to json_mode / plain
                if tools:
                    modes: List[Tuple[bool, bool]] = [(True, False)]
                    if json_mode:
                        modes.append((False, True))
                    modes.append((False, False))
                elif json_mode:
                    modes = [(False, True), (False, False)]
                else:
                    modes = [(False, False)]

                for use_tools, use_json in modes:
                    key_attempts = max(1, len(spec.api_keys()))
                    model_aborted = False
                    provider_exhausted = False
                    for _k_idx in range(key_attempts):
                        cur_key = self._select_key(spec)
                        if cur_key is None and not spec.local:
                            provider_exhausted = True
                            break
                        t0 = time.perf_counter()
                        try:
                            payload = self._payload(
                                cand_spec,
                                messages,
                                max_tokens,
                                temperature,
                                use_json,
                                tools=tools if use_tools else None,
                                tool_choice=tool_choice if use_tools else None,
                                enable_prompt_cache=enable_prompt_cache,
                                reasoning_effort=reasoning_effort,
                            )
                            data = self._post(
                                cand_spec,
                                payload,
                                enable_prompt_cache=enable_prompt_cache,
                                api_key_override=cur_key,
                            )
                            text, actual_model, pt, ct, cache_r, cache_w, tcalls, thinking = self._parse_response(
                                cand_spec, data, cand_model
                            )
                            call_cost = estimate_cost_usd(
                                actual_model,
                                pt,
                                ct,
                                cache_read_tokens=cache_r,
                                cache_write_tokens=cache_w,
                            )
                            with self._lock:
                                self._failures[spec.name] = 0
                                self._cooldown_until.pop(spec.name, None)
                                self.total_prompt_tokens += pt
                                self.total_completion_tokens += ct
                                self.total_cache_read_tokens += cache_r
                                self.total_cache_write_tokens += cache_w
                                self.total_cost_usd = round(self.total_cost_usd + call_cost, 8)
                                self.calls += 1
                            if not text.strip() and not tcalls:
                                raise ValueError("empty completion")
                            lat_ms = round((time.perf_counter() - t0) * 1000, 1)
                            return LLMResponse(
                                text,
                                spec.name,
                                actual_model,
                                pt,
                                ct,
                                lat_ms,
                                attempts,
                                cache_read_tokens=cache_r,
                                cost_usd=call_cost,
                                cache_write_tokens=cache_w,
                                tool_calls=tcalls,
                                thinking_text=thinking,
                                ttft_ms=lat_ms,
                            )
                        except urllib.error.HTTPError as exc:
                            detail = exc.read()[:300].decode("utf-8", "replace")
                            attempts.append(
                                {
                                    "provider": spec.name,
                                    "model": cand_model,
                                    "http": exc.code,
                                    "detail": detail,
                                    "use_tools": use_tools,
                                    "json_mode": use_json,
                                }
                            )
                            if exc.code == 400 and (use_tools or use_json):
                                break  # retry next mode
                            quota_dead = "insufficient_quota" in detail or "credit_balance" in detail
                            if exc.code in (401, 402, 403, 429) or quota_dead:
                                rotated = self._rotate_key(
                                    spec,
                                    cur_key,
                                    mark_bad=(exc.code in (401, 402, 403) or quota_dead),
                                )
                                if rotated and (_k_idx + 1) < key_attempts:
                                    continue
                            if exc.code in (402, 404) or "not found" in detail.lower():
                                model_aborted = True
                                break
                            if exc.code not in self.RETRYABLE_HTTP or quota_dead:
                                with self._lock:
                                    self._dead.add(spec.name)
                                    self._failures[spec.name] = self.breaker_threshold
                                provider_exhausted = True
                            else:
                                with self._lock:
                                    fails = self._failures.get(spec.name, 0) + 1
                                    self._failures[spec.name] = fails
                                    if fails >= self.breaker_threshold:
                                        self._cooldown_until[spec.name] = time.monotonic() + self.breaker_cooldown_s
                            model_aborted = True
                            break
                        except (
                            urllib.error.URLError,
                            TimeoutError,
                            socket.timeout,
                            OSError,
                            ValueError,
                            json.JSONDecodeError,
                        ) as exc:
                            attempts.append(
                                {
                                    "provider": spec.name,
                                    "model": cand_model,
                                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                                }
                            )
                            with self._lock:
                                fails = self._failures.get(spec.name, 0) + 1
                                self._failures[spec.name] = fails
                                if fails >= self.breaker_threshold:
                                    self._cooldown_until[spec.name] = time.monotonic() + self.breaker_cooldown_s
                            model_aborted = True
                            break
                    if provider_exhausted or model_aborted:
                        break
                if provider_exhausted:
                    break
        raise LLMUnavailableError(f"All LLM providers failed: {attempts}")

    def chat_multimodal(
        self,
        prompt: str,
        image_path: Path | str,
        *,
        system_prompt: Optional[str] = None,
        fallback_text_context: str = "",
        max_tokens: int = 800,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> LLMResponse:
        """Send a Set-of-Mark screenshot + text prompt to vision-capable models, with text fallback."""
        img_file = Path(image_path).resolve()
        if not img_file.is_file():
            raise FileNotFoundError(f"Multimodal image not found: {img_file}")
        b64_data = base64.b64encode(img_file.read_bytes()).decode("ascii")
        mime = "image/png" if img_file.suffix.lower() == ".png" else "image/jpeg"

        mm_messages: List[Dict[str, Any]] = []
        if system_prompt:
            mm_messages.append({"role": "system", "content": system_prompt})
        mm_messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{b64_data}"},
                    },
                ],
            }
        )
        try:
            return self.chat(
                mm_messages,
                max_tokens=max_tokens,
                temperature=temperature,
                json_mode=json_mode,
            )
        except Exception:
            # Automatic fallback when current provider/model is text-only: inject structured SoM table
            txt_messages: List[Dict[str, Any]] = []
            if system_prompt:
                txt_messages.append({"role": "system", "content": system_prompt})
            combined = f"{prompt}\n\n[STRUCTURED SET-OF-MARK & OCR TABLE FALLBACK]:\n{fallback_text_context}"
            txt_messages.append({"role": "user", "content": combined})
            return self.chat(
                txt_messages,
                max_tokens=max_tokens,
                temperature=temperature,
                json_mode=json_mode,
            )

    def chat_stream(
        self,
        messages: Sequence[Dict[str, Any]],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        json_mode: bool = False,
        prefer: Optional[str] = None,
        on_delta: Optional[Callable[[str], None]] = None,
        on_thinking_delta: Optional[Callable[[str], None]] = None,
        tools: Optional[Sequence[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        enable_prompt_cache: bool = True,
        reasoning_effort: Optional[str] = None,
    ) -> LLMResponse:
        """Stream OpenAI-compat or Anthropic SSE deltas (`on_delta`), assembling streamed `tool_calls` cleanly."""
        ordered = (
            [p for p in self.providers if p.name == prefer] + [p for p in self.providers if p.name != prefer]
            if prefer
            else list(self.providers)
        )
        if not ordered:
            raise LLMUnavailableError("No LLM providers configured/available")

        spec = ordered[0]
        proto = (spec.protocol or "openai_compat").lower()
        if proto == "gemini_native":
            return self.chat(
                messages,
                max_tokens=max_tokens,
                temperature=temperature,
                json_mode=json_mode,
                prefer=prefer,
                tools=tools,
                tool_choice=tool_choice,
                enable_prompt_cache=enable_prompt_cache,
                reasoning_effort=reasoning_effort,
            )

        payload = self._payload(
            spec,
            list(messages),
            max_tokens,
            temperature,
            json_mode,
            tools=tools,
            tool_choice=tool_choice,
            enable_prompt_cache=enable_prompt_cache,
            reasoning_effort=reasoning_effort,
        )
        payload["stream"] = True
        url, headers = self._endpoint_and_headers(
            spec, stream=True, enable_prompt_cache=enable_prompt_cache
        )
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        t0 = time.perf_counter()
        first_tok_t: Optional[float] = None
        prev_tok_t: Optional[float] = None
        itl_samples: List[float] = []

        def _mark_stream_tick() -> None:
            nonlocal first_tok_t, prev_tok_t
            now = time.perf_counter()
            if first_tok_t is None:
                first_tok_t = now
            elif prev_tok_t is not None and len(itl_samples) < 250:
                itl_samples.append(round((now - prev_tok_t) * 1000, 3))
            prev_tok_t = now

        chunks: List[str] = []
        think_chunks: List[str] = []
        streamed_tc_acc: Dict[int, Dict[str, str]] = {}
        pt, ct, cache_r, cache_w = 0, 0, 0, 0
        actual_model = spec.model
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "text/event-stream" not in ctype:
                    raw = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(raw)
                    text, actual_model, pt, ct, cache_r, cache_w, tcalls, thinking = self._parse_response(
                        spec, data, spec.model
                    )
                    if text and on_delta is not None:
                        on_delta(text)
                    if thinking and on_thinking_delta is not None:
                        on_thinking_delta(thinking)
                    cost = estimate_cost_usd(
                        actual_model, pt, ct, cache_read_tokens=cache_r, cache_write_tokens=cache_w
                    )
                    with self._lock:
                        self.total_prompt_tokens += pt
                        self.total_completion_tokens += ct
                        self.total_cache_read_tokens += cache_r
                        self.total_cache_write_tokens += cache_w
                        self.total_cost_usd = round(self.total_cost_usd + cost, 8)
                        self.calls += 1
                    lat_ms = round((time.perf_counter() - t0) * 1000, 1)
                    return LLMResponse(
                        text,
                        spec.name,
                        actual_model,
                        pt,
                        ct,
                        lat_ms,
                        cache_read_tokens=cache_r,
                        cost_usd=cost,
                        cache_write_tokens=cache_w,
                        tool_calls=tcalls,
                        thinking_text=thinking,
                        ttft_ms=lat_ms,
                    )

                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if not data_str or data_str == "[DONE]":
                        if data_str == "[DONE]":
                            break
                        continue
                    ev = json.loads(data_str)

                    if proto == "anthropic":
                        etype = ev.get("type")
                        if etype == "message_start":
                            m_obj = ev.get("message") or {}
                            actual_model = str(m_obj.get("model") or actual_model)
                            u = m_obj.get("usage") or {}
                            cache_r = int(u.get("cache_read_input_tokens") or cache_r)
                            cache_w = int(u.get("cache_creation_input_tokens") or cache_w)
                            pt = int(u.get("input_tokens") or 0) + cache_r + cache_w
                        elif etype == "content_block_start":
                            idx = int(ev.get("index", 0))
                            cb = ev.get("content_block") or {}
                            if cb.get("type") == "tool_use":
                                streamed_tc_acc[idx] = {
                                    "id": str(cb.get("id") or f"toolu_{idx}"),
                                    "name": str(cb.get("name") or ""),
                                    "arguments": "",
                                }
                        elif etype == "content_block_delta":
                            idx = int(ev.get("index", 0))
                            delta_obj = ev.get("delta") or {}
                            dtype = delta_obj.get("type")
                            if dtype == "text_delta" and delta_obj.get("text"):
                                _mark_stream_tick()
                                txt = str(delta_obj["text"])
                                chunks.append(txt)
                                if on_delta is not None:
                                    on_delta(txt)
                            elif dtype == "thinking_delta" and delta_obj.get("thinking"):
                                _mark_stream_tick()
                                tk = str(delta_obj["thinking"])
                                think_chunks.append(tk)
                                if on_thinking_delta is not None:
                                    on_thinking_delta(tk)
                            elif dtype == "input_json_delta" and delta_obj.get("partial_json"):
                                _mark_stream_tick()
                                acc = streamed_tc_acc.setdefault(idx, {"id": f"toolu_{idx}", "name": "", "arguments": ""})
                                acc["arguments"] += str(delta_obj["partial_json"])
                        elif etype == "message_delta":
                            u = ev.get("usage") or {}
                            ct = int(u.get("output_tokens") or ct)
                        continue

                    # OpenAI-compatible SSE stream
                    if ev.get("model"):
                        actual_model = str(ev["model"])
                    delta_obj = ((ev.get("choices") or [{}])[0]).get("delta") or {}
                    delta_txt = delta_obj.get("content")
                    if delta_txt:
                        _mark_stream_tick()
                        chunks.append(delta_txt)
                        if on_delta is not None:
                            on_delta(delta_txt)
                    delta_think = delta_obj.get("reasoning_content") or delta_obj.get("reasoning")
                    if delta_think:
                        _mark_stream_tick()
                        think_chunks.append(str(delta_think))
                        if on_thinking_delta is not None:
                            on_thinking_delta(str(delta_think))
                    for tc_delta in delta_obj.get("tool_calls") or []:
                        if not isinstance(tc_delta, dict):
                            continue
                        _mark_stream_tick()
                        idx = int(tc_delta.get("index", 0))
                        acc = streamed_tc_acc.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                        if tc_delta.get("id"):
                            acc["id"] = str(tc_delta["id"])
                        fn_d = tc_delta.get("function") or {}
                        if fn_d.get("name"):
                            acc["name"] += str(fn_d["name"])
                        if fn_d.get("arguments"):
                            acc["arguments"] += str(fn_d["arguments"])
                    if ev.get("usage"):
                        u = ev["usage"]
                        pt = int(u.get("prompt_tokens") or pt)
                        ct = int(u.get("completion_tokens") or ct)
                        ptd = u.get("prompt_tokens_details") or {}
                        cache_r = int(ptd.get("cached_tokens") or u.get("cache_read_input_tokens") or cache_r)

            tcalls_out: List[ToolCall] = []
            for idx in sorted(streamed_tc_acc.keys()):
                acc = streamed_tc_acc[idx]
                if not acc["name"]:
                    continue
                args_dict, raw_args = _safe_parse_tool_args(acc["arguments"])
                tcalls_out.append(
                    ToolCall(
                        id=acc["id"] or f"call_{idx}_{uuid.uuid4().hex[:6]}",
                        name=acc["name"],
                        arguments=args_dict,
                        raw_arguments=raw_args,
                    )
                )

            full_text = "".join(chunks)
            full_thinking = "".join(think_chunks)
            if not full_text.strip() and not tcalls_out:
                raise ValueError("empty streamed completion")
            cost = estimate_cost_usd(
                actual_model, pt, ct, cache_read_tokens=cache_r, cache_write_tokens=cache_w
            )
            with self._lock:
                self.total_prompt_tokens += pt
                self.total_completion_tokens += ct
                self.total_cache_read_tokens += cache_r
                self.total_cache_write_tokens += cache_w
                self.total_cost_usd = round(self.total_cost_usd + cost, 8)
                self.calls += 1
            lat_ms = round((time.perf_counter() - t0) * 1000, 1)
            ttft_val = round((first_tok_t - t0) * 1000, 2) if first_tok_t is not None else lat_ms
            return LLMResponse(
                full_text,
                spec.name,
                actual_model,
                pt,
                ct,
                lat_ms,
                cache_read_tokens=cache_r,
                cost_usd=cost,
                cache_write_tokens=cache_w,
                tool_calls=tcalls_out,
                thinking_text=full_thinking,
                ttft_ms=ttft_val,
                itl_ms=itl_samples,
            )
        except Exception:
            return self.chat(
                messages,
                max_tokens=max_tokens,
                temperature=temperature,
                json_mode=json_mode,
                prefer=prefer,
                tools=tools,
                tool_choice=tool_choice,
                enable_prompt_cache=enable_prompt_cache,
                reasoning_effort=reasoning_effort,
            )


def extract_json_object(text: str) -> Dict[str, Any]:
    """Extract the first balanced top-level JSON object from model output (tolerates fences/prose)."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise ValueError("no JSON object found in model output")
