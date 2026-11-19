"""Real multi-provider LLM client (fixes bottleneck B1/B2: the kernel had no reachable brain).

Before this module, `OmniModelRouter` only pointed at localhost endpoints (20128/8317/3700) that were
offline, and `execute_mission` never invoked any model. This client talks to real OpenAI-compatible
endpoints with:
  - ordered provider chain with automatic failover (429/5xx/timeout/network)
  - per-session circuit breaker
  - real token accounting taken from the provider `usage` block (no hardcoded token numbers)
  - secrets never logged (keys only read from env at call time)

Provider order / models are configurable via env:
  AM_UA_PROVIDERS="groq,openrouter,openai"   AM_UA_GROQ_MODEL=...  AM_UA_OPENAI_MODEL=... etc.
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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse


class LLMUnavailableError(RuntimeError):
    """Raised when every provider in the chain failed."""


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    base_url: str
    key_env: Optional[str]
    model: str
    local: bool = False
    fallback_models: Tuple[str, ...] = ()

    def api_key(self) -> Optional[str]:
        return os.environ.get(self.key_env) if self.key_env else None

    def is_configured(self) -> bool:
        return self.local or bool(self.api_key())


MODEL_PRICING_PER_1M: Dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-5": (1.25, 10.00),
    "o3-mini": (1.10, 4.40),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-haiku-4": (0.80, 4.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "deepseek-chat": (0.27, 1.10),
    "deepseek-reasoner": (0.55, 2.19),
    "llama-3.3-70b": (0.59, 0.79),
    "qwen-2.5-72b": (0.40, 1.20),
}


def estimate_cost_usd(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    *,
    cache_read_tokens: int = 0,
) -> float:
    """Estimate USD inference cost from model name and token counts."""
    m = (model or "").lower().strip()
    in_rate, out_rate = (0.0, 0.0)
    # Match longest prefix first so gpt-4o-mini beats gpt-4o
    for key in sorted(MODEL_PRICING_PER_1M.keys(), key=len, reverse=True):
        if key in m:
            in_rate, out_rate = MODEL_PRICING_PER_1M[key]
            break
    if in_rate == 0.0 and out_rate == 0.0:
        return 0.0
    cached = max(0, min(int(cache_read_tokens or 0), int(prompt_tokens or 0)))
    uncached_prompt = max(0, int(prompt_tokens or 0) - cached)
    cost = (
        (uncached_prompt * in_rate)
        + (cached * in_rate * 0.25)
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

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "omniroute": {"base_url": "http://127.0.0.1:20128/v1", "key_env": None, "model": "auto", "local": True},
    # 2026-11-04: `llama-3.3-70b-versatile` returns 404 model_not_found on Groq; gpt-oss-120b verified live.
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
        "model": "openai/gpt-oss-120b",
        "fallback_models": ("qwen/qwen3.8-27b", "openai/gpt-oss-20b"),
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "model": "cohere/north-mini-code:free",
        "fallback_models": ("nvidia/nemotron-3.5-lightning:free",),
    },
    "openai": {"base_url": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY", "model": "gpt-5-mini"},
}

DEFAULT_ORDER = ("omniroute", "groq", "openrouter", "openai")


def _tcp_alive(url: str, timeout_s: float = 0.3) -> bool:
    p = urlparse(url)
    try:
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 80), timeout=timeout_s):
            return True
    except OSError:
        return False


def build_provider_chain(order: Optional[Sequence[str]] = None) -> List[ProviderSpec]:
    names = list(order or [n.strip() for n in os.environ.get("AM_UA_PROVIDERS", ",".join(DEFAULT_ORDER)).split(",") if n.strip()])
    chain: List[ProviderSpec] = []
    for n in names:
        d = _DEFAULTS.get(n)
        if d is None:
            continue
        model = os.environ.get(f"AM_UA_{n.upper()}_MODEL", d["model"])
        fb = tuple(d.get("fallback_models", ()))
        spec = ProviderSpec(n, d["base_url"], d["key_env"], model, bool(d.get("local", False)), fallback_models=fb)
        if spec.local and not _tcp_alive(spec.base_url):
            continue  # offline local endpoint: skip silently, never pretend it exists
        if spec.is_configured():
            chain.append(spec)
    return chain


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
        self._lock = threading.Lock()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cache_read_tokens = 0
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

    @staticmethod
    def _payload(spec: ProviderSpec, messages: List[Dict[str, str]], max_tokens: int, temperature: Optional[float], json_mode: bool) -> Dict[str, Any]:
        body: Dict[str, Any] = {"model": spec.model, "messages": messages}
        reasoning_family = spec.name == "openai" and (spec.model.startswith("gpt-5") or spec.model.startswith("o"))
        if reasoning_family:
            body["max_completion_tokens"] = max_tokens
        else:
            body["max_tokens"] = max_tokens
            if temperature is not None:
                body["temperature"] = temperature
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def _post(self, spec: ProviderSpec, body: Dict[str, Any]) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json", "User-Agent": "omni-executor/4.1"}
        key = spec.api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(
            spec.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # --------------------------------------------------------------------- API
    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        max_tokens: int = 2048,
        temperature: Optional[float] = 0.2,
        json_mode: bool = False,
        prefer: Optional[str] = None,
        exclude: Optional[Sequence[str]] = None,
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
                    spec.name, spec.base_url, spec.key_env, cand_model, spec.local, spec.fallback_models
                )
                for use_json in ([json_mode, False] if json_mode else [False]):
                    t0 = time.perf_counter()
                    try:
                        data = self._post(cand_spec, self._payload(cand_spec, messages, max_tokens, temperature, use_json))
                        choice = (data.get("choices") or [{}])[0]
                        text = ((choice.get("message") or {}).get("content")) or ""
                        usage = data.get("usage") or {}
                        pt = int(usage.get("prompt_tokens") or 0)
                        ct = int(usage.get("completion_tokens") or 0)
                        pt_details = usage.get("prompt_tokens_details") or {}
                        cached_tok = int(
                            pt_details.get("cached_tokens")
                            or usage.get("cache_read_input_tokens")
                            or 0
                        )
                        actual_model = data.get("model", cand_model)
                        call_cost = estimate_cost_usd(
                            actual_model, pt, ct, cache_read_tokens=cached_tok
                        )
                        with self._lock:
                            self._failures[spec.name] = 0
                            self._cooldown_until.pop(spec.name, None)
                            self.total_prompt_tokens += pt
                            self.total_completion_tokens += ct
                            self.total_cache_read_tokens += cached_tok
                            self.total_cost_usd = round(self.total_cost_usd + call_cost, 8)
                            self.calls += 1
                        if not text.strip():
                            raise ValueError("empty completion")
                        return LLMResponse(text, spec.name, actual_model, pt, ct,
                                           round((time.perf_counter() - t0) * 1000, 1), attempts,
                                           cache_read_tokens=cached_tok, cost_usd=call_cost)
                    except urllib.error.HTTPError as exc:
                        detail = exc.read()[:300].decode("utf-8", "replace")
                        attempts.append({"provider": spec.name, "model": cand_model, "http": exc.code, "detail": detail, "json_mode": use_json})
                        if exc.code == 400 and use_json:
                            continue  # provider rejects response_format -> retry same model without it
                        if exc.code in (402, 404) or "not found" in detail.lower():
                            break  # advance to next candidate model
                        quota_dead = "insufficient_quota" in detail or "credit_balance" in detail
                        if exc.code not in self.RETRYABLE_HTTP or quota_dead:
                            with self._lock:
                                self._dead.add(spec.name)
                                self._failures[spec.name] = self.breaker_threshold
                        else:
                            with self._lock:
                                fails = self._failures.get(spec.name, 0) + 1
                                self._failures[spec.name] = fails
                                if fails >= self.breaker_threshold:
                                    self._cooldown_until[spec.name] = time.monotonic() + self.breaker_cooldown_s
                        break
                    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, ValueError, json.JSONDecodeError) as exc:
                        attempts.append({"provider": spec.name, "model": cand_model, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                        with self._lock:
                            fails = self._failures.get(spec.name, 0) + 1
                            self._failures[spec.name] = fails
                            if fails >= self.breaker_threshold:
                                self._cooldown_until[spec.name] = time.monotonic() + self.breaker_cooldown_s
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
                mm_messages,  # type: ignore[arg-type]
                max_tokens=max_tokens,
                temperature=temperature,
                json_mode=json_mode,
            )
        except Exception:
            # Automatic fallback when current provider/model is text-only: inject structured SoM table
            txt_messages: List[Dict[str, str]] = []
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
