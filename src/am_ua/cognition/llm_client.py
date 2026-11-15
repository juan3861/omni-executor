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


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    attempts: List[Dict[str, Any]] = field(default_factory=list)

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
        breaker_threshold: int = 2,
    ) -> None:
        self.providers = providers if providers is not None else build_provider_chain()
        self.timeout_s = timeout_s
        self.breaker_threshold = breaker_threshold
        self._failures: Dict[str, int] = {}
        self._lock = threading.Lock()
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.calls = 0

    # ------------------------------------------------------------------ helpers
    def available(self) -> List[str]:
        return [p.name for p in self.providers if self._failures.get(p.name, 0) < self.breaker_threshold]

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
        headers = {"Content-Type": "application/json", "User-Agent": "aethermind-ua/3.2"}
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
        for spec in chain:
            if self._failures.get(spec.name, 0) >= self.breaker_threshold:
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
                        with self._lock:
                            self._failures[spec.name] = 0
                            self.total_prompt_tokens += pt
                            self.total_completion_tokens += ct
                            self.calls += 1
                        if not text.strip():
                            raise ValueError("empty completion")
                        return LLMResponse(text, spec.name, data.get("model", cand_model), pt, ct,
                                           round((time.perf_counter() - t0) * 1000, 1), attempts)
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
                                self._failures[spec.name] = self.breaker_threshold
                        else:
                            with self._lock:
                                self._failures[spec.name] = self._failures.get(spec.name, 0) + 1
                        break
                    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, ValueError, json.JSONDecodeError) as exc:
                        attempts.append({"provider": spec.name, "model": cand_model, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                        with self._lock:
                            self._failures[spec.name] = self._failures.get(spec.name, 0) + 1
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
