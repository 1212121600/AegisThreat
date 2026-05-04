"""Unified LLM client supporting OpenAI, vLLM, and Ollama backends.

Provides a single interface for all LLM calls across the AegisThreat system.
Falls back to TemplateFallback when no LLM backend is available.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = "stop"
    raw_response: Any = None


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: str = ""
    api_base: str = ""
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_seconds: int = 30


class LLMBackend(ABC):
    @abstractmethod
    def complete(self, prompt: str, system_prompt: str = "", **kwargs: Any) -> LLMResponse:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...


class OpenAIBackend(LLMBackend):
    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client: Any = None
        self._available = False
        self._init_client()

    def _init_client(self) -> None:
        api_key = self._config.api_key or os.environ.get("LLM_API_KEY", "")
        api_base = self._config.api_base or os.environ.get("LLM_API_BASE", "https://api.openai.com/v1")
        if not api_key:
            logger.warning("OpenAI backend: no API key configured")
            return
        try:
            from httpx import Client
            self._client = Client(
                base_url=api_base,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                timeout=self._config.timeout_seconds,
            )
            self._available = True
        except ImportError:
            logger.warning("httpx not installed")

    def complete(self, prompt: str, system_prompt: str = "", **kwargs: Any) -> LLMResponse:
        if not self._client:
            return LLMResponse(text="", model="none", finish_reason="error")
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self._config.model, "messages": messages,
            "temperature": kwargs.get("temperature", self._config.temperature),
            "max_tokens": kwargs.get("max_tokens", self._config.max_tokens),
        }
        try:
            import time
            start = time.time()
            resp = self._client.post("/chat/completions", json=payload)
            latency = (time.time() - start) * 1000
            if resp.status_code != 200:
                return LLMResponse(text="", model="none", finish_reason="error")
            data = resp.json()
            choice = data["choices"][0]
            usage = data.get("usage", {})
            return LLMResponse(
                text=choice["message"]["content"], model=data.get("model", self._config.model),
                prompt_tokens=usage.get("prompt_tokens", 0), completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0), latency_ms=latency,
                finish_reason=choice.get("finish_reason", "stop"), raw_response=data,
            )
        except Exception as e:
            logger.exception("OpenAI API call failed")
            return LLMResponse(text="", model="none", finish_reason=f"error: {e}")

    def is_available(self) -> bool:
        return self._available


class VLLMBackend(LLMBackend):
    def __init__(self, config: LLMConfig) -> None:
        self._openai = OpenAIBackend(LLMConfig(
            provider="vllm", model=config.model or "meta-llama/Llama-3-8B-Instruct",
            api_key="not-needed", api_base=config.api_base or "http://localhost:8000/v1",
            temperature=config.temperature, max_tokens=config.max_tokens,
        ))
    def complete(self, prompt: str, system_prompt: str = "", **kwargs: Any) -> LLMResponse:
        return self._openai.complete(prompt, system_prompt, **kwargs)
    def is_available(self) -> bool:
        return self._openai.is_available()


class OllamaBackend(LLMBackend):
    def __init__(self, config: LLMConfig) -> None:
        self._openai = OpenAIBackend(LLMConfig(
            provider="ollama", model=config.model or "llama3:8b",
            api_key="ollama", api_base=config.api_base or "http://localhost:11434/v1",
            temperature=config.temperature, max_tokens=config.max_tokens,
        ))
    def complete(self, prompt: str, system_prompt: str = "", **kwargs: Any) -> LLMResponse:
        return self._openai.complete(prompt, system_prompt, **kwargs)
    def is_available(self) -> bool:
        return self._openai.is_available()


class TemplateFallback:
    """Template-based fallback when no LLM backend is available."""

    def classify_alert(self, alert_summary: str) -> str:
        text = alert_summary.lower()
        if any(w in text for w in ["brute", "password", "login fail"]):
            return "credential_access"
        if any(w in text for w in ["phish", "email", "attachment"]):
            return "phishing"
        if any(w in text for w in ["exploit", "cve", "rce"]):
            return "exploitation"
        if any(w in text for w in ["beacon", "c2", "callback"]):
            return "c2_communication"
        if any(w in text for w in ["exfil", "upload", "transfer"]):
            return "data_exfiltration"
        if any(w in text for w in ["lateral", "psexec", "smb"]):
            return "lateral_movement"
        return "other"

    def verify_attack_path(self, path: str) -> str:
        patterns = ["T1566", "T1059", "T1566", "T1204", "T1003", "T1021", "T1071", "T1048"]
        for i in range(len(patterns) - 1):
            if patterns[i] in path and patterns[i + 1] in path:
                return f"coherent=yes, confidence=80"
        return "coherent=maybe, confidence=50"

    def generate_summary(self, alerts_text: str) -> str:
        lines = alerts_text.strip().split("\n")[:5]
        return f"Alert cluster: {len(lines)} events. Manual review recommended."

    def generate_debate_response(self, context: str) -> str:
        return "Red-team: Verify all TTPs covered. Check alternative techniques."


class LLMClient:
    """Unified LLM client with automatic fallback."""

    def __init__(self, configs: Optional[list[LLMConfig]] = None) -> None:
        self._backends: list[LLMBackend] = []
        self._fallback = TemplateFallback()
        if configs:
            for c in configs:
                b = self._create_backend(c)
                if b and b.is_available():
                    self._backends.append(b)
        else:
            self._init_defaults()

    def _init_defaults(self) -> None:
        for conf in [
            LLMConfig(provider="vllm", model="meta-llama/Llama-3-8B-Instruct", api_base="http://localhost:8000/v1", api_key="local"),
            LLMConfig(provider="ollama", model="llama3:8b", api_base="http://localhost:11434/v1", api_key="local"),
            LLMConfig(provider="openai", model=os.environ.get("LLM_MODEL", "gpt-4o")),
        ]:
            backend = self._create_backend(conf)
            if backend and backend.is_available():
                self._backends.append(backend)

    @staticmethod
    def _create_backend(config: LLMConfig) -> Optional[LLMBackend]:
        if config.provider == "vllm":
            return VLLMBackend(config)
        elif config.provider == "ollama":
            return OllamaBackend(config)
        elif config.provider == "openai":
            return OpenAIBackend(config)
        return None

    def complete(self, prompt: str, system_prompt: str = "", **kwargs: Any) -> LLMResponse:
        for backend in self._backends:
            if backend.is_available():
                resp = backend.complete(prompt, system_prompt, **kwargs)
                if resp.finish_reason == "stop":
                    return resp
        return LLMResponse(text="[template] " + prompt[:100], model="template-fallback", finish_reason="stop")

    def classify_alert(self, alert_summary: str) -> LLMResponse:
        system = "You are a security analyst. Classify the alert into one category."
        resp = self.complete(alert_summary, system_prompt=system, max_tokens=50)
        if resp.model == "template-fallback":
            resp.text = self._fallback.classify_alert(alert_summary)
        return resp

    def verify_attack_path(self, path_description: str) -> LLMResponse:
        system = "You are an ATT&CK expert. Evaluate if the attack path is coherent."
        resp = self.complete(path_description, system_prompt=system, max_tokens=200)
        if resp.model == "template-fallback":
            resp.text = self._fallback.verify_attack_path(path_description)
        return resp

    def generate_summary(self, alerts_text: str) -> LLMResponse:
        system = "Summarize the security event sequence in 2-3 sentences."
        resp = self.complete(alerts_text, system_prompt=system, max_tokens=300)
        if resp.model == "template-fallback":
            resp.text = self._fallback.generate_summary(alerts_text)
        return resp

    def generate_debate_response(self, context: str) -> LLMResponse:
        system = "You are a red-team security expert."
        resp = self.complete(context, system_prompt=system, max_tokens=500)
        if resp.model == "template-fallback":
            resp.text = self._fallback.generate_debate_response(context)
        return resp

    @property
    def available_backends(self) -> list[str]:
        return [b.__class__.__name__ for b in self._backends if b.is_available()]

    @property
    def has_any_backend(self) -> bool:
        return any(b.is_available() for b in self._backends)
