"""Compatibility shim — Groq access now lives in ``shared.llm``.

Kept so Phase-3 imports (``from .groq_client import GroqClient``) keep working;
new code should call ``shared.llm`` directly.
"""

from __future__ import annotations

from shared.llm import groq_available, groq_chat, groq_model


class GroqClient:
    def __init__(self, model: str | None = None) -> None:
        self.model = model or groq_model()

    @property
    def available(self) -> bool:
        return groq_available()

    def generate(self, system: str, user: str, temperature: float = 0.2,
                 max_tokens: int = 700) -> str | None:
        return groq_chat(system, user, temperature=temperature, max_tokens=max_tokens)
