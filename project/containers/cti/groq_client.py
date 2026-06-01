"""Thin Groq SDK wrapper. Absent/!invalid key -> ``available`` is False (caller
falls back to a template), so the worker never hard-fails offline."""

from __future__ import annotations

import logging
import os

LOG = logging.getLogger("cti.groq")


class GroqClient:
    def __init__(self, model: str | None = None) -> None:
        self.api_key = os.getenv("GROQ_API_KEY", "").strip()
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self._client = None
        if not self.api_key:
            LOG.warning("GROQ_API_KEY not set — CTI will use the offline template.")
            return
        try:
            from groq import Groq

            self._client = Groq(api_key=self.api_key)
            LOG.info("Groq client ready (model=%s)", self.model)
        except Exception as exc:  # noqa: BLE001
            LOG.error("Groq client init failed (%s) — using offline template.", exc)

    @property
    def available(self) -> bool:
        return self._client is not None

    def generate(self, system: str, user: str, temperature: float = 0.2,
                 max_tokens: int = 700) -> str | None:
        if self._client is None:
            return None
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            )
            return resp.choices[0].message.content
        except Exception as exc:  # noqa: BLE001 — never let an API hiccup kill the worker
            LOG.error("Groq generation failed: %s", exc)
            return None
