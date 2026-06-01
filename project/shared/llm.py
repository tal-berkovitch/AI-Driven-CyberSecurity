"""One place for Groq access, shared by the CTI worker (AG2) and the UI (chat).

Groq exposes an OpenAI-compatible endpoint, so we drive it through the ``openai``
SDK. Everything degrades gracefully when ``GROQ_API_KEY`` is unset or the SDK is
missing — ``groq_available()`` is False and the callers fall back (deterministic
CTI template / "LLM unavailable" in the UI). The detonation plane never imports
this; only the egress-side containers do.
"""

from __future__ import annotations

import logging
import os

LOG = logging.getLogger("shared.llm")

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


def groq_api_key() -> str:
    return os.getenv("GROQ_API_KEY", "").strip()


def groq_model() -> str:
    return os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


def groq_available() -> bool:
    """True only if a key is set AND the openai SDK is importable."""
    if not groq_api_key():
        return False
    try:
        import openai  # noqa: F401
    except ImportError:
        LOG.warning("openai SDK not installed — Groq features disabled.")
        return False
    return True


def groq_llm_config() -> dict | None:
    """AG2-style llm_config (a ``config_list`` pointed at Groq's compat endpoint).

    Returns None when Groq is unavailable so callers can fall back.
    """
    if not groq_available():
        return None
    return {
        "config_list": [{
            "model": groq_model(),
            "api_key": groq_api_key(),
            "base_url": GROQ_BASE_URL,
            "api_type": "openai",
        }],
        "temperature": 0.2,
        "cache_seed": None,
    }


def groq_chat(system: str, user: str, *, temperature: float = 0.2,
              max_tokens: int = 700) -> str | None:
    """One-shot chat completion via Groq. None on any failure (never raises)."""
    if not groq_available():
        return None
    try:
        from openai import OpenAI

        client = OpenAI(api_key=groq_api_key(), base_url=GROQ_BASE_URL)
        resp = client.chat.completions.create(
            model=groq_model(),
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
        )
        return resp.choices[0].message.content
    except Exception as exc:  # noqa: BLE001 — an API hiccup must not kill the caller
        LOG.error("Groq chat failed: %s", exc)
        return None
