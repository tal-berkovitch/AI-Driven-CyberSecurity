"""One place for Groq access, shared by the CTI worker (AG2) and the UI (chat).

Groq exposes an OpenAI-compatible endpoint, so we drive it through the ``openai``
SDK. Everything degrades gracefully when ``GROQ_API_KEY`` is unset or the SDK is
missing — ``groq_available()`` is False and the callers fall back. The detonation
plane never imports this; only the egress-side containers do.

The active model is read from a control file (``CONTROL_DIR/llm_model``) when
present, else ``GROQ_MODEL`` — so the dashboard can switch the model for the whole
system (CTI + UI) live, with no restart.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

LOG = logging.getLogger("shared.llm")

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
CONTROL_DIR = os.getenv("CONTROL_DIR", "/app/control")


def groq_api_key() -> str:
    return os.getenv("GROQ_API_KEY", "").strip()


def groq_model() -> str:
    """Selected model: control file (live switch) takes precedence over the env."""
    try:
        sel = (Path(CONTROL_DIR) / "llm_model").read_text(encoding="utf-8").strip()
        if sel:
            return sel
    except OSError:
        pass
    return os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")


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
    """AG2-style llm_config (a ``config_list`` pointed at Groq's compat endpoint)."""
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


def _usage_path() -> Path:
    return Path(CONTROL_DIR) / "llm_usage.json"


def read_llm_usage() -> dict:
    """Last persisted Groq token-budget sample ({ts, model, status, used_pct, ...})."""
    try:
        return json.loads(_usage_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_usage(status: int | None, rate: dict) -> None:
    """Persist the latest budget sample so the dashboard survives restarts and can
    show its freshness (age). Best-effort: silently skips if control is read-only."""
    try:
        p = _usage_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "ts": time.time(), "model": groq_model(), "status": status,
            "used_pct": rate.get("used_pct"), "remaining_tokens": rate.get("remaining_tokens"),
            "limit_tokens": rate.get("limit_tokens"),
        }), encoding="utf-8")
    except OSError:
        pass


def _rate_from_headers(headers) -> dict:
    """Parse Groq's token rate-limit headers into a small usage dict."""
    def _num(name):
        try:
            return float(str(headers.get(name)).rstrip("s"))
        except (TypeError, ValueError):
            return None
    limit = _num("x-ratelimit-limit-tokens")
    remaining = _num("x-ratelimit-remaining-tokens")
    used_pct = None
    if limit and remaining is not None and limit > 0:
        used_pct = max(0.0, min(100.0, (limit - remaining) / limit * 100.0))
    return {"limit_tokens": limit, "remaining_tokens": remaining,
            "used_pct": used_pct, "reset": headers.get("x-ratelimit-reset-tokens")}


def groq_complete(system: str, user: str, *, temperature: float = 0.2,
                  max_tokens: int = 700) -> dict:
    """Full result: ``{text, status, error, rate}``. Never raises.

    ``status`` is 429 on a rate limit, ``None`` when unavailable/other. ``rate``
    carries the token-budget headers for the dashboard's usage bar.
    """
    out = {"text": None, "status": None, "error": None, "rate": {}}
    if not groq_available():
        out["error"] = "unavailable"
        return out
    try:
        import openai
        from openai import OpenAI

        client = OpenAI(api_key=groq_api_key(), base_url=GROQ_BASE_URL)
        raw = client.chat.completions.with_raw_response.create(
            model=groq_model(), temperature=temperature, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
        )
        out["rate"] = _rate_from_headers(raw.headers)
        out["text"] = raw.parse().choices[0].message.content
        out["status"] = 200
        _write_usage(200, out["rate"])
        return out
    except openai.RateLimitError as exc:  # 429 — too many requests / TPM exhausted
        out["status"] = 429
        out["error"] = "rate_limited"
        try:
            out["rate"] = _rate_from_headers(exc.response.headers)
        except AttributeError:
            pass
        _write_usage(429, out["rate"])
        return out
    except Exception as exc:  # noqa: BLE001 — an API hiccup must not kill the caller
        LOG.error("Groq completion failed: %s", exc)
        out["error"] = str(exc)
        return out


def groq_chat(system: str, user: str, *, temperature: float = 0.2,
              max_tokens: int = 700) -> str | None:
    """One-shot chat completion via Groq. None on any failure (text-only wrapper)."""
    return groq_complete(system, user, temperature=temperature, max_tokens=max_tokens)["text"]


# Non-chat model ids to hide from the dashboard's model switch.
_MODEL_EXCLUDE = ("whisper", "guard", "orpheus", "tts", "embed")
FALLBACK_MODELS = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile",
                   "openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3-32b"]


def groq_list_models() -> list[str]:
    """Chat-capable models available to the key (live from Groq); [] if unavailable."""
    if not groq_available():
        return []
    try:
        from openai import OpenAI

        client = OpenAI(api_key=groq_api_key(), base_url=GROQ_BASE_URL)
        ids = [m.id for m in client.models.list().data]
        return sorted(m for m in ids if not any(x in m.lower() for x in _MODEL_EXCLUDE))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("groq_list_models failed: %s", exc)
        return []
