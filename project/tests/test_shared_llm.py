"""shared.llm degrades gracefully with no key (offline), and the Phase-3
GroqClient shim still imports and delegates to it."""

import shared.llm as llm


def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert llm.groq_available() is False
    assert llm.groq_llm_config() is None
    assert llm.groq_chat("sys", "user") is None


def test_llm_config_shape_when_available(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_MODEL", "some-model")
    # Force "SDK present" without importing the real openai package.
    monkeypatch.setattr(llm, "groq_available", lambda: True)

    cfg = llm.groq_llm_config()
    assert cfg is not None
    entry = cfg["config_list"][0]
    assert entry["model"] == "some-model"
    assert entry["base_url"] == llm.GROQ_BASE_URL
    assert entry["api_key"] == "test-key"


def test_groq_client_shim_delegates(monkeypatch):
    from cti.groq_client import GroqClient

    monkeypatch.setattr("cti.groq_client.groq_available", lambda: False)
    client = GroqClient()
    assert client.available is False
    # generate delegates to groq_chat, which is offline -> None
    assert client.generate("s", "u") is None
