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


def test_model_control_file_takes_precedence(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "CONTROL_DIR", str(tmp_path))
    monkeypatch.setenv("GROQ_MODEL", "env-model")
    assert llm.groq_model() == "env-model"               # no control file -> env
    (tmp_path / "llm_model").write_text("picked-model", encoding="utf-8")
    assert llm.groq_model() == "picked-model"            # control file wins


def test_groq_complete_offline_returns_empty(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    res = llm.groq_complete("sys", "user")
    assert res["text"] is None and res["status"] is None
    assert res["error"] == "unavailable" and res["rate"] == {}


def test_llm_usage_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "CONTROL_DIR", str(tmp_path))
    assert llm.read_llm_usage() == {}                       # nothing yet
    llm._write_usage(200, {"used_pct": 42.0, "remaining_tokens": 3480.0, "limit_tokens": 6000.0})
    u = llm.read_llm_usage()
    assert u["status"] == 200 and u["used_pct"] == 42.0 and "ts" in u


def test_groq_client_shim_delegates(monkeypatch):
    from cti.groq_client import GroqClient

    monkeypatch.setattr("cti.groq_client.groq_available", lambda: False)
    client = GroqClient()
    assert client.available is False
    # generate delegates to groq_chat, which is offline -> None
    assert client.generate("s", "u") is None
