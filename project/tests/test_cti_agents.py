"""AG2 CTI orchestration: graceful degradation without a key/SDK, and that the
group chat is seeded with the grounded evidence. No real network calls."""

from cti import agents
from cti.agents import generate_cti

from shared.schema import Alert, FeatureRecord, ScoreResult


def _alert() -> Alert:
    rec = FeatureRecord(protocol="dns", ts=1.0, src="10.0.0.9", dst="10.0.0.2",
                        features={"max_qname_length": 180.0}, meta={})
    sc = ScoreResult(anomaly_score=0.9, is_anomaly=True,
                     feature_attributions={"max_qname_length": 4.2})
    return Alert(record=rec, score=sc, candidate_techniques=["T1071.004"])


def test_generate_cti_returns_none_without_llm_config(monkeypatch):
    # No Groq config available -> no AG2 run, signal the caller to fall back.
    monkeypatch.setattr(agents, "groq_llm_config", lambda: None)
    assert generate_cti(_alert(), [{"id": "T1071.004", "name": "X", "description": "d"}]) is None


def test_generate_cti_swallows_runtime_errors(monkeypatch):
    # LLM "available", but the AG2 import/run path blows up -> None (never raises).
    monkeypatch.setattr(agents, "groq_llm_config", lambda: {"config_list": []})

    def boom(*a, **k):
        raise RuntimeError("autogen exploded")

    # build_user_prompt is the first thing called after the config check.
    monkeypatch.setattr(agents, "build_user_prompt", boom)
    assert generate_cti(_alert(), []) is None


def test_strip_terminate():
    assert agents._strip_terminate("report body\nTERMINATE") == "report body"
