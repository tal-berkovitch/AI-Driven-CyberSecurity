"""CTI generation: grounded prompt + report selection, no network.

`make_report` now drives an AG2 multi-agent group chat (`cti.agents.generate_cti`)
when an LLM is available, falling back to the deterministic offline template.
Here we stub `generate_cti` so no SDK / network is needed; the grounding of the
prompt and the offline template are tested directly."""

from cti import main as cti_main
from cti.main import _load_cards, make_report
from cti.prompts import SYSTEM, build_user_prompt, offline_report

from shared.schema import Alert, FeatureRecord, ScoreResult

CARDS = _load_cards()


def _dns_alert() -> Alert:
    rec = FeatureRecord(
        protocol="dns", ts=1_700_000_000.0, src="10.0.0.9", dst="10.0.0.2",
        features={"mean_subdomain_entropy": 4.7, "max_qname_length": 180.0,
                  "txt_query_count": 22.0},
        meta={"sample_qnames": ["aGVsbG8.tunnel.evil.example"], "qtype_mix": {"TXT": 22}},
    )
    sc = ScoreResult(
        anomaly_score=0.93, is_anomaly=True,
        feature_attributions={"mean_subdomain_entropy": 5.1, "max_qname_length": 4.2,
                              "txt_query_count": 3.0, "query_count": 0.2},
    )
    return Alert(record=rec, score=sc, candidate_techniques=["T1071.004", "T1048.003"])


def test_user_prompt_is_grounded_in_evidence():
    alert = _dns_alert()
    cards = [CARDS[t] for t in alert.candidate_techniques]
    prompt = build_user_prompt(alert, cards)

    assert "mean_subdomain_entropy" in prompt          # driving feature cited
    assert "0.93" in prompt                             # score cited
    assert "T1071.004" in prompt and "T1048.003" in prompt
    assert "sample_qnames" in prompt                    # raw context surfaced
    assert "do not invent" in SYSTEM.lower()            # grounding contract


def test_make_report_uses_agents_when_llm_available(monkeypatch):
    alert = _dns_alert()
    seen = {}

    def fake_generate(a, cards):
        seen["alert"] = a
        seen["cards"] = cards
        return "AG2 MULTI-AGENT REPORT"

    monkeypatch.setattr(cti_main, "generate_cti", fake_generate)
    report = make_report(alert, CARDS, llm_available=True)

    assert report == "AG2 MULTI-AGENT REPORT"
    assert seen["alert"] is alert
    assert [c["id"] for c in seen["cards"]] == ["T1071.004", "T1048.003"]  # only mapped cards


def test_make_report_falls_back_when_agents_return_none(monkeypatch):
    monkeypatch.setattr(cti_main, "generate_cti", lambda a, c: None)
    report = make_report(_dns_alert(), CARDS, llm_available=True)
    assert "offline/template" in report
    assert "mean_subdomain_entropy" in report
    assert "T1071.004" in report


def test_make_report_offline_when_llm_unavailable():
    report = make_report(_dns_alert(), CARDS, llm_available=False)
    assert "offline/template" in report
    assert "10.0.0.9" in report                         # cites the source


def test_offline_report_handles_no_matched_techniques():
    alert = _dns_alert()
    alert.candidate_techniques = []
    report = offline_report(alert, [])
    assert "none matched" in report
    assert "10.0.0.9" in report
