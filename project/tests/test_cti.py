"""CTI generation: grounded prompt + report, with the Groq client stubbed.

No network and no `groq` SDK needed — we exercise `build_user_prompt`,
`offline_report`, and `make_report`'s LLM/offline branch selection directly.
The point is *grounding*: prompt and report cite only the supplied evidence
(feature values + retrieved technique cards)."""

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


class _StubGroq:
    """Mimics GroqClient: `available` + `generate` without importing the SDK."""

    def __init__(self, *, available: bool, text: str | None = "LLM NARRATIVE") -> None:
        self.available = available
        self._text = text
        self.seen: tuple[str, str] | None = None

    def generate(self, system: str, user: str, **_: object) -> str | None:
        self.seen = (system, user)
        return self._text


def test_user_prompt_is_grounded_in_evidence():
    alert = _dns_alert()
    cards = [CARDS[t] for t in alert.candidate_techniques]
    prompt = build_user_prompt(alert, cards)

    # cites the driving features (top attribution first) and the score
    assert "mean_subdomain_entropy" in prompt
    assert "0.93" in prompt
    # carries the retrieved technique cards by ID + name
    assert "T1071.004" in prompt and "T1048.003" in prompt
    # raw context surfaced for the analyst
    assert "sample_qnames" in prompt
    # the system prompt forbids invention — grounding contract
    assert "do not invent" in SYSTEM.lower()


def test_make_report_uses_llm_when_available():
    alert = _dns_alert()
    groq = _StubGroq(available=True, text="LLM NARRATIVE")
    report = make_report(alert, CARDS, groq)

    assert report == "LLM NARRATIVE"
    # the LLM actually received the grounded evidence
    assert groq.seen is not None
    assert "mean_subdomain_entropy" in groq.seen[1]


def test_make_report_falls_back_to_template_when_unavailable():
    alert = _dns_alert()
    report = make_report(alert, CARDS, _StubGroq(available=False))

    assert "offline/template" in report
    assert "mean_subdomain_entropy" in report          # top feature named
    assert "T1071.004" in report                        # mapped technique named


def test_make_report_falls_back_when_llm_returns_none():
    """Available client but a failed/empty generation must not lose the alert."""
    alert = _dns_alert()
    report = make_report(alert, CARDS, _StubGroq(available=True, text=None))
    assert "offline/template" in report


def test_offline_report_handles_no_matched_techniques():
    alert = _dns_alert()
    alert.candidate_techniques = []
    report = offline_report(alert, [])
    assert "none matched" in report
    assert "10.0.0.9" in report                         # still cites the source
