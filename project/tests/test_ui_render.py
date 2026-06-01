"""UI rendering is pure: format alert cards / CTI / capture summaries and the
chat-grounding context from plain queue dicts — no ChainLit, no network."""

from ui.render import (
    alert_context,
    format_alert,
    format_capture_summary,
    format_cti,
)

from shared.schema import Alert, FeatureRecord, ScoreResult


def _alert_dict() -> dict:
    rec = FeatureRecord(protocol="dns", ts=1.0, src="10.0.0.9", dst="10.0.0.2",
                        features={}, meta={"sample_qnames": ["a.b.evil.example"]})
    sc = ScoreResult(anomaly_score=12.34, is_anomaly=True,
                     feature_attributions={"max_qname_length": 9.0, "txt_query_count": 3.0})
    return Alert(record=rec, score=sc, candidate_techniques=["T1071.004", "T1048.003"],
                 cti_report="# Report\nbody").to_dict()


def test_format_alert_shows_evidence_and_techniques():
    out = format_alert(_alert_dict())
    assert "DNS anomaly" in out
    assert "10.0.0.9" in out
    assert "12.3400" in out
    assert "T1071.004" in out and "T1048.003" in out
    assert "max_qname_length" in out                    # top feature listed first


def test_format_cti_embeds_report():
    out = format_cti(_alert_dict())
    assert "CTI report" in out
    assert "body" in out


def test_format_capture_summary_counts_by_proto():
    events = [{"proto": "dns"}, {"proto": "dns"}, {"proto": "snmp"}]
    out = format_capture_summary(events)
    assert "captured 3 events" in out
    assert "2 dns" in out and "1 snmp" in out
    assert format_capture_summary([]) is None


def test_alert_context_is_compact_grounded_text():
    ctx = alert_context(_alert_dict())
    assert "protocol=dns" in ctx
    assert "anomaly_score=12.3400" in ctx
    assert "max_qname_length" in ctx
    assert "T1071.004" in ctx
    assert "sample_qnames" in ctx                        # raw context carried for the LLM
