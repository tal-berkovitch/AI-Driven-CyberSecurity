"""Dashboard state is pure and BOUNDED: counters/charts update correctly, ring
buffers respect maxlen, and the summary prompt never grows with history."""

from ui.dashboard import (
    DashboardState,
    alert_summary,
    build_summary_prompt,
    offline_summary,
    traffic_row,
)

from shared.schema import Alert, FeatureRecord, ScoreResult


def _alert_dict(src="10.0.0.9", techs=("T1071.004", "T1048.003"), score=12.34) -> dict:
    rec = FeatureRecord(protocol="dns", ts=1.0, src=src, dst="10.0.0.2",
                        features={}, meta={})
    sc = ScoreResult(anomaly_score=score, is_anomaly=True,
                     feature_attributions={"max_qname_length": 9.0, "txt_query_count": 3.0})
    return Alert(record=rec, score=sc, candidate_techniques=list(techs),
                 cti_report="# Report\nbody").to_dict()


def test_traffic_row_and_alert_summary_extract_fields():
    row = traffic_row({"proto": "dns", "src": "a", "dst": "b", "qname": "x.evil.com"})
    assert row["proto"] == "dns" and row["detail"] == "x.evil.com"

    s = alert_summary(_alert_dict())
    assert s["proto"] == "dns" and s["src"] == "10.0.0.9"
    assert s["top_feature"] == "max_qname_length"      # highest attribution first
    assert s["techniques"] == ["T1071.004", "T1048.003"]
    assert s["report"].startswith("# Report")


def test_state_counters_and_technique_freq():
    st = DashboardState()
    st.add_capture([{"proto": "dns"}, {"proto": "snmp"}, {"proto": "dns"}])
    st.add_cti(_alert_dict(techs=["T1046"]))
    st.add_cti(_alert_dict(techs=["T1046", "T1602.001"]))

    stats = st.stats()
    assert stats["total_captures"] == 3
    assert stats["total_alerts"] == 2
    assert stats["by_proto"] == {"dns": 2}
    assert stats["technique_freq"]["T1046"] == 2
    assert sum(stats["alert_buckets"]) == 2            # both alerts counted in the chart


def test_ring_buffers_are_bounded():
    st = DashboardState(traffic_max=5, alerts_max=3)
    st.add_capture([{"proto": "dns"} for _ in range(20)])
    for _ in range(10):
        st.add_cti(_alert_dict())
    assert len(st.traffic) == 5                        # capped
    assert len(st.alerts) == 3                         # capped
    assert st.total_captures == 20 and st.total_alerts == 10  # counters keep truth


def test_summary_prompt_is_bounded_to_last_k():
    st = DashboardState()
    for i in range(50):
        st.add_cti(_alert_dict(src=f"10.0.0.{i}"))
    prompt = build_summary_prompt(st, last_k=15)
    # Only the last 15 alerts appear, regardless of the 50 ingested.
    assert prompt.count("\n- dns from ") == 15
    assert "10.0.0.49" in prompt and "10.0.0.0" not in prompt
    assert "anomaly alerts: 50" in prompt              # counters still reflect all


def test_offline_summary_with_and_without_alerts():
    empty = DashboardState()
    assert "No anomalies yet" in offline_summary(empty)

    st = DashboardState()
    st.add_cti(_alert_dict(techs=["T1071.004"]))
    out = offline_summary(st)
    assert "1 anomaly alerts" in out
    assert "T1071.004" in out
