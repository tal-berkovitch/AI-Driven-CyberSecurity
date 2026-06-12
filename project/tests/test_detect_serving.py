"""Defender detect-mode wiring: FeatureRecords -> scored -> enriched -> Alerts on
the `alerts` topic. Skipped if torch (the `detect` extra) isn't installed."""

import pytest

pytest.importorskip("torch")

from defender.detect import make_detector  # noqa: E402
from defender.enrich import MitreEnricher  # noqa: E402
from defender.features.dns import DNS_FEATURES  # noqa: E402
from defender.main import DetectSink  # noqa: E402

from eval import scenarios  # noqa: E402

import pandas as pd  # noqa: E402

from shared.schema import Alert  # noqa: E402
from shared.transport.file_queue import FileQueueConsumer, FileQueueProducer  # noqa: E402


def _frame(records):
    return pd.DataFrame([{c: r.features.get(c, 0.0) for c in DNS_FEATURES} for r in records],
                        columns=list(DNS_FEATURES))


def test_detect_sink_emits_enriched_alerts(tmp_path):
    det = make_detector("local")
    det.fit(_frame(scenarios.benign_dns(140, seed=10)))

    sink = DetectSink({"dns": det}, MitreEnricher(), FileQueueProducer(tmp_path))
    sink.handle(scenarios.tunnel_dns(20, "loud", seed=11))

    assert sink.n_alerts > 0, "loud tunneling produced no alerts"
    alerts = FileQueueConsumer(tmp_path).poll("alerts")
    assert alerts
    a0 = Alert.from_dict(alerts[0])
    assert a0.score.is_anomaly
    assert a0.candidate_techniques                      # enrichment ran
    assert a0.score.feature_attributions                # evidence carried


def test_detect_sink_ignores_protocol_without_model(tmp_path):
    det = make_detector("local")
    det.fit(_frame(scenarios.benign_dns(120, seed=20)))
    sink = DetectSink({"dns": det}, MitreEnricher(), FileQueueProducer(tmp_path))
    # SNMP records arrive but no SNMP model is loaded -> skipped, no crash, no alerts.
    sink.handle(scenarios.walk_snmp(10, "loud", seed=21))
    assert sink.n_alerts == 0


def test_detect_sink_suppresses_response_dominated_windows(tmp_path):
    det = make_detector("local")
    det.fit(_frame(scenarios.benign_dns(140, seed=30)))
    sink = DetectSink({"dns": det}, MitreEnricher(), FileQueueProducer(tmp_path))

    # Loud-tunnel records that WOULD alert, but marked as the response half of the
    # exchange (server echo) -> must be suppressed, not alerted.
    recs = scenarios.tunnel_dns(20, "loud", seed=31)
    for r in recs:
        r.meta["response_fraction"] = 1.0
    sink.handle(recs)
    assert sink.n_alerts == 0
    assert sink.n_suppressed > 0


def test_build_model_card_multi_backend(tmp_path):
    from defender.main import build_model_card

    frame = _frame(scenarios.benign_dns(120, seed=40))
    for backend in ("local", "isolation_forest"):
        det = make_detector(backend)
        det.fit(frame)
        det.save(str(tmp_path / f"dns_{backend}.pt"))

    card = build_model_card("local", str(tmp_path))
    assert card["active_backend"] == "local"
    b = card["backends"]
    # autoencoder card carries the real layer shape + bottleneck
    ae = b["local"]["models"]["dns"]
    assert b["local"]["available"] and ae["type"] == "autoencoder"
    assert ae["layers"][0] == len(DNS_FEATURES) and min(ae["layers"]) == 6
    assert ae["n_params"] > 0
    # isolation forest card carries its config
    iff = b["isolation_forest"]["models"]["dns"]
    assert b["isolation_forest"]["available"] and iff["type"] == "isolation_forest"
    assert iff["n_estimators"] > 0
    # morpheus is a declared-but-unavailable placeholder
    assert b["morpheus"]["available"] is False and "note" in b["morpheus"]


def test_resolve_backend_prefers_valid_control_file(tmp_path):
    from defender.main import resolve_backend

    # no control file -> env
    assert resolve_backend("local", str(tmp_path)) == "local"
    # valid selection wins
    (tmp_path / "detector_backend").write_text("isolation_forest", encoding="utf-8")
    assert resolve_backend("local", str(tmp_path)) == "isolation_forest"
    # junk / disallowed selection is ignored -> env
    (tmp_path / "detector_backend").write_text("nonsense", encoding="utf-8")
    assert resolve_backend("local", str(tmp_path)) == "local"
