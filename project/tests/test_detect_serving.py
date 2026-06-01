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
