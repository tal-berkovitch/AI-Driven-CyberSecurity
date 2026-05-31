"""Round-trip tests for the shared contracts and transport."""

from shared.schema import Alert, FeatureRecord, ScoreResult
from shared.transport import FileQueueConsumer, FileQueueProducer


def _sample_alert() -> Alert:
    rec = FeatureRecord(
        protocol="dns",
        ts=1234.5,
        src="10.0.0.2",
        dst="10.0.0.3",
        features={"query_name_length": 84.0, "subdomain_entropy": 4.2},
        meta={"qname": "ZXhmaWw.tunnel.example.local"},
    )
    score = ScoreResult(
        anomaly_score=0.93,
        is_anomaly=True,
        feature_attributions={"query_name_length": 0.7, "subdomain_entropy": 0.3},
    )
    return Alert(record=rec, score=score, candidate_techniques=["T1071.004", "T1048.003"])


def test_alert_json_roundtrip() -> None:
    alert = _sample_alert()
    restored = Alert.from_json(alert.to_json())
    assert restored == alert


def test_feature_record_roundtrip() -> None:
    rec = _sample_alert().record
    assert FeatureRecord.from_dict(rec.to_dict()) == rec


def test_file_queue_delivers_new_messages_only(tmp_path) -> None:
    producer = FileQueueProducer(tmp_path)
    consumer = FileQueueConsumer(tmp_path)

    assert consumer.poll("features") == []

    producer.send("features", {"a": 1})
    producer.send("features", {"a": 2})
    first = consumer.poll("features")
    assert first == [{"a": 1}, {"a": 2}]

    # Second poll sees nothing until more is produced.
    assert consumer.poll("features") == []
    producer.send("features", {"a": 3})
    assert consumer.poll("features") == [{"a": 3}]
