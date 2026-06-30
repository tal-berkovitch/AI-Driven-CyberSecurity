"""The transport factory selects file vs Kafka by TRANSPORT, and the Kafka path is
lazy — constructing it needs no live broker (so this runs without Kafka)."""

from shared.transport import (
    FileQueueConsumer,
    FileQueueProducer,
    make_consumer,
    make_producer,
)


def test_factory_defaults_to_file(monkeypatch, tmp_path):
    monkeypatch.delenv("TRANSPORT", raising=False)
    assert isinstance(make_producer(str(tmp_path)), FileQueueProducer)
    assert isinstance(make_consumer(str(tmp_path)), FileQueueConsumer)


def test_factory_file_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("TRANSPORT", "file")
    assert isinstance(make_producer(str(tmp_path)), FileQueueProducer)


def test_factory_selects_kafka_lazily(monkeypatch, tmp_path):
    monkeypatch.setenv("TRANSPORT", "kafka")
    # No broker here: construction must not connect (lazy clients).
    prod = make_producer(str(tmp_path))
    cons = make_consumer(str(tmp_path), group="ui", live=True)
    assert prod.__class__.__name__ == "KafkaProducer"
    assert cons.__class__.__name__ == "KafkaConsumer"
    assert cons.group == "ui" and cons.live is True
