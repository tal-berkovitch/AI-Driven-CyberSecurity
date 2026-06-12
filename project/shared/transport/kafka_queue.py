"""Kafka-backed transport (Apache Kafka), implementing the same Producer/Consumer
protocol as the file queue so the pipeline is unchanged by the swap.

Everything connects **lazily** (the underlying kafka-python client is built on the
first ``send``/``poll``), so importing/constructing needs no live broker — keeping
module import and unit tests broker-free. The streaming spine (capture/alerts/cti)
uses this when ``TRANSPORT=kafka``; the control plane stays on the file queue.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

LOG = logging.getLogger("transport.kafka")


def _bootstrap() -> list[str]:
    return os.getenv("KAFKA_BOOTSTRAP", "kafka:9092").split(",")


class KafkaProducer:
    """Publishes JSON payloads to a topic. Lazy: the client connects on first send."""

    def __init__(self, *_args, **_kwargs) -> None:
        self._producer = None

    def _client(self):
        if self._producer is None:
            from kafka import KafkaProducer as _KP

            self._producer = _KP(
                bootstrap_servers=_bootstrap(),
                value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode(),
                retries=5, linger_ms=50, acks=1,
            )
        return self._producer

    def send(self, topic: str, payload: dict[str, Any]) -> None:
        self._client().send(topic, payload)


class KafkaConsumer:
    """Returns new messages per topic. One underlying consumer per topic, created
    lazily on first ``poll(topic)``.

    ``live=True``  -> ephemeral group + ``auto_offset_reset=latest`` (start at EOF
                      every run; matches the file consumer's seek-to-end).
    ``live=False`` -> stable group + ``auto_offset_reset=earliest`` (process all and
                      resume from the committed offset on restart).
    """

    def __init__(self, *_args, group: str = "soc", live: bool = False, **_kwargs) -> None:
        self.group = group
        self.live = live
        self._consumers: dict[str, Any] = {}

    def _client(self, topic: str):
        c = self._consumers.get(topic)
        if c is None:
            from kafka import KafkaConsumer as _KC

            group_id = f"{self.group}-{uuid.uuid4().hex[:8]}" if self.live else self.group
            c = _KC(
                topic,
                bootstrap_servers=_bootstrap(),
                group_id=group_id,
                auto_offset_reset="latest" if self.live else "earliest",
                enable_auto_commit=True,
                value_deserializer=lambda b: json.loads(b.decode()),
                consumer_timeout_ms=0,
            )
            self._consumers[topic] = c
        return c

    def poll(self, topic: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            batches = self._client(topic).poll(timeout_ms=200)
        except Exception as exc:  # noqa: BLE001 — broker hiccup must not kill the loop
            LOG.warning("kafka poll(%s) failed: %s", topic, exc)
            return out
        for records in batches.values():
            for rec in records:
                out.append(rec.value)
        return out
