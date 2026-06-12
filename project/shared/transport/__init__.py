"""Pluggable message transport between pipeline stages.

The streaming spine (capture/alerts/cti) runs over a file-backed queue
(``FileQueueProducer`` / ``FileQueueConsumer``) or Apache **Kafka**, behind the
same ``Producer`` / ``Consumer`` protocols — selected by the ``TRANSPORT`` env var
(``file`` | ``kafka``, default ``file``). Use :func:`make_producer` /
:func:`make_consumer` so a stage is agnostic to the backend; the control plane
(ops requests/health, model/backend selection) stays on the file queue regardless.
"""

from __future__ import annotations

import os

from shared.transport.base import Consumer, Producer
from shared.transport.file_queue import FileQueueConsumer, FileQueueProducer

__all__ = [
    "Producer",
    "Consumer",
    "FileQueueProducer",
    "FileQueueConsumer",
    "make_producer",
    "make_consumer",
]


def _transport() -> str:
    return os.getenv("TRANSPORT", "file").lower().strip()


def make_producer(queue_root: str) -> Producer:
    """Producer for the selected transport (``TRANSPORT``); file uses ``queue_root``."""
    if _transport() == "kafka":
        from shared.transport.kafka_queue import KafkaProducer

        return KafkaProducer()
    return FileQueueProducer(queue_root)


def make_consumer(queue_root: str, group: str = "soc", live: bool = False) -> Consumer:
    """Consumer for the selected transport.

    ``group``/``live`` apply to Kafka (consumer-group + offset reset). For the file
    queue they're ignored — callers keep their existing seek-to-end discard-poll.
    """
    if _transport() == "kafka":
        from shared.transport.kafka_queue import KafkaConsumer

        return KafkaConsumer(group=group, live=live)
    return FileQueueConsumer(queue_root)
