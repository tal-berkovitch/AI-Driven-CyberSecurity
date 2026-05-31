"""Pluggable message transport between pipeline stages.

Phase 0-2 use a file-backed queue (``FileQueueProducer`` / ``FileQueueConsumer``).
Phase 4 swaps in Kafka behind the same ``Producer`` / ``Consumer`` protocols,
which is also what lets the Morpheus backend read the *same* ``features`` topic.
"""

from shared.transport.base import Consumer, Producer
from shared.transport.file_queue import FileQueueConsumer, FileQueueProducer

__all__ = [
    "Producer",
    "Consumer",
    "FileQueueProducer",
    "FileQueueConsumer",
]
