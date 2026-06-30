"""Transport protocols. Any backend (file queue now, Kafka later) implements these."""

from __future__ import annotations

from typing import Any, Protocol


class Producer(Protocol):
    def send(self, topic: str, payload: dict[str, Any]) -> None:
        """Publish a JSON-serialisable payload to a topic."""
        ...


class Consumer(Protocol):
    def poll(self, topic: str) -> list[dict[str, Any]]:
        """Return payloads published since the last poll for this topic."""
        ...
