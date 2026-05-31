"""File-backed JSON-lines queue.

A deliberately tiny transport for the early phases: each topic is an append-only
``<root>/<topic>.jsonl`` file. The producer appends one JSON object per line; the
consumer remembers its byte offset per topic and returns only new lines on each
``poll``. Good enough for single-host development; replaced by Kafka in Phase 4.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class FileQueueProducer:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, topic: str) -> Path:
        return self.root / f"{topic}.jsonl"

    def send(self, topic: str, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        with open(self._path(topic), "a", encoding="utf-8") as fh:
            fh.write(line)


class FileQueueConsumer:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self._offsets: dict[str, int] = {}

    def _path(self, topic: str) -> Path:
        return self.root / f"{topic}.jsonl"

    def poll(self, topic: str) -> list[dict[str, Any]]:
        path = self._path(topic)
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            fh.seek(self._offsets.get(topic, 0))
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
            self._offsets[topic] = fh.tell()
        return out
