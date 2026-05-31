"""Defender agent — Phase 1 (capture-consumer + feature plane).

Pipeline wired so far:

    [collector tap] --capture topic--> consume -> features -> FeatureRecord -> baseline CSV
                                                              ^^^^^^^^^^^^^^^^ Phase 1 deliverable

The detector (Phase 2), enrichment + CTI (Phase 3) plug in right after feature
extraction with no rewiring — the FeatureRecord contract is the seam. The
detection backend is still selected by DETECTOR_BACKEND so the home->Morpheus
switch stays a config change.
"""

from __future__ import annotations

import logging
import os
import signal
import time

from shared.capture import CaptureEvent
from shared.transport.file_queue import FileQueueConsumer

from .baseline import BaselineWriter
from .features import WindowAggregator

LOG = logging.getLogger("defender")

VALID_BACKENDS = {"local", "isolation_forest", "morpheus"}
CAPTURE_TOPIC = "capture"

_running = True


def _stop(_signo, _frame) -> None:  # noqa: ANN001
    global _running
    _running = False


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    backend = os.getenv("DETECTOR_BACKEND", "local")
    if backend not in VALID_BACKENDS:
        LOG.warning("unknown DETECTOR_BACKEND=%r (expected one of %s)", backend, VALID_BACKENDS)

    queue_root = os.getenv("QUEUE_ROOT", "/app/data/queue")
    baseline_dir = os.getenv("BASELINE_DIR", "/app/data/baseline")
    window_s = float(os.getenv("WINDOW_SECONDS", "10"))
    poll_s = float(os.getenv("POLL_SECONDS", "1"))
    # Force-close the trailing window after this much silence so the tail is saved.
    idle_flush_s = float(os.getenv("IDLE_FLUSH_SECONDS", str(max(3 * window_s, 15))))

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    consumer = FileQueueConsumer(queue_root)
    agg = WindowAggregator(window_s=window_s)
    writer = BaselineWriter(baseline_dir)

    LOG.info("defender up; backend=%s window=%ss queue=%s -> %s",
             backend, window_s, queue_root, baseline_dir)

    last_event_t = time.monotonic()
    total = 0
    while _running:
        events = consumer.poll(CAPTURE_TOPIC)
        if events:
            last_event_t = time.monotonic()
            for raw in events:
                try:
                    records = agg.add(CaptureEvent.from_dict(raw))
                except (KeyError, ValueError, TypeError) as exc:
                    LOG.warning("skipping malformed capture event: %s", exc)
                    continue
                if records:
                    writer.write_many(records)
                    total += len(records)
                    LOG.info("wrote %d feature rows (dns=%d snmp=%d total=%d)",
                             len(records), writer.counts["dns"], writer.counts["snmp"], total)
        elif time.monotonic() - last_event_t > idle_flush_s:
            tail = agg.flush_all()
            if tail:
                writer.write_many(tail)
                total += len(tail)
                LOG.info("idle flush: wrote %d trailing feature rows (total=%d)", len(tail), total)
            last_event_t = time.monotonic()
        time.sleep(poll_s)

    # Graceful shutdown: persist whatever is still buffered.
    tail = agg.flush_all()
    if tail:
        writer.write_many(tail)
    LOG.info("defender stopping; baseline rows dns=%d snmp=%d",
             writer.counts["dns"], writer.counts["snmp"])


if __name__ == "__main__":
    main()
