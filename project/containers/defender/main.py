"""Defender agent — the SOC AI plane.

Two modes (DEFENDER_MODE):
  record  — consume capture -> features -> baseline CSV (build the training dataset)
  detect  — consume capture -> features -> AE.score() -> enrich(MITRE) -> Alert on `alerts`

    [collector tap] --capture--> features --+--> [record] baseline CSV
                                            +--> [detect]  score -> enrich -> [alerts topic]

In detect mode the per-feature reconstruction error from the autoencoder is the
evidence carried on every Alert; the CTI worker consumes `alerts` (off the
air-gapped net) and turns that evidence into a report. Backend stays selected by
DETECTOR_BACKEND so the home->Morpheus swap is a config change.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from pathlib import Path

import pandas as pd

from shared.capture import CaptureEvent
from shared.schema import Alert, FeatureRecord
from shared.transport.file_queue import FileQueueConsumer, FileQueueProducer

from .baseline import BaselineWriter
from .features import WindowAggregator
from .features.dns import DNS_FEATURES
from .features.snmp import SNMP_FEATURES

LOG = logging.getLogger("defender")

VALID_BACKENDS = {"local", "isolation_forest", "morpheus"}
SCHEMAS = {"dns": DNS_FEATURES, "snmp": SNMP_FEATURES}
CAPTURE_TOPIC = "capture"
ALERTS_TOPIC = "alerts"

_running = True


def _stop(_signo, _frame) -> None:  # noqa: ANN001
    global _running
    _running = False


# --- sinks: what to do with each window's FeatureRecords --------------------

class RecordSink:
    """Persist FeatureRecords to the benign baseline CSV (dataset building)."""

    def __init__(self, baseline_dir: str) -> None:
        self.writer = BaselineWriter(baseline_dir)

    def handle(self, records: list[FeatureRecord]) -> None:
        if not records:
            return
        self.writer.write_many(records)
        LOG.info("wrote %d feature rows (dns=%d snmp=%d)",
                 len(records), self.writer.counts["dns"], self.writer.counts["snmp"])


class DetectSink:
    """Score each FeatureRecord; enrich + emit an Alert for anomalies."""

    def __init__(self, detectors: dict, enricher, producer: FileQueueProducer) -> None:
        self.detectors = detectors
        self.enricher = enricher
        self.producer = producer
        self.n_alerts = 0

    def handle(self, records: list[FeatureRecord]) -> None:
        for rec in records:
            det = self.detectors.get(rec.protocol)
            if det is None:
                continue
            schema = SCHEMAS[rec.protocol]
            frame = pd.DataFrame([{c: rec.features.get(c, 0.0) for c in schema}],
                                 columns=list(schema))
            score = det.score(frame)[0]
            if not score.is_anomaly:
                continue
            alert = self.enricher.enrich(Alert(record=rec, score=score))
            self.producer.send(ALERTS_TOPIC, alert.to_dict())
            self.n_alerts += 1
            top = max(score.feature_attributions, key=score.feature_attributions.get,
                      default="?")
            LOG.warning("ALERT #%d proto=%s src=%s score=%.4f top=%s techniques=%s",
                        self.n_alerts, rec.protocol, rec.src, score.anomaly_score,
                        top, alert.candidate_techniques)


def _load_detectors(backend: str, models_dir: str) -> dict:
    """Load one trained detector per protocol; empty dict if none are present."""
    from .detect import make_detector  # lazy: record mode needs no torch

    detectors: dict = {}
    for proto in ("dns", "snmp"):
        path = Path(models_dir) / f"{proto}_{backend}.pt"
        if not path.exists():
            LOG.warning("no model for %s at %s", proto, path)
            continue
        det = make_detector(backend)
        det.load(str(path))
        detectors[proto] = det
        LOG.info("loaded %s detector for %s from %s", backend, proto, path)
    return detectors


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    backend = os.getenv("DETECTOR_BACKEND", "local")
    if backend not in VALID_BACKENDS:
        LOG.warning("unknown DETECTOR_BACKEND=%r (expected one of %s)", backend, VALID_BACKENDS)

    mode = os.getenv("DEFENDER_MODE", "record").lower()
    queue_root = os.getenv("QUEUE_ROOT", "/app/data/queue")
    baseline_dir = os.getenv("BASELINE_DIR", "/app/data/baseline")
    models_dir = os.getenv("MODELS_DIR", "/app/models")
    window_s = float(os.getenv("WINDOW_SECONDS", "10"))
    poll_s = float(os.getenv("POLL_SECONDS", "1"))
    idle_flush_s = float(os.getenv("IDLE_FLUSH_SECONDS", str(max(3 * window_s, 15))))

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    consumer = FileQueueConsumer(queue_root)
    agg = WindowAggregator(window_s=window_s)

    if mode == "detect":
        detectors = _load_detectors(backend, models_dir)
        if not detectors:
            LOG.warning("no models found in %s -> falling back to record mode "
                        "(train with `python -m eval.train`)", models_dir)
            mode = "record"

    if mode == "detect":
        from .enrich import MitreEnricher
        sink: RecordSink | DetectSink = DetectSink(
            detectors, MitreEnricher(), FileQueueProducer(queue_root))
    else:
        sink = RecordSink(baseline_dir)

    LOG.info("defender up; mode=%s backend=%s window=%ss queue=%s",
             mode, backend, window_s, queue_root)

    last_event_t = time.monotonic()
    while _running:
        events = consumer.poll(CAPTURE_TOPIC)
        if events:
            last_event_t = time.monotonic()
            for raw in events:
                try:
                    sink.handle(agg.add(CaptureEvent.from_dict(raw)))
                except (KeyError, ValueError, TypeError) as exc:
                    LOG.warning("skipping malformed capture event: %s", exc)
        elif time.monotonic() - last_event_t > idle_flush_s:
            sink.handle(agg.flush_all())
            last_event_t = time.monotonic()
        time.sleep(poll_s)

    sink.handle(agg.flush_all())  # graceful shutdown: drain the tail
    LOG.info("defender stopping (mode=%s)", mode)


if __name__ == "__main__":
    main()
