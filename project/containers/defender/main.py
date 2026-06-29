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

import json
import logging
import os
import signal
import time
from pathlib import Path

import pandas as pd

from shared.capture import CaptureEvent
from shared.schema import Alert, FeatureRecord
from shared.transport import Producer, make_consumer, make_producer

from .baseline import BaselineWriter
from .features import WindowAggregator
from .features.dns import DNS_FEATURES

LOG = logging.getLogger("defender")

VALID_BACKENDS = {"local", "charae", "isolation_forest", "morpheus"}
# Backends the dashboard may select via the control file (loadable here).
CONTROL_BACKENDS = {"local", "charae", "isolation_forest"}
SCHEMAS = {"dns": DNS_FEATURES}
CAPTURE_TOPIC = "capture"
ALERTS_TOPIC = "alerts"
# Frame column carrying raw qnames to the char-AE backend (mirrors char_ae.QNAME_COL;
# defined here so record mode needn't import torch).
QNAME_COL = "qnames"
# A window whose packets are mostly responses is a server echoing the other side
# of an exchange; alerting on it duplicates the initiator's alert. Suppress it.
RESPONSE_ALERT_THRESHOLD = float(os.getenv("RESPONSE_ALERT_THRESHOLD", "0.5"))

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
        LOG.info("wrote %d feature rows (dns=%d)", len(records), self.writer.counts["dns"])


class DetectSink:
    """Score each FeatureRecord; enrich + emit an Alert for anomalies."""

    def __init__(self, detectors: dict, enricher, producer: Producer) -> None:
        self.detectors = detectors
        self.enricher = enricher
        self.producer = producer
        self.n_alerts = 0
        self.n_suppressed = 0

    def handle(self, records: list[FeatureRecord]) -> None:
        for rec in records:
            det = self.detectors.get(rec.protocol)
            if det is None:
                continue
            # Skip the server/response half of an exchange — the initiating client's
            # window carries the same anomaly and is attributed to the real source.
            if rec.meta.get("response_fraction", 0.0) >= RESPONSE_ALERT_THRESHOLD:
                self.n_suppressed += 1
                continue
            schema = SCHEMAS[rec.protocol]
            frame = pd.DataFrame([{c: rec.features.get(c, 0.0) for c in schema}],
                                 columns=list(schema))
            # Carry the raw qnames alongside the numeric features: the char-embedding
            # AE backend scores the strings; numeric backends select their own columns
            # and ignore this one.
            frame[QNAME_COL] = [rec.meta.get("qnames") or rec.meta.get("sample_qnames") or []]
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
    for proto in ("dns",):
        path = Path(models_dir) / f"{proto}_{backend}.pt"
        if not path.exists():
            LOG.warning("no model for %s at %s", proto, path)
            continue
        try:
            det = make_detector(backend)
            det.load(str(path))
        except Exception as exc:  # noqa: BLE001 — e.g. morpheus model but no dfencoder
            LOG.warning("could not load %s detector for %s (%s); skipping", backend, proto, exc)
            continue
        detectors[proto] = det
        LOG.info("loaded %s detector for %s from %s", backend, proto, path)
    return detectors


BACKEND_LABELS = {"local": "Autoencoder", "charae": "Char-Embedding AE",
                  "isolation_forest": "Isolation Forest", "morpheus": "Morpheus DFP"}


def _ae_card(det, proto: str) -> dict:
    feats = list(getattr(getattr(det, "scaler", None), "features", []) or SCHEMAS.get(proto, []))
    hidden = list(getattr(det, "hidden", []) or [])
    input_dim = len(feats)
    # input -> encoder(hidden) -> bottleneck -> decoder(reverse) -> output
    layers = [input_dim, *hidden, *hidden[-2::-1], input_dim] if hidden else [input_dim]
    n_params = 0
    model = getattr(det, "model", None)
    if model is not None:
        try:
            n_params = int(sum(p.numel() for p in model.parameters()))
        except (AttributeError, TypeError):
            n_params = 0
    return {"type": "autoencoder", "input_dim": input_dim, "hidden": hidden,
            "layers": layers, "threshold": float(getattr(det, "threshold", 0.0)),
            "n_params": n_params, "features": feats}


def _charae_card(det, proto: str) -> dict:
    # Char-embedding sequence AE: vocab -> embed -> GRU(hidden) -> latent -> GRU -> vocab.
    # Rendered with the autoencoder network view (funnel) using its real dimensions.
    vocab_size = len(getattr(det, "vocab", {})) + 2
    from .detect.char_ae import EMBED, HIDDEN, LATENT
    layers = [vocab_size, EMBED, HIDDEN, LATENT, HIDDEN, EMBED, vocab_size]
    n_params = 0
    model = getattr(det, "model", None)
    if model is not None:
        try:
            n_params = int(sum(p.numel() for p in model.parameters()))
        except (AttributeError, TypeError):
            n_params = 0
    return {"type": "autoencoder", "input_dim": vocab_size, "hidden": [EMBED, HIDDEN, LATENT],
            "layers": layers, "threshold": float(getattr(det, "threshold", 0.0)),
            "n_params": n_params, "vocab_size": vocab_size,
            "features": ["query_name_length", "subdomain_entropy", "encoded_labels",
                         "qname_reconstruction_error"],
            "note": "Character-embedding GRU sequence autoencoder — scores qname strings "
                    "(lexical), trained on benign qnames only. Catches high-entropy DNS exfil."}


def _if_card(det, proto: str) -> dict:
    feats = list(getattr(getattr(det, "scaler", None), "features", []) or SCHEMAS.get(proto, []))
    m = getattr(det, "model", None)
    return {"type": "isolation_forest", "input_dim": len(feats),
            "n_estimators": int(getattr(m, "n_estimators", 0)),
            "contamination": str(getattr(m, "contamination", "auto")),
            "max_samples": str(getattr(m, "max_samples", "auto")),
            "features": feats,
            "note": "Ensemble of isolation trees — no native per-feature attribution."}


def _morpheus_card(det, proto: str) -> dict:
    # dfencoder is an autoencoder, so it renders with the same network view as `local`.
    feats = list(getattr(det, "features", []) or SCHEMAS.get(proto, []))
    hidden = [24, 12, 6]
    input_dim = len(feats)
    layers = [input_dim, *hidden, *hidden[-2::-1], input_dim]
    return {"type": "autoencoder", "input_dim": input_dim, "hidden": hidden, "layers": layers,
            "threshold": float(getattr(det, "threshold", 0.0)), "n_params": 0, "features": feats,
            "note": "Morpheus DFP (dfencoder) — per-feature z-score attribution."}


def resolve_backend(env_backend: str, control_dir: str) -> str:
    """Active backend = a valid dashboard selection (control file) else the env.

    The control file is written by the egress ops-agent (on a UI 'apply backend'
    request); we validate it against CONTROL_BACKENDS so the only egress->defender
    influence is a known backend label.
    """
    try:
        sel = (Path(control_dir) / "detector_backend").read_text(encoding="utf-8").strip()
        if sel in CONTROL_BACKENDS:
            return sel
    except OSError:
        pass
    return env_backend


def build_model_card(active_backend: str, models_dir: str) -> dict:
    """Describe every available detector backend for the dashboard's model panel.

    For each trainable backend we load its saved per-protocol models and emit a
    type-appropriate card (autoencoder layer shape / IsolationForest config). The
    `active_backend` is the one actually scoring; `morpheus` is a Phase-5 placeholder.
    """
    from .detect import make_detector

    md = Path(models_dir)
    builders = {"local": ("autoencoder", _ae_card),
                "charae": ("autoencoder", _charae_card),
                "isolation_forest": ("isolation_forest", _if_card),
                "morpheus": ("autoencoder", _morpheus_card)}
    backends: dict = {}
    for backend, (btype, builder) in builders.items():
        models: dict = {}
        for proto in ("dns",):
            path = md / f"{proto}_{backend}.pt"
            if not path.exists():
                continue
            try:
                det = make_detector(backend)
                det.load(str(path))
                models[proto] = builder(det, proto)
            except Exception as exc:  # noqa: BLE001 — a bad model must not break the card
                LOG.warning("model card: %s/%s load failed: %s", backend, proto, exc)
        backends[backend] = {"type": btype, "label": BACKEND_LABELS[backend],
                             "available": bool(models), "models": models}
    if not backends["morpheus"]["available"]:                # dev box: keep the placeholder
        backends["morpheus"]["note"] = "Not implemented here — train on the lab GPU box (Phase 5)."
    return {"active_backend": active_backend, "generated_ts": time.time(), "backends": backends}


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    control_dir = os.getenv("CONTROL_DIR", "/app/control")
    backend = resolve_backend(os.getenv("DETECTOR_BACKEND", "local"), control_dir)
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

    consumer = make_consumer(queue_root, group="defender", live=True)
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
            detectors, MitreEnricher(), make_producer(queue_root))
        # Publish a model card to the shared volume for the UI's network view.
        try:
            card_path = Path(queue_root).parent / "model_card.json"
            card = build_model_card(backend, models_dir)
            card_path.write_text(json.dumps(card), encoding="utf-8")
            avail = [b for b, v in card["backends"].items() if v["available"]]
            LOG.info("wrote model card (active=%s, available=%s) -> %s",
                     backend, avail, card_path)
        except OSError as exc:
            LOG.warning("could not write model card: %s", exc)
    else:
        sink = RecordSink(baseline_dir)

    # Start live: skip whatever is already in the queue so a restart doesn't replay
    # (and re-alert / re-record) the whole capture backlog. Set SEEK_TO_END=false to
    # process the existing backlog instead.
    seek_to_end = os.getenv("SEEK_TO_END", "true").lower() not in ("0", "false", "no")
    if seek_to_end:
        skipped = len(consumer.poll(CAPTURE_TOPIC))
        if skipped:
            LOG.info("seek-to-end: skipped %d backlog capture events "
                     "(SEEK_TO_END=false to process them)", skipped)

    LOG.info("defender up; mode=%s backend=%s window=%ss seek_to_end=%s queue=%s",
             mode, backend, window_s, seek_to_end, queue_root)

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
