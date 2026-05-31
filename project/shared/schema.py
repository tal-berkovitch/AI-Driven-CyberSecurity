"""Stable data contracts shared by every stage of the pipeline.

These three types are the *only* coupling between stages. As long as the feature
extractor emits ``FeatureRecord`` and the detector emits ``ScoreResult``, the
detection backend (local autoencoder / Isolation Forest / Morpheus DFP) can be
swapped with zero downstream changes.

``FeatureRecord.features`` is intentionally a flat ``{str: float}`` mapping so it
maps directly onto a columnar table — the input shape Morpheus DFP expects.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FeatureRecord:
    """One extracted observation (a DNS query window or SNMP exchange)."""

    protocol: str                       # "dns" | "snmp"
    ts: float                           # unix timestamp
    src: str                            # source address/host
    dst: str                            # destination address/host
    features: dict[str, float]          # flat numeric vector (Morpheus-compatible)
    meta: dict[str, Any] = field(default_factory=dict)  # raw context for the LLM

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FeatureRecord":
        return cls(
            protocol=d["protocol"],
            ts=d["ts"],
            src=d["src"],
            dst=d["dst"],
            features=dict(d["features"]),
            meta=dict(d.get("meta", {})),
        )


@dataclass
class ScoreResult:
    """A detector's verdict for one ``FeatureRecord``.

    ``feature_attributions`` is the per-feature contribution to the anomaly score
    (e.g. autoencoder per-feature reconstruction loss / z-score). It is both the
    quantified evidence for evaluation and the structured input the LLM turns
    into human-readable CTI — one mechanism, two deliverables.
    """

    anomaly_score: float
    is_anomaly: bool
    feature_attributions: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScoreResult":
        return cls(
            anomaly_score=float(d["anomaly_score"]),
            is_anomaly=bool(d["is_anomaly"]),
            feature_attributions=dict(d.get("feature_attributions", {})),
        )


@dataclass
class Alert:
    """A scored anomaly, optionally enriched with MITRE techniques and a report."""

    record: FeatureRecord
    score: ScoreResult
    candidate_techniques: list[str] = field(default_factory=list)  # MITRE IDs
    cti_report: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record.to_dict(),
            "score": self.score.to_dict(),
            "candidate_techniques": list(self.candidate_techniques),
            "cti_report": self.cti_report,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        return cls(
            record=FeatureRecord.from_dict(d["record"]),
            score=ScoreResult.from_dict(d["score"]),
            candidate_techniques=list(d.get("candidate_techniques", [])),
            cti_report=d.get("cti_report"),
        )

    @classmethod
    def from_json(cls, s: str) -> "Alert":
        return cls.from_dict(json.loads(s))
