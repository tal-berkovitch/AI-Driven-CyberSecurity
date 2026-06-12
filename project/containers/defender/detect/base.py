"""Detector contract + backend factory."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import pandas as pd

    from shared.schema import ScoreResult

VALID_BACKENDS = ("local", "isolation_forest", "morpheus")


@runtime_checkable
class Detector(Protocol):
    """The only seam between feature extraction and detection.

    ``fit`` learns "normal" from a benign baseline; ``score`` returns one
    :class:`ScoreResult` per input row. Implementations standardise features
    internally and persist everything needed via ``save``/``load``.
    """

    def fit(self, baseline: "pd.DataFrame") -> None: ...
    def score(self, features: "pd.DataFrame") -> list["ScoreResult"]: ...
    def save(self, path: str) -> None: ...
    def load(self, path: str) -> None: ...


def make_detector(backend: str | None = None, **kwargs) -> Detector:
    """Construct the detector named by ``backend`` (default ``local``)."""
    backend = (backend or "local").lower()
    if backend == "isolation_forest":
        from .isolation_forest import IsolationForestDetector

        return IsolationForestDetector(**kwargs)
    if backend == "local":
        from .local_ae import LocalAutoencoderDetector

        return LocalAutoencoderDetector(**kwargs)
    if backend == "morpheus":
        # Import-safe scaffold: constructs fine without Morpheus installed; only
        # fit/score/load raise (with install hints) if dfencoder is absent.
        from .morpheus import MorpheusDetector

        return MorpheusDetector(**kwargs)
    raise ValueError(f"unknown DETECTOR_BACKEND={backend!r}; expected one of {VALID_BACKENDS}")
