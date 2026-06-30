"""Pluggable anomaly-detection backends (ARCHITECTURE.md §3).

Every backend implements the same :class:`Detector` interface and is selected by
the ``DETECTOR_BACKEND`` env var, so the home pipeline can switch to the lab
Morpheus box with zero downstream change. The detector consumes ``FeatureRecord``
feature vectors and emits ``ScoreResult`` (anomaly score + per-feature
attribution — the quantified evidence that also feeds the Phase 3 LLM).
"""

from .base import Detector, make_detector

__all__ = ["Detector", "make_detector"]
