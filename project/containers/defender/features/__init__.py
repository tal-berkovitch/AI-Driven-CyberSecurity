"""Feature engineering plane.

Turns windows of :class:`~shared.capture.CaptureEvent` into flat, numeric
:class:`~shared.schema.FeatureRecord` rows. The feature schema follows
ARCHITECTURE.md §4 and is intentionally physically meaningful so that the
per-feature attribution surfaced in Phase 2 reads as human SOC evidence.
"""

from .windows import WindowAggregator

__all__ = ["WindowAggregator"]
