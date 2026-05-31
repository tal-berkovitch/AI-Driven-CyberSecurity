"""IsolationForest detector — the unsupervised baseline the autoencoder must beat.

Trained on benign only (novelty-detection style). ``anomaly_score`` is the
negated ``score_samples`` so higher = more anomalous, consistent with the AE.
IsolationForest has no native per-feature attribution, so we report the squared
standardised deviation per feature as a transparent proxy — same shape as the
AE's attribution, keeping the LLM-facing evidence interface uniform.
"""

from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from shared.schema import ScoreResult

from ._common import Standardizer


class IsolationForestDetector:
    def __init__(self, n_estimators: int = 200, contamination: float | str = "auto",
                 random_state: int = 42) -> None:
        self.model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination, random_state=random_state,
        )
        self.scaler = Standardizer()

    def fit(self, baseline: pd.DataFrame) -> None:
        z = self.scaler.fit(baseline).transform(baseline)
        self.model.fit(z)

    def score(self, features: pd.DataFrame) -> list[ScoreResult]:
        z = self.scaler.transform(features)
        raw = -self.model.score_samples(z)          # higher = more anomalous
        is_anom = self.model.predict(z) == -1        # IF's own contamination cutoff
        names = self.scaler.features
        results: list[ScoreResult] = []
        for i in range(z.shape[0]):
            attr = {names[j]: float(z[i, j] ** 2) for j in range(len(names))}
            results.append(ScoreResult(
                anomaly_score=float(raw[i]), is_anomaly=bool(is_anom[i]),
                feature_attributions=attr,
            ))
        return results

    def save(self, path: str) -> None:
        joblib.dump({"model": self.model, "scaler": self.scaler.to_dict()}, path)

    def load(self, path: str) -> None:
        blob = joblib.load(path)
        self.model = blob["model"]
        self.scaler = Standardizer.from_dict(blob["scaler"])
