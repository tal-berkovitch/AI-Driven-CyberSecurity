"""Shared numeric helpers for detectors: standardisation + attribution shaping."""

from __future__ import annotations

import numpy as np
import pandas as pd


class Standardizer:
    """Per-feature mean/std standardiser fit on the benign baseline.

    Stores the feature order so ``transform`` is robust to column reordering and
    so the detector errors loudly if asked to score an unknown feature set.
    """

    def __init__(self) -> None:
        self.features: list[str] = []
        self.mean: np.ndarray = np.empty(0)
        self.std: np.ndarray = np.empty(0)

    def fit(self, df: pd.DataFrame) -> "Standardizer":
        self.features = list(df.columns)
        x = df.to_numpy(dtype=float)
        self.mean = x.mean(axis=0)
        std = x.std(axis=0)
        std[std == 0] = 1.0  # constant features -> avoid divide-by-zero
        self.std = std
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        x = df[self.features].to_numpy(dtype=float)  # KeyError if a feature is missing
        return (x - self.mean) / self.std

    def to_dict(self) -> dict:
        return {"features": self.features, "mean": self.mean.tolist(), "std": self.std.tolist()}

    @classmethod
    def from_dict(cls, d: dict) -> "Standardizer":
        s = cls()
        s.features = list(d["features"])
        s.mean = np.asarray(d["mean"], dtype=float)
        s.std = np.asarray(d["std"], dtype=float)
        return s
