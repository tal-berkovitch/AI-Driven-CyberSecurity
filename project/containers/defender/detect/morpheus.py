"""Morpheus DFP backend (Phase 5) — plug-and-play scaffold for the lab GPU box.

NVIDIA Morpheus' Digital Fingerprinting (DFP) pipeline is built on the
``dfencoder.AutoEncoder``, whose **per-feature z-score loss** is exactly our
``ScoreResult.feature_attributions`` contract — so this backend slots into the
same FeatureRecord -> ScoreResult -> Alert -> MITRE -> CTI path with no
downstream change. (It is the lab counterpart of the home ``local`` autoencoder.)

This module is **import-safe**: it never imports ``dfencoder`` at module load, so
the defender image (which has no Morpheus installed) imports it fine and only
errors if you actually ``fit``/``score`` without ``dfencoder`` present — at which
point the defender logs it and falls back, rather than crashing.

== Enable it on the lab box (NO further code changes needed) ==
1. Install NVIDIA Morpheus + ``dfencoder`` on the GPU box (conda / NGC per the
   Morpheus docs).
2. Train:  ``uv run --extra detect python -m eval.train --backends morpheus``
           (writes ``models/{dns,snmp}_morpheus.pt``).
3. Run:    ``DETECTOR_BACKEND=morpheus DEFENDER_MODE=detect docker compose up``.
   The dashboard's backend switch shows **Morpheus DFP** as the active (green) backend.

If your Morpheus/dfencoder version's API differs, the ONLY spots to adjust are the
two marked ``# ADJUST`` lines in ``fit`` / ``_results`` below.
"""

from __future__ import annotations

import pickle

import numpy as np
import pandas as pd

from shared.schema import ScoreResult

# dfencoder's encoder funnel — kept identical to the home AE so results compare.
HIDDEN = (24, 12, 6)
_INSTALL_HINT = (
    "Morpheus/dfencoder is not installed in this container. Install NVIDIA Morpheus "
    "+ dfencoder on the lab GPU box to use DETECTOR_BACKEND=morpheus."
)


def _autoencoder_cls():
    try:
        from dfencoder import AutoEncoder
    except ImportError as exc:                       # import-safe: only fails on real use
        raise RuntimeError(_INSTALL_HINT) from exc
    return AutoEncoder


class MorpheusDetector:
    """Detector backend wrapping Morpheus DFP's ``dfencoder.AutoEncoder``."""

    def __init__(self, epochs: int = 100, threshold_q: float = 0.99, **kwargs) -> None:
        self.epochs = epochs
        self.threshold_q = threshold_q
        self.kwargs = kwargs
        self.model = None
        self.features: list[str] = []
        self.threshold: float = float("inf")

    def fit(self, baseline: pd.DataFrame) -> None:
        auto_encoder = _autoencoder_cls()
        self.features = list(baseline.columns)
        # ADJUST: ctor kwargs vary across dfencoder versions.
        self.model = auto_encoder(
            encoder_layers=list(HIDDEN), decoder_layers=list(reversed(HIDDEN)),
            activation="relu", swap_p=0.0, lr=1e-3, verbose=False, **self.kwargs,
        )
        self.model.fit(baseline, epochs=self.epochs)
        self.threshold = float(np.quantile(self._overall(self._results(baseline)),
                                           self.threshold_q))

    def _results(self, features: pd.DataFrame) -> pd.DataFrame:
        # ADJUST: dfencoder returns per-feature '<feat>_z_loss' cols (+ 'mean_abs_z').
        return self.model.get_results(features[self.features])

    @staticmethod
    def _overall(res: pd.DataFrame) -> np.ndarray:
        if "mean_abs_z" in res.columns:
            return res["mean_abs_z"].to_numpy()
        zc = [c for c in res.columns if c.endswith("_z_loss")]
        return res[zc].abs().mean(axis=1).to_numpy() if zc else np.zeros(len(res))

    def score(self, features: pd.DataFrame) -> list[ScoreResult]:
        if self.model is None:
            raise RuntimeError("MorpheusDetector is not fitted/loaded")
        res = self._results(features)
        row = self._overall(res)
        zcols = {f: f"{f}_z_loss" for f in self.features if f"{f}_z_loss" in res.columns}
        out: list[ScoreResult] = []
        for i in range(len(features)):
            attr = {f: float(res[zc].iloc[i]) for f, zc in zcols.items()}
            out.append(ScoreResult(anomaly_score=float(row[i]),
                                   is_anomaly=bool(row[i] > self.threshold),
                                   feature_attributions=attr))
        return out

    def save(self, path: str) -> None:
        with open(path, "wb") as fh:
            pickle.dump({"model": self.model, "features": self.features,
                         "threshold": self.threshold}, fh)

    def load(self, path: str) -> None:
        _autoencoder_cls()                           # ensure dfencoder is importable
        with open(path, "rb") as fh:
            blob = pickle.load(fh)
        self.model = blob["model"]
        self.features = list(blob["features"])
        self.threshold = float(blob["threshold"])
