"""Local autoencoder detector (PyTorch) — the "home" backend.

Trains a small MLP autoencoder on benign feature vectors only. At inference the
reconstruction error is the anomaly score; the **per-feature** reconstruction
error is the attribution. That per-feature loss is deliberately the same signal
Morpheus' ``dfencoder`` exposes, so explainability is identical when the backend
is swapped — and it is exactly what the Phase 3 LLM turns into CTI prose
(e.g. "query_name_length and subdomain_entropy dominate the error → DNS tunneling").
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import torch
from torch import nn

from shared.schema import ScoreResult

from ._common import Standardizer


class _AE(nn.Module):
    def __init__(self, n_features: int, hidden: tuple[int, ...] = (24, 12, 6)) -> None:
        super().__init__()
        dims = [n_features, *hidden]
        enc: list[nn.Module] = []
        for a, b in zip(dims[:-1], dims[1:]):
            enc += [nn.Linear(a, b), nn.ReLU()]
        dec: list[nn.Module] = []
        rev = dims[::-1]
        for a, b in zip(rev[:-1], rev[1:]):
            dec += [nn.Linear(a, b), nn.ReLU()]
        dec = dec[:-1]  # no activation on the reconstruction layer
        self.net = nn.Sequential(*enc, *dec)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class LocalAutoencoderDetector:
    def __init__(self, hidden: tuple[int, ...] = (24, 12, 6), epochs: int = 300,
                 lr: float = 1e-3, threshold_q: float = 0.99, seed: int = 42) -> None:
        self.hidden = hidden
        self.epochs = epochs
        self.lr = lr
        self.threshold_q = threshold_q
        self.seed = seed
        self.scaler = Standardizer()
        self.model: _AE | None = None
        self.threshold: float = float("inf")

    def _recon_err(self, z: np.ndarray) -> np.ndarray:
        """Per-feature squared reconstruction error, shape (n_rows, n_features)."""
        assert self.model is not None
        self.model.eval()
        with torch.no_grad():
            x = torch.tensor(z, dtype=torch.float32)
            recon = self.model(x).numpy()
        return (z - recon) ** 2

    def fit(self, baseline: pd.DataFrame) -> None:
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        z = self.scaler.fit(baseline).transform(baseline)
        self.model = _AE(z.shape[1], self.hidden)
        opt = torch.optim.Adam(self.model.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        x = torch.tensor(z, dtype=torch.float32)
        self.model.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            loss = loss_fn(self.model(x), x)
            loss.backward()
            opt.step()
        # Threshold = a high quantile of benign reconstruction error (per-row MSE).
        train_err = self._recon_err(z).mean(axis=1)
        self.threshold = float(np.quantile(train_err, self.threshold_q))

    def score(self, features: pd.DataFrame) -> list[ScoreResult]:
        z = self.scaler.transform(features)
        per_feat = self._recon_err(z)
        row_err = per_feat.mean(axis=1)
        names = self.scaler.features
        results: list[ScoreResult] = []
        for i in range(z.shape[0]):
            attr = {names[j]: float(per_feat[i, j]) for j in range(len(names))}
            results.append(ScoreResult(
                anomaly_score=float(row_err[i]),
                is_anomaly=bool(row_err[i] > self.threshold),
                feature_attributions=attr,
            ))
        return results

    def save(self, path: str) -> None:
        torch.save({
            "state_dict": self.model.state_dict() if self.model else None,
            "hidden": self.hidden,
            "scaler": self.scaler.to_dict(),
            "threshold": self.threshold,
        }, path)

    def load(self, path: str) -> None:
        blob = torch.load(path, weights_only=False)
        self.scaler = Standardizer.from_dict(blob["scaler"])
        self.hidden = tuple(blob["hidden"])
        self.threshold = float(blob["threshold"])
        self.model = _AE(len(self.scaler.features), self.hidden)
        if blob["state_dict"] is not None:
            self.model.load_state_dict(blob["state_dict"])
