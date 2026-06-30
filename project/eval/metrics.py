"""Detection metrics (ARCHITECTURE.md §6).

Reported for every backend so the comparison is apples-to-apples: ranking quality
(ROC-AUC, PR-AUC), the operationally meaningful FPR at a fixed recall, and
per-attack recall at the detector's own decision threshold.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def roc_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    if len(set(y_true.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y_true, scores))


def pr_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    if len(set(y_true.tolist())) < 2:
        return float("nan")
    return float(average_precision_score(y_true, scores))


def fpr_at_recall(y_true: np.ndarray, scores: np.ndarray, target_recall: float = 0.90) -> float:
    """Smallest false-positive rate at which recall (TPR) >= target_recall."""
    if len(set(y_true.tolist())) < 2:
        return float("nan")
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = tpr >= target_recall
    return float(fpr[ok].min()) if ok.any() else float("nan")


def per_attack_recall(labels: np.ndarray, preds: np.ndarray) -> dict[str, float]:
    """Recall per attack class, using the detector's own is_anomaly predictions."""
    out: dict[str, float] = {}
    for cls in sorted(set(labels.tolist())):
        if cls == "benign":
            continue
        mask = labels == cls
        out[cls] = float(preds[mask].mean()) if mask.any() else float("nan")
    return out


def benign_fpr(labels: np.ndarray, preds: np.ndarray) -> float:
    mask = labels == "benign"
    return float(preds[mask].mean()) if mask.any() else float("nan")
