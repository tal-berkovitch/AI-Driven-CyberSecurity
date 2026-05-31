"""Benchmark every detector backend on identical labeled data -> one table.

Run:  uv run --extra detect python -m eval.run_eval
Writes eval/report/results.md and results.csv. This is the Phase-2 deliverable
that answers the lecturer's "robust evaluation" concern.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import numpy as np
import pandas as pd

from defender.detect import make_detector
from defender.features.dns import DNS_FEATURES
from defender.features.snmp import SNMP_FEATURES

from . import metrics
from .scenarios import build_labeled_records

BACKENDS = ("isolation_forest", "local")
SCHEMAS = {"dns": DNS_FEATURES, "snmp": SNMP_FEATURES}
REPORT_DIR = Path(__file__).resolve().parent / "report"


def _to_frame(records, schema) -> tuple[pd.DataFrame, np.ndarray]:
    rows = [{c: r.features.get(c, 0.0) for c in schema} for r in records]
    labels = np.array([r.meta["label"] for r in records])
    return pd.DataFrame(rows, columns=list(schema)), labels


def _split(labels: np.ndarray, train_frac: float, seed: int):
    rng = np.random.default_rng(seed)
    benign_idx = np.where(labels == "benign")[0]
    rng.shuffle(benign_idx)
    cut = int(len(benign_idx) * train_frac)
    train_idx = benign_idx[:cut]
    test_idx = np.concatenate([benign_idx[cut:], np.where(labels != "benign")[0]])
    return train_idx, test_idx


def evaluate_protocol(proto: str, records, train_frac: float = 0.6, seed: int = 7,
                      dataset: str = "synthetic") -> list[dict]:
    schema = SCHEMAS[proto]
    frame, labels = _to_frame(records, schema)
    train_idx, test_idx = _split(labels, train_frac, seed)
    train_x = frame.iloc[train_idx].reset_index(drop=True)
    test_x = frame.iloc[test_idx].reset_index(drop=True)
    test_labels = labels[test_idx]
    y_true = (test_labels != "benign").astype(int)

    out: list[dict] = []
    for backend in BACKENDS:
        det = make_detector(backend)
        t0 = time.perf_counter()
        det.fit(train_x)
        fit_ms = (time.perf_counter() - t0) * 1e3

        t1 = time.perf_counter()
        results = det.score(test_x)
        score_us = (time.perf_counter() - t1) / max(len(results), 1) * 1e6

        scores = np.array([r.anomaly_score for r in results])
        preds = np.array([r.is_anomaly for r in results]).astype(int)
        recalls = metrics.per_attack_recall(test_labels, preds)

        out.append({
            "dataset": dataset,
            "protocol": proto,
            "backend": backend,
            "n_train": len(train_idx),
            "n_test": len(test_idx),
            "roc_auc": metrics.roc_auc(y_true, scores),
            "pr_auc": metrics.pr_auc(y_true, scores),
            "fpr@recall0.9": metrics.fpr_at_recall(y_true, scores, 0.90),
            "benign_fpr": metrics.benign_fpr(test_labels, preds),
            "recall_by_attack": "; ".join(f"{k}={v:.2f}" for k, v in recalls.items()),
            "fit_ms": round(fit_ms, 1),
            "score_us/row": round(score_us, 1),
        })
    return out


def _markdown(rows: list[dict]) -> str:
    cols = ["dataset", "protocol", "backend", "n_train", "n_test", "roc_auc", "pr_auc",
            "fpr@recall0.9", "benign_fpr", "recall_by_attack", "fit_ms", "score_us/row"]

    def fmt(v):
        return f"{v:.3f}" if isinstance(v, float) else str(v)

    head = "| " + " | ".join(cols) + " |\n"
    sep = "| " + " | ".join("---" for _ in cols) + " |\n"
    body = "".join("| " + " | ".join(fmt(r[c]) for c in cols) + " |\n" for r in rows)
    return head + sep + body


def _real_dataset_rows() -> list[dict]:
    """Evaluate on CIC-Bell-DNS-EXF-2021 if it's been placed on disk; else skip."""
    default_dir = Path(__file__).resolve().parent.parent / "data" / "real" / "cic_bell"
    real_dir = Path(os.getenv("CIC_BELL_DIR", default_dir))
    if not real_dir.exists() or not any(real_dir.iterdir()):
        print(f"[real dataset] none found at {real_dir} — synthetic-only run.")
        print("  To include it: download CIC-Bell-DNS-EXF-2021 and arrange as")
        print(f"  {real_dir}/benign/*.pcap and {real_dir}/attack/*.pcap")
        return []
    try:
        from .datasets.cic_bell import load_cic_bell
    except ImportError as exc:
        print(f"[real dataset] scapy not installed ({exc}); run with --extra capture.")
        return []
    records = load_cic_bell(real_dir)
    if not records:
        print(f"[real dataset] {real_dir} had no parsable DNS pcaps.")
        return []
    print(f"[real dataset] loaded {len(records)} feature rows from CIC-Bell.")
    return evaluate_protocol("dns", records, dataset="cic_bell")


def main() -> None:
    corpus = build_labeled_records()
    all_rows: list[dict] = []
    for proto, records in corpus.items():
        all_rows.extend(evaluate_protocol(proto, records))
    all_rows.extend(_real_dataset_rows())

    table = _markdown(all_rows)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "results.md").write_text(
        "# Detector backend comparison (synthetic graded scenarios)\n\n" + table,
        encoding="utf-8",
    )
    pd.DataFrame(all_rows).to_csv(REPORT_DIR / "results.csv", index=False)

    print("\n=== Detector backend comparison ===\n")
    print(table)
    print(f"written: {REPORT_DIR/'results.md'}  and  results.csv")


if __name__ == "__main__":
    main()
