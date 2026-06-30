"""Train + evaluate the character-embedding autoencoder on the DNS qname corpus.

The model itself lives in the defender backend
(``containers/defender/detect/char_ae.py``) so training and serving share one
definition; this script is the offline trainer/benchmark that produces the
artifact the live defender loads (``models/dns_charae.pt``).

It trains on **benign qnames only** (the CIC-Bell cache), reports held-out
ROC-AUC / PR-AUC / recall@FPR against unseen attack qnames, and saves the
detector. Run:

    uv run --extra detect python -m eval.charae
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from defender.detect.char_ae import (
    CharAE,
    CharAEDetector,
    build_vocab,
    fpr_threshold,
    score_names,
    train_chars,
    window_threshold,
)

from eval import metrics
from eval.datasets.qname_cache import load_cache, synthetic_reverse_dns

SEED = 13
MODEL_PATH = Path("models/dns_charae.pt")


def recall_at_fpr(y: np.ndarray, s: np.ndarray, fpr: float = 0.01) -> float:
    benign = np.sort(s[y == 0])
    thr = benign[int((1 - fpr) * len(benign)) - 1]
    return float((s[y == 1] > thr).mean())


def main() -> None:
    df = load_cache().drop_duplicates("qname")               # unique names only (no leakage)
    rng = np.random.default_rng(SEED)
    # Augment benign with reverse-DNS (PTR) names absent from CIC-Bell's forward
    # domains, so the model treats the abundant in-addr.arpa lookups as normal.
    benign = df[df.label == "benign"]["qname"].tolist() + synthetic_reverse_dns()
    attack = df[df.label == "attack"]["qname"].tolist()
    rng.shuffle(benign)
    n_tr = int(0.7 * len(benign))
    n_val = int(0.15 * len(benign))
    tr, va, te_b = benign[:n_tr], benign[n_tr:n_tr + n_val], benign[n_tr + n_val:]
    print(f"unique qnames: benign={len(benign)} attack={len(attack)} | "
          f"train={len(tr)} val={len(va)} test_benign={len(te_b)}")

    vocab = build_vocab(tr)
    model = CharAE(len(vocab) + 2)
    print(f"vocab={len(vocab)}  params={sum(p.numel() for p in model.parameters())}")
    train_chars(model, tr, vocab, val=va)

    test_names = te_b + attack
    y = np.array([0] * len(te_b) + [1] * len(attack))
    s = score_names(model, test_names, vocab)
    print("\n=== Char-embedding AE (unsupervised, benign-trained) ===")
    print(f"  ROC-AUC          {metrics.roc_auc(y, s):.3f}")
    print(f"  PR-AUC           {metrics.pr_auc(y, s):.3f}")
    print(f"  recall@1%FPR     {recall_at_fpr(y, s, 0.01):.3f}")
    print(f"  recall@0.1%FPR   {recall_at_fpr(y, s, 0.001):.3f}")

    # Wrap in the live detector and persist the artifact the defender loads. The
    # live detector scores a window by its worst qname, so its operating point is
    # the window-aware threshold (a per-name FPR would explode under max-agg).
    benign_test_scores = s[y == 0]
    det = CharAEDetector()
    det.model = model
    det.vocab = vocab
    det.thresholds = {
        "window": window_threshold(benign_test_scores, det.cal_window, 0.01),
        "1pct": fpr_threshold(benign_test_scores, 0.01),
        "0.1pct": fpr_threshold(benign_test_scores, 0.001),
    }
    det.threshold = det.thresholds["window"]
    print(f"  thresholds: window={det.thresholds['window']:.3f} "
          f"p99={det.thresholds['1pct']:.3f} p99.9={det.thresholds['0.1pct']:.3f}")
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    det.save(str(MODEL_PATH))
    print(f"  saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
