"""Character-embedding autoencoder detector — the DNS *lexical* backend.

This is "the autoencoder, but with embeddings" (the model the lecturer pointed at).
Unlike the ``local`` autoencoder, which scores a *window* of aggregated numeric
features, this one scores the **qname strings themselves**: every character is
embedded, a GRU encodes the name into a small latent vector, and a GRU decoder
reconstructs the character sequence. Trained on **benign qnames only**, the
per-character reconstruction loss is the anomaly score — benign names
(dictionary-like, low entropy) reconstruct well; exfil names (long, high-entropy
base32/base64) reconstruct badly. It is unsupervised, so it flags tunnelers it
never trained on (zero-day), and on real CIC-Bell DNS exfil it separates near
perfectly (ROC-AUC 1.000) where the window-aggregate backends top out ~0.9.

It plugs into the same ``Detector`` seam as the other backends: ``score`` consumes
the per-window ``FeatureRecord`` frame but reads the raw qnames carried alongside
it (the ``qnames`` column main.py attaches from ``meta``), scores each, and
reports the window's **worst** qname as the anomaly — with lexical attribution
(``query_name_length`` / ``subdomain_entropy`` / ``encoded_labels``) so the same
MITRE retrieval + LLM-CTI path lights up unchanged.

The model definition lives here (not in ``eval/``) so training and serving share
one source of truth; ``eval.charae`` imports it to train ``models/dns_charae.pt``.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence

from shared.schema import ScoreResult

from ..features.util import char_entropy

PAD, UNK = 0, 1
MAX_LEN = 48
EMBED = 32
HIDDEN = 64
LATENT = 16
SEED = 13
# Column main.py attaches to the score frame carrying the window's raw qnames.
QNAME_COL = "qnames"


# --- model + tokeniser (shared by training in eval.charae and serving here) ---

def build_vocab(names: list[str]) -> dict[str, int]:
    chars = sorted({c for n in names for c in n})
    return {c: i + 2 for i, c in enumerate(chars)}  # 0=PAD, 1=UNK


def encode(name: str, vocab: dict[str, int]) -> list[int]:
    ids = [vocab.get(c, UNK) for c in name[:MAX_LEN]]
    return ids + [PAD] * (MAX_LEN - len(ids))


class CharAE(nn.Module):
    def __init__(self, vocab_size: int, dropout: float = 0.1) -> None:
        super().__init__()
        self.emb = nn.Embedding(vocab_size, EMBED, padding_idx=PAD)
        self.enc = nn.GRU(EMBED, HIDDEN, batch_first=True)
        self.to_latent = nn.Linear(HIDDEN, LATENT)
        self.from_latent = nn.Linear(LATENT, HIDDEN)
        self.dec = nn.GRU(EMBED, HIDDEN, batch_first=True)
        self.out = nn.Linear(HIDDEN, vocab_size)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        e = self.emb(x)
        packed = pack_padded_sequence(e, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, h = self.enc(packed)
        z = self.to_latent(self.drop(h[-1]))                  # (B, LATENT)
        h0 = self.from_latent(z).unsqueeze(0)                 # (1, B, HIDDEN)
        dec_in = torch.zeros_like(e)                          # teacher forcing (shifted input)
        dec_in[:, 1:, :] = e[:, :-1, :]
        out, _ = self.dec(dec_in, h0)
        return self.out(out)                                  # (B, L, V)


def _tensors(names: list[str], vocab: dict[str, int]) -> tuple[torch.Tensor, torch.Tensor]:
    ids = np.array([encode(n, vocab) for n in names], dtype=np.int64)
    x = torch.tensor(ids)
    lengths = torch.tensor([max(min(len(n), MAX_LEN), 1) for n in names])
    return x, lengths


def score_names(model: CharAE, names: list[str], vocab: dict[str, int], bs: int = 2048) -> np.ndarray:
    """Per-name mean per-character reconstruction loss (the anomaly score)."""
    if not names:
        return np.zeros(0, dtype=np.float64)
    model.eval()
    loss_fn = nn.CrossEntropyLoss(ignore_index=PAD, reduction="none")
    out = []
    with torch.no_grad():
        for i in range(0, len(names), bs):
            x, lengths = _tensors(names[i:i + bs], vocab)
            logits = model(x, lengths)
            per = loss_fn(logits.transpose(1, 2), x)          # (B, L)
            mask = (x != PAD).float()
            out.append((per.sum(1) / mask.sum(1).clamp(min=1)).numpy())
    return np.concatenate(out)


def train_chars(model: CharAE, names: list[str], vocab: dict[str, int], *, epochs: int = 25,
                bs: int = 512, lr: float = 1e-3, val: list[str] | None = None,
                patience: int = 4, verbose: bool = True) -> CharAE:
    """Minibatch SGD + early-stopping on benign-only qnames (over/underfit guarded)."""
    torch.manual_seed(SEED)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=PAD)
    x_all, len_all = _tensors(names, vocab)
    n = len(names)
    best, best_state, waited = float("inf"), None, 0
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(n)
        tot = 0.0
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss = loss_fn(model(x_all[idx], len_all[idx]).transpose(1, 2), x_all[idx])
            loss.backward()
            opt.step()
            tot += loss.item() * len(idx)
        tr = tot / n
        vl = float(score_names(model, val, vocab).mean()) if val else tr
        flag = ""
        if vl < best - 1e-4:
            best, best_state, waited = vl, {k: v.clone() for k, v in model.state_dict().items()}, 0
            flag = " *"
        else:
            waited += 1
        if verbose:
            print(f"  epoch {ep:2d}  train_ce={tr:.4f}  val_ce={vl:.4f}{flag}")
        if waited >= patience:
            if verbose:
                print("  early stop")
            break
    if best_state:
        model.load_state_dict(best_state)
    return model


def fpr_threshold(benign_scores: np.ndarray, fpr: float) -> float:
    """Per-name score cutoff admitting ``fpr`` of benign names as alerts."""
    b = np.sort(benign_scores)
    return float(b[int((1 - fpr) * len(b)) - 1])


def window_threshold(benign_scores: np.ndarray, window_size: int = 64, fpr: float = 0.01,
                     n_sim: int = 8000, seed: int = SEED) -> float:
    """Window-level cutoff for the **max-over-qnames** score.

    The detector flags a window by its worst (max) qname score, so a per-*name*
    FPR explodes once aggregated over a window of many benign names
    (1%/name over 64 names ≈ 48% per window). We instead bootstrap synthetic
    benign windows of ``window_size`` names, take each window's max, and set the
    threshold at the ``1-fpr`` quantile of that window-max distribution — the
    honest per-*window* operating point. ``window_size`` is a conservative middle
    of the live window sizes; larger live windows drift slightly above ``fpr``.
    """
    if len(benign_scores) == 0:
        return float("inf")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(benign_scores), (n_sim, window_size))
    window_max = benign_scores[idx].max(axis=1)
    return float(np.quantile(window_max, 1.0 - fpr))


# --- attribution (so the MITRE/LLM path reads discriminating evidence) ---------

def _data_label(qname: str) -> str:
    """The longest label of a qname — where exfil packs its payload."""
    labels = [x for x in qname.rstrip(".").split(".") if x]
    return max(labels, key=len) if labels else ""


# Benign-ish reference scales: attribution is expressed as "x normal" prominence
# so the heterogeneous lexical + behavioral features compete fairly in the MITRE
# token-overlap retrieval (raw magnitudes would let qname length swamp everything).
_REF = {
    "query_name_length": 25.0,
    "subdomain_entropy": 3.0,
    "encoded_labels": 12.0,
    "txt_record_count": 2.0,
    "unique_subdomains_per_domain": 3.0,
}
_PROM_CAP = 8.0


def _prom(value: float, ref: float) -> float:
    return min(float(value) / ref, _PROM_CAP) if ref else 0.0


def _attribution(qname: str, recon_err: float, row) -> dict[str, float]:
    """Evidence for the worst qname + its window, as MITRE/LLM-readable prominence.

    The detection is purely lexical (per-character reconstruction error), but the
    *explanation* fuses the window's behavioral fingerprint so different DNS attack
    shapes map to different techniques: ``subdomain_entropy`` /
    ``unique_subdomains_per_domain`` → tunnelling (T1572), ``txt_record_count`` →
    DNS C2 (T1071.004), ``encoded_labels`` → exfiltration (T1048.003). Keys are
    chosen to overlap exactly one technique's KB indicators (see dns_techniques.json).
    """
    label = _data_label(qname)

    def feat(name: str) -> float:
        try:
            v = row[name] if row is not None and name in row else 0.0
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError, KeyError):
            return 0.0

    entropy = max(feat("max_subdomain_entropy"), char_entropy(label))
    attr = {
        "query_name_length": _prom(len(qname), _REF["query_name_length"]),
        "subdomain_entropy": _prom(entropy, _REF["subdomain_entropy"]),
        "encoded_labels": _prom(len(label), _REF["encoded_labels"]),
        "txt_record_count": _prom(feat("txt_query_count"), _REF["txt_record_count"]),
        "unique_subdomains_per_domain": _prom(
            feat("unique_subdomains_per_domain"), _REF["unique_subdomains_per_domain"]),
        # raw reconstruction error — the detection signal, kept as evidence (no MITRE
        # token overlap, so it never skews retrieval).
        "qname_reconstruction_error": float(recon_err),
    }
    # Drop inactive behavioral keys so the evidence stays clean per attack shape.
    return {k: v for k, v in attr.items()
            if v > 0 or k in ("query_name_length", "qname_reconstruction_error")}


# --- the Detector backend -----------------------------------------------------

class CharAEDetector:
    """Char-embedding AE wrapped as a pluggable :class:`Detector` backend."""

    def __init__(self, epochs: int = 25, batch_size: int = 512, lr: float = 1e-3,
                 dropout: float = 0.1, threshold_fpr: float = 0.01, cal_window: int = 64,
                 **kwargs) -> None:
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.dropout = dropout
        self.threshold_fpr = threshold_fpr
        self.cal_window = cal_window
        self.model: CharAE | None = None
        self.vocab: dict[str, int] = {}
        self.threshold: float = float("inf")
        self.thresholds: dict[str, float] = {}

    # ``baseline`` here is a frame of benign *qnames* (a ``qname`` column), not the
    # numeric window matrix the other backends use — eval.train feeds the right one.
    def fit(self, baseline: pd.DataFrame) -> None:
        if "qname" not in baseline.columns:
            raise ValueError("CharAEDetector.fit expects a 'qname' column of benign qnames")
        names = [str(q) for q in baseline["qname"].dropna().tolist() if str(q)]
        rng = np.random.default_rng(SEED)
        rng.shuffle(names)
        cut = max(int(0.85 * len(names)), 1)
        tr, va = names[:cut], names[cut:] or names[:1]
        self.vocab = build_vocab(tr)
        self.model = CharAE(len(self.vocab) + 2, dropout=self.dropout)
        train_chars(self.model, tr, self.vocab, epochs=self.epochs, bs=self.batch_size,
                    lr=self.lr, val=va, verbose=False)
        benign_scores = score_names(self.model, va, self.vocab)
        self.thresholds = {
            "window": window_threshold(benign_scores, self.cal_window, self.threshold_fpr),
            "1pct": fpr_threshold(benign_scores, 0.01),
            "0.1pct": fpr_threshold(benign_scores, 0.001),
        }
        # The live detector scores a window by its worst qname -> use the
        # window-aware threshold so per-name FPR doesn't explode under aggregation.
        self.threshold = self.thresholds["window"]

    def score(self, features: pd.DataFrame) -> list[ScoreResult]:
        if self.model is None:
            raise RuntimeError("CharAEDetector is not fitted/loaded")
        results: list[ScoreResult] = []
        col = features[QNAME_COL] if QNAME_COL in features.columns else None
        for i in range(len(features)):
            names = list(col.iloc[i]) if col is not None and col.iloc[i] is not None else []
            names = [str(n) for n in names if n]
            if not names:
                results.append(ScoreResult(anomaly_score=0.0, is_anomaly=False))
                continue
            s = score_names(self.model, names, self.vocab)
            worst = int(np.argmax(s))
            window_score = float(s[worst])
            row = features.iloc[i]                            # window behavioral features
            results.append(ScoreResult(
                anomaly_score=window_score,
                is_anomaly=bool(window_score > self.threshold),
                feature_attributions=_attribution(names[worst], window_score, row),
            ))
        return results

    def save(self, path: str) -> None:
        torch.save({
            "state_dict": self.model.state_dict() if self.model else None,
            "vocab": self.vocab,
            "threshold": self.threshold,
            "thresholds": self.thresholds,
            "dropout": self.dropout,
            "threshold_fpr": self.threshold_fpr,
        }, path)

    def load(self, path: str) -> None:
        blob = torch.load(path, weights_only=False)
        self.vocab = blob["vocab"]
        self.thresholds = blob.get("thresholds", {})
        self.dropout = blob.get("dropout", self.dropout)
        self.threshold_fpr = blob.get("threshold_fpr", self.threshold_fpr)
        self.threshold = float(blob["threshold"])
        self.model = CharAE(len(self.vocab) + 2, dropout=self.dropout)
        if blob["state_dict"] is not None:
            self.model.load_state_dict(blob["state_dict"])
        self.model.eval()
