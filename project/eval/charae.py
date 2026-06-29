"""Character-embedding autoencoder for DNS qnames (the lecturer's "autoencoder
with embeddings").

A sequence autoencoder: each character is embedded, a GRU encodes the qname into
a small latent vector, and a GRU decoder reconstructs the character sequence. It
is trained on **benign qnames only**; the per-character reconstruction loss is the
anomaly score. Benign names (dictionary-like, low entropy) reconstruct well; exfil
names (long, high-entropy base32/base64) reconstruct badly -> high score. This is
unsupervised, so it flags tunneling tools it never trained on (zero-day), unlike a
supervised classifier.

Run:  uv run --extra detect python -m eval.charae
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence

from eval import metrics
from eval.datasets.qname_cache import load_cache

PAD, UNK = 0, 1
MAX_LEN = 48
EMBED = 32
HIDDEN = 64
LATENT = 16
SEED = 13
MODEL_PATH = Path("models/charae.pt")


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
        # teacher forcing with the (shifted) embedded input as decoder input
        dec_in = torch.zeros_like(e)
        dec_in[:, 1:, :] = e[:, :-1, :]
        out, _ = self.dec(dec_in, h0)
        return self.out(out)                                  # (B, L, V)


def _tensors(names, vocab):
    ids = np.array([encode(n, vocab) for n in names], dtype=np.int64)
    x = torch.tensor(ids)
    lengths = torch.tensor([max(min(len(n), MAX_LEN), 1) for n in names])
    return x, lengths


def score(model, names, vocab, bs=2048) -> np.ndarray:
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


def train(model, names, vocab, epochs=25, bs=512, lr=1e-3, val=None):
    torch.manual_seed(SEED)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=PAD)
    x_all, len_all = _tensors(names, vocab)
    n = len(names)
    best, best_state, patience = float("inf"), None, 0
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(n)
        tot = 0.0
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            logits = model(x_all[idx], len_all[idx])
            loss = loss_fn(logits.transpose(1, 2), x_all[idx])
            loss.backward()
            opt.step()
            tot += loss.item() * len(idx)
        tr = tot / n
        vl = float(score(model, val, vocab).mean()) if val is not None else tr
        flag = ""
        if vl < best - 1e-4:
            best, best_state, patience = vl, {k: v.clone() for k, v in model.state_dict().items()}, 0
            flag = " *"
        else:
            patience += 1
        print(f"  epoch {ep:2d}  train_ce={tr:.4f}  val_ce={vl:.4f}{flag}")
        if patience >= 4:
            print("  early stop")
            break
    if best_state:
        model.load_state_dict(best_state)
    return model


def recall_at_fpr(y, s, fpr=0.01) -> float:
    benign = np.sort(s[y == 0])
    thr = benign[int((1 - fpr) * len(benign)) - 1]
    return float((s[y == 1] > thr).mean())


def fpr_threshold(benign_scores: np.ndarray, fpr: float) -> float:
    b = np.sort(benign_scores)
    return float(b[int((1 - fpr) * len(b)) - 1])


def save_model(model, vocab, benign_test_scores, path: Path = MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "vocab": vocab,
        "thr_1pct": fpr_threshold(benign_test_scores, 0.01),
        "thr_01pct": fpr_threshold(benign_test_scores, 0.001),
    }, path)


def load_model(path: Path = MODEL_PATH):
    blob = torch.load(path, weights_only=False)
    model = CharAE(len(blob["vocab"]) + 2)
    model.load_state_dict(blob["state_dict"])
    model.eval()
    return model, blob["vocab"], blob["thr_1pct"], blob["thr_01pct"]


def main():
    df = load_cache()
    df = df.drop_duplicates("qname")                          # unique names only (no leakage)
    rng = np.random.default_rng(SEED)
    benign = df[df.label == "benign"]["qname"].tolist()
    attack = df[df.label == "attack"]["qname"].tolist()
    rng.shuffle(benign)
    n_tr = int(0.7 * len(benign)); n_val = int(0.15 * len(benign))
    tr, va, te_b = benign[:n_tr], benign[n_tr:n_tr + n_val], benign[n_tr + n_val:]
    print(f"unique qnames: benign={len(benign)} attack={len(attack)} | "
          f"train={len(tr)} val={len(va)} test_benign={len(te_b)}")

    vocab = build_vocab(tr)
    model = CharAE(len(vocab) + 2)
    print(f"vocab={len(vocab)}  params={sum(p.numel() for p in model.parameters())}")
    train(model, tr, vocab, val=va)

    test_names = te_b + attack
    y = np.array([0] * len(te_b) + [1] * len(attack))
    s = score(model, test_names, vocab)
    print("\n=== Char-embedding AE (unsupervised, benign-trained) ===")
    print(f"  ROC-AUC          {metrics.roc_auc(y, s):.3f}")
    print(f"  PR-AUC           {metrics.pr_auc(y, s):.3f}")
    print(f"  recall@1%FPR     {recall_at_fpr(y, s, 0.01):.3f}")
    print(f"  recall@0.1%FPR   {recall_at_fpr(y, s, 0.001):.3f}")

    save_model(model, vocab, s[y == 0])
    print(f"  saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
