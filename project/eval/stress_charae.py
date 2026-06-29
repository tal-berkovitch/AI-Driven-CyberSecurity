"""Robustness stress-test for the char-embedding AE.

CIC-Bell exfil is lexically overt, so the AE scores ~1.0 — but that flatters it.
This crafts progressively *stealthier* synthetic exfil (high-entropy base32 ->
hex -> chunked -> short subdomains -> benign-word-encoded) and measures recall at
the model's fixed 1%-FPR threshold, to find the breaking point and report an
honest recall-vs-stealthiness envelope rather than a single rosy number.

Run (after `python -m eval.charae` has saved models/charae.pt):
    uv run --extra detect python -m eval.stress_charae
"""

from __future__ import annotations

import base64
import math
from collections import Counter

import numpy as np

from eval.charae import load_model, score
from eval.datasets.qname_cache import load_cache

RNG = np.random.default_rng(7)
N = 3000


def _entropy(s: str) -> float:
    s = s.replace(".", "")
    if not s:
        return 0.0
    c = Counter(s); n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def _benign_assets(df):
    """Real benign registered domains (as exfil parents) + a benign wordlist."""
    names = df[df.label == "benign"]["qname"].dropna().tolist()
    domains, words = [], Counter()
    for q in names:
        labels = [x for x in q.split(".") if x]
        if 2 <= len(labels) <= 3 and all(x.replace("-", "").isalnum() for x in labels):
            domains.append(".".join(labels[-2:]))
        for x in labels:
            if x.isalpha() and 3 <= len(x) <= 10:
                words[x] += 1
    domains = list(dict.fromkeys(domains)) or ["example.com"]
    wordlist = [w for w, _ in words.most_common(512)] or ["host", "mail", "data"]
    return domains, wordlist


def _b32(nbytes: int) -> str:
    return base64.b32encode(RNG.integers(0, 256, nbytes, dtype=np.uint8).tobytes()).decode().lower().rstrip("=")


def _hex(nbytes: int) -> str:
    return RNG.integers(0, 256, nbytes, dtype=np.uint8).tobytes().hex()


def make_families(domains, words):
    dom = lambda: domains[RNG.integers(len(domains))]
    w = lambda k: "".join(words[i] for i in RNG.integers(0, len(words), k))
    fams = {
        # overt -> stealthy
        "overt_base32_40": lambda: f"{_b32(25)[:40]}.{dom()}",
        "hex_40":          lambda: f"{_hex(20)[:40]}.{dom()}",
        "b32_chunked_8":   lambda: ".".join(_b32(25)[i:i + 8] for i in range(0, 32, 8)) + f".{dom()}",
        "short_b32_8":     lambda: f"{_b32(5)[:8]}.{dom()}",
        "word4_label":     lambda: f"{w(4)}.{dom()}",        # 4 benign words mashed -> one label
        "word2_label":     lambda: f"{w(2)}.{dom()}",        # 2 benign words -> short, pronounceable
    }
    return {k: [g() for _ in range(N)] for k, g in fams.items()}


def main():
    df = load_cache().drop_duplicates("qname")
    model, vocab, thr1, thr01 = load_model()
    domains, words = _benign_assets(df)
    print(f"benign parent-domains={len(domains)}  wordlist={len(words)}  thr@1%FPR={thr1:.3f}\n")

    print(f"{'family':18s} {'recall@1%FPR':>12s} {'med_score':>10s} {'mean_len':>9s} {'mean_H':>7s}")
    for fam, names in make_families(domains, words).items():
        s = score(model, names, vocab)
        recall = float((s > thr1).mean())
        mlen = float(np.mean([len(n) for n in names]))
        mH = float(np.mean([_entropy(n.split(".")[0]) for n in names]))
        print(f"{fam:18s} {recall:12.3f} {np.median(s):10.3f} {mlen:9.1f} {mH:7.2f}")


if __name__ == "__main__":
    main()
