"""Per-query DNS EDA on CIC-Bell-DNS-EXF-2021 (benign vs exfil).

Step 1 of the embedding-AE effort: confirm the discriminative signal lives at the
*per-query* lexical level (it gets averaged away by the 10s-window aggregates the
current detector uses). Parses raw qnames straight from the PCAPs, builds classic
DNS-tunneling lexical features, and reports per-feature separability + correlation.
"""

from __future__ import annotations

import glob
import math
from collections import Counter

import numpy as np
import pandas as pd

from collector.sensor import parse_packet
from eval.metrics import roc_auc

VOWELS = set("aeiou")
B32 = set("abcdefghijklmnopqrstuvwxyz234567")
MAX_PER_FILE = 20000


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def lexical(qname: str) -> dict:
    q = qname.lower().rstrip(".")
    bare = q.replace(".", "")
    labels = [x for x in q.split(".") if x]
    n = max(len(bare), 1)
    digits = sum(c.isdigit() for c in bare)
    vowels = sum(c in VOWELS for c in bare)
    alnum = sum(c.isalnum() for c in bare)
    return {
        "length": len(q),
        "n_labels": len(labels),
        "max_label_len": max((len(x) for x in labels), default=0),
        "entropy": _entropy(bare),
        "digit_ratio": digits / n,
        "vowel_ratio": vowels / n,
        "unique_char_ratio": len(set(bare)) / n,
        "b32_ratio": sum(c in B32 for c in bare) / n,
        "non_alnum_ratio": (len(bare) - alnum) / n,
    }


def _queries(paths, label):
    from scapy.utils import PcapReader
    rows = []
    for p in paths:
        seen = 0
        with PcapReader(p) as r:
            for pkt in r:
                ev = parse_packet(pkt)
                if ev is None or ev.proto != "dns" or ev.is_response or not ev.qname:
                    continue
                d = lexical(ev.qname)
                d["label"] = label
                rows.append(d)
                seen += 1
                if seen >= MAX_PER_FILE:
                    break
    return rows


def main():
    benign = sorted(glob.glob("data/real/cic_bell/benign/**/*.pcap", recursive=True))
    attack = sorted(glob.glob("data/real/cic_bell/attack/**/*.pcap", recursive=True))
    rows = _queries(benign, "benign") + _queries(attack, "attack")
    df = pd.DataFrame(rows)
    y = (df["label"] == "attack").astype(int).to_numpy()
    feats = [c for c in df.columns if c != "label"]

    print(f"queries: {len(df)}  benign={int((y==0).sum())}  attack={int((y==1).sum())}\n")
    print("=== distributions (median benign | median attack) + per-query ROC-AUC ===")
    scored = []
    for c in feats:
        col = df[c].to_numpy(float)
        mb = np.median(col[y == 0])
        ma = np.median(col[y == 1])
        auc = roc_auc(y, col)
        scored.append((abs(auc - 0.5), auc, c, mb, ma))
    for _, auc, c, mb, ma in sorted(scored, reverse=True):
        print(f"  {c:20s} auc={auc:.3f}   benign~{mb:7.2f}  attack~{ma:7.2f}")

    print("\n=== feature correlation (|r|>0.8 = redundant) ===")
    corr = df[feats].corr().abs()
    pairs = [(corr.iloc[i, j], feats[i], feats[j])
             for i in range(len(feats)) for j in range(i + 1, len(feats))]
    for r, a, b in sorted(pairs, reverse=True)[:8]:
        print(f"  {a:20s} ~ {b:20s} r={r:.2f}")

    # Supervised ceiling: how separable is per-query, really?
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        rf = RandomForestClassifier(n_estimators=120, max_depth=8, n_jobs=-1, random_state=0)
        auc = cross_val_score(rf, df[feats], y, cv=3, scoring="roc_auc").mean()
        print(f"\n=== supervised ceiling (RF 3-fold, lexical only) ROC-AUC = {auc:.3f} ===")
    except ImportError:
        pass


if __name__ == "__main__":
    main()
