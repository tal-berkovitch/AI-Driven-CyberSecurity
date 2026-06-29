"""One-time per-query qname cache for CIC-Bell, so model experiments don't
re-parse ~290 MB of PCAPs every run.

build_cache() parses every DNS *query* (not responses) out of the PCAPs and
writes a CSV of (qname, label, src). load_cache() reads it back. Split by `src`
file at train time to avoid near-duplicate-qname leakage across train/test.
"""

from __future__ import annotations

import glob
from pathlib import Path

import pandas as pd

from collector.sensor import parse_packet

DEFAULT_CACHE = Path("data/real/cic_bell_qnames.csv")
CAP_PER_FILE = 30000


def _queries(paths: list[str], label: str, cap: int) -> list[dict]:
    from scapy.utils import PcapReader
    rows = []
    for p in paths:
        name = Path(p).name
        seen = 0
        with PcapReader(p) as r:
            for pkt in r:
                ev = parse_packet(pkt)
                if ev is None or ev.proto != "dns" or ev.is_response or not ev.qname:
                    continue
                rows.append({"qname": ev.qname.lower().rstrip("."), "label": label, "src": name})
                seen += 1
                if seen >= cap:
                    break
    return rows


def build_cache(root: str = "data/real/cic_bell", out: Path = DEFAULT_CACHE,
                cap: int = CAP_PER_FILE) -> pd.DataFrame:
    benign = sorted(glob.glob(f"{root}/benign/**/*.pcap", recursive=True))
    attack = sorted(glob.glob(f"{root}/attack/**/*.pcap", recursive=True))
    rows = _queries(benign, "benign", cap) + _queries(attack, "attack", cap)
    df = pd.DataFrame(rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"cached {len(df)} queries -> {out}  "
          f"(benign={int((df.label=='benign').sum())} attack={int((df.label=='attack').sum())})")
    return df


def load_cache(path: Path = DEFAULT_CACHE) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str).dropna(subset=["qname"])
    return df


if __name__ == "__main__":
    build_cache()
