"""CIC-Bell-DNS-EXF-2021 adapter (PCAP replay).

CIC-Bell-DNS-EXF-2021 is a real DNS exfiltration/tunneling dataset from the
Canadian Institute for Cybersecurity. This adapter replays its PCAPs through the
**same** packet parser and feature extractors the live tap uses, so the rows it
produces are byte-for-byte schema-compatible with the synthetic/live data and
drop straight into ``run_eval``. (CIC-Bell is a real DNS exfiltration corpus —
the headline dataset for this DNS-focused project.)

Expected layout (you organise the downloaded captures into label subdirs):

    data/real/cic_bell/
        benign/      *.pcap | *.pcapng        -> label "benign"
        attack/      *.pcap | *.pcapng        -> label "dns_tunnel"
        # ("attack" | "exfil" | "malicious" | "tunnel" all map to dns_tunnel)

Override the root with the CIC_BELL_DIR env var. If the dataset ships as feature
CSVs instead of PCAPs, call :func:`inspect_csv` to dump the column names and we
add a column mapping (the PCAP path needs no such mapping).
"""

from __future__ import annotations

import logging
from pathlib import Path

from defender.features.windows import WindowAggregator
from shared.schema import FeatureRecord

LOG = logging.getLogger("dataset.cic_bell")
WINDOW_S = 10.0

_LABEL_ALIASES = {
    "benign": "benign", "normal": "benign", "legit": "benign",
    "attack": "dns_tunnel", "attacks": "dns_tunnel", "exfil": "dns_tunnel",
    "exfiltration": "dns_tunnel", "malicious": "dns_tunnel", "tunnel": "dns_tunnel",
    "dns_tunnel": "dns_tunnel",
}


def normalize_label(name: str) -> str:
    return _LABEL_ALIASES.get(name.strip().lower(), name.strip().lower())


def pcap_to_records(pcap_path: str | Path, label: str,
                    window_s: float = WINDOW_S) -> list[FeatureRecord]:
    """Stream a PCAP through the shared parser + extractors into labeled records."""
    from scapy.utils import PcapReader

    from collector.sensor import parse_packet

    agg = WindowAggregator(window_s=window_s)
    events = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            ev = parse_packet(pkt)
            if ev is not None:
                events.append(ev)

    out: list[FeatureRecord] = []
    for ev in sorted(events, key=lambda e: e.ts):
        out.extend(agg.add(ev))
    out.extend(agg.flush_all())
    for r in out:
        r.meta["label"] = label
    LOG.info("%s: %d packets -> %d feature rows (label=%s)",
             Path(pcap_path).name, len(events), len(out), label)
    return out


def load_cic_bell(root: str | Path, window_s: float = WINDOW_S) -> list[FeatureRecord]:
    """Load every PCAP under label subdirectories of ``root`` into labeled records."""
    root = Path(root)
    records: list[FeatureRecord] = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        label = normalize_label(sub.name)
        pcaps = sorted(sub.rglob("*.pcap")) + sorted(sub.rglob("*.pcapng"))
        if not pcaps:
            LOG.warning("no pcaps under %s", sub)
        for pcap in pcaps:
            records.extend(pcap_to_records(pcap, label, window_s))
    return records


def inspect_csv(csv_path: str | Path, n: int = 3) -> list[str]:
    """Print the header + a few rows of a CIC-Bell feature CSV (column-mapping aid)."""
    import pandas as pd

    df = pd.read_csv(csv_path, nrows=n)
    print(f"{csv_path}: {len(df.columns)} columns")
    print(list(df.columns))
    print(df.head(n).to_string())
    return list(df.columns)
