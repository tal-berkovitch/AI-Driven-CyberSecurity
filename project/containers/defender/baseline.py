"""Persist FeatureRecords as the Phase 1 deliverable: the benign baseline CSV.

One CSV per protocol with a stable, ordered header (``ts,src,dst`` + the §4
feature columns). This is the dataset Phase 2 trains the autoencoder on and
benchmarks every detector backend against.
"""

from __future__ import annotations

import csv
from pathlib import Path

from shared.schema import FeatureRecord

from .features.dns import DNS_FEATURES
from .features.snmp import SNMP_FEATURES

_BASE_COLS = ("ts", "src", "dst")
_SCHEMAS = {"dns": DNS_FEATURES, "snmp": SNMP_FEATURES}


class BaselineWriter:
    def __init__(self, out_dir: str | Path) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.counts: dict[str, int] = {"dns": 0, "snmp": 0}

    def _path(self, proto: str) -> Path:
        return self.out_dir / f"{proto}_baseline.csv"

    def write(self, record: FeatureRecord) -> None:
        proto = record.protocol
        schema = _SCHEMAS.get(proto)
        if schema is None:
            return
        header = list(_BASE_COLS) + list(schema)
        path = self._path(proto)
        new_file = not path.exists() or path.stat().st_size == 0
        row = {"ts": record.ts, "src": record.src, "dst": record.dst}
        # Pull features in schema order; missing -> 0.0 keeps the matrix dense.
        for col in schema:
            row[col] = record.features.get(col, 0.0)
        with open(path, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=header)
            if new_file:
                writer.writeheader()
            writer.writerow(row)
        self.counts[proto] = self.counts.get(proto, 0) + 1

    def write_many(self, records: list[FeatureRecord]) -> None:
        for r in records:
            self.write(r)
