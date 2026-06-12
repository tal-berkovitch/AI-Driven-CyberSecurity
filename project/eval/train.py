"""Train the live detector on benign data and persist it to models/.

    uv run --extra detect python -m eval.train               # from data/baseline/*.csv
    uv run --extra detect python -m eval.train --source synthetic   # reproducible fallback

The defender (DEFENDER_MODE=detect) loads models/{proto}_local.pt at runtime. Train
on *captured-live* benign for the deployed model (distribution match with what it
scores live); synthetic benign is a reproducible fallback for tests/demos.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from defender.detect import make_detector
from defender.features.dns import DNS_FEATURES
from defender.features.snmp import SNMP_FEATURES

from . import scenarios

SCHEMAS = {"dns": DNS_FEATURES, "snmp": SNMP_FEATURES}
REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_DIR = REPO_ROOT / "data" / "baseline"
MODELS_DIR = REPO_ROOT / "models"


def _synthetic_frame(proto: str) -> pd.DataFrame:
    gen = scenarios.benign_dns if proto == "dns" else scenarios.benign_snmp
    records = gen(160, seed=99)
    schema = SCHEMAS[proto]
    return pd.DataFrame([{c: r.features.get(c, 0.0) for c in schema} for r in records],
                        columns=list(schema))


def _baseline_frame(proto: str) -> pd.DataFrame | None:
    path = BASELINE_DIR / f"{proto}_baseline.csv"
    if not path.exists() or path.stat().st_size == 0:
        return None
    df = pd.read_csv(path)
    cols = [c for c in SCHEMAS[proto] if c in df.columns]
    return df[cols].reindex(columns=list(SCHEMAS[proto]), fill_value=0.0)


def load_frame(proto: str, source: str) -> tuple[pd.DataFrame, str]:
    if source == "synthetic":
        return _synthetic_frame(proto), "synthetic"
    frame = _baseline_frame(proto)
    if frame is None or len(frame) < 10:
        print(f"  [{proto}] baseline missing/too small -> falling back to synthetic benign")
        return _synthetic_frame(proto), "synthetic(fallback)"
    return frame, "baseline"


# Both pluggable backends are trained on the same benign frame so the defender can
# run either (DETECTOR_BACKEND) and the dashboard can compare them. `morpheus` is the
# lab-GPU backend (Phase 5) and is not trained here.
BACKENDS = ("local", "isolation_forest")


def train(proto: str, source: str, out_dir: Path, epochs: int, backends) -> None:
    frame, used = load_frame(proto, source)
    out_dir.mkdir(parents=True, exist_ok=True)
    for backend in backends:
        kwargs = {"epochs": epochs} if backend in ("local", "morpheus") else {}
        det = make_detector(backend, **kwargs)
        det.fit(frame)
        out = out_dir / f"{proto}_{backend}.pt"
        det.save(str(out))
        detail = (f"n_estimators={det.model.n_estimators}" if backend == "isolation_forest"
                  else f"threshold={det.threshold:.5f}")
        print(f"  [{proto}/{backend}] trained on {len(frame)} rows ({used}); {detail} -> {out}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the live detectors on benign data.")
    ap.add_argument("--source", choices=["baseline", "synthetic"], default="baseline")
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--out", default=str(MODELS_DIR))
    # Default trains the home backends; on the lab GPU box add: --backends morpheus
    ap.add_argument("--backends", default=",".join(BACKENDS),
                    help="comma-list of local,isolation_forest,morpheus")
    args = ap.parse_args()
    backends = [b.strip() for b in args.backends.split(",") if b.strip()]

    print(f"training {', '.join(backends)} (source={args.source}) -> {args.out}")
    for proto in ("dns", "snmp"):
        train(proto, args.source, Path(args.out), args.epochs, backends)
    print("done.")


if __name__ == "__main__":
    main()
