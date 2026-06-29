"""Train the live detector on benign data and persist it to models/.

    uv run --extra detect python -m eval.train               # from data/baseline/*.csv
    uv run --extra detect python -m eval.train --source synthetic   # reproducible fallback

The defender (DEFENDER_MODE=detect) loads models/dns_{charae,isolation_forest}.pt at
runtime. Train on *captured-live* benign for the deployed model (distribution match
with what it scores live); synthetic benign is a reproducible fallback for tests/demos.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from defender.detect import make_detector
from defender.features.dns import DNS_FEATURES

from . import scenarios

SCHEMAS = {"dns": DNS_FEATURES}
REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_DIR = REPO_ROOT / "data" / "baseline"
MODELS_DIR = REPO_ROOT / "models"


def _synthetic_frame(proto: str) -> pd.DataFrame:
    records = scenarios.benign_dns(160, seed=99)
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


# Numeric (window-aggregate) backend trained on the benign frame so the defender
# can run it (DETECTOR_BACKEND=isolation_forest) and the dashboard can compare it
# with the char-AE. `morpheus` is the lab-GPU backend (Phase 5) and is not trained
# here. `charae` (the char-embedding AE) is lexical — it trains on qname *strings*,
# so it is handled separately in train_charae() rather than on the numeric frame.
BACKENDS = ("isolation_forest",)


def train_charae(out_dir: Path, epochs: int) -> None:
    """Train the DNS char-embedding AE on benign qnames -> models/dns_charae.pt.

    Lexical backend: trains on the qname corpus (CIC-Bell cache), not the numeric
    baseline. Skips with a hint if the cache is absent (build it with
    ``python -m eval.datasets.qname_cache``).
    """
    from defender.detect.char_ae import CharAEDetector
    from eval.datasets.qname_cache import load_cache, synthetic_reverse_dns

    try:
        df = load_cache().drop_duplicates("qname")
    except FileNotFoundError:
        print("  [dns/charae] qname cache missing -> skipping "
              "(build it with `python -m eval.datasets.qname_cache`)")
        return
    # Mix in reverse-DNS (PTR) names so the model treats in-addr.arpa as normal
    # (CIC-Bell is forward-domain-only -> reverse lookups would false-positive).
    benign_names = df[df.label == "benign"]["qname"].tolist() + synthetic_reverse_dns()
    benign = pd.DataFrame({"qname": benign_names})
    out_dir.mkdir(parents=True, exist_ok=True)
    det = CharAEDetector(epochs=epochs)
    det.fit(benign)
    out = out_dir / "dns_charae.pt"
    det.save(str(out))
    print(f"  [dns/charae] trained on {len(benign)} benign qnames; "
          f"threshold={det.threshold:.5f} -> {out}")


def train(proto: str, source: str, out_dir: Path, epochs: int, backends) -> None:
    frame, used = load_frame(proto, source)
    out_dir.mkdir(parents=True, exist_ok=True)
    for backend in backends:
        kwargs = {"epochs": epochs} if backend == "morpheus" else {}
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
    ap.add_argument("--backends", default=",".join((*BACKENDS, "charae")),
                    help="comma-list of charae,isolation_forest,morpheus")
    ap.add_argument("--charae-epochs", type=int, default=25)
    args = ap.parse_args()
    backends = [b.strip() for b in args.backends.split(",") if b.strip()]
    numeric = [b for b in backends if b != "charae"]

    print(f"training {', '.join(backends)} (source={args.source}) -> {args.out}")
    train("dns", args.source, Path(args.out), args.epochs, numeric)
    if "charae" in backends:
        train_charae(Path(args.out), args.charae_epochs)
    print("done.")


if __name__ == "__main__":
    main()
