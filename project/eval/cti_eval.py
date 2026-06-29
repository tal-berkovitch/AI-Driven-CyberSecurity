"""CTI mapping evaluation (ARCHITECTURE.md §6, CTI metrics).

Measures whether the enrichment maps a scored anomaly to the *right* MITRE
technique: train the AE on benign, score labeled attack windows, run the top
attributions through the enricher, and score the candidate techniques against
ground truth. Offline (no LLM) — this isolates retrieval/mapping quality from
generation quality.

    uv run --extra detect python -m eval.cti_eval
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from defender.detect import make_detector
from defender.enrich import MitreEnricher
from defender.features.dns import DNS_FEATURES

from . import scenarios

SCHEMAS = {"dns": DNS_FEATURES}
REPORT_DIR = Path(__file__).resolve().parent / "report"

# Acceptable techniques per attack class (ARCHITECTURE.md §5).
GROUND_TRUTH = {
    "dns_tunnel": {"T1071.004", "T1572", "T1048.003"},
}


def _frame(records, schema) -> pd.DataFrame:
    return pd.DataFrame([{c: r.features.get(c, 0.0) for c in schema} for r in records],
                        columns=list(schema))


def _trained(proto: str):
    benign = scenarios.benign_dns(160, seed=99)
    det = make_detector("local")
    det.fit(_frame(benign, SCHEMAS[proto]))
    return det


def evaluate(top_k: int = 3) -> list[dict]:
    enricher = MitreEnricher()
    attacks = {
        "dns": scenarios.tunnel_dns(35, "loud", seed=1) + scenarios.tunnel_dns(35, "slow", seed=2),
    }
    rows: list[dict] = []
    for proto, records in attacks.items():
        det = _trained(proto)
        per_class: dict[str, list[bool]] = {}
        per_class_k: dict[str, list[bool]] = {}
        frame = _frame(records, SCHEMAS[proto])
        results = det.score(frame)
        for rec, res in zip(records, results):
            cls = rec.meta["label"]
            cands = enricher.candidate_techniques(proto, res.feature_attributions)
            gt = GROUND_TRUTH[cls]
            per_class.setdefault(cls, []).append(bool(cands) and cands[0] in gt)
            per_class_k.setdefault(cls, []).append(bool(set(cands[:top_k]) & gt))
        for cls in per_class:
            n = len(per_class[cls])
            rows.append({
                "attack_class": cls,
                "n": n,
                "top1_acc": sum(per_class[cls]) / n,
                f"top{top_k}_hit_rate": sum(per_class_k[cls]) / n,
            })
    return rows


def _markdown(rows: list[dict]) -> str:
    cols = list(rows[0])
    fmt = lambda v: f"{v:.3f}" if isinstance(v, float) else str(v)  # noqa: E731
    head = "| " + " | ".join(cols) + " |\n| " + " | ".join("---" for _ in cols) + " |\n"
    return head + "".join("| " + " | ".join(fmt(r[c]) for c in cols) + " |\n" for r in rows)


def main() -> None:
    rows = evaluate()
    table = _markdown(rows)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "cti_results.md").write_text(
        "# CTI MITRE-mapping accuracy (offline, synthetic attacks)\n\n" + table,
        encoding="utf-8")
    print("\n=== CTI MITRE-mapping accuracy ===\n")
    print(table)
    print(f"written: {REPORT_DIR / 'cti_results.md'}")


if __name__ == "__main__":
    main()
