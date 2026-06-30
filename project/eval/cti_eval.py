"""CTI mapping evaluation (ARCHITECTURE.md §6, CTI metrics).

Measures whether the live enrichment maps a detected anomaly to the *right* MITRE
technique. Scores labeled attack windows with the **char-embedding AE** (the live
backend), runs its attribution through the enricher, and scores the candidate
techniques against the per-class primary technique. Offline (no LLM) — this
isolates retrieval/mapping quality from generation quality.

    uv run --extra detect python -m eval.cti_eval

Requires the trained model (models/dns_charae.pt); skips with a hint if absent.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from defender.enrich import MitreEnricher
from defender.features.dns import DNS_FEATURES

from . import scenarios

REPORT_DIR = Path(__file__).resolve().parent / "report"
CHARAE_PATH = Path("models/dns_charae.pt")

# Primary MITRE technique each attack class should map to (the discriminator the
# behavioral-aware attribution is designed to surface).
GROUND_TRUTH = {
    "dns_tunnel": "T1572",       # Protocol Tunneling — subdomain fan-out
    "dns_exfil": "T1048.003",    # Exfiltration over DNS — long data labels
    "dns_c2": "T1071.004",       # App Layer Protocol: DNS — TXT beaconing
}


def _frame(records) -> pd.DataFrame:
    """Per-window numeric features + the qnames column the char-AE scores."""
    rows = [{c: r.features.get(c, 0.0) for c in DNS_FEATURES} for r in records]
    frame = pd.DataFrame(rows, columns=list(DNS_FEATURES))
    frame["qnames"] = [r.meta.get("qnames") or r.meta.get("sample_qnames") or []
                       for r in records]
    return frame


def _attack_records() -> list:
    return (
        scenarios.tunnel_dns(40, "loud", seed=1) + scenarios.tunnel_dns(20, "slow", seed=2)
        + scenarios.exfil_dns(40, "loud", seed=3) + scenarios.exfil_dns(20, "slow", seed=4)
        + scenarios.c2_dns(40, "loud", seed=5) + scenarios.c2_dns(20, "slow", seed=6)
    )


def evaluate(top_k: int = 3) -> list[dict]:
    from defender.detect.char_ae import CharAEDetector

    det = CharAEDetector()
    det.load(str(CHARAE_PATH))
    enricher = MitreEnricher()

    records = _attack_records()
    results = det.score(_frame(records))
    per_class: dict[str, list[bool]] = {}
    per_class_k: dict[str, list[bool]] = {}
    for rec, res in zip(records, results):
        if not res.is_anomaly:          # CTI only runs on detected windows
            continue
        cls = rec.meta["label"]
        cands = enricher.candidate_techniques("dns", res.feature_attributions)
        primary = GROUND_TRUTH[cls]
        per_class.setdefault(cls, []).append(bool(cands) and cands[0] == primary)
        per_class_k.setdefault(cls, []).append(primary in cands[:top_k])

    rows: list[dict] = []
    for cls in GROUND_TRUTH:
        hits = per_class.get(cls, [])
        n = len(hits)
        rows.append({
            "attack_class": cls,
            "primary_technique": GROUND_TRUTH[cls],
            "n_detected": n,
            "top1_acc": (sum(hits) / n) if n else 0.0,
            f"top{top_k}_hit_rate": (sum(per_class_k[cls]) / n) if n else 0.0,
        })
    return rows


def _markdown(rows: list[dict]) -> str:
    cols = list(rows[0])

    def fmt(v):
        return f"{v:.3f}" if isinstance(v, float) else str(v)

    head = "| " + " | ".join(cols) + " |\n| " + " | ".join("---" for _ in cols) + " |\n"
    return head + "".join("| " + " | ".join(fmt(r[c]) for c in cols) + " |\n" for r in rows)


def main() -> None:
    if not CHARAE_PATH.exists():
        print(f"[cti_eval] {CHARAE_PATH} missing -> skipped "
              "(train with `python -m eval.charae`).")
        return
    rows = evaluate()
    table = _markdown(rows)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "cti_results.md").write_text(
        "# CTI MITRE-mapping accuracy (char-embedding AE, synthetic attacks)\n\n"
        "Each DNS attack class maps to a distinct primary technique via the "
        "behavioral-aware attribution. `top1_acc` = fraction of detected windows whose "
        "top candidate is the primary technique.\n\n" + table,
        encoding="utf-8")
    print("\n=== CTI MITRE-mapping accuracy ===\n")
    print(table)
    print(f"written: {REPORT_DIR / 'cti_results.md'}")


if __name__ == "__main__":
    main()
