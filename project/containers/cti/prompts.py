"""Grounded CTI prompt + an offline template fallback.

Both render from the SAME evidence (anomaly score, top per-feature attributions,
retrieved MITRE technique cards) so the LLM is constrained to provided facts —
"RAG, not free generation" (ARCHITECTURE.md §5).
"""

from __future__ import annotations

from typing import Any

from shared.schema import Alert

SYSTEM = (
    "You are a senior SOC analyst writing concise, factual cyber threat intelligence. "
    "Use ONLY the evidence provided below — do not invent indicators, IPs, or numbers. "
    "Map the activity to the supplied MITRE ATT&CK techniques by their IDs. "
    "Write for an incident responder. Output these sections: "
    "Summary (1-2 sentences), Evidence (bullets citing the feature values), "
    "MITRE techniques (IDs + names), Severity (low/medium/high with one-line justification), "
    "Recommended actions (2-4 bullets)."
)


def _top_features(alert: Alert, k: int = 6) -> list[tuple[str, float]]:
    attrs = alert.score.feature_attributions
    return sorted(attrs.items(), key=lambda kv: kv[1], reverse=True)[:k]


def build_user_prompt(alert: Alert, cards: list[dict[str, Any]]) -> str:
    rec, sc = alert.record, alert.score
    lines = [
        "## Anomaly",
        f"- protocol: {rec.protocol}",
        f"- source: {rec.src} -> dest: {rec.dst}",
        f"- anomaly_score: {sc.anomaly_score:.4f} (flagged anomalous)",
        "",
        "## Top contributing features (per-feature reconstruction error)",
    ]
    lines += [f"- {name}: {val:.4f}" for name, val in _top_features(alert)]

    meta_bits = {k: rec.meta[k] for k in ("sample_qnames", "qtype_mix", "pdu_mix",
                                          "communities", "sample_oids") if k in rec.meta}
    if meta_bits:
        lines += ["", "## Raw context", *[f"- {k}: {v}" for k, v in meta_bits.items()]]

    lines += ["", "## Candidate MITRE techniques (retrieved)"]
    if cards:
        for c in cards:
            lines.append(f"- {c['id']} {c['name']} ({c.get('tactic', '?')}): {c['description']}")
    else:
        lines.append("- (none matched)")
    return "\n".join(lines)


def offline_report(alert: Alert, cards: list[dict[str, Any]]) -> str:
    """Deterministic grounded report used when no LLM is available."""
    rec, sc = alert.record, alert.score
    top = _top_features(alert, 5)
    tech = ", ".join(f"{c['id']} {c['name']}" for c in cards) or "none matched"
    drivers = ", ".join(f"{n} ({v:.3f})" for n, v in top)
    return (
        f"# CTI report (offline/template) — {rec.protocol.upper()} anomaly\n\n"
        f"**Summary.** Anomalous {rec.protocol} activity from {rec.src} "
        f"(score {sc.anomaly_score:.4f}). Reconstruction error is dominated by: {drivers}.\n\n"
        f"**MITRE techniques (retrieved):** {tech}.\n\n"
        f"**Severity.** medium — automated detection, not yet triaged.\n\n"
        f"**Recommended actions.** Review {rec.src} traffic to {rec.dst}; "
        f"validate against the listed techniques; set GROQ_API_KEY for a full narrative.\n"
    )
