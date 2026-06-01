"""Pure formatting for the SOC UI — no ChainLit, no network, fully unit-testable.

Every function takes plain dicts (as read off the file-queue: capture events and
``Alert.to_dict()`` payloads) and returns display strings. Keeping this separate
from ``app.py`` means the rendering logic is tested directly while the ChainLit
shell stays thin.
"""

from __future__ import annotations

from typing import Any


def _top_features(attrs: dict[str, float], k: int = 6) -> list[tuple[str, float]]:
    return sorted(attrs.items(), key=lambda kv: kv[1], reverse=True)[:k]


def format_alert(alert: dict[str, Any]) -> str:
    """A markdown alert card: who/score/driving features/MITRE techniques."""
    rec = alert.get("record", {})
    sc = alert.get("score", {})
    techs = alert.get("candidate_techniques", []) or []
    top = _top_features(sc.get("feature_attributions", {}))
    proto = str(rec.get("protocol", "?")).upper()

    lines = [
        f"🚨 **{proto} anomaly** — `{rec.get('src', '?')}` → `{rec.get('dst', '?')}`",
        f"- anomaly score: **{float(sc.get('anomaly_score', 0.0)):.4f}**",
        f"- MITRE: {', '.join(techs) if techs else '(none mapped)'}",
        "- top features:",
        *[f"    - `{name}` ({val:.3f})" for name, val in top],
    ]
    return "\n".join(lines)


def format_cti(alert: dict[str, Any]) -> str:
    """Render the generated CTI report carried on the `cti` topic."""
    rec = alert.get("record", {})
    report = alert.get("cti_report") or "_(no report)_"
    proto = str(rec.get("protocol", "?")).upper()
    return f"📄 **CTI report — {proto} / `{rec.get('src', '?')}`**\n\n{report}"


def format_capture_summary(events: list[dict[str, Any]]) -> str | None:
    """Compact one-liner summarising a batch of capture events (None if empty)."""
    if not events:
        return None
    by_proto: dict[str, int] = {}
    for e in events:
        by_proto[e.get("proto", "?")] = by_proto.get(e.get("proto", "?"), 0) + 1
    parts = ", ".join(f"{n} {p}" for p, n in sorted(by_proto.items()))
    return f"📡 captured {len(events)} events ({parts})"


def alert_context(alert: dict[str, Any]) -> str:
    """Compact grounded evidence string used to seed the analyst chat (LLM)."""
    rec = alert.get("record", {})
    sc = alert.get("score", {})
    techs = alert.get("candidate_techniques", []) or []
    top = _top_features(sc.get("feature_attributions", {}))
    lines = [
        f"protocol={rec.get('protocol', '?')} src={rec.get('src', '?')} "
        f"dst={rec.get('dst', '?')} anomaly_score={float(sc.get('anomaly_score', 0.0)):.4f}",
        "top features (reconstruction error): "
        + ", ".join(f"{n}={v:.3f}" for n, v in top),
        "candidate MITRE techniques: " + (", ".join(techs) if techs else "none"),
    ]
    meta = rec.get("meta", {})
    bits = {k: meta[k] for k in ("sample_qnames", "qtype_mix", "pdu_mix",
                                 "communities", "sample_oids") if k in meta}
    if bits:
        lines.append("raw context: " + "; ".join(f"{k}={v}" for k, v in bits.items()))
    return "\n".join(lines)
