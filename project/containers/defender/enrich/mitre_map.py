"""Feature-attribution -> MITRE technique retrieval.

The KB ``indicators`` are written in our feature vocabulary (e.g.
"high subdomain_entropy", "high query_name_length"), so we can rank techniques by
how well an alert's *top-attributed* features overlap a technique's indicators,
weighted by attribution magnitude. Deterministic and grounded — the retrieval
step of "RAG, not free generation".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import shared
from shared.schema import Alert

# Words that carry no discriminating signal (qualifiers + generic aggregations).
_STOP = {
    "high", "low", "many", "elevated", "wide", "bulk", "sustained", "abnormal",
    "large", "spoofed", "very", "per", "window", "vs", "of", "the", "a", "and",
    "distribution", "rate", "count", "ratio", "size", "frac", "mean", "max",
    "num", "total", "avg", "sum", "config", "ranges",
}


def _tokens(text: str) -> set[str]:
    """Meaningful, singularised word tokens from a feature name or indicator."""
    out: set[str] = set()
    for raw in text.lower().replace("-", "_").replace(" ", "_").split("_"):
        tok = "".join(c for c in raw if c.isalnum())
        if len(tok) > 3 and tok.endswith("s"):
            tok = tok[:-1]  # crude singularise: oids->oid, subdomains->subdomain
        if len(tok) >= 2 and tok not in _STOP:
            out.add(tok)
    return out


def _default_kb_path() -> Path:
    # Resolve via the shared package so it works on host AND in-container.
    return Path(shared.__file__).resolve().parent / "mitre" / "dns_techniques.json"


class MitreEnricher:
    def __init__(self, kb_path: str | Path | None = None) -> None:
        path = Path(kb_path) if kb_path else _default_kb_path()
        self.techniques: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))[
            "techniques"
        ]
        # Precompute the union of indicator tokens per technique.
        self._tokens: dict[str, set[str]] = {}
        for t in self.techniques:
            toks: set[str] = set()
            for ind in t.get("indicators", []):
                toks |= _tokens(ind)
            self._tokens[t["id"]] = toks

    def card(self, technique_id: str) -> dict[str, Any] | None:
        """Return the full technique record (for grounding the CTI prompt)."""
        return next((t for t in self.techniques if t["id"] == technique_id), None)

    def candidate_techniques(self, protocol: str, feature_attributions: dict[str, float],
                             top_k_features: int = 6, max_techniques: int = 4) -> list[str]:
        """Rank protocol-matching techniques by attribution-weighted token overlap."""
        top = sorted(feature_attributions.items(), key=lambda kv: kv[1], reverse=True)
        top = [(f, v) for f, v in top[:top_k_features] if v > 0]

        scores: dict[str, float] = {}
        for t in self.techniques:
            if t.get("protocol") and t["protocol"] != protocol:
                continue
            ind_tokens = self._tokens[t["id"]]
            score = sum(v for fname, v in top if _tokens(fname) & ind_tokens)
            if score > 0:
                scores[t["id"]] = score
        ranked = sorted(scores, key=lambda tid: scores[tid], reverse=True)
        return ranked[:max_techniques]

    def enrich(self, alert: Alert, **kwargs) -> Alert:
        """Fill ``alert.candidate_techniques`` in place and return it."""
        alert.candidate_techniques = self.candidate_techniques(
            alert.record.protocol, alert.score.feature_attributions, **kwargs
        )
        return alert
