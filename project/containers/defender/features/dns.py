"""DNS window -> feature vector (ARCHITECTURE.md §4).

Given all DNS :class:`CaptureEvent`s for one source in one time window, produce a
flat ``{feature: float}`` mapping plus a ``meta`` dict of raw context (sample
qnames, qtype mix) that the Phase 3 LLM uses to write the CTI narrative.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from shared.capture import CaptureEvent

from .util import char_entropy, registered_domain, safe_div, subdomain_of

# Stable, ordered feature schema. Order is the CSV column order.
DNS_FEATURES = (
    "query_count",
    "query_rate",
    "response_count",
    "response_rate",
    "mean_qname_length",
    "max_qname_length",
    "mean_subdomain_entropy",
    "max_subdomain_entropy",
    "mean_label_count",
    "max_label_count",
    "txt_query_count",
    "null_query_count",
    "a_frac",
    "aaaa_frac",
    "txt_frac",
    "mx_frac",
    "ptr_frac",
    "other_frac",
    "unique_qnames",
    "unique_domains",
    "unique_subdomains_per_domain",
    "mean_response_size",
    "nxdomain_count",
    "nxdomain_rate",
)


def extract(events: list[CaptureEvent], window_s: float) -> tuple[dict[str, float], dict[str, Any]]:
    queries = [e for e in events if not e.is_response]
    responses = [e for e in events if e.is_response]

    qnames = [e.qname for e in queries if e.qname]
    lengths = [len(q) for q in qnames] or [0.0]
    sub_entropies = [char_entropy(subdomain_of(q)) for q in qnames] or [0.0]
    label_counts = [q.rstrip(".").count(".") + 1 for q in qnames] or [0.0]

    qtypes = Counter((e.qtype or "OTHER") for e in queries)
    n_q = len(queries)

    def frac(t: str) -> float:
        return safe_div(qtypes.get(t, 0), n_q)

    known = qtypes.get("A", 0) + qtypes.get("AAAA", 0) + qtypes.get("TXT", 0) \
        + qtypes.get("MX", 0) + qtypes.get("PTR", 0)
    other = n_q - known

    domains = {registered_domain(q) for q in qnames}
    resp_sizes = [e.size for e in responses] or [0.0]
    nxdomain = sum(1 for e in responses if e.rcode in ("name-error", "nxdomain"))

    feats: dict[str, float] = {
        "query_count": float(n_q),
        "query_rate": safe_div(n_q, window_s),
        "response_count": float(len(responses)),
        "response_rate": safe_div(len(responses), window_s),
        "mean_qname_length": sum(lengths) / len(lengths),
        "max_qname_length": float(max(lengths)),
        "mean_subdomain_entropy": sum(sub_entropies) / len(sub_entropies),
        "max_subdomain_entropy": float(max(sub_entropies)),
        "mean_label_count": sum(label_counts) / len(label_counts),
        "max_label_count": float(max(label_counts)),
        "txt_query_count": float(qtypes.get("TXT", 0)),
        "null_query_count": float(qtypes.get("NULL", 0)),
        "a_frac": frac("A"),
        "aaaa_frac": frac("AAAA"),
        "txt_frac": frac("TXT"),
        "mx_frac": frac("MX"),
        "ptr_frac": frac("PTR"),
        "other_frac": safe_div(other, n_q),
        "unique_qnames": float(len(set(qnames))),
        "unique_domains": float(len(domains)),
        "unique_subdomains_per_domain": safe_div(len(set(qnames)), len(domains)),
        "mean_response_size": sum(resp_sizes) / len(resp_sizes),
        "nxdomain_count": float(nxdomain),
        "nxdomain_rate": safe_div(nxdomain, len(responses)),
    }

    meta: dict[str, Any] = {
        "sample_qnames": list(dict.fromkeys(qnames))[:8],
        "qtype_mix": dict(qtypes),
        "domains": sorted(domains)[:8],
    }
    return feats, meta
