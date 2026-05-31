"""SNMP window -> feature vector (ARCHITECTURE.md §4).

Given all SNMP :class:`CaptureEvent`s for one source in one time window, produce a
flat ``{feature: float}`` mapping. SNMP reconnaissance/walks inflate
``getnext_rate`` + ``distinct_oids`` + ``oid_range_walked``; community brute
force inflates ``community_entropy`` — exactly the per-feature evidence Phase 2/3
surface.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from shared.capture import CaptureEvent

from .util import dist_entropy, safe_div

SNMP_FEATURES = (
    "request_count",
    "request_rate",
    "get_rate",
    "getnext_rate",
    "getbulk_rate",
    "response_count",
    "request_response_ratio",
    "distinct_oids",
    "oid_range_walked",
    "mean_packet_size",
    "max_packet_size",
    "community_entropy",
    "distinct_communities",
)


def extract(events: list[CaptureEvent], window_s: float) -> tuple[dict[str, float], dict[str, Any]]:
    requests = [e for e in events if e.pdu in ("get", "getnext", "getbulk")]
    responses = [e for e in events if e.pdu == "response"]

    pdus = Counter(e.pdu for e in requests)
    sizes = [e.size for e in events] or [0.0]

    # OIDs touched by traversal requests = walk breadth.
    walk_oids: set[str] = set()
    for e in requests:
        if e.pdu in ("getnext", "getbulk"):
            walk_oids.update(e.oids)
    all_oids: set[str] = set()
    for e in requests:
        all_oids.update(e.oids)

    communities = Counter(e.community for e in events if e.community is not None)

    feats: dict[str, float] = {
        "request_count": float(len(requests)),
        "request_rate": safe_div(len(requests), window_s),
        "get_rate": safe_div(pdus.get("get", 0), window_s),
        "getnext_rate": safe_div(pdus.get("getnext", 0), window_s),
        "getbulk_rate": safe_div(pdus.get("getbulk", 0), window_s),
        "response_count": float(len(responses)),
        "request_response_ratio": safe_div(len(requests), max(len(responses), 1)),
        "distinct_oids": float(len(all_oids)),
        "oid_range_walked": float(len(walk_oids)),
        "mean_packet_size": sum(sizes) / len(sizes),
        "max_packet_size": float(max(sizes)),
        "community_entropy": dist_entropy(communities.values()),
        "distinct_communities": float(len(communities)),
    }

    meta: dict[str, Any] = {
        "pdu_mix": dict(pdus),
        "communities": list(communities),
        "sample_oids": sorted(all_oids)[:8],
    }
    return feats, meta
