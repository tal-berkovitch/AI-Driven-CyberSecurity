"""Labeled, difficulty-graded traffic scenarios.

Each generator emits :class:`CaptureEvent`s that are fed through the production
:class:`WindowAggregator` + extractors, so the resulting ``FeatureRecord``s are
produced by the *exact same code* that runs live — the eval is never measuring a
different feature pipeline than the system. The ground-truth class is stamped
into ``record.meta['label']``.

Difficulty gradient (ARCHITECTURE.md §6): attacks range from *loud* (high volume)
to *low-and-slow* (sparse, paced) so the benchmark is not trivially separable.
"""

from __future__ import annotations

import numpy as np

from defender.features.windows import WindowAggregator
from shared.capture import CaptureEvent
from shared.schema import FeatureRecord

WINDOW_S = 10.0
CLIENT = "10.20.0.99"      # the "monitored host" / poller
SERVER = "10.20.0.2"       # collector (resolver / SNMP agent)
DOMAIN = "example.local"
HOSTS = ["www", "api", "mail", "db", "cdn", "ntp", "vpn"]
_B32 = "abcdefghijklmnopqrstuvwxyz234567"

# Binary + multiclass labels.
ATTACK_CLASSES = ("dns_tunnel", "snmp_recon", "snmp_amplify")


def _run(events: list[CaptureEvent], label: str) -> list[FeatureRecord]:
    """Feed events (any order) through the real aggregator and label the output."""
    agg = WindowAggregator(window_s=WINDOW_S)
    out: list[FeatureRecord] = []
    for ev in sorted(events, key=lambda e: e.ts):
        out.extend(agg.add(ev))
    out.extend(agg.flush_all())
    for r in out:
        r.meta["label"] = label
    return out


def _ts(rng, w: int) -> float:
    return w * WINDOW_S + float(rng.uniform(0, WINDOW_S))


# --- DNS ---------------------------------------------------------------------

def benign_dns(n_windows: int, seed: int = 0) -> list[FeatureRecord]:
    rng = np.random.default_rng(seed)
    qtypes = ["A", "A", "A", "A", "AAAA", "TXT", "MX", "PTR"]  # A-dominated
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(int(rng.integers(4, 11))):
            qt = str(rng.choice(qtypes))
            host = str(rng.choice(HOSTS))
            qname = DOMAIN if qt in ("TXT", "MX") else f"{host}.{DOMAIN}"
            events.append(CaptureEvent("dns", _ts(rng, w), CLIENT, SERVER,
                                       size=int(rng.integers(28, 48)),
                                       is_response=False, qname=qname, qtype=qt))
    return _run(events, "benign")


def tunnel_dns(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """DNS tunneling: long, high-entropy subdomains, TXT/NULL-heavy.

    loud = high query volume; slow = low-and-slow (few queries/window but the same
    encoded-payload fingerprint), which rate-based detection misses.
    """
    rng = np.random.default_rng(seed)
    lo, hi = (25, 55) if intensity == "loud" else (2, 5)
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(int(rng.integers(lo, hi + 1))):
            blob = "".join(rng.choice(list(_B32), size=int(rng.integers(28, 45))))
            qname = f"{blob}.t.tunnel.{DOMAIN}"
            qt = str(rng.choice(["TXT", "TXT", "NULL", "A"]))
            events.append(CaptureEvent("dns", _ts(rng, w), CLIENT, SERVER,
                                       size=len(qname) + 16,
                                       is_response=False, qname=qname, qtype=qt))
    return _run(events, "dns_tunnel")


# --- SNMP --------------------------------------------------------------------

def benign_snmp(n_windows: int, seed: int = 0) -> list[FeatureRecord]:
    rng = np.random.default_rng(seed)
    scalars = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        events.append(CaptureEvent("snmp", _ts(rng, w), CLIENT, SERVER, size=71,
                                   pdu="get", community="public", oids=list(scalars)))
        for _ in range(int(rng.integers(1, 3))):
            events.append(CaptureEvent("snmp", _ts(rng, w), CLIENT, SERVER, size=70,
                                       pdu="getnext", community="public",
                                       oids=[f"1.3.6.1.2.1.2.2.1.10.{rng.integers(1, 4)}"]))
    return _run(events, "benign")


def walk_snmp(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """SNMP recon/walk: sequential getnext sweeping many OIDs (T1046)."""
    rng = np.random.default_rng(seed)
    step = 40 if intensity == "loud" else 6
    events: list[CaptureEvent] = []
    oid = 1
    for w in range(n_windows):
        for _ in range(step):
            events.append(CaptureEvent("snmp", _ts(rng, w), CLIENT, SERVER, size=68,
                                       pdu="getnext", community="public",
                                       oids=[f"1.3.6.1.2.1.2.2.1.{(oid % 22) + 1}.{oid}"]))
            oid += 1
    return _run(events, "snmp_recon")


def amplify_snmp(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """SNMP amplification: getbulk with large responses (T1498.002)."""
    rng = np.random.default_rng(seed)
    reqs = 12 if intensity == "loud" else 3
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(reqs):
            events.append(CaptureEvent("snmp", _ts(rng, w), CLIENT, SERVER, size=62,
                                       pdu="getbulk", community="public",
                                       oids=["1.3.6.1.2.1.2.2.1"]))
            # large amplified response from the agent
            events.append(CaptureEvent("snmp", _ts(rng, w), SERVER, CLIENT,
                                       size=int(rng.integers(1200, 1480)),
                                       pdu="response", community="public",
                                       oids=[f"1.3.6.1.2.1.2.2.1.{k}" for k in range(10)]))
    return _run(events, "snmp_amplify")


def build_labeled_records(seed: int = 7) -> dict[str, list[FeatureRecord]]:
    """Assemble the full labeled corpus, keyed by protocol."""
    return {
        "dns": (
            benign_dns(140, seed=seed)
            + tunnel_dns(35, "loud", seed=seed + 1)
            + tunnel_dns(35, "slow", seed=seed + 2)
        ),
        "snmp": (
            benign_snmp(140, seed=seed + 3)
            + walk_snmp(30, "loud", seed=seed + 4)
            + walk_snmp(30, "slow", seed=seed + 5)
            + amplify_snmp(30, "loud", seed=seed + 6)
        ),
    }
