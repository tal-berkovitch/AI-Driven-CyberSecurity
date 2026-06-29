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
CLIENT = "10.20.0.99"      # the "monitored host"
SERVER = "10.20.0.2"       # collector (resolver)
DOMAIN = "example.local"
HOSTS = ["www", "api", "mail", "db", "cdn", "ntp", "vpn"]
_B32 = "abcdefghijklmnopqrstuvwxyz234567"

# Binary + multiclass labels.
ATTACK_CLASSES = ("dns_tunnel", "dns_exfil", "dns_c2")


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


def _blob(rng, lo: int, hi: int) -> str:
    return "".join(rng.choice(list(_B32), size=int(rng.integers(lo, hi + 1))))


def tunnel_dns(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """DNS tunneling (T1572): fan-out — MANY distinct moderate high-entropy
    subdomains under one tunnel domain (A/CNAME). The discriminator is *unique
    subdomains per domain*, not payload size. loud = high volume; slow = low-and-slow.
    """
    rng = np.random.default_rng(seed)
    lo, hi = (15, 30) if intensity == "loud" else (2, 4)
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(int(rng.integers(lo, hi + 1))):
            qname = f"{_blob(rng, 12, 18)}.t.tunnel.{DOMAIN}"
            qt = str(rng.choice(["A", "A", "CNAME"]))
            events.append(CaptureEvent("dns", _ts(rng, w), CLIENT, SERVER,
                                       size=len(qname) + 16,
                                       is_response=False, qname=qname, qtype=qt))
    return _run(events, "dns_tunnel")


def exfil_dns(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """DNS exfiltration (T1048.003): few-but-huge queries — each one very long
    base32 *data label* under a drop domain (A). The discriminator is *encoded
    label length*, not fan-out.
    """
    rng = np.random.default_rng(seed)
    lo, hi = (2, 5) if intensity == "loud" else (1, 2)
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(int(rng.integers(lo, hi + 1))):
            qname = f"{_blob(rng, 40, 52)}.exfil.{DOMAIN}"
            events.append(CaptureEvent("dns", _ts(rng, w), CLIENT, SERVER,
                                       size=len(qname) + 16,
                                       is_response=False, qname=qname, qtype="A"))
    return _run(events, "dns_exfil")


def c2_dns(n_windows: int, intensity: str = "loud", seed: int = 0) -> list[FeatureRecord]:
    """DNS C2 beacon (T1071.004): TXT-record-heavy beaconing to encoded subdomains
    on a regular cadence. The discriminator is *elevated TXT-record count*.
    """
    rng = np.random.default_rng(seed)
    lo, hi = (5, 9) if intensity == "loud" else (3, 5)
    events: list[CaptureEvent] = []
    for w in range(n_windows):
        for _ in range(int(rng.integers(lo, hi + 1))):
            qname = f"{_blob(rng, 18, 26)}.beacon.{DOMAIN}"
            events.append(CaptureEvent("dns", _ts(rng, w), CLIENT, SERVER,
                                       size=len(qname) + 16,
                                       is_response=False, qname=qname, qtype="TXT"))
    return _run(events, "dns_c2")


def build_labeled_records(seed: int = 7) -> dict[str, list[FeatureRecord]]:
    """Assemble the full labeled corpus, keyed by protocol."""
    return {
        "dns": (
            benign_dns(140, seed=seed)
            + tunnel_dns(30, "loud", seed=seed + 1)
            + tunnel_dns(20, "slow", seed=seed + 2)
            + exfil_dns(30, "loud", seed=seed + 3)
            + exfil_dns(20, "slow", seed=seed + 4)
            + c2_dns(30, "loud", seed=seed + 5)
            + c2_dns(20, "slow", seed=seed + 6)
        ),
    }
