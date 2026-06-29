"""Small numeric helpers for the DNS feature extractor."""

from __future__ import annotations

import math
from collections import Counter


def char_entropy(s: str) -> float:
    """Shannon entropy (bits/symbol) over the characters of ``s``.

    DNS tunneling encodes data into subdomain labels (base32/64), which pushes
    this well above the ~3-4 bits of ordinary words — the signal Phase 2 keys on.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registered_domain(qname: str) -> str:
    """Best-effort registered domain = last two labels (lab uses ``*.example.local``)."""
    labels = qname.rstrip(".").split(".")
    if len(labels) <= 2:
        return qname.rstrip(".")
    return ".".join(labels[-2:])


def subdomain_of(qname: str) -> str:
    """Everything to the left of the registered domain, dots stripped."""
    labels = qname.rstrip(".").split(".")
    if len(labels) <= 2:
        return ""
    return "".join(labels[:-2])


def safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0
