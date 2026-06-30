"""DNS command-and-control beacon injector (MITRE T1071.004 — App Layer: DNS).

The C2 fingerprint is **TXT-record abuse on a regular beacon cadence**: the
implant polls its controller with TXT lookups to encoded subdomains at steady
intervals. Elevated TXT-record count — not raw payload size or fan-out — is the
discriminator. The beacon interval is deliberately regular (low jitter) so the
behavioral signature reads as a beacon rather than organic traffic.
"""

from __future__ import annotations

import logging
import threading

import dns.resolver

from ._campaign import new_rng, run_campaign

LOG = logging.getLogger("attack.dns_c2")
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
C2_BASE = "beacon.example.local"


def _enc(rng) -> str:
    return "".join(rng.choice(_B32) for _ in range(rng.randint(18, 26)))


def run(server_ip: str, stop_event: threading.Event) -> None:
    rng = new_rng()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    def burst(intensity: str) -> None:
        # TXT-heavy poll cycle; the count of TXT lookups is the C2 signal.
        n = rng.randint(5, 9) if intensity == "loud" else rng.randint(3, 5)
        for _ in range(n):
            qname = f"{_enc(rng)}.{C2_BASE}"
            try:
                resolver.resolve(qname, "TXT")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
        # Regular beacon interval (low jitter) — the hallmark of a C2 beacon.
        stop_event.wait(rng.uniform(2.8, 3.6))

    LOG.warning("DNS C2 beacon injector active (TXT beaconing, organic campaign)")
    # Short, concentrated active waves; long quiet gaps -> attacks are the minority.
    run_campaign(rng, stop_event, burst, active=(10.0, 20.0), quiet=(45.0, 95.0))
