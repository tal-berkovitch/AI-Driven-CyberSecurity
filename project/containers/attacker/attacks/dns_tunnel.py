"""DNS tunneling injector (MITRE T1572 — Protocol Tunneling).

The tunnelling fingerprint is **fan-out**: a chatty, interactive channel that
sprays many distinct high-entropy subdomains under one tunnel domain (A/CNAME
lookups). High query volume + many unique subdomains per domain is what separates
it from the bulk-exfil and C2-beacon injectors. Runs as an organic campaign
(waves + quiet gaps) so the live demo varies every run.
"""

from __future__ import annotations

import logging
import threading

import dns.resolver

from ._campaign import new_rng, run_campaign

LOG = logging.getLogger("attack.dns_tunnel")
_B32 = "abcdefghijklmnopqrstuvwxyz234567"
TUNNEL_BASE = "t.tunnel.example.local"


def _label(rng) -> str:
    return "".join(rng.choice(_B32) for _ in range(rng.randint(12, 18)))


def run(server_ip: str, stop_event: threading.Event) -> None:
    rng = new_rng()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    def burst(intensity: str) -> None:
        # Many distinct subdomains per wave -> high unique_subdomains_per_domain.
        n = rng.randint(15, 30) if intensity == "loud" else rng.randint(2, 4)
        for _ in range(n):
            qname = f"{_label(rng)}.{TUNNEL_BASE}"
            try:
                resolver.resolve(qname, rng.choice(["A", "A", "CNAME"]))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass  # the query packet on the wire is the attack; answers are irrelevant
        stop_event.wait(rng.uniform(0.2, 0.8) if intensity == "loud" else rng.uniform(4.0, 9.0))

    LOG.warning("DNS tunneling injector active (fan-out subdomains, organic campaign)")
    run_campaign(rng, stop_event, burst)
