"""Attacker agent — Phase 1: realistic BENIGN DNS traffic generator.

Phase 1 is baseline-only: this produces the kind of varied, well-behaved DNS
traffic a normal network emits, so the defender can learn a clean "normal". The
attack injector (DNS tunneling) arrives in Phase 2 and reuses this same client
scaffolding.

DNS uses dnspython pointed at the collector's dnsmasq (real protocol packets on
the wire for the tap to capture), on its own realistic cadence + jitter.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import threading
import time

import dns.resolver

LOG = logging.getLogger("attacker")

HOSTS = ["www", "api", "mail", "db", "cdn", "ntp", "vpn"]
DOMAIN = "example.local"
# (qtype, weight) — a realistic-ish mix dominated by A lookups.
QTYPE_WEIGHTS = [("A", 50), ("AAAA", 15), ("TXT", 10), ("MX", 10), ("PTR", 10), ("NX", 5)]

_stop = threading.Event()


def _weighted_qtype() -> str:
    pool = [q for q, w in QTYPE_WEIGHTS for _ in range(w)]
    return random.choice(pool)


def dns_loop(server_ip: str) -> None:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    while not _stop.is_set():
        qt = _weighted_qtype()
        try:
            if qt == "PTR":
                ip = f"10.20.0.{random.choice([10, 11])}"
                name = dns.reversename.from_address(ip)
                resolver.resolve(name, "PTR")
                LOG.info("DNS PTR %s", ip)
            elif qt == "MX" or qt == "TXT":
                resolver.resolve(DOMAIN, qt)
                LOG.info("DNS %s %s", qt, DOMAIN)
            elif qt == "NX":
                name = f"{random.randint(1000, 9999)}.{DOMAIN}"  # benign miss -> NXDOMAIN
                resolver.resolve(name, "A")
                LOG.info("DNS A %s", name)
            else:
                name = f"{random.choice(HOSTS)}.{DOMAIN}"
                resolver.resolve(name, qt)
                LOG.info("DNS %s %s", qt, name)
        except dns.resolver.NXDOMAIN:
            pass  # expected for the NX class
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            LOG.debug("dns query (%s) -> %s", qt, exc.__class__.__name__)
        _stop.wait(random.uniform(0.5, 3.0))


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host = os.getenv("COLLECTOR_HOST", "collector")
    try:
        server_ip = socket.gethostbyname(host)
        LOG.info("benign generator up; collector '%s' -> %s", host, server_ip)
    except OSError as exc:
        LOG.error("cannot resolve collector host '%s': %s", host, exc)
        return

    threads = [
        threading.Thread(target=dns_loop, args=(server_ip,), daemon=True, name="dns"),
    ]

    # ATTACK_MODE adds real-packet attack injectors ON TOP of benign traffic so
    # captures contain a realistic benign+attack mix. "benign" (default) = none;
    # "all" = every injector; or a comma-separated list of attack names.
    from .attacks import REGISTRY  # local import keeps benign-only startup lean

    mode = os.getenv("ATTACK_MODE", "benign").lower().strip()
    selected = list(REGISTRY) if mode == "all" else [m for m in mode.split(",") if m in REGISTRY]
    if mode not in ("benign", "") and not selected:
        LOG.warning("ATTACK_MODE=%r matched no injectors (known: %s)", mode, list(REGISTRY))
    for name in selected:
        LOG.warning("launching attack injector: %s", name)
        threads.append(threading.Thread(
            target=REGISTRY[name], args=(server_ip, _stop), daemon=True, name=name))

    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _stop.set()


if __name__ == "__main__":
    main()
