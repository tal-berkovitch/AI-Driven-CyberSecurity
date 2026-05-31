"""Attacker agent — Phase 1: realistic BENIGN traffic generator.

Phase 1 is baseline-only: this produces the kind of varied, well-behaved DNS and
SNMP traffic a normal network emits, so the defender can learn a clean "normal".
The attack injectors (DNS tunneling, SNMP recon/walk, SNMP amplification) arrive
in Phase 2 and reuse this same client scaffolding.

DNS uses dnspython pointed at the collector's dnsmasq; SNMP shells out to the
net-snmp clients (real protocol packets on the wire for the tap to capture).
Two independent threads give DNS and SNMP their own realistic cadences + jitter.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import subprocess
import threading
import time

import dns.resolver

LOG = logging.getLogger("attacker")

HOSTS = ["www", "api", "mail", "db", "cdn", "ntp", "vpn"]
DOMAIN = "example.local"
# (qtype, weight) — a realistic-ish mix dominated by A lookups.
QTYPE_WEIGHTS = [("A", 50), ("AAAA", 15), ("TXT", 10), ("MX", 10), ("PTR", 10), ("NX", 5)]

# A few system/interface OIDs a monitoring poller would normally read (numeric to
# avoid any MIB-file dependency in the client).
SNMP_GET_OIDS = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]
SNMP_NEXT_OIDS = ["1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.16", "1.3.6.1.2.1.25.1.1"]
SNMP_BULK_ROOT = "1.3.6.1.2.1.2.2.1"

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


def _snmp(tool: str, host: str, *oids: str) -> None:
    cmd = [tool, "-v2c", "-c", "public", "-t", "2", "-r", "1", "-On", host, *oids]
    if tool == "snmpbulkget":
        cmd = [tool, "-v2c", "-c", "public", "-t", "2", "-r", "1",
               "-Cn0", "-Cr8", "-On", host, *oids]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=6, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        LOG.debug("snmp %s -> %s", tool, exc)


def snmp_loop(host: str) -> None:
    while not _stop.is_set():
        # A normal poll cycle: read a few scalars, step through a couple of
        # table columns, occasionally a small bulk read.
        _snmp("snmpget", host, *SNMP_GET_OIDS)
        for oid in random.sample(SNMP_NEXT_OIDS, k=2):
            _snmp("snmpgetnext", host, oid)
        if random.random() < 0.4:
            _snmp("snmpbulkget", host, SNMP_BULK_ROOT)
        LOG.info("SNMP poll cycle done")
        _stop.wait(random.uniform(15.0, 35.0))


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
        threading.Thread(target=snmp_loop, args=(server_ip,), daemon=True, name="snmp"),
    ]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _stop.set()


if __name__ == "__main__":
    main()
