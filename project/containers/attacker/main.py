"""Attacker agent — Phase 0 stub.

Sends a slow trickle of *benign* DNS and SNMP-shaped traffic to the collector to
prove the isolated network is wired correctly. Phase 1 replaces this with the
real benign generator (varied qtypes, realistic timing) and the attack injectors
(DNS tunneling, SNMP recon/walk, SNMP amplification).
"""

from __future__ import annotations

import logging
import os
import socket
import time

from shared.dns import build_query

LOG = logging.getLogger("attacker")

BENIGN_DOMAINS = ["www.example.local", "api.example.local", "mail.example.local"]


def send_dns(sock: socket.socket, host: str, port: int = 53) -> None:
    qname = BENIGN_DOMAINS[int(time.time()) % len(BENIGN_DOMAINS)]
    sock.sendto(build_query(qname), (host, port))
    LOG.info("sent DNS query qname=%s -> %s:%d", qname, host, port)


def send_snmp(sock: socket.socket, host: str, port: int = 161) -> None:
    # Phase 0 placeholder payload (community + marker). Phase 1: real SNMP GET/walk.
    payload = b"\x30\x0bpublic:get"
    sock.sendto(payload, (host, port))
    LOG.info("sent SNMP-stub (%d bytes) -> %s:%d", len(payload), host, port)


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host = os.getenv("COLLECTOR_HOST", "collector")

    # Resolve once so a DNS failure is loud and obvious.
    try:
        ip = socket.gethostbyname(host)
        LOG.info("attacker up; collector '%s' resolves to %s", host, ip)
    except OSError as exc:
        LOG.error("cannot resolve collector host '%s': %s", host, exc)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            send_dns(sock, host)
            send_snmp(sock, host)
        except OSError as exc:
            LOG.warning("send failed: %s", exc)
        time.sleep(5)


if __name__ == "__main__":
    main()
