"""Collector agent — Phase 0 stub (dummy destination).

Listens on UDP/53, logs what arrives, and replies so flows complete naturally.
Phase 1 replaces this with a real resolver (dnsmasq/CoreDNS).
"""

from __future__ import annotations

import logging
import os
import selectors
import socket

from shared.dns import parse_qname

LOG = logging.getLogger("collector")


def _bind(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.setblocking(False)
    return sock


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    sel = selectors.DefaultSelector()
    dns_sock = _bind(53)
    sel.register(dns_sock, selectors.EVENT_READ, "dns")
    LOG.info("collector up; listening on udp/53 (dns)")

    while True:
        for key, _ in sel.select(timeout=None):
            sock: socket.socket = key.fileobj  # type: ignore[assignment]
            data, addr = sock.recvfrom(4096)
            qname = parse_qname(data)
            LOG.info("DNS query from %s qname=%s (%d bytes)", addr[0], qname, len(data))
            # Echo back a stub response so the round trip completes.
            sock.sendto(b"\x00", addr)


if __name__ == "__main__":
    main()
