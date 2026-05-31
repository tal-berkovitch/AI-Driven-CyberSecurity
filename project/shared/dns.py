"""Minimal DNS wire helpers (stdlib only).

Just enough to build/parse a query for the Phase 0 connectivity demo and the
Phase 1 benign generator, without pulling in scapy on the lightweight containers.
"""

from __future__ import annotations

import struct


def build_query(qname: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    """Build a single-question DNS query. qtype 1=A, 16=TXT, 10=NULL."""
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    question = b""
    for label in qname.rstrip(".").split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + struct.pack(">HH", qtype, 1)  # qtype, class IN
    return header + question


def parse_qname(packet: bytes) -> str | None:
    """Extract the queried name from a DNS query packet. Returns None on parse error."""
    try:
        pos = 12  # skip header
        labels = []
        while True:
            length = packet[pos]
            pos += 1
            if length == 0:
                break
            labels.append(packet[pos : pos + length].decode("ascii", "replace"))
            pos += length
        return ".".join(labels)
    except (IndexError, UnicodeDecodeError):
        return None
