"""Passive packet tap (collector side).

Sniffs DNS (udp/53) on the collector's interface — where 100%% of the lab's
benign traffic terminates, so capture is fully passive and needs no inline
routing (a plain Docker bridge hides unicast from third containers, which is why
the tap lives here and not on the defender).

Each parsed packet becomes a :class:`CaptureEvent` published on the ``capture``
topic of the shared transport spine; the defender consumes and extracts features.
"""

from __future__ import annotations

import logging
import os

from shared.capture import CaptureEvent
from shared.transport import make_producer

# Quiet scapy's import-time IPv6/route warnings before importing it; these scapy
# imports must follow the log-level setup, hence the E402 suppressions.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.sendrecv import sniff  # noqa: E402

LOG = logging.getLogger("sensor")
CAPTURE_TOPIC = "capture"

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
_RCODES = {0: "ok", 1: "format-error", 2: "server-failure",
           3: "name-error", 4: "not-implemented", 5: "refused"}


def _decode(v) -> str:  # noqa: ANN001
    if isinstance(v, bytes):
        return v.decode("ascii", "replace").rstrip(".")
    return str(v).rstrip(".")


def _rr_list(field) -> list:  # noqa: ANN001
    """scapy >=2.5 exposes qd/an/ns/ar as list-like objects (empty for a query);
    older scapy uses a single record. Normalise both to a plain list."""
    if field is None:
        return []
    try:
        return list(field)
    except TypeError:
        return [field]


def _decode_raw_question(buf: bytes) -> tuple[str | None, int | None]:
    """Walk DNS wire-format labels out of a raw question blob.

    DNS tunneling/exfil tools pack long base32/base64 payloads into the qname;
    scapy often can't dissect these into a ``DNSQR`` and leaves the question as a
    ``Raw`` blob. The name is still there in wire format (``<len><label>...\\x00``
    then qtype/qclass), so we decode it ourselves rather than drop the packet —
    without this, every real exfil query would be silently lost.
    """
    labels: list[str] = []
    i, n = 0, len(buf)
    while i < n:
        length = buf[i]
        if length == 0:  # end of name
            i += 1
            break
        if length & 0xC0:  # compression pointer/reserved — can't follow in a blob
            return (".".join(labels) or None), None
        i += 1
        labels.append(buf[i:i + length].decode("ascii", "replace"))
        i += length  # tolerates a label that runs off the end (truncated capture)
    qname = ".".join(labels) or None
    qtype = int.from_bytes(buf[i:i + 2], "big") if i + 2 <= n and qname else None
    return qname, qtype


def _question_fields(rr) -> tuple[str | None, str | None]:  # noqa: ANN001
    """(qname, qtype) from a question record — a real DNSQR or a Raw exfil blob."""
    qname = getattr(rr, "qname", None)
    if qname is not None:
        return _decode(qname), _QTYPES.get(int(rr.qtype), str(rr.qtype))
    load = getattr(rr, "load", None)
    if isinstance(load, (bytes, bytearray)):
        name, qt = _decode_raw_question(bytes(load))
        return name, (_QTYPES.get(qt, str(qt)) if qt is not None else None)
    return None, None


def _parse_dns(pkt) -> CaptureEvent | None:  # noqa: ANN001
    dns = pkt[DNS]
    udp = pkt[UDP]
    is_resp = int(dns.qr) == 1
    qname = qtype = None
    questions = _rr_list(dns.qd)
    if questions:
        qname, qtype = _question_fields(questions[0])
    answer_types: list[str] = []
    for rr in _rr_list(dns.an):
        try:
            answer_types.append(_QTYPES.get(int(rr.type), str(rr.type)))
        except (AttributeError, TypeError):
            continue
    return CaptureEvent(
        proto="dns",
        ts=float(pkt.time),
        src=pkt[IP].src,
        dst=pkt[IP].dst,
        size=len(bytes(udp.payload)),
        is_response=is_resp,
        qname=qname,
        qtype=qtype,
        rcode=_RCODES.get(int(dns.rcode or 0), str(dns.rcode)) if is_resp else None,
        ancount=int(dns.ancount or 0),
        answer_types=answer_types,
    )


def parse_packet(pkt) -> CaptureEvent | None:  # noqa: ANN001
    """Parse one scapy packet into a CaptureEvent, or None if it isn't udp/53.

    Shared by the live tap and the offline PCAP adapter (eval/datasets) so real
    datasets are turned into features by the *exact same* code path as live traffic.
    Never raises — a malformed packet just yields None.
    """
    if UDP not in pkt or IP not in pkt:
        return None
    udp = pkt[UDP]
    try:
        if udp.dport == 53 or udp.sport == 53:
            return _parse_dns(pkt) if DNS in pkt else None
    except Exception:  # noqa: BLE001 — never let one bad packet kill the tap
        return None
    return None


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    queue_root = os.getenv("QUEUE_ROOT", "/app/data/queue")
    iface = os.getenv("CAPTURE_IFACE", "eth0")
    producer = make_producer(queue_root)
    n = 0

    def handle(pkt) -> None:  # noqa: ANN001
        nonlocal n
        ev = parse_packet(pkt)
        if ev is None:
            return
        producer.send(CAPTURE_TOPIC, ev.to_dict())
        n += 1
        if n % 25 == 0:
            LOG.info("captured %d events", n)

    # No BPF filter (avoids a libpcap/tcpdump dependency); we select udp/53 in
    # handle(). Lab traffic volume is tiny, so userspace filtering is fine.
    LOG.info("sensor up; sniffing udp/53 on %s -> topic %r", iface, CAPTURE_TOPIC)
    try:
        sniff(iface=iface, prn=handle, store=False)
    except OSError as exc:
        LOG.warning("sniff on %s failed (%s); falling back to default iface", iface, exc)
        sniff(prn=handle, store=False)


if __name__ == "__main__":
    main()
