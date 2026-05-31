"""Passive packet tap (collector side).

Sniffs DNS (udp/53) and SNMP (udp/161) on the collector's interface — where
100%% of the lab's benign traffic terminates, so capture is fully passive and
needs no inline routing (a plain Docker bridge hides unicast from third
containers, which is why the tap lives here and not on the defender).

Each parsed packet becomes a :class:`CaptureEvent` published on the ``capture``
topic of the shared transport spine; the defender consumes and extracts features.
"""

from __future__ import annotations

import logging
import os

from shared.capture import CaptureEvent
from shared.transport.file_queue import FileQueueProducer

# Quiet scapy's import-time IPv6/route warnings before importing it; these scapy
# imports must follow the log-level setup, hence the E402 suppressions.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.snmp import (  # noqa: E402
    SNMP,
    SNMPbulk,
    SNMPget,
    SNMPnext,
    SNMPresponse,
    SNMPset,
)
from scapy.sendrecv import sniff  # noqa: E402

LOG = logging.getLogger("sensor")
CAPTURE_TOPIC = "capture"

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
_RCODES = {0: "ok", 1: "format-error", 2: "server-failure",
           3: "name-error", 4: "not-implemented", 5: "refused"}
_SNMP_PDU = [(SNMPget, "get"), (SNMPnext, "getnext"), (SNMPbulk, "getbulk"),
             (SNMPresponse, "response"), (SNMPset, "set")]


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


def _parse_dns(pkt) -> CaptureEvent | None:  # noqa: ANN001
    dns = pkt[DNS]
    udp = pkt[UDP]
    is_resp = int(dns.qr) == 1
    qname = qtype = None
    questions = _rr_list(dns.qd)
    if questions:
        q0 = questions[0]
        qname = _decode(q0.qname)
        qtype = _QTYPES.get(int(q0.qtype), str(q0.qtype))
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
        rcode=_RCODES.get(int(dns.rcode), str(dns.rcode)) if is_resp else None,
        ancount=int(dns.ancount),
        answer_types=answer_types,
    )


def _parse_snmp(pkt) -> CaptureEvent | None:  # noqa: ANN001
    snmp = pkt[SNMP]
    udp = pkt[UDP]
    pdu = snmp.PDU
    pdu_name = "other"
    for cls, name in _SNMP_PDU:
        if isinstance(pdu, cls):
            pdu_name = name
            break
    oids: list[str] = []
    vbl = getattr(pdu, "varbindlist", None) or []
    for vb in vbl:
        try:
            oids.append(str(vb.oid.val))
        except AttributeError:
            continue
    community = None
    try:
        community = _decode(snmp.community.val)
    except AttributeError:
        pass
    return CaptureEvent(
        proto="snmp",
        ts=float(pkt.time),
        src=pkt[IP].src,
        dst=pkt[IP].dst,
        size=len(bytes(udp.payload)),
        pdu=pdu_name,
        community=community,
        oids=oids,
    )


def parse_packet(pkt) -> CaptureEvent | None:  # noqa: ANN001
    """Parse one scapy packet into a CaptureEvent, or None if it isn't udp/53|161.

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
        if udp.dport == 161 or udp.sport == 161:
            return _parse_snmp(pkt) if SNMP in pkt else None
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
    producer = FileQueueProducer(queue_root)
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

    # No BPF filter (avoids a libpcap/tcpdump dependency); we select udp/53+161
    # in handle(). Lab traffic volume is tiny, so userspace filtering is fine.
    LOG.info("sensor up; sniffing udp/53 + udp/161 on %s -> topic %r", iface, CAPTURE_TOPIC)
    try:
        sniff(iface=iface, prn=handle, store=False)
    except OSError as exc:
        LOG.warning("sniff on %s failed (%s); falling back to default iface", iface, exc)
        sniff(prn=handle, store=False)


if __name__ == "__main__":
    main()
