"""Raw capture-event contract (sensor -> feature plane).

The collector runs a passive packet tap (scapy) and parses each DNS/SNMP packet
into a flat :class:`CaptureEvent`, which it publishes onto the transport spine
(topic ``capture``). The defender consumes these and turns *windows* of events
into :class:`~shared.schema.FeatureRecord` rows.

This is deliberately a *separate* contract from ``FeatureRecord``: it is the
internal sensor->extractor link. In the full-vision (Kafka + Morpheus) topology
the extractor moves upstream and the spine carries ``FeatureRecord`` directly,
but the producer/consumer interface stays identical (see ARCHITECTURE.md §2).

Keep this stdlib-only: the collector image is intentionally lean.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DNS = "dns"
SNMP = "snmp"


@dataclass
class CaptureEvent:
    """One parsed packet observed on the wire.

    Fields are a superset across protocols; only the relevant ones are filled.
    ``proto`` selects which group applies.
    """

    proto: str          # "dns" | "snmp"
    ts: float           # capture timestamp (unix)
    src: str            # source IP
    dst: str            # destination IP
    size: int           # UDP payload size in bytes

    # --- DNS ---
    is_response: bool = False
    qname: str | None = None
    qtype: str | None = None          # "A" | "AAAA" | "TXT" | "MX" | "PTR" | "NULL" | ...
    rcode: str | None = None          # response code name, e.g. "ok" | "name-error"
    ancount: int = 0
    answer_types: list[str] = field(default_factory=list)

    # --- SNMP ---
    pdu: str | None = None            # "get" | "getnext" | "getbulk" | "response" | ...
    community: str | None = None
    oids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CaptureEvent":
        return cls(
            proto=d["proto"],
            ts=float(d["ts"]),
            src=d["src"],
            dst=d["dst"],
            size=int(d.get("size", 0)),
            is_response=bool(d.get("is_response", False)),
            qname=d.get("qname"),
            qtype=d.get("qtype"),
            rcode=d.get("rcode"),
            ancount=int(d.get("ancount", 0)),
            answer_types=list(d.get("answer_types", [])),
            pdu=d.get("pdu"),
            community=d.get("community"),
            oids=list(d.get("oids", [])),
        )
