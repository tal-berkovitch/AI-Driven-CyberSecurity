"""Real DNS-exfil tools pack long base32/base64 payloads into the qname; scapy
often can't dissect those into a DNSQR and leaves the question as a Raw blob.
The parser must recover the qname from the wire bytes rather than drop the packet
(otherwise 100%% of the attack traffic in CIC-Bell-DNS-EXF is silently lost)."""

import pytest

pytest.importorskip("scapy")

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from collector.sensor import (  # noqa: E402
    _decode_raw_question,
    _question_fields,
    parse_packet,
)


def test_decode_raw_question_recovers_name_and_qtype():
    # wire form: <len>data <len>MJZGC2LO <0x00 terminator> <qtype A=0x0001> <qclass>
    blob = b"\x04data\x08MJZGC2LO\x00\x00\x01\x00\x01"
    name, qtype = _decode_raw_question(blob)
    assert name == "data.MJZGC2LO"
    assert qtype == 1  # A


def test_decode_raw_question_tolerates_truncated_label():
    # CIC-Bell light-exfil queries are a 2-label tag.<data> name with no null
    # terminator captured — the decoder takes what's there and stops cleanly.
    blob = b"\x04init\x26MJZGC2LOFVZGKZ3JN5XHGLLBOJSWC4ZOM5UW01"
    name, qtype = _decode_raw_question(blob)
    assert name == "init.MJZGC2LOFVZGKZ3JN5XHGLLBOJSWC4ZOM5UW01"
    assert qtype is None  # ran off the end before qtype/qclass


def test_decode_raw_question_stops_on_compression_pointer():
    name, qtype = _decode_raw_question(b"\x03abc\xc0\x0c")
    assert name == "abc"
    assert qtype is None


def test_question_fields_from_raw_blob():
    # The integration point: a Raw question (scapy gave up) -> decoded name.
    rr = Raw(load=b"\x04init\x28MJZGC2LOFVZGKZ3JN5XHGLLBOJSWC4ZOM5UWabcd")
    name, qtype = _question_fields(rr)
    assert name == "init.MJZGC2LOFVZGKZ3JN5XHGLLBOJSWC4ZOM5UWabcd"
    assert qtype is None  # no terminator/qtype in this stealthy 2-label name


def test_question_fields_from_normal_dnsqr_unchanged():
    # A properly-dissected question still goes through the fast path untouched.
    name, qtype = _question_fields(DNSQR(qname="www.example.com", qtype="A"))
    assert name == "www.example.com"
    assert qtype == "A"


def test_parse_packet_normal_query_still_parses():
    pkt = (IP(src="10.0.0.9", dst="10.0.0.2")
           / UDP(sport=40000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname="host.example.local", qtype="A")))
    pkt.time = 0.0
    ev = parse_packet(pkt)
    assert ev is not None
    assert ev.proto == "dns"
    assert ev.qname == "host.example.local"
    assert ev.is_response is False
