"""CIC-Bell PCAP adapter: a replayed PCAP must yield the SAME FeatureRecord shape
as live traffic, with directory names mapped to ground-truth labels.
Skipped automatically if scapy (the `capture` extra) isn't installed."""

import pytest

pytest.importorskip("scapy")

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from defender.features.dns import DNS_FEATURES  # noqa: E402

from eval.datasets.cic_bell import load_cic_bell, normalize_label, pcap_to_records  # noqa: E402


def _dns_query(qname: str, qtype: str = "A", t: float = 0.0):
    pkt = (IP(src="10.0.0.9", dst="10.0.0.2")
           / UDP(sport=40000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    pkt.time = t
    return pkt


def test_label_aliases_map_to_canonical_classes():
    assert normalize_label("Benign") == "benign"
    assert normalize_label("exfiltration") == "dns_tunnel"
    assert normalize_label("attack") == "dns_tunnel"


def test_pcap_replay_produces_dns_feature_records(tmp_path):
    pcap = tmp_path / "sample.pcap"
    pkts = [_dns_query(f"host{i}.example.local", "A", t=float(i)) for i in range(6)]
    wrpcap(str(pcap), pkts)

    records = pcap_to_records(pcap, label="benign")
    assert records, "adapter produced no records"
    r = records[0]
    assert r.protocol == "dns"
    assert r.meta["label"] == "benign"
    # Same schema as the live/synthetic path.
    assert set(r.features) == set(DNS_FEATURES)
    assert sum(rec.features["query_count"] for rec in records) == 6


def test_load_cic_bell_walks_label_subdirs(tmp_path):
    (tmp_path / "benign").mkdir()
    (tmp_path / "attack").mkdir()
    wrpcap(str(tmp_path / "benign" / "b.pcap"),
           [_dns_query("www.example.local", "A", t=0.0)])
    wrpcap(str(tmp_path / "attack" / "a.pcap"),
           [_dns_query("mfrgg2loorxw.t.tunnel.example.local", "TXT", t=0.0)])

    records = load_cic_bell(tmp_path)
    labels = {r.meta["label"] for r in records}
    assert labels == {"benign", "dns_tunnel"}
