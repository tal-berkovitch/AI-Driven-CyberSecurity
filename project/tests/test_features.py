"""Feature-extraction tests: benign vs attack-shaped traffic must separate, and
the windowing must close windows correctly. These features are the Phase-2
detector's input and the Phase-3 LLM's evidence, so their behavior is pinned."""

from defender.baseline import BaselineWriter
from defender.features import WindowAggregator
from defender.features.dns import DNS_FEATURES
from defender.features.dns import extract as dns_extract
from defender.features.snmp import SNMP_FEATURES
from defender.features.snmp import extract as snmp_extract
from defender.features.util import char_entropy, registered_domain, subdomain_of

from shared.capture import CaptureEvent


def _dns(qname, qtype="A", is_response=False, **kw):
    return CaptureEvent(proto="dns", ts=kw.pop("ts", 0.0), src=kw.pop("src", "10.20.0.99"),
                        dst="10.20.0.2", size=kw.pop("size", 64), is_response=is_response,
                        qname=qname, qtype=qtype, **kw)


def _snmp(pdu, oids, community="public", **kw):
    return CaptureEvent(proto="snmp", ts=kw.pop("ts", 0.0), src=kw.pop("src", "10.20.0.99"),
                        dst="10.20.0.2", size=kw.pop("size", 80), pdu=pdu,
                        community=community, oids=oids)


# --- utilities ---------------------------------------------------------------

def test_char_entropy_orders_words_below_random_blobs():
    assert char_entropy("www") < char_entropy("k7zq9x3mab2v8")


def test_domain_split():
    assert registered_domain("a.b.example.local") == "example.local"
    assert subdomain_of("a.b.example.local") == "ab"
    assert subdomain_of("example.local") == ""


# --- DNS features ------------------------------------------------------------

def test_dns_benign_has_low_entropy_and_full_schema():
    events = [_dns(f"{h}.example.local") for h in ("www", "api", "mail", "db")]
    feats, meta = dns_extract(events, window_s=10.0)
    assert set(feats) == set(DNS_FEATURES)            # schema is complete + exact
    assert feats["query_count"] == 4
    assert feats["mean_subdomain_entropy"] < 2.0       # real words = low entropy
    assert feats["a_frac"] == 1.0
    assert "sample_qnames" in meta


def test_dns_tunneling_shape_spikes_entropy_and_length():
    benign = [_dns("www.example.local")]
    tunnel = [_dns(f"{blob}.tunnel.example.local")
              for blob in ("mfrgg2loor", "nbswy3dpfq", "ozqwy5dbnz", "k7zq9x3mab2v8q1")]
    b, _ = dns_extract(benign, 10.0)
    t, _ = dns_extract(tunnel, 10.0)
    assert t["mean_subdomain_entropy"] > b["mean_subdomain_entropy"]
    assert t["max_qname_length"] > b["max_qname_length"]


def test_dns_nxdomain_counted_from_responses():
    events = [_dns("nope.example.local", is_response=True, rcode="name-error")]
    feats, _ = dns_extract(events, 10.0)
    assert feats["nxdomain_count"] == 1
    assert feats["response_count"] == 1


# --- SNMP features -----------------------------------------------------------

def test_snmp_walk_shape_inflates_getnext_and_oid_breadth():
    walk = [_snmp("getnext", [f"1.3.6.1.2.1.2.2.1.10.{i}"]) for i in range(1, 9)]
    feats, _ = snmp_extract(walk, window_s=10.0)
    assert set(feats) == set(SNMP_FEATURES)
    assert feats["getnext_rate"] > 0
    assert feats["oid_range_walked"] == 8
    assert feats["distinct_oids"] == 8


def test_snmp_community_entropy_zero_for_single_community():
    events = [_snmp("get", ["1.3.6.1.2.1.1.1.0"]) for _ in range(5)]
    feats, _ = snmp_extract(events, 10.0)
    assert feats["community_entropy"] == 0.0
    assert feats["distinct_communities"] == 1


# --- windowing ---------------------------------------------------------------

def test_aggregator_closes_window_when_later_event_arrives():
    agg = WindowAggregator(window_s=10.0)
    # window 0 events
    assert agg.add(_dns("www.example.local", ts=1.0)) == []
    assert agg.add(_dns("api.example.local", ts=2.0)) == []
    # an event in window 1 closes window 0
    out = agg.add(_dns("db.example.local", ts=11.0))
    assert len(out) == 1
    rec = out[0]
    assert rec.protocol == "dns"
    assert rec.ts == 0.0                 # window start
    assert rec.features["query_count"] == 2
    # window 1 still open until flushed
    tail = agg.flush_all()
    assert len(tail) == 1 and tail[0].ts == 10.0


def test_aggregator_separates_protocols_and_sources():
    agg = WindowAggregator(window_s=10.0)
    agg.add(_dns("www.example.local", ts=1.0, src="10.20.0.5"))
    agg.add(_dns("www.example.local", ts=1.0, src="10.20.0.6"))
    agg.add(_snmp("get", ["1.3.6.1.2.1.1.1.0"], ts=1.0))
    out = agg.flush_all()
    keys = {(r.protocol, r.src) for r in out}
    assert keys == {("dns", "10.20.0.5"), ("dns", "10.20.0.6"), ("snmp", "10.20.0.99")}


def test_baseline_writer_emits_header_and_rows(tmp_path):
    agg = WindowAggregator(window_s=10.0)
    agg.add(_dns("www.example.local", ts=1.0))
    records = agg.flush_all()
    writer = BaselineWriter(tmp_path)
    writer.write_many(records)
    csv_path = tmp_path / "dns_baseline.csv"
    assert csv_path.exists()
    lines = csv_path.read_text().splitlines()
    assert lines[0].startswith("ts,src,dst,")
    assert "query_count" in lines[0]
    assert len(lines) == 2                # header + one row
    assert writer.counts["dns"] == 1
