"""Enrichment: a scored anomaly's top features must map to the right MITRE
techniques, and protocol filtering must hold. Pure/offline — no extras needed."""

from defender.enrich import MitreEnricher

ENR = MitreEnricher()


def test_dns_tunnel_attribution_maps_to_c2_exfil_techniques():
    attr = {"mean_subdomain_entropy": 5.0, "max_qname_length": 4.0,
            "txt_query_count": 3.0, "unique_subdomains_per_domain": 2.0,
            "query_count": 0.1}
    cands = ENR.candidate_techniques("dns", attr)
    assert cands, "no techniques returned"
    assert cands[0] in {"T1071.004", "T1572", "T1048.003"}
    # every returned technique is DNS-scoped
    assert all(ENR.card(t)["protocol"] == "dns" for t in cands)


def test_snmp_walk_attribution_maps_to_discovery():
    attr = {"getnext_rate": 5.0, "oid_range_walked": 4.0, "distinct_oids": 3.0}
    cands = ENR.candidate_techniques("snmp", attr)
    assert "T1046" in cands
    assert all(ENR.card(t)["protocol"] == "snmp" for t in cands)


def test_snmp_amplify_attribution_maps_to_amplification_or_mibdump():
    attr = {"getbulk_rate": 5.0, "request_response_ratio": 4.0, "max_packet_size": 3.0}
    cands = ENR.candidate_techniques("snmp", attr)
    assert {"T1498.002", "T1602.001"} & set(cands)


def test_card_lookup_and_protocol_isolation():
    assert ENR.card("T1071.004")["name"].startswith("Application Layer Protocol")
    # DNS attribution never returns SNMP techniques
    dns = ENR.candidate_techniques("dns", {"mean_subdomain_entropy": 9.0})
    assert "T1046" not in dns
