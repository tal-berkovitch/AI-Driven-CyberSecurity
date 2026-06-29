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


def test_charae_lexical_attribution_maps_to_dns_techniques():
    # The char-embedding AE backend emits these lexical keys for the worst qname.
    attr = {"query_name_length": 54.0, "subdomain_entropy": 4.2, "encoded_labels": 37.0,
            "qname_reconstruction_error": 12.7}
    cands = ENR.candidate_techniques("dns", attr)
    assert cands, "no techniques returned"
    assert cands[0] in {"T1071.004", "T1572", "T1048.003"}
    assert all(ENR.card(t)["protocol"] == "dns" for t in cands)


def test_card_lookup_and_all_techniques_are_dns_scoped():
    assert ENR.card("T1071.004")["name"].startswith("Application Layer Protocol")
    cands = ENR.candidate_techniques("dns", {"mean_subdomain_entropy": 9.0})
    assert cands and all(ENR.card(t)["protocol"] == "dns" for t in cands)
