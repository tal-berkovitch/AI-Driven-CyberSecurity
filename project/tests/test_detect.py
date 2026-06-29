"""Phase 2: detectors must separate benign from graded attacks, the AE must
attribute anomalies to the right features, and the metrics must be correct.
Skipped automatically if the `detect` extras (torch/scikit-learn) aren't present."""

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("torch")

from defender.detect import make_detector  # noqa: E402
from defender.detect.base import Detector  # noqa: E402
from defender.features.dns import DNS_FEATURES  # noqa: E402

from eval import metrics  # noqa: E402
from eval import scenarios  # noqa: E402


def _frame(records, schema):
    rows = [{c: r.features.get(c, 0.0) for c in schema} for r in records]
    return pd.DataFrame(rows, columns=list(schema))


# --- scenarios ---------------------------------------------------------------

def test_tunnel_separates_from_benign_in_feature_space():
    benign = scenarios.benign_dns(20, seed=1)
    tunnel = scenarios.tunnel_dns(20, "loud", seed=2)
    b = _frame(benign, DNS_FEATURES)
    t = _frame(tunnel, DNS_FEATURES)
    assert t["mean_subdomain_entropy"].mean() > b["mean_subdomain_entropy"].mean()
    assert t["max_qname_length"].mean() > b["max_qname_length"].mean()
    assert all(r.meta["label"] == "dns_tunnel" for r in tunnel)


# --- detectors ---------------------------------------------------------------

@pytest.mark.parametrize("backend", ["isolation_forest"])
def test_detector_scores_attacks_higher_than_benign(backend):
    det = make_detector(backend)
    assert isinstance(det, Detector)
    benign = scenarios.benign_dns(120, seed=10)
    train = _frame(benign[:80], DNS_FEATURES)
    benign_test = _frame(benign[80:], DNS_FEATURES)
    attack_test = _frame(scenarios.tunnel_dns(30, "loud", seed=11), DNS_FEATURES)

    det.fit(train)
    benign_scores = np.array([s.anomaly_score for s in det.score(benign_test)])
    attack_scores = np.array([s.anomaly_score for s in det.score(attack_test)])
    # Loud tunneling must be clearly more anomalous than benign on average.
    assert attack_scores.mean() > benign_scores.mean()
    # And most loud-attack windows should trip the detector's own threshold.
    preds = np.array([s.is_anomaly for s in det.score(attack_test)])
    assert preds.mean() >= 0.7


def test_isolation_forest_attributes_tunnel_to_dns_features():
    det = make_detector("isolation_forest")
    benign = scenarios.benign_dns(120, seed=20)
    det.fit(_frame(benign, DNS_FEATURES))
    attack = _frame(scenarios.tunnel_dns(10, "loud", seed=21), DNS_FEATURES)
    res = det.score(attack)[0]
    top3 = sorted(res.feature_attributions, key=res.feature_attributions.get, reverse=True)[:3]
    expected = {"mean_subdomain_entropy", "max_subdomain_entropy",
                "mean_qname_length", "max_qname_length",
                "txt_frac", "unique_subdomains_per_domain", "mean_label_count"}
    assert expected.intersection(top3), f"top features {top3} miss tunneling signature"


def test_save_load_roundtrip(tmp_path):
    det = make_detector("isolation_forest")
    benign = scenarios.benign_dns(60, seed=30)
    frame = _frame(benign, DNS_FEATURES)
    det.fit(frame)
    before = [s.anomaly_score for s in det.score(frame)]
    path = str(tmp_path / "if.joblib")
    det.save(path)
    reloaded = make_detector("isolation_forest")
    reloaded.load(path)
    after = [s.anomaly_score for s in reloaded.score(frame)]
    assert np.allclose(before, after)


def test_morpheus_backend_is_import_safe_scaffold():
    # Phase-5 scaffold: constructs without Morpheus/dfencoder installed (so the
    # defender image is unaffected); see tests/test_morpheus.py for the use-path error.
    det = make_detector("morpheus")
    assert det.__class__.__name__ == "MorpheusDetector"


# --- metrics -----------------------------------------------------------------

def test_metrics_on_perfect_separation():
    y = np.array([0, 0, 0, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9, 1.0])
    assert metrics.roc_auc(y, scores) == 1.0
    assert metrics.pr_auc(y, scores) == 1.0
    assert metrics.fpr_at_recall(y, scores, 0.9) == 0.0


def test_per_attack_recall_counts_only_attack_rows():
    labels = np.array(["benign", "benign", "dns_tunnel", "dns_tunnel"])
    preds = np.array([0, 1, 1, 0])
    rec = metrics.per_attack_recall(labels, preds)
    assert rec == {"dns_tunnel": 0.5}
    assert metrics.benign_fpr(labels, preds) == 0.5
