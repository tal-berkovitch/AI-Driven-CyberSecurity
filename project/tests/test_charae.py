"""Char-embedding AE backend: the lexical DNS detector. It must register behind
the Detector seam, score exfil qnames above benign through the live frame
contract (a `qnames` column), and leave the numeric backends untouched.
Skipped if the `detect` extra (torch) isn't installed."""

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("torch")

from defender.detect import make_detector  # noqa: E402
from defender.detect.base import Detector  # noqa: E402
from defender.detect.char_ae import QNAME_COL, CharAEDetector  # noqa: E402
from defender.features.dns import DNS_FEATURES  # noqa: E402

# A small benign corpus (dictionary-like) vs overt high-entropy exfil names.
_BENIGN = [f"{h}.example.com" for h in
           ("www", "mail", "api", "cdn", "ns1", "shop", "login", "static",
            "img", "assets", "blog", "docs", "help", "vpn", "mx")] * 8
_EXFIL = ["mfrgg2lojnswy3dpfqqhi2djomqxa4tpnu.tunnel.evil.com",
          "k7zq9x3mab2v8q1w5e6r7t8y9u0i.exfil.bad.io",
          "nbswy3dpfqqhi2djomqgc3tufqqgs4za.c2.attacker.net"]


def _window_frame(qnames):
    """One window row: zeroed numeric features + the qnames column main.py attaches."""
    row = {c: 0.0 for c in DNS_FEATURES}
    frame = pd.DataFrame([row], columns=list(DNS_FEATURES))
    frame[QNAME_COL] = [qnames]
    return frame


@pytest.fixture(scope="module")
def fitted():
    det = CharAEDetector(epochs=8)
    det.fit(pd.DataFrame({"qname": _BENIGN}))
    return det


def test_registered_behind_detector_seam():
    det = make_detector("charae")
    assert isinstance(det, CharAEDetector)
    assert isinstance(det, Detector)


def test_scores_exfil_above_benign(fitted):
    benign = fitted.score(_window_frame(_BENIGN[:6]))[0]
    exfil = fitted.score(_window_frame(_EXFIL))[0]
    assert exfil.anomaly_score > benign.anomaly_score
    assert exfil.is_anomaly and not benign.is_anomaly


def test_attribution_uses_lexical_keys_for_mitre(fitted):
    res = fitted.score(_window_frame(_EXFIL))[0]
    assert {"query_name_length", "subdomain_entropy", "encoded_labels"} <= set(
        res.feature_attributions)
    # the worst qname is long -> its length attribution dominates
    assert res.feature_attributions["query_name_length"] > 20


def test_empty_window_is_not_anomalous(fitted):
    res = fitted.score(_window_frame([]))[0]
    assert res.anomaly_score == 0.0 and not res.is_anomaly


def test_numeric_backends_ignore_qnames_column():
    # IF selects only its own feature columns -> the extra object column is inert.
    iso = make_detector("isolation_forest")
    iso.fit(pd.DataFrame([{c: float(i % 5) for c in DNS_FEATURES} for i in range(50)],
                         columns=list(DNS_FEATURES)))
    res = iso.score(_window_frame(_EXFIL))[0]
    assert isinstance(res.anomaly_score, float)


def test_save_load_roundtrip(fitted, tmp_path):
    path = str(tmp_path / "dns_charae.pt")
    fitted.save(path)
    reloaded = make_detector("charae")
    reloaded.load(path)
    before = fitted.score(_window_frame(_EXFIL))[0].anomaly_score
    after = reloaded.score(_window_frame(_EXFIL))[0].anomaly_score
    assert np.isclose(before, after)
    assert reloaded.threshold == fitted.threshold
