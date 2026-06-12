"""Morpheus backend is a plug-and-play scaffold: import-safe everywhere, and it
only errors (with an install hint) when actually used without dfencoder."""

import pandas as pd
import pytest

from defender.detect import make_detector


def test_make_morpheus_is_import_safe():
    # Constructing the backend must NOT require Morpheus/dfencoder to be installed.
    det = make_detector("morpheus")
    assert det.__class__.__name__ == "MorpheusDetector"


def test_morpheus_errors_clearly_without_dfencoder():
    try:
        import dfencoder  # noqa: F401
        pytest.skip("dfencoder installed — the failure path doesn't apply")
    except ImportError:
        pass
    det = make_detector("morpheus")
    with pytest.raises(RuntimeError, match="dfencoder|Morpheus"):
        det.fit(pd.DataFrame({"a": [0.0, 1.0]}))
