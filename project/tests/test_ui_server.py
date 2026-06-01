"""Server smoke test — skipped unless FastAPI + the test client (httpx) are
installed (the `ui` extra). Exercises the static routes only; SSE streaming and
the background tasks are verified live, not in unit tests."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from ui.server import app  # noqa: E402


def test_healthz_ok():
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["ok"] is True


def test_index_serves_dashboard_html():
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "SOC Dashboard" in r.text
        assert 'id="traffic"' in r.text          # the live-traffic panel is present
