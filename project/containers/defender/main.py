"""Defender agent — Phase 0 stub (gateway + AI plane).

Phase 0 only confirms the agent boots, can see its configured detection backend,
and can import the shared contracts. The real pipeline is assembled here over the
next phases:

    capture -> features -> DETECTOR (pluggable) -> enrich (MITRE) -> CTI (LLM) -> UI

The backend is chosen from DETECTOR_BACKEND (local | isolation_forest | morpheus)
so the home->Morpheus switch is a config change, not a code change.
"""

from __future__ import annotations

import logging
import os
import time

# Importing these here proves the shared contract package is wired into the image.
from shared.schema import Alert, FeatureRecord, ScoreResult  # noqa: F401

LOG = logging.getLogger("defender")

VALID_BACKENDS = {"local", "isolation_forest", "morpheus"}


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    backend = os.getenv("DETECTOR_BACKEND", "local")
    if backend not in VALID_BACKENDS:
        LOG.warning("unknown DETECTOR_BACKEND=%r (expected one of %s)", backend, VALID_BACKENDS)

    LOG.info("defender up; detection backend=%s", backend)
    LOG.info("shared contracts loaded: FeatureRecord/ScoreResult/Alert OK")
    LOG.info("Phase 0 stub — capture/detect/enrich/cti pipeline not yet wired")

    # Heartbeat so the container stays alive and visible in `docker compose logs`.
    while True:
        time.sleep(30)
        LOG.debug("heartbeat (backend=%s)", backend)


if __name__ == "__main__":
    main()
