"""Ops-agent — the ONLY component holding the Docker socket.

It exists so the read-only UI never needs host access: the agent reports per-
container CPU/RAM/status to the shared control volume (``health.json``) and
performs **allowlisted** actions (restart a `soc-*` container, apply a detector
backend) requested by the UI via the ``requests`` control topic. The detonation-
network air-gap is unaffected — this only concerns the UI/host boundary.
"""
