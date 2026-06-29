"""Real-packet attack injectors for the isolated lab (Phase 2).

Each module exposes ``run(server_ip, stop_event)`` and emits genuine protocol
traffic against the collector so the passive tap captures real attack packets —
the live counterpart to the reproducible synthetic scenarios in ``eval/``. These
run only on the internal-only bridge (no route off-host); the attack classes map
to MITRE techniques in ARCHITECTURE.md §5.
"""

from . import dns_tunnel

REGISTRY = {
    "dns_tunnel": dns_tunnel.run,
}

__all__ = ["REGISTRY"]
