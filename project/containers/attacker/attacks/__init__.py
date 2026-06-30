"""Real-packet attack injectors for the isolated lab (Phase 2).

Each module exposes ``run(server_ip, stop_event)`` and emits genuine protocol
traffic against the collector so the passive tap captures real attack packets —
the live counterpart to the reproducible synthetic scenarios in ``eval/``. These
run only on the internal-only bridge (no route off-host); the attack classes map
to MITRE techniques in ARCHITECTURE.md §5.
"""

from . import dns_c2, dns_exfil, dns_tunnel

REGISTRY = {
    "dns_tunnel": dns_tunnel.run,   # T1572  — fan-out subdomains
    "dns_exfil": dns_exfil.run,     # T1048.003 — long data labels
    "dns_c2": dns_c2.run,           # T1071.004 — TXT beaconing
}

__all__ = ["REGISTRY"]
