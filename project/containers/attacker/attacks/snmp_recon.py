"""SNMP reconnaissance / MIB walk injector (MITRE T1046, T1602.001).

Sweeps the agent's MIB tree with `snmpwalk` (a long sequential run of getnext),
the signature of SNMP enumeration: high getnext rate, broad distinct-OID range.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading

LOG = logging.getLogger("attack.snmp_recon")
WALK_ROOTS = ["1.3.6.1.2.1.2", "1.3.6.1.2.1.1", "1.3.6.1.2.1.25", "1.3.6.1.2.1.4"]


def run(server_ip: str, stop_event: threading.Event) -> None:
    intensity = os.getenv("ATTACK_INTENSITY", "loud").lower()
    gap = (1.0, 3.0) if intensity == "loud" else (8.0, 15.0)
    import random
    rng = random.Random(2025)

    LOG.warning("SNMP recon/walk injector active (intensity=%s)", intensity)
    while not stop_event.is_set():
        root = rng.choice(WALK_ROOTS) if intensity == "loud" else "1.3.6.1.2.1.2.2"
        cmd = ["snmpwalk", "-v2c", "-c", "public", "-t", "2", "-r", "0", "-On",
               server_ip, root]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=20, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            LOG.debug("snmpwalk -> %s", exc)
        stop_event.wait(rng.uniform(*gap))
