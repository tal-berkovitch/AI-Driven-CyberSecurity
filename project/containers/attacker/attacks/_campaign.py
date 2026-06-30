"""Shared 'organic campaign' rhythm for the LIVE attack injectors.

Real attacks aren't a metronome: they arrive in waves with quiet gaps, vary in
intensity, and don't line up across protocols. These helpers give each injector
an **entropy-seeded**, intermittent cadence so the live dashboard looks organic
and differs every run.

(The reproducible, seeded traffic used for *evaluation* lives in
``eval/scenarios.py`` and is untouched — only the live demo cadence changes.)
"""

from __future__ import annotations

import os
import random
import threading
import time
from collections.abc import Callable

# Default active-wave / quiet-gap ranges (seconds). An injector can override.
ACTIVE_RANGE = (15.0, 40.0)
QUIET_RANGE = (20.0, 55.0)
STAGGER_MAX = 12.0


def new_rng() -> random.Random:
    """Entropy-seeded RNG — every container run produces a different sequence."""
    return random.Random()


def resolve_intensity(rng: random.Random) -> str:
    """Per-wave intensity. An explicit ATTACK_INTENSITY=loud|slow is honored;
    anything else (default 'mixed') randomizes each wave (slight loud bias)."""
    setting = os.getenv("ATTACK_INTENSITY", "mixed").lower().strip()
    if setting in ("loud", "slow"):
        return setting
    return rng.choice(["loud", "loud", "slow"])


def run_campaign(rng: random.Random, stop_event: threading.Event,
                 do_burst: Callable[[str], None], *,
                 active: tuple[float, float] = ACTIVE_RANGE,
                 quiet: tuple[float, float] = QUIET_RANGE) -> None:
    """Alternate active waves (repeated ``do_burst(intensity)``) with quiet gaps.

    ``do_burst`` performs one burst AND waits its own inter-burst gap, so it owns
    intra-wave pacing; this loop owns wave/quiet structure and per-wave intensity.
    """
    stop_event.wait(rng.uniform(0.0, STAGGER_MAX))  # desync injectors at startup
    while not stop_event.is_set():
        intensity = resolve_intensity(rng)
        deadline = time.monotonic() + rng.uniform(*active)
        while not stop_event.is_set() and time.monotonic() < deadline:
            do_burst(intensity)
        stop_event.wait(rng.uniform(*quiet))  # quiet period between waves
