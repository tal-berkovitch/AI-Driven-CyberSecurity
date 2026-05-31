"""Evaluation harness — the rigor centerpiece (ARCHITECTURE.md §6).

Generates labeled, difficulty-graded synthetic scenarios through the *real*
feature extractors, then benchmarks every detector backend on identical data and
emits one comparison table. The synthetic track here is paired with a real
dataset (CIC-Bell-DNS-EXF-2021) adapter so evaluation is not self-referential.
"""

# The per-agent packages live under containers/ (imported as `defender.*` /
# `shared.*` inside their images). Make them importable when the eval harness
# runs on the host via `python -m eval.run_eval`, mirroring pytest's pythonpath.
import sys as _sys
from pathlib import Path as _Path

_CONTAINERS = _Path(__file__).resolve().parent.parent / "containers"
if str(_CONTAINERS) not in _sys.path:
    _sys.path.insert(0, str(_CONTAINERS))
