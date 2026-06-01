"""Enrichment: map a scored anomaly to candidate MITRE ATT&CK techniques.

Runs locally and offline (the KB is a small curated JSON), so it stays inside the
air-gapped defender. It grounds the later LLM CTI step on retrieved technique
cards rather than free generation (ARCHITECTURE.md §5).
"""

from .mitre_map import MitreEnricher

__all__ = ["MitreEnricher"]
