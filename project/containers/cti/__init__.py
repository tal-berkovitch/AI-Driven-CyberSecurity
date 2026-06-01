"""CTI worker — turns scored, MITRE-enriched Alerts into analyst-readable reports.

Runs OUTSIDE the isolated detonation network (it needs egress to reach Groq) and
shares only the file-queue volume: it consumes the `alerts` topic and emits the
`cti` topic + report files. Detonation (attacker/collector/defender) stays
air-gapped. Without a GROQ_API_KEY it degrades to a deterministic, grounded
template so the loop still produces output offline.
"""
