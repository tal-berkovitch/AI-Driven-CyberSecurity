"""Custom FastAPI + SSE SOC dashboard (Phase 4.5).

Runs on the egress side, OUTSIDE the air-gapped detonation net. It only *reads*
the shared file-queue volume (mounted read-only) to stream three live panels —
traffic, analysis/statistics, and an auto-refreshing LLM situation summary — and
reaches Groq solely for that summary. All state is bounded (ring buffers +
counters in ``dashboard.DashboardState``) so memory stays flat over time.
"""
