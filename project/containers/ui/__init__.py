"""ChainLit SOC UI (Phase 4).

Runs on the egress side, OUTSIDE the air-gapped detonation net. It only *reads*
the shared file-queue volume (mounted read-only) to stream live traffic,
anomaly alerts with per-feature evidence, and the generated CTI reports — and
offers an interactive analyst chat (Groq) grounded on the most recent alert.
Pure formatting lives in ``render`` so it can be unit-tested without ChainLit.
"""
