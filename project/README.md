# Multi-Agent AI SOC — DNS Exfiltration/Tunneling Detection & CTI Generation

Real-time anomaly detection for DNS exfiltration and tunneling, with an LLM SOC
analyst that turns detections into explainable Cyber Threat Intelligence mapped to
MITRE ATT&CK. Built for the HIT course *AI in Cybersecurity based on NVIDIA Morpheus*.

> Full design rationale and the phased plan are in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Core idea

Two complementary unsupervised detectors learn the "normal heartbeat" of a
network's DNS traffic; deviation flags anomalies. A **character-embedding sequence
autoencoder** scores the qname strings themselves (the *lexical* signal — long,
high-entropy exfil names reconstruct badly), while an **Isolation Forest** scores
the per-window behavioral features. Both sit behind a stable interface so the
**home backends** swap for the **lab backend** (NVIDIA Morpheus DFP on a GPU box)
with a single flag — `DETECTOR_BACKEND=charae | isolation_forest | morpheus`.
On the real CIC-Bell-DNS-EXF-2021 corpus the char-AE reaches ROC-AUC 1.000
(recall 1.000 @ 0.1% FPR) on held-out exfil.

```
attacker ──▶ defender (capture ─▶ features ─▶ DETECTOR ─▶ enrich ─▶ CTI ─▶ UI) ──▶ collector
                                              ▲ pluggable backend
```

## Status

**Phase 4 — full multi-agent SOC.** Live loop verified end-to-end: isolated
3-container detonation plane (attacker/collector/defender) → autoencoder detection →
MITRE enrichment → **AG2 multi-agent** CTI → custom **FastAPI/SSE** SOC dashboard.
The two LLM-facing services (CTI worker, UI) run on the egress side and share only
the read path of `./data`; the detonation plane stays air-gapped. See the phase
table in ARCHITECTURE.md §9.

## Quick start

```bash
cp .env.example .env          # set GROQ_API_KEY for AG2 CTI + the analyst chat

# Train the detectors once (writes models/dns_{charae,isolation_forest}.pt):
uv run --extra detect python -m eval.train

# Bring up the full stack in live-detection mode:
DEFENDER_MODE=detect ATTACK_MODE=all docker compose up --build

# Then open the SOC dashboard:
#   http://localhost:8000
# Three live panels: traffic feed, analysis & statistics (counters + charts), and an
# auto-refreshing LLM situation summary.
```

Without a `GROQ_API_KEY` everything still runs: CTI falls back to a deterministic
grounded template and the summary panel renders a deterministic counters-based report.

### Verify the network is truly isolated

```bash
# Service discovery works (internal DNS):
docker compose exec attacker python -c "import socket; print(socket.gethostbyname('collector'))"

# But there is NO route to the internet (this should FAIL):
docker compose exec attacker python -c "import socket; socket.create_connection(('8.8.8.8',53),3)"
```

## Local dev environment

```bash
uv venv && uv pip install -e ".[dev]"   # add ,capture,detect,cti,ui per phase
uv run pytest                            # contract + transport round-trip tests
```

## Layout

| Path | Purpose |
|------|---------|
| `shared/schema.py` | `FeatureRecord` / `ScoreResult` / `Alert` — the only cross-stage coupling |
| `shared/transport/` | Pluggable spine: **Apache Kafka** (`TRANSPORT=kafka`, default) or file queue (`file`) |
| `shared/mitre/` | Curated DNS MITRE ATT&CK knowledge base |
| `containers/attacker` | Benign generator + attack injectors |
| `containers/collector` | DNS resolver (dnsmasq) destination + passive tap |
| `containers/defender` | Capture → features → detect → enrich → alerts (air-gapped) |
| `containers/cti` | Egress worker: AG2 multi-agent CTI from alerts → reports |
| `containers/ui` | Egress FastAPI/SSE SOC dashboard — 3 live panels (port 8000) |
| `shared/llm.py` | Groq (OpenAI-compatible) access shared by cti + ui |
| `eval/` | Evaluation harness (metrics, graded attacks, CTI mapping) |
