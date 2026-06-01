# Multi-Agent AI SOC — DNS/SNMP Anomaly Detection & CTI Generation

Real-time behavioral anomaly detection for DNS and SNMP traffic, with an LLM SOC
analyst that turns detections into explainable Cyber Threat Intelligence mapped to
MITRE ATT&CK. Built for the HIT course *AI in Cybersecurity based on NVIDIA Morpheus*.

> Full design rationale and the phased plan are in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Core idea

An unsupervised autoencoder learns the "normal heartbeat" of a network's DNS/SNMP
traffic; high reconstruction error flags anomalies. The detector sits behind a
stable interface so the **home backend** (local PyTorch AE) can be swapped for the
**lab backend** (NVIDIA Morpheus DFP on a GPU box) with a single config flag —
`DETECTOR_BACKEND=local | isolation_forest | morpheus`.

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

# Train the detector(s) once (writes models/{dns,snmp}_local.pt):
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
| `shared/transport/` | Pluggable message transport (file queue now, Kafka later) |
| `shared/mitre/` | Curated DNS/SNMP MITRE ATT&CK knowledge base |
| `containers/attacker` | Benign generator + attack injectors |
| `containers/collector` | Dummy DNS/SNMP destination + passive tap |
| `containers/defender` | Capture → features → detect → enrich → alerts (air-gapped) |
| `containers/cti` | Egress worker: AG2 multi-agent CTI from alerts → reports |
| `containers/ui` | Egress FastAPI/SSE SOC dashboard — 3 live panels (port 8000) |
| `shared/llm.py` | Groq (OpenAI-compatible) access shared by cti + ui |
| `eval/` | Evaluation harness (metrics, graded attacks, CTI mapping) |
