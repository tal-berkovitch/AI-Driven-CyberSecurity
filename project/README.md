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

**Phase 0 — skeleton complete.** Isolated 3-container network, shared data
contracts (`shared/schema.py`), and the transport interface (`shared/transport/`)
are in place. See the phase table in ARCHITECTURE.md §9.

## Quick start

```bash
cp .env.example .env          # then set GROQ_API_KEY when you reach Phase 3

# Bring up the isolated 3-container network
docker compose up --build

# In the logs you should see:
#   soc-collector  | collector up; listening on udp/53 (dns) and udp/161 (snmp)
#   soc-defender   | defender up; detection backend=local
#   soc-attacker   | sent DNS query qname=www.example.local -> collector:53
#   soc-collector  | DNS query from 10.x.x.x qname=www.example.local
```

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
| `containers/collector` | Dummy DNS/SNMP destination |
| `containers/defender` | Capture → detect → enrich → CTI → UI pipeline |
| `eval/` | Evaluation harness (metrics, graded attacks) |
