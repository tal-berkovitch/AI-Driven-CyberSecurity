# Requirements Traceability

Maps every clause of **`Multi-Agent Project Proposal.docx`** to its implementation,
status, and evidence. Use this as the viva / submission checklist.

Legend: ✅ done & verified · ⚠️ deviation (deliberate, defensible) · 🔜 planned (Phase 4)

---

## §1 — Problem Statement & Goal

| # | Proposal clause | Status | Where / evidence |
|---|---|---|---|
| 1.1 | Real-time anomaly detector for DNS exfiltration/tunneling | ✅ | `containers/defender/main.py` (`DetectSink`), live `DEFENDER_MODE=detect` |
| 1.2 | Isolated three-container architecture | ✅ | `docker-compose.yaml` `socnet` `internal: true` (attacker/collector/defender) |
| 1.3 | Unsupervised **Autoencoder** baselines "normal" traffic | ✅ | `containers/defender/detect/char_ae.py` (char-embedding AE); trained by `eval/charae.py` / `eval/train.py` |
| 1.4 | LLM acts as SOC Analyst → xAI + human-readable CTI | ✅ | `containers/cti/{main,prompts,groq_client}.py` |
| 1.5 | Reports mapped to **MITRE ATT&CK** | ✅ | `containers/defender/enrich/mitre_map.py`, `shared/mitre/dns_techniques.json` |
| 1.6 | Triggered "when anomalies are detected" | ✅ | AE `is_anomaly` → `Alert` → `alerts` topic → CTI worker |

## §2 — Isolated 3-Container Architecture

| # | Proposal clause | Status | Where / evidence |
|---|---|---|---|
| 2.1 | Strictly isolated Docker bridge, no leak risk | ✅ | Verified live: `defender → 8.8.8.8` = *Network unreachable* |
| 2.2 | **Attacker**: replays benign baseline + injects DNS tunneling | ✅ | `containers/attacker/main.py`, `attacks/dns_tunnel.py`, `ATTACK_MODE` |
| 2.3 | **Collector**: destination receiving DNS | ✅ | Real `dnsmasq` — `containers/collector/dnsmasq.conf`, `entrypoint.sh` |
| 2.4 | **Defender**: passively intercept, extract protocol features, route to AI pipeline | ⚠️ | Feature extraction + AI pipeline ✅ (`features/`, `detect/`, `enrich/`). **Deviation D1**: the packet *tap* runs on the collector, not the defender. |
| 2.5 | Autoencoder flags high reconstruction error | ✅ | `char_ae.py` per-character reconstruction error → `ScoreResult` |
| 2.6 | Threat-Intel Memory via **Embeddings & Vector DB** → MITRE | ⚠️ | MITRE mapping ✅ (`enrich/mitre_map.py`). **Deviation D2**: deterministic retrieval, not embeddings/vector DB. |
| 2.7 | SOC Analyst LLM → explainable report from anomaly context + raw protocol data | ✅ | `cti/prompts.py` grounds the prompt on attributions + raw `meta` context |

## §3 — Chosen Technologies

| # | Proposal clause | Status | Where / evidence |
|---|---|---|---|
| 3.1 | Docker internal-only isolated bridge | ✅ | `docker-compose.yaml` |
| 3.2 | **AG2** (multi-agent workflow) | ✅ | `containers/cti/agents.py` — per-alert Threat-Analyst + Report-Writer group chat (Groq), offline-template fallback |
| 3.3 | **ChainLit** (UI) | ⚠️✅ | Custom FastAPI/SSE dashboard instead — `containers/ui/{server,dashboard}.py` + `static/`, `ui` service (port 8000). **Deviation D3** below. |
| 3.4 | **Groq** (LPU inference) | ✅ | `containers/cti/groq_client.py` |
| 3.5 | **uv** package management | ✅ | `pyproject.toml`, all `uv run --extra …` workflows |

## §4 — Data Collection & Dataset Preparation

| # | Proposal clause | Status | Where / evidence |
|---|---|---|---|
| 4.1 | Generate & capture a **custom benign baseline** (not massive generic datasets) | ✅ | `containers/attacker` (benign gen) → tap → `data/baseline/*.csv`. **On-spec by design.** |
| 4.2 | Use that baseline to train the autoencoder | ✅ | `eval/train.py --source baseline` |
| 4.x | *(beyond proposal)* Real-dataset adapter for headline eval | ✅+ | `eval/datasets/cic_bell.py` (CIC-Bell-DNS-EXF-2021 PCAP replay) |

## §5 — Deliverables & Evaluation

| # | Proposal clause | Status | Where / evidence |
|---|---|---|---|
| 5.1 | Functional MVP with **multi-agent UI** | ✅ | FastAPI/SSE dashboard: 3 live panels (traffic / analysis+stats / LLM summary) in `containers/ui/`; AG2 multi-agent CTI (`containers/cti/agents.py`) |
| 5.2 | Isolated 3-container network | ✅ | §2.1 |
| 5.3 | AI integration | ✅ | detect → enrich → CTI loop, verified live |
| 5.4 | **Test Case A** (benign → low error, no FPs) | ✅ | `eval/run_eval.py` FPR@recall; *caveat:* small baseline → a few FPs (grow baseline) |
| 5.5 | **Test Case B** (attack → AE flags + LLM maps correct MITRE tactic) | ✅ | live loop + `eval/cti_eval.py` MITRE-mapping accuracy table |

---

## Deviations (deliberate, defensible, reversible)

### D1 — Packet tap on the collector, not the defender ("invisible gateway")
A Docker bridge is a **learning switch**: a third container cannot passively sniff
unicast traffic between two others. The tap therefore runs on the collector (which sees
100% of the flows) and feeds the defender over the file-queue spine. The defender still
performs all proposal-assigned work (feature extraction + the full AI pipeline); only the
*capture point* moved, for a correct networking reason.
*Reversible:* make the defender a routing gateway if the literal inline topology is required.
See `ARCHITECTURE.md` §2.

### D3 — Custom FastAPI/SSE dashboard instead of ChainLit
The proposal named ChainLit (§3.3), but ChainLit is a *chat* product — a single
conversational message stream — and a live SOC view forced into it becomes a flood of chat
messages, not a dashboard. We substituted a custom **FastAPI + Server-Sent-Events** web app
(`containers/ui/`) with three bordered live panels (traffic / analysis+stats charts / auto-
refreshing LLM situation summary). This satisfies the same "multi-agent UI" deliverable
(§5.1) and is a strictly better fit for a real-time operations board. All UI state is bounded
(ring buffers + fixed-size summary prompt), so memory and prompt size stay flat over uptime.

### D2 — Deterministic MITRE retrieval, not embeddings + vector DB
Mapping uses attribution-weighted token overlap between an alert's top features and a JSON
technique KB ("retrieval, not free generation") — deterministic, unit-tested
(`tests/test_enrich.py`), no model download, accuracy measured by `eval/cti_eval.py`.
*Reversible:* `chromadb` + `sentence-transformers` remain listed in the `cti` extra of
`pyproject.toml` as a drop-in upgrade path.

---

## Beyond the proposal (strengthens the lecturer's two stated concerns)
- **Pluggable detector backend** — autoencoder / isolation-forest baseline / Morpheus path
  (`containers/defender/detect/base.py`).
- **Rigorous evaluation harness** — ROC-AUC, PR-AUC, FPR@recall, per-attack recall,
  AE-vs-baseline comparison (`eval/run_eval.py`, `eval/metrics.py`). → *robust evaluation*.
- **Real-dataset adapter + graded attack intensities** (`eval/datasets/cic_bell.py`,
  `eval/scenarios.py`). → *real data*.

## Outstanding for final MVP
- All proposal clauses are now implemented. Remaining polish (not proposal requirements):
  grow the benign baseline for tighter live thresholds (§5.4 caveat); optional embedding-RAG
  upgrade for §2.6; download CIC-Bell for a real-data headline eval (§4.x).
