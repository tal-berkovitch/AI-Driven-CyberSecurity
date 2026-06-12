# Architecture: Multi-Agent AI System for DNS/SNMP Anomaly Detection & CTI Generation

**Course:** AI in Cybersecurity based on NVIDIA Morpheus (HIT)
**Category:** Type 2 — Integrated Project
**Author:** Tal Berkovitch

---

## 1. Design principles

Three principles drive every decision below:

1. **Swappable detection backend.** The anomaly detector is hidden behind one
   interface. The "home" backend (local autoencoder, CPU/local GPU) and the
   "lab" backend (NVIDIA Morpheus DFP on a lab GPU box) are interchangeable via
   a single config flag. *No downstream code changes when switching.*
2. **Stable data contracts.** Every stage communicates through fixed schemas
   (`FeatureRecord`, `ScoreResult`, `Alert`). The feature schema is designed to
   be **Morpheus-DFP-compatible from day one** (flat numeric/categorical table)
   so there is zero migration tax when the Morpheus box becomes available.
3. **Incremental full vision.** The full proposal (3 isolated containers, inline
   gateway, multi-agent orchestration) is built in phases; each phase leaves a
   working, demonstrable, defensible slice.

---

## 2. Runtime topology (the "full vision")

Strictly isolated Docker bridge network (`internal: true`, no route to host/WAN).

```
            ┌──────────────────────────────────────────────────────────┐
            │            isolated docker bridge (internal-only)          │
            │                                                            │
  ┌─────────┴─────────┐      ┌───────────────────────┐     ┌────────────┴────────┐
  │  Container 1       │      │  Container 2           │     │  Container 3        │
  │  ATTACKER          │      │  DEFENDER              │     │  COLLECTOR          │
  │  (traffic gen)     │─────▶│  (gateway + AI plane)  │────▶│  (dummy dest)       │
  │                    │      │                        │     │                     │
  │ benign generator   │      │ capture → features     │     │ DNS resolver        │
  │ attack injectors:  │      │   → DETECTOR (pluggable)│     │   (dnsmasq/CoreDNS) │
  │  - DNS tunneling   │      │   → enrichment (MITRE) │     │ SNMP agent (snmpd)  │
  │  - SNMP recon/walk │      │   → CTI (LLM)          │     │                     │
  │  - SNMP amplify    │      │   → ChainLit UI        │     │                     │
  └────────────────────┘      └───────────┬────────────┘     └─────────────────────┘
                                           │
                              feature/alert transport (Kafka topic)
                                           │
                       ┌───────────────────┴────────────────────┐
                       │  DETECTION BACKEND (swappable consumer)  │
                       │   local: Python AE / IsolationForest     │
                       │   lab:   Morpheus DFP pipeline (GPU)     │
                       └──────────────────────────────────────────┘
```

**Why Kafka as the spine.** The feature extractor publishes to a `features`
topic and consumes from an `alerts` topic. In *local mode* a plain Python
consumer reads `features`, scores, and writes `alerts`. In *Morpheus mode* a
Morpheus `KafkaSourceStage` reads the **same** `features` topic, runs GPU
inference, and writes the **same** `alerts` topic. Enrichment, CTI, and UI
consume `alerts` and never know which backend produced them. This is what makes
the home→Morpheus switch free. (Kafka + Morpheus + Triton is also the exact
accelerated stack the course examples reference.)

> **Transport (Phase 4.7).** The streaming spine (`capture`/`alerts`/`cti`) runs over
> **Apache Kafka (KRaft, single broker)** by default — `TRANSPORT=kafka`, selected by
> `shared/transport.make_producer/make_consumer` behind the `Producer`/`Consumer`
> protocol; the file-queue (`TRANSPORT=file`) stays the offline/test fallback. The
> broker is **dual-homed** on `socnet` + the egress net so both planes share one bus,
> but `socnet` stays `internal:true` (detonation still has **no internet**) and topics
> are one-way (detonation publishes; egress consumes). The **control plane** (ops
> requests/health, model/backend selection) and `model_card.json`/reports stay on the
> shared `./data` volume. This is the same Kafka spine Morpheus' `KafkaSourceStage` reads.

**Where the packet tap runs (Phase 1 decision).** A Docker bridge is a learning
switch, so a third container in promiscuous mode cannot passively see unicast
traffic between two *other* containers. The defender therefore cannot sniff
attacker→collector traffic directly. The tap instead lives on the **collector**,
where 100% of benign traffic terminates and is visible — capture stays fully
passive, no inline routing required. The collector parses each packet into a
flat `CaptureEvent` and publishes it on a `capture` topic of the file-queue
spine; the **defender** consumes those, extracts features, and (Phase 2+) scores
them. So Phase 1 already exercises the producer/consumer spine end-to-end; the
only change at the Kafka/Morpheus boundary is that the topic carries
`FeatureRecord` instead of `CaptureEvent`.

---

## 3. The detection contract (the linchpin)

```python
# shared/schema.py
@dataclass
class FeatureRecord:
    protocol: str            # "dns" | "snmp"
    ts: float
    src: str
    dst: str
    features: dict[str, float]   # flat, numeric — Morpheus-DFP compatible
    meta: dict                    # raw context for the LLM (query name, OIDs…)

@dataclass
class ScoreResult:
    anomaly_score: float          # reconstruction error / model score
    is_anomaly: bool
    feature_attributions: dict[str, float]   # per-feature contribution (z-score)

@dataclass
class Alert:
    record: FeatureRecord
    score: ScoreResult
    candidate_techniques: list[str]   # MITRE IDs from enrichment
    cti_report: str | None            # filled by CTI stage
```

```python
# defender/detect/base.py
class Detector(Protocol):
    def fit(self, baseline: pd.DataFrame) -> None: ...
    def score(self, features: pd.DataFrame) -> list[ScoreResult]: ...
    def save(self, path: str) -> None: ...
    def load(self, path: str) -> None: ...
```

Backends (selected by `DETECTOR_BACKEND` env var):

| Backend            | Class                       | Role                                   |
|--------------------|-----------------------------|----------------------------------------|
| `local`            | `LocalAutoencoderDetector`  | Home pipeline (PyTorch, CPU/local GPU) |
| `isolation_forest` | `IsolationForestDetector`   | **Evaluation baseline to beat**        |
| `morpheus`         | `MorpheusDetector`          | Lab GPU pipeline (Morpheus DFP)        |

**Key alignment:** the local autoencoder mirrors Morpheus `dfencoder`'s
per-feature loss, so `feature_attributions` (the explainability signal feeding
the LLM) is identical across backends. Evaluation rigor and LLM explainability
share one mechanism.

---

## 4. Feature engineering (physically meaningful → explainable)

**DNS** — `query_name_length`, `subdomain_entropy`, `label_count`,
`txt_record_count`, `null_record_count`, `qtype_distribution`,
`unique_subdomains_per_domain`, `query_rate`, `response_size`,
`upstream_vs_cached_ratio`.

**SNMP** — `get_rate`, `getnext_rate`, `getbulk_rate`, `oid_range_walked`,
`packet_size`, `request_response_ratio`, `community_string_entropy`,
`distinct_oids_per_window`.

These map directly to attacker behavior (e.g., DNS tunneling inflates
`query_name_length` + `subdomain_entropy` + `txt_record_count`; an SNMP walk
inflates `getnext_rate` + `distinct_oids_per_window`), which is exactly what the
per-feature attribution will surface for the LLM.

---

## 5. CTI / explainability layer

```
ScoreResult.feature_attributions  ─┐
FeatureRecord.meta (raw context)  ─┼─▶ vector DB (MITRE DNS/SNMP KB)
                                   │      → candidate techniques (RAG)
                                   └─▶ Groq LLM (SOC-analyst prompt)
                                          → human-readable CTI report
```

- **MITRE knowledge base** (`shared/mitre/`): curated JSON of DNS/SNMP-relevant
  techniques with descriptions, embedded for retrieval. Small and auditable.
- **RAG, not free generation:** the LLM is grounded on retrieved technique cards
  + the quantified anomaly evidence, reducing hallucination.

**MITRE ground-truth labels** (also the eval keys):

| Attack class        | MITRE technique(s)                                          |
|---------------------|------------------------------------------------------------|
| DNS tunneling (C2)  | T1071.004 (App Layer Protocol: DNS), T1572 (Protocol Tunneling) |
| DNS exfiltration    | T1048 / T1048.003 (Exfil over alternative/unencrypted protocol) |
| SNMP recon / walk   | T1046 (Network Service Discovery)                          |
| SNMP MIB dump       | T1602.001 (Data from Config Repo: SNMP MIB Dump)           |
| SNMP amplification  | T1498.002 (Reflection Amplification — DDoS)                |

> Note: the proposal mixed "SNMP reconnaissance" (T1046) and "SNMP reflection"
> (T1498.002) — these are distinct. We support both as separate attack classes.

---

## 6. Evaluation harness (a first-class deliverable)

This is the centerpiece that answers the lecturer's "robust evaluation" concern.

**Datasets**
- Benign: diverse, realistic (multiple qtypes, realistic timing/jitter, mixed
  SNMP polling cadences). Split train/validation/test.
- Attacks on a **difficulty gradient**: loud (high-volume tunneling, fast walk)
  → subtle (low-and-slow tunneling, paced walk). This is what prevents the
  evaluation from being trivially separable.

**Detection metrics** — ROC-AUC, PR-AUC, **FPR at fixed recall**, per-attack
recall, detection latency. Reported **for every backend** (local AE vs
Isolation Forest vs Morpheus AE) → a single comparison table.

**CTI metrics** — MITRE mapping **top-1 / top-k accuracy** vs ground truth;
retrieval hit-rate (reported separately from generation quality); report
faithfulness via a short rubric.

**Throughput** — events/sec and per-event latency, used for the **CPU vs GPU**
comparison once Morpheus is in (directly hits a course example).

---

## 7. Orchestration & UI (Phase 4)

Both LLM-facing pieces run on the **egress side**, OFF the air-gapped `socnet`,
and touch the pipeline only through the shared `./data` file-queue. The detonation
plane (attacker/collector/defender) never gains internet access.

- **AG2** drives CTI generation in the **CTI worker** (`containers/cti/agents.py`):
  a bounded per-alert group chat — a **Threat-Analyst** agent assesses severity and
  confirms which retrieved MITRE techniques the evidence supports, a **Report-Writer**
  agent emits the final report. It reuses the *same* grounded evidence as the
  deterministic path, and `generate_cti` returns `None` (→ offline template) on a
  missing key, a missing `autogen` install, or any error — so AG2 is a presentation/
  orchestration layer, never a hard dependency of the core.
- **SOC dashboard** (`containers/ui/`, FastAPI + Server-Sent Events): a 5th container on
  the egress network, port 8000. It tails the shared queue **read-only** and pushes three
  bordered live panels to the browser — (1) **Live Traffic** (capture feed), (2) **Analysis
  & Statistics** (counters + alerts-over-time and MITRE-frequency charts + a recent-alerts
  list expandable to its CTI report), (3) an auto-refreshing **LLM Situation Summary**.
  All state is **bounded**: `deque(maxlen=…)` ring buffers + small counters, and the queue
  consumer **seeks to EOF on startup** so the on-disk backlog is never loaded into memory.
  The summary prompt is built only from the rolling counters + the last K alerts, so it is
  fixed-size regardless of uptime. Pure state/builders live in `ui/dashboard.py`; the
  FastAPI shell + SSE in `ui/server.py`; the hand-built panels in `ui/static/`.
  *(The proposal named ChainLit, but ChainLit is a chat product — a multi-panel SOC board
  is what the project needs, so we substituted a custom dashboard; same "multi-agent UI"
  requirement, better fit.)*
- **Groq** (OpenAI-compatible endpoint, via `shared/llm.py`) for both AG2 and the UI
  situation summary; **uv** for the Python environment.

---

## 8. Repository structure

```
project/
  docker-compose.yaml         # isolated bridge, 3 services (+ kafka)
  .env.example                # DETECTOR_BACKEND, GROQ_API_KEY, ...
  pyproject.toml              # uv-managed
  ARCHITECTURE.md
  shared/
    schema.py                 # FeatureRecord / ScoreResult / Alert
    capture.py                # CaptureEvent (sensor -> feature plane)  [Phase 1]
    dns.py                    # stdlib DNS wire helpers
    llm.py                    # Groq (OpenAI-compat) access for cti+ui   [Phase 4]
    mitre/                    # curated DNS/SNMP technique KB (json)
    transport/                # producer/consumer iface (file → kafka)
  containers/
    attacker/  main.py (benign DNS+SNMP generator) [Phase 1]; attacks/ [Phase 2]
    collector/ dnsmasq.conf, snmpd.conf, entrypoint.sh, sensor.py (passive tap) [Phase 1]
    defender/
      features/   util.py, dns.py, snmp.py, windows.py → FeatureRecord   [Phase 1]
      baseline.py capture-consumer writes benign baseline CSV            [Phase 1]
      detect/     base.py, local_ae.py, isolation_forest.py, morpheus/   [Phase 2]
      enrich/     mitre_map.py: attribution → MITRE techniques           [Phase 3]
      main.py     record: features→CSV | detect: score→enrich→alerts     [Phase 1/3]
    cti/          prompts.py, main.py — egress worker                    [Phase 3]
                  agents.py: AG2 multi-agent CTI group chat (egress)     [Phase 4]
    ui/           server.py (FastAPI+SSE), dashboard.py, static/ —       [Phase 4.5]
                  egress 3-panel SOC dashboard (traffic/stats/LLM summary)
  eval/
    scenarios.py  graded labeled synthetic traffic via real extractors  [Phase 2]
    metrics.py    ROC/PR-AUC, FPR@recall, per-attack recall             [Phase 2]
    run_eval.py   benchmark all backends -> report/results.{md,csv}     [Phase 2]
    datasets/cic_bell.py  CIC-Bell-DNS-EXF-2021 PCAP-replay adapter      [Phase 2]
    train.py      fit AE on benign baseline -> models/{proto}_local.pt   [Phase 3]
    cti_eval.py   MITRE mapping top-1/top-k accuracy                     [Phase 3]
  data/
    queue/  baseline/  eval/  real/  reports/   # spine; CSVs; datasets; CTI reports
  models/      # trained detectors (gitignored)
  notebooks/   tests/
```

---

## 9. Phased build plan

| Phase | Deliverable (each is independently defensible)                          |
|-------|------------------------------------------------------------------------|
| 0 | Repo + uv + docker-compose; 3 stub containers on isolated bridge; `schema.py`; transport iface. **Proof: containers talk, net is isolated.** |
| 1 | Benign generators (DNS+SNMP), collector services, capture + feature extraction → baseline CSV. **Proof: real benign feature dataset.** |
| 2 | `local` AE + `isolation_forest` behind `Detector`; graded attack injectors; eval harness. **Proof: benchmark table — the rigor centerpiece.** |
| 3 | MITRE KB + vector DB + Groq CTI using per-feature attributions; CTI eval. **Proof: explainable reports + mapping accuracy.** |
| 4 | ✅ AG2 multi-agent CTI (egress) + custom FastAPI/SSE SOC dashboard — 3 live panels: traffic, analysis+stats charts, auto-refreshing LLM summary (egress, port 8000). **Proof: live multi-agent SOC demo; air-gap preserved.** (Kafka transport deferred — file-queue spine still in use.) |
| 5 | `morpheus` backend — **plug-and-play scaffold ready** (`detect/morpheus.py`, dfencoder-based, import-safe). On the lab GPU box: `eval.train --backends morpheus` + `DETECTOR_BACKEND=morpheus`; no further code. **Proof (next): Morpheus results + CPU-vs-GPU throughput.** |
| 6 | Written report + presentation/demo. |

**Scope-control guarantee:** if time runs short, stopping after Phase 3 still
yields a complete, evaluated, explainable detection system. Phases 4–5 are
upside, not load-bearing.

---

## 10. Open risks & mitigations

| Risk | Mitigation |
|------|------------|
| Evaluation looks circular (synthetic benign vs synthetic attack) | Difficulty-graded attacks + baselines to beat + FPR reporting (§6) |
| Inline transparent gateway eats time | Start with passive bridge sniffer (same features); true inline = stretch |
| AG2 adds failure modes to the core | Core pipeline works without AG2; AG2 is a Phase-4 presentation layer |
| Morpheus box availability/timing | Home pipeline is fully functional; Morpheus is a swap-in via stable contract |
| LLM hallucinated CTI | RAG grounding + separate retrieval-accuracy metric |
```
