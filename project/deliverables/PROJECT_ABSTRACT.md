# Project Abstract — DNS Threat Detection & Cyber Threat Intelligence (CTI)

| | |
|---|---|
| **Project title** | DNS Threat Detection & Cyber Threat Intelligence (CTI): A Multi-Agent AI SOC for DNS Exfiltration / Tunneling / C2 |
| **Author / participant(s)** | Tal Berkovitch |
| **Institution** | Holon Institute of Technology (HIT) |
| **Course** | AI in Cybersecurity based on NVIDIA Morpheus |
| **Lecturer** | Andrei Kojukhov |
| **Project category** | Type 2 — Integrated Project |
| **Year / semester** | 2026 · Semester B |

---

## Abstract

Security Operations Centers are overwhelmed by false positives, and DNS — a protocol
rarely blocked at the perimeter — is routinely abused for covert data exfiltration,
tunneling, and command-and-control (C2). Signature-based tools miss novel and
low-and-slow abuse. This project delivers a real-time, multi-agent AI Security
Operations Center that detects DNS abuse from **behaviour alone** (unsupervised, with
no attack labels) and explains every detection as analyst-ready Cyber Threat
Intelligence mapped to the MITRE ATT&CK framework.

Two complementary unsupervised detectors learn the benign "normal heartbeat" of a
network's DNS traffic: a **character-embedding sequence autoencoder** that scores the
lexical shape of each query name, and an **Isolation Forest** that scores per-window
behavioural features. Both sit behind one stable interface, so the CPU "home" backends
swap for an NVIDIA **Morpheus DFP** GPU backend with a single flag. On the real
**CIC-Bell-DNS-EXF-2021** corpus the autoencoder reaches **ROC-AUC 1.000** (recall
1.000 at 0.1% false-positive rate) on held-out exfiltration. Each alert is enriched
with MITRE ATT&CK techniques via grounded retrieval and turned into a human-readable
report by a bounded multi-agent LLM workflow. The whole system runs inside a strictly
isolated, air-gapped three-container lab and streams to a live SOC dashboard.

---

## 1. Problem statement & motivation

- DNS is allowed out of almost every network, which makes it an ideal covert channel:
  attackers encode stolen data into query names (exfiltration), build interactive
  tunnels over subdomains, and beacon to C2 over TXT records.
- Generic, supervised detectors generalise poorly to a specific network and produce
  high false-positive rates; labelled attack data for every variant does not exist.
- A useful SOC tool must not only *detect* but *explain* — analysts need the evidence
  and the ATT&CK mapping, not just a score.

## 2. Goals & objectives

- **Goal:** an integrated, multi-agent AI system that is a real-time behavioural
  anomaly detector for DNS, paired with an LLM "SOC analyst" producing explainable
  CTI mapped to MITRE ATT&CK.
- **Objectives:** (1) learn a benign baseline of DNS with no attack labels; (2) flag
  exfiltration / tunneling / C2 at a very low false-positive rate; (3) auto-generate
  grounded, human-readable CTI per alert; (4) run safely in an isolated, air-gapped
  environment; (5) keep the detector swappable so a GPU Morpheus backend drops in
  unchanged.

## 3. System architecture

A strictly isolated Docker bridge network (`internal: true`, **no route to the
internet**) hosts a three-container detonation plane:

- **Attacker** — generates realistic benign DNS plus attack injectors (DNS tunneling,
  exfiltration, C2 beaconing).
- **Collector** — the destination DNS resolver (dnsmasq) where traffic terminates; it
  also hosts the **passive packet tap** (a Docker bridge is a learning switch, so the
  tap must live where the traffic terminates).
- **Defender** — capture → feature extraction → **pluggable detector** → MITRE
  enrichment → alerts.

Two further services run on the **egress** side (off the air-gapped network, sharing
only the read path of a data volume): a **CTI worker** (multi-agent LLM) and a
**FastAPI/SSE SOC dashboard**. An **Apache Kafka** topic spine carries
capture / alerts / CTI; it is the same spine Morpheus' `KafkaSourceStage` consumes.

## 4. Methods

- **Character-embedding sequence autoencoder (lexical, per query).** Embedding → GRU
  encoder → latent bottleneck → GRU decoder; the per-character reconstruction loss is
  the anomaly score. Trained on benign query names only, it learns the lexical "shape"
  of normal names, so high-entropy base32/base64 exfil labels reconstruct badly and
  stand out. A bootstrapped, window-aware threshold controls the per-window
  false-positive rate.
- **Isolation Forest (behavioural, per window).** Scores aggregate features — query
  rate, subdomain entropy, qtype mix, NXDOMAIN rate, unique subdomains per domain —
  catching volumetric and word-encoded abuse the lexical model misses.
- **Swappable backend.** Both implement one `Detector` contract
  (`fit`/`score`/`save`/`load`); `DETECTOR_BACKEND = charae | isolation_forest |
  morpheus` selects at runtime with no downstream changes.
- **Explainable CTI.** Per-feature attribution + raw context → retrieval over a curated
  DNS MITRE ATT&CK knowledge base (RAG) → a bounded **AG2** multi-agent group chat
  (Threat-Analyst confirms the supported techniques, Report-Writer emits the report)
  on the **Groq** LLM endpoint. The LLM is grounded on retrieved technique cards plus
  the quantified evidence; a deterministic template is the offline fallback.

## 5. Datasets

- **Benign baseline** — realistic, self-generated DNS (multiple qtypes, jitter),
  augmented with synthetic reverse-DNS (PTR) names to prevent a domain-shift false
  positive; split train / validation / test.
- **Real attacks** — **CIC-Bell-DNS-EXF-2021** PCAPs, replayed through the *same* live
  feature parser used in production, for the headline evaluation.
- **Graded synthetic attacks** — a difficulty gradient from overt high-entropy exfil
  down to word-encoded, low-and-slow payloads, so the evaluation is not trivially
  separable.

## 6. Evaluation & results

| Metric (held-out exfiltration, CIC-Bell) | Char-AE | Isolation Forest |
|---|---|---|
| ROC-AUC | **1.000** | ~0.91 |
| PR-AUC | **1.000** | — |
| Recall @ 0.1% FPR | **1.000** | — |

- **Representation > algorithm:** the per-query lexical signal separates real
  exfiltration that the window-aggregate behavioural model tops out at ~0.91 ROC-AUC on.
- **Domain-shift false positive found and fixed:** reverse-DNS PTR lookups were
  over-flagged (score 4.89); benign augmentation dropped them to 1.04, with 100% of
  benign PTR below threshold and exfil detection unchanged.
- **Honest robustness envelope:** high-entropy exfil is caught perfectly; word-encoded
  payloads evade the lexical model and are covered by the behavioural complement.
- **CTI mapping:** correct MITRE technique at **top-3 = 1.000** across tunneling
  (T1572), exfiltration (T1048.003), and C2 (T1071.004).
- **Air-gap verified:** the detonation plane has no internet (defender → 8.8.8.8 fails)
  while internal service discovery works.

## 7. Key contributions

1. A label-free DNS abuse detector that reaches ROC-AUC 1.000 on a real corpus by
   modelling the *lexical* structure of query names per query rather than per window.
2. A defence-in-depth pairing (lexical + behavioural) behind one interface, with a
   documented honest failure mode.
3. An end-to-end explainability path: the same per-feature attribution that drives
   evaluation also grounds the LLM CTI, mapped to MITRE ATT&CK.
4. A safe, reproducible, air-gapped multi-agent SOC with a CPU→GPU (Morpheus) swap
   built in from day one.

## 8. Technologies

Docker (internal-only isolated bridge) · Apache Kafka (KRaft) transport spine ·
PyTorch (char-embedding autoencoder) · scikit-learn (Isolation Forest) · NVIDIA
Morpheus DFP (plug-and-play GPU backend) · AG2 multi-agent orchestration · Groq
(OpenAI-compatible LLM inference) · FastAPI + Server-Sent Events dashboard · `uv`
Python environment.

## 9. Deliverables

- Fully functional multi-agent SOC (isolated 3-container plane + egress CTI/UI),
  runnable with `docker compose`.
- Trained detectors and a reproducible evaluation harness emitting a single results
  report (ROC/PR/recall, the reverse-DNS fix, the stress envelope, the behavioural
  baseline).
- Live SOC dashboard (traffic feed, analysis & statistics, LLM situation summary).

## 10. Limitations & future work

- The lexical model is, by design, blind to word-encoded payloads (covered today by
  the behavioural detector); adaptive thresholds and online learning would track
  domain shift further.
- Run the **Morpheus DFP** GPU backend (scaffold ready) for a CPU-vs-GPU throughput
  comparison.
- Extend the approach to additional covert-channel protocols.

## References

- CIC-Bell-DNS-EXF-2021 dataset (Canadian Institute for Cybersecurity).
- MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol
  Tunneling), T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol).
- NVIDIA Morpheus (Digital Fingerprinting pipeline).
