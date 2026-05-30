# AI-Driven CyberSecurity

**Author: Tal Berkovitch**

A collection of labs exploring the intersection of AI/LLMs and cybersecurity — from threat intelligence analysis to agentic defense systems and event-driven pipelines.

## Labs

### Lab 1 — CTI Report Mapping to MITRE ATT&CK
Manual analysis of a real-world cyber threat intelligence report (a suspected APT campaign targeting Ivanti VPN appliances via two zero-day CVEs). Maps observed attacker behaviors to the MITRE ATT&CK framework across tactics: Initial Access, Persistence, Defense Evasion, Credential Access, and Exfiltration.

### Lab 2 — Anomaly Detection on Authentication Logs
Unsupervised anomaly detection on a synthetic dataset of 10,000 authentication events. An Isolation Forest model identifies two MITRE ATT&CK behaviors — T1110 (Brute Force) and T1078 (Valid Accounts / compromised credentials) — without access to ground-truth labels. Results are visualized via a 2D PCA projection showing clear separation between normal and malicious clusters.

### Lab 3 — Network Security Analyzer Agent
A conversational AI agent built with Chainlit and Groq that analyzes network security topics using tool use. The agent can reason through security questions, invoke tools, and return structured findings. Runs in Docker.

### Lab 4 — Prompt Injection Defense Workflow
A multi-agent workflow that defends an LLM-based cybersecurity advisor against prompt injection attacks. A dedicated `GuardAgent` classifies every incoming message (`allowed` / `offtopic` / `injection`) before it reaches the advisor. Blocked inputs are routed to a `RefusalAgent` — the protected advisor never sees injected instructions.

### Lab 5 — Event-Driven Cybersecurity Pipeline with Kafka and Tracing
An event-driven pipeline for cybersecurity event classification using Kafka (via Redpanda), Jaeger for distributed tracing, and JupyterLab notebooks. A producer publishes security events, a consumer classifies them against MITRE ATT&CK, and a statistics notebook visualizes the results.

## Tech Stack

- **LLM inference:** Groq API
- **Agent UI:** Chainlit
- **Messaging:** Apache Kafka / Redpanda
- **Tracing:** Jaeger (OpenTelemetry)
- **Notebooks:** JupyterLab
- **Containerization:** Docker / Docker Compose
