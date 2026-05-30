# Lab 5 — Event-Driven Cybersecurity Pipeline with Kafka and Tracing

Event-driven cybersecurity analysis pipeline using Kafka, Jaeger, and JupyterLab.

## Quick Start

```bash
docker compose up -d
```

## Services

| Service | URL |
|---|---|
| JupyterLab | http://localhost:8888 |
| Redpanda Console | http://localhost:8080 |
| Jaeger UI | http://localhost:16686 |

## Pipeline

1. **Producer** (`notebooks/1. Mittre classification/Producer.ipynb`) — generates and publishes events to Kafka
2. **Consumer & Classifier** (`notebooks/1. Mittre classification/Consumer_Classifier.ipynb`) — consumes, classifies, and traces events
3. **Statistics** (`notebooks/1. Mittre classification/Statistics.ipynb`) — loads results and visualizes statistics
