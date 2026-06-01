# CTI worker (Phase 3+4). Runs OFF the isolated detonation net (needs egress to Groq).
# Phase 4: AG2 multi-agent group chat drives report generation via Groq's
# OpenAI-compatible endpoint (so we need `openai`, pulled in alongside `ag2`).
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir "ag2>=0.3" "openai>=1.0"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/cti/ ./cti/

CMD ["python", "-m", "cti.main"]
