# CTI worker (Phase 3). Runs OFF the isolated detonation net (needs egress to Groq).
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir "groq>=0.11"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/cti/ ./cti/

CMD ["python", "-m", "cti.main"]
