# Attacker agent (Phase 1): realistic benign DNS traffic generator.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir "dnspython>=2.6"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/attacker/ ./attacker/

CMD ["python", "-m", "attacker.main"]
