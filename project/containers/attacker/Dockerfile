# Attacker agent (Phase 0 stub). Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY shared/ ./shared/
COPY containers/attacker/ ./attacker/

CMD ["python", "-m", "attacker.main"]
