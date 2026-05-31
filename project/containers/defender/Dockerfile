# Defender agent (Phase 0 stub). Build context = repo root.
# Kept lean for Phase 0; detection/CTI dependencies are added per-phase.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY shared/ ./shared/
COPY containers/defender/ ./defender/

CMD ["python", "-m", "defender.main"]
