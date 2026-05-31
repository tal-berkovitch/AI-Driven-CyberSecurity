# Collector agent (Phase 0 stub). Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY shared/ ./shared/
COPY containers/collector/ ./collector/

CMD ["python", "-m", "collector.main"]
