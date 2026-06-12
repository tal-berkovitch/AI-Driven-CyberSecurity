# SOC dashboard (Phase 4.5): FastAPI + SSE. Runs OFF the isolated detonation net:
# reads the shared file-queue (mounted read-only) and reaches Groq for the summary.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29" "openai>=1.0" "kafka-python>=2.0"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/ui/ ./ui/

EXPOSE 8000

CMD ["uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "8000"]
