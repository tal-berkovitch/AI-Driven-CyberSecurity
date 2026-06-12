# Ops-agent (Phase 4.6): the ONLY container with the Docker socket. Reports
# container health to the control volume and runs allowlisted restarts on request.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN pip install --no-cache-dir "docker>=7"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/ops/ ./ops/

CMD ["python", "-m", "ops.main"]
