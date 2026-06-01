# ChainLit SOC UI (Phase 4). Runs OFF the isolated detonation net: it reads the
# shared file-queue (mounted read-only) and reaches Groq for the analyst chat.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN pip install --no-cache-dir "chainlit>=1.1" "openai>=1.0"

WORKDIR /app

COPY shared/ ./shared/
COPY containers/ui/ ./ui/

EXPOSE 8000

# --headless: don't try to open a browser inside the container.
CMD ["chainlit", "run", "ui/app.py", "--host", "0.0.0.0", "--port", "8000", "--headless"]
