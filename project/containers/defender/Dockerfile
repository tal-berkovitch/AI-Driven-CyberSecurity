# Defender agent (Phase 3): capture-consumer + feature plane + live detection.
# Build context = repo root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Feature/serving deps + CPU-only PyTorch (autoencoder backend) + scikit-learn
# (Isolation Forest backend, so DETECTOR_BACKEND=isolation_forest also runs live
# and its model card can be exported for the dashboard's backend comparison).
# torch CPU wheel is large (~200MB) — first build is slow, then cached.
RUN pip install --no-cache-dir "numpy>=1.26" "pandas>=2.2" "scikit-learn>=1.4" "kafka-python>=2.0" \
    && pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY shared/ ./shared/
COPY containers/defender/ ./defender/

CMD ["python", "-m", "defender.main"]
