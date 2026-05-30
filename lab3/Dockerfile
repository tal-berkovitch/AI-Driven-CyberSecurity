FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Suppress UV hardlink warning by using copy mode
ENV UV_LINK_MODE=copy

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies into the system Python (no venv needed inside Docker)
RUN uv sync --frozen --no-dev

# Copy application source
COPY chainlit.md ./
COPY app/ ./app/

# Chainlit default port
EXPOSE 8000

CMD ["uv", "run", "chainlit", "run", "app/agent/app.py", "--host", "0.0.0.0", "--port", "8000"]
