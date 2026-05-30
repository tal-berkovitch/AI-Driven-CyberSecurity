# Lab 3 – Network Security Analyzer Agent

> AI-Enhanced Cybersecurity · Single Agent with Tool Usage

The agent implementation lives in [`app/agent/`](app/agent/) — see its own `README.md` for a full description of the agent, its tools, and example interactions.

---

## Project Structure

```
lab3/
├── app/
│   └── agent/
│       ├── app.py       ← agent implementation (edit this)
│       └── README.md    ← agent documentation (deliverable)
├── .dockerignore
├── .env.example         ← copy to .env and add your API key
├── .gitignore
├── chainlit.md          ← Chainlit welcome page
├── compose.yaml
├── Dockerfile
├── pyproject.toml
├── README.md            ← this file
└── uv.lock
```

---

## Setup

### 1. Get a Groq API key

Register at [https://console.groq.com](https://console.groq.com) (free tier is sufficient).

### 2. Create your `.env` file

```bash
cp .env.example .env
# open .env and paste your API key
```

### 3. Generate the lock file (first time only, requires uv locally)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv lock
```

### 4. Build and run

```bash
docker build -t lab3-security-agent .
docker compose up
```

Open **[http://localhost:8000](http://localhost:8000)**.

### 5. After editing code

```bash
docker compose down
docker compose up
```

No rebuild needed thanks to the volume mount in `compose.yaml`.
Rebuild only when you change `pyproject.toml`.
