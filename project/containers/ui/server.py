"""FastAPI + SSE SOC dashboard backend.

Runs on the egress side, OUTSIDE the air-gapped detonation net. It reads the shared
file-queue (read-only), reaches Groq for the situation summary, and exposes a small
control API (switch LLM model, request a container restart / backend apply) that it
writes to the shared *control* volume — the privileged work (Docker stats/restart)
is done by the separate ops-agent. Background tasks fan Server-Sent Events out to
every browser. State is bounded (``dashboard.DashboardState``); on startup we seek
the queue to EOF so the backlog is never loaded into memory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from shared.llm import (
    CONTROL_DIR,
    FALLBACK_MODELS,
    groq_available,
    groq_complete,
    groq_list_models,
    groq_model,
    read_llm_usage,
)
from shared.transport import make_consumer
from shared.transport.file_queue import FileQueueProducer  # control plane stays file-based

from .dashboard import DashboardState, build_ops_payload, build_summary_prompt, offline_summary

LOG = logging.getLogger("ui")

QUEUE_ROOT = os.getenv("QUEUE_ROOT", "/app/data/queue")
POLL_SECONDS = float(os.getenv("POLL_SECONDS", "1"))
SUMMARY_INTERVAL = float(os.getenv("SUMMARY_INTERVAL", "25"))
SUMMARY_LAST_K = int(os.getenv("SUMMARY_LAST_K", "15"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
MODEL_CARD_PATH = Path(QUEUE_ROOT).parent / "model_card.json"
CONTROL_PATH = Path(CONTROL_DIR)
HEALTH_PATH = CONTROL_PATH / "health.json"

CAPTURE_TOPIC = "capture"
CTI_TOPIC = "cti"
# Containers the UI may ask the ops-agent to restart (not the ops-agent itself).
RESTART_TARGETS = {"soc-collector", "soc-defender", "soc-attacker", "soc-cti", "soc-ui"}
APPLY_BACKENDS = {"charae", "isolation_forest"}

_SUMMARY_SYSTEM = (
    "You are a senior SOC analyst writing a live situation summary. Using ONLY the state "
    "provided, write a short paragraph of 4-6 sentences covering: what is happening right "
    "now, the dominant MITRE techniques and the most active sources, an overall severity "
    "assessment, and one recommended focus for the analyst. Do not invent indicators, IPs, "
    "or numbers beyond what is given."
)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    CONTROL_PATH.mkdir(parents=True, exist_ok=True)
    tasks = [asyncio.create_task(_poller()), asyncio.create_task(_summarizer())]
    LOG.info("SOC dashboard up; queue=%s control=%s llm=%s", QUEUE_ROOT, CONTROL_PATH,
             "groq" if groq_available() else "offline")
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(title="SOC Dashboard", lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_state = DashboardState()
_subscribers: set[asyncio.Queue] = set()
_latest_summary = {"text": "Waiting for the first situation summary…", "ts": 0.0, "transient": None}
_model_card: dict = {}
_model_card_mtime = 0.0
_latest_detector: dict = {}
_control_producer: FileQueueProducer | None = None


def _requests_producer() -> FileQueueProducer:
    # Lazy so importing this module doesn't create the control dir (matters on the
    # host during tests; in the container the dir is the mounted ./control).
    global _control_producer
    if _control_producer is None:
        _control_producer = FileQueueProducer(str(CONTROL_PATH))
    return _control_producer


def _load_model_card() -> dict:
    global _model_card, _model_card_mtime
    try:
        mtime = MODEL_CARD_PATH.stat().st_mtime
        if mtime != _model_card_mtime:
            _model_card = json.loads(MODEL_CARD_PATH.read_text(encoding="utf-8"))
            _model_card_mtime = mtime
    except (OSError, ValueError):
        pass
    return _model_card


def _read_health() -> dict:
    try:
        return json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _llm_state() -> dict:
    """LLM budget/status from the last persisted Groq sample (survives restarts;
    carries an `age_s` so the dashboard can show how fresh the sample is)."""
    u = read_llm_usage()
    if u.get("status") == 429:
        status = "rate_limited"
    elif u.get("status") == 200:
        status = "online"
    else:
        status = "online" if groq_available() else "offline"
    return {
        "model": groq_model(),
        "status": status,
        "used_pct": u.get("used_pct"),
        "remaining_tokens": u.get("remaining_tokens"),
        "limit_tokens": u.get("limit_tokens"),
        "age_s": round(time.time() - u["ts"]) if u.get("ts") else None,
    }


def _ops_payload() -> dict:
    return build_ops_payload(_read_health(), _llm_state())


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _broadcast(event: str, data) -> None:
    payload = _sse(event, data)
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass  # slow client — drop; it catches up on the next tick


async def _poller() -> None:
    global _latest_detector
    consumer = make_consumer(QUEUE_ROOT, group="ui", live=True)
    consumer.poll(CAPTURE_TOPIC)        # seek to EOF — never replay the backlog
    consumer.poll(CTI_TOPIC)
    last_card_mtime = None
    while True:
        try:
            rows = _state.add_capture(consumer.poll(CAPTURE_TOPIC))
            if rows:
                await _broadcast("traffic", rows)

            cti_raw = consumer.poll(CTI_TOPIC)
            new_alerts = [_state.add_cti(a) for a in cti_raw]
            if new_alerts:
                await _broadcast("alerts", new_alerts)
                last = cti_raw[-1]
                _latest_detector = {
                    "protocol": last.get("record", {}).get("protocol"),
                    "score": last.get("score", {}).get("anomaly_score"),
                    "attributions": last.get("score", {}).get("feature_attributions", {}),
                }
                await _broadcast("detector", _latest_detector)

            if rows or new_alerts:
                await _broadcast("stats", _state.stats())

            # (Re)publish the model card whenever the defender rewrites it — e.g. a
            # backend switch changes active_backend, so the green 'active' dot moves.
            if _load_model_card() and _model_card_mtime != last_card_mtime:
                await _broadcast("model", _model_card)
                last_card_mtime = _model_card_mtime

            await _broadcast("ops", _ops_payload())     # container health each tick
        except Exception as exc:  # noqa: BLE001 — a bad line must not kill the stream
            LOG.warning("poller error: %s", exc)
        await asyncio.sleep(POLL_SECONDS)


async def _summarizer() -> None:
    await asyncio.sleep(min(3.0, SUMMARY_INTERVAL))
    while True:
        try:
            if groq_available():
                prompt = build_summary_prompt(_state, last_k=SUMMARY_LAST_K)
                res = await asyncio.to_thread(groq_complete, _SUMMARY_SYSTEM, prompt)
                if res["text"]:
                    _latest_summary.update(text=res["text"], ts=time.time(), transient=None)
                elif res["status"] == 429:
                    # keep the last good summary; show a transient retry note instead
                    _latest_summary["transient"] = "Groq had too many requests — retrying shortly…"
                else:
                    _latest_summary["transient"] = None
                    if str(_latest_summary.get("text", "")).startswith("Waiting"):
                        _latest_summary.update(text=offline_summary(_state), ts=time.time())
            else:
                _llm_state["status"] = "offline"
                _latest_summary.update(text=offline_summary(_state), ts=time.time(), transient=None)
            await _broadcast("summary", _latest_summary)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("summarizer error: %s", exc)
        await asyncio.sleep(SUMMARY_INTERVAL)


# --- control API (writes to the shared control volume; ops-agent acts on it) ---

@app.get("/api/models")
async def api_models() -> dict:
    return {"models": groq_list_models() or FALLBACK_MODELS, "selected": groq_model()}


@app.post("/api/model")
async def api_set_model(payload: dict = Body(...)) -> dict:
    model = str(payload.get("model", "")).strip()
    if model not in set(groq_list_models() or FALLBACK_MODELS):
        raise HTTPException(status_code=400, detail="unknown model")
    (CONTROL_PATH / "llm_model").write_text(model, encoding="utf-8")
    LOG.info("LLM model switched to %s", model)
    return {"ok": True, "selected": model}


@app.post("/api/restart")
async def api_restart(payload: dict = Body(...)) -> dict:
    target = str(payload.get("target", "")).strip()
    if target not in RESTART_TARGETS:
        raise HTTPException(status_code=400, detail="unknown target")
    _requests_producer().send("requests", {"action": "restart", "target": target, "ts": time.time()})
    return {"ok": True}


@app.post("/api/backend")
async def api_backend(payload: dict = Body(...)) -> dict:
    backend = str(payload.get("backend", "")).strip()
    if backend not in APPLY_BACKENDS:
        raise HTTPException(status_code=400, detail="unknown backend")
    _requests_producer().send("requests", {"action": "apply_backend", "backend": backend,
                                        "target": "soc-defender", "ts": time.time()})
    return {"ok": True}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "llm": groq_available()}


@app.get("/")
async def index() -> HTMLResponse:
    # Cache-bust the JS/CSS with a token derived from their mtimes, so a rebuild
    # always forces the browser to fetch the fresh assets (no stale cached app.js).
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    token = "0"
    try:
        token = str(int(max((STATIC_DIR / f).stat().st_mtime
                            for f in ("app.js", "styles.css"))))
    except OSError:
        pass
    html = (html.replace("/static/app.js", f"/static/app.js?v={token}")
                .replace("/static/styles.css", f"/static/styles.css?v={token}"))
    # Never cache the HTML itself, so the new ?v= token is always seen on reload.
    return HTMLResponse(html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


@app.get("/events")
async def events(request: Request) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)

    async def stream():
        try:
            yield _sse("snapshot", _state.snapshot())
            yield _sse("summary", _latest_summary)
            yield _sse("ops", _ops_payload())
            if _load_model_card():
                yield _sse("model", _model_card)
            if _latest_detector:
                yield _sse("detector", _latest_detector)
            while True:
                if await request.is_disconnected():
                    break
                try:
                    yield await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            _subscribers.discard(q)

    return StreamingResponse(stream(), media_type="text/event-stream")
