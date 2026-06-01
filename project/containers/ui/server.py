"""FastAPI + SSE SOC dashboard backend.

Runs on the egress side, OUTSIDE the air-gapped detonation net. It only *reads*
the shared file-queue (mounted read-only) and reaches Groq solely for the periodic
situation summary. Two background tasks feed an in-process pub/sub that fans out
Server-Sent Events to every connected browser:

  * poller      — tails `capture` (→ traffic) and `cti` (→ alerts/stats), bounded.
  * summarizer  — every SUMMARY_INTERVAL builds a fixed-size prompt and asks Groq
                  (or renders a deterministic offline summary).

All state is bounded (see ``dashboard.DashboardState``); on startup we seek each
topic to EOF so the on-disk backlog is never loaded into memory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from shared.llm import groq_available, groq_chat
from shared.transport.file_queue import FileQueueConsumer

from .dashboard import DashboardState, build_summary_prompt, offline_summary

LOG = logging.getLogger("ui")

QUEUE_ROOT = os.getenv("QUEUE_ROOT", "/app/data/queue")
POLL_SECONDS = float(os.getenv("POLL_SECONDS", "1"))
SUMMARY_INTERVAL = float(os.getenv("SUMMARY_INTERVAL", "25"))
SUMMARY_LAST_K = int(os.getenv("SUMMARY_LAST_K", "15"))
STATIC_DIR = Path(__file__).resolve().parent / "static"

CAPTURE_TOPIC = "capture"
CTI_TOPIC = "cti"

_SUMMARY_SYSTEM = (
    "You are a senior SOC analyst writing a brief live situation summary. Using ONLY "
    "the state provided, write 2-4 sentences: what is happening, the dominant MITRE "
    "techniques and sources, and a severity sense. Do not invent indicators or numbers."
)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    tasks = [asyncio.create_task(_poller()), asyncio.create_task(_summarizer())]
    LOG.info("SOC dashboard up; queue=%s llm=%s", QUEUE_ROOT,
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
_latest_summary = {"text": "Waiting for the first situation summary…", "ts": 0.0}


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _broadcast(event: str, data) -> None:
    payload = _sse(event, data)
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass  # slow client — drop; it will catch up on the next stats tick


async def _poller() -> None:
    consumer = FileQueueConsumer(QUEUE_ROOT)
    # Seek to EOF: ingest the existing backlog's offsets without keeping it.
    consumer.poll(CAPTURE_TOPIC)
    consumer.poll(CTI_TOPIC)
    while True:
        try:
            rows = _state.add_capture(consumer.poll(CAPTURE_TOPIC))
            if rows:
                await _broadcast("traffic", rows)

            new_alerts = [_state.add_cti(a) for a in consumer.poll(CTI_TOPIC)]
            if new_alerts:
                await _broadcast("alerts", new_alerts)

            if rows or new_alerts:
                await _broadcast("stats", _state.stats())
        except Exception as exc:  # noqa: BLE001 — a bad line must not kill the stream
            LOG.warning("poller error: %s", exc)
        await asyncio.sleep(POLL_SECONDS)


async def _summarizer() -> None:
    import time
    # Brief settle so the first poll has a chance to populate state, then summarize
    # immediately and on every interval thereafter (no long initial blank).
    await asyncio.sleep(min(3.0, SUMMARY_INTERVAL))
    while True:
        try:
            text = None
            if groq_available():
                prompt = build_summary_prompt(_state, last_k=SUMMARY_LAST_K)
                text = await asyncio.to_thread(groq_chat, _SUMMARY_SYSTEM, prompt)
            if not text:
                text = offline_summary(_state)
            _latest_summary.update(text=text, ts=time.time())
            await _broadcast("summary", _latest_summary)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("summarizer error: %s", exc)
        await asyncio.sleep(SUMMARY_INTERVAL)


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "llm": groq_available()}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/events")
async def events(request: Request) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)

    async def stream():
        try:
            # Immediately hydrate the new client with current state.
            yield _sse("snapshot", _state.snapshot())
            yield _sse("summary", _latest_summary)
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
