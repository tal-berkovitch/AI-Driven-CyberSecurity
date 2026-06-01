"""ChainLit SOC dashboard + analyst chat.

On session start we begin tailing the shared file-queue (read-only) and stream
capture summaries, anomaly alerts, and CTI reports into the chat. The user can
ask follow-up questions about the most recent alert; those are answered by Groq,
grounded on that alert's evidence + the retrieved MITRE technique cards. With no
GROQ_API_KEY the dashboard still streams; only the chat answers degrade.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import chainlit as cl

import shared
from shared.llm import groq_available, groq_chat
from shared.transport.file_queue import FileQueueConsumer

# Absolute import: `chainlit run` loads this file as a top-level module, so a
# package-relative import would fail. PYTHONPATH=/app makes `ui` + `shared` resolve.
from ui.render import alert_context, format_alert, format_capture_summary, format_cti

QUEUE_ROOT = os.getenv("QUEUE_ROOT", "/app/data/queue")
POLL_SECONDS = float(os.getenv("POLL_SECONDS", "2"))
_KB_PATH = Path(shared.__file__).resolve().parent / "mitre" / "dns_snmp_techniques.json"

_CHAT_SYSTEM = (
    "You are a SOC analyst assistant. Answer the user's question using ONLY the alert "
    "evidence and MITRE technique context provided below. Do not invent indicators, IPs, "
    "or numbers. If the answer is not supported by the evidence, say so plainly."
)


def _load_cards() -> dict[str, dict]:
    try:
        techs = json.loads(_KB_PATH.read_text(encoding="utf-8"))["techniques"]
        return {t["id"]: t for t in techs}
    except (OSError, ValueError, KeyError):
        return {}


def _cards_for(alert: dict) -> str:
    cards = _load_cards()
    chosen = [cards[t] for t in alert.get("candidate_techniques", []) if t in cards]
    return "\n".join(
        f"- {c['id']} {c['name']} ({c.get('tactic', '?')}): {c['description']}"
        for c in chosen
    ) or "(none)"


async def _tail_queue() -> None:
    """Background task: stream new capture/alerts/cti items into the UI."""
    consumer = FileQueueConsumer(QUEUE_ROOT)
    while True:
        try:
            summary = format_capture_summary(consumer.poll("capture"))
            if summary:
                await cl.Message(content=summary, author="sensor").send()

            for raw in consumer.poll("alerts"):
                cl.user_session.set("last_alert", raw)
                await cl.Message(content=format_alert(raw), author="defender").send()

            for raw in consumer.poll("cti"):
                await cl.Message(content=format_cti(raw), author="cti").send()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a bad line must not kill the stream
            await cl.Message(content=f"_stream error: {exc}_", author="system").send()
        await asyncio.sleep(POLL_SECONDS)


@cl.on_chat_start
async def start() -> None:
    llm = "Groq+AG2 online" if groq_available() else "offline (no GROQ_API_KEY)"
    await cl.Message(
        content=(f"**SOC console up.** Watching `{QUEUE_ROOT}` — {llm}.\n"
                 "Live traffic, anomaly alerts, and CTI reports will stream below. "
                 "Ask me anything about the most recent alert."),
        author="system",
    ).send()
    cl.user_session.set("tail_task", asyncio.create_task(_tail_queue()))


@cl.on_chat_end
async def end() -> None:
    task = cl.user_session.get("tail_task")
    if task:
        task.cancel()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    alert = cl.user_session.get("last_alert")
    if alert is None:
        await cl.Message(content="No alert seen yet — waiting for the first detection.",
                         author="analyst").send()
        return
    if not groq_available():
        await cl.Message(
            content="LLM unavailable (set `GROQ_API_KEY`). The dashboard still streams "
                    "alerts and the deterministic CTI reports above.",
            author="analyst").send()
        return

    user_prompt = (
        f"## Question\n{message.content}\n\n"
        f"## Alert evidence\n{alert_context(alert)}\n\n"
        f"## MITRE technique cards\n{_cards_for(alert)}"
    )
    answer = await asyncio.to_thread(groq_chat, _CHAT_SYSTEM, user_prompt)
    await cl.Message(content=answer or "_(no response from the model)_",
                     author="analyst").send()
