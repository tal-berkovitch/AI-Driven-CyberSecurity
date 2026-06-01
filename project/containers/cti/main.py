"""CTI worker loop: consume `alerts` -> generate report -> emit `cti` + write file."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import shared
from shared.llm import groq_available
from shared.schema import Alert
from shared.transport.file_queue import FileQueueConsumer, FileQueueProducer

from .agents import generate_cti
from .prompts import offline_report

LOG = logging.getLogger("cti")
ALERTS_TOPIC = "alerts"
CTI_TOPIC = "cti"

_KB_PATH = Path(shared.__file__).resolve().parent / "mitre" / "dns_snmp_techniques.json"


def _load_cards() -> dict[str, dict]:
    techs = json.loads(_KB_PATH.read_text(encoding="utf-8"))["techniques"]
    return {t["id"]: t for t in techs}


def make_report(alert: Alert, cards_by_id: dict[str, dict], llm_available: bool) -> str:
    """AG2 multi-agent report when an LLM is available, else the grounded template."""
    cards = [cards_by_id[t] for t in alert.candidate_techniques if t in cards_by_id]
    if llm_available:
        text = generate_cti(alert, cards)
        if text:
            return text
    return offline_report(alert, cards)


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    queue_root = os.getenv("QUEUE_ROOT", "/app/data/queue")
    reports_dir = Path(os.getenv("REPORTS_DIR", "/app/data/reports"))
    poll_s = float(os.getenv("POLL_SECONDS", "2"))
    reports_dir.mkdir(parents=True, exist_ok=True)

    consumer = FileQueueConsumer(queue_root)
    producer = FileQueueProducer(queue_root)
    llm_available = groq_available()
    cards_by_id = _load_cards()
    n = 0

    LOG.info("cti worker up; consuming %r (llm=%s) -> %s",
             ALERTS_TOPIC, "groq+ag2" if llm_available else "offline-template", reports_dir)
    while True:
        for raw in consumer.poll(ALERTS_TOPIC):
            try:
                alert = Alert.from_dict(raw)
            except (KeyError, ValueError, TypeError) as exc:
                LOG.warning("skipping malformed alert: %s", exc)
                continue
            alert.cti_report = make_report(alert, cards_by_id, llm_available)
            producer.send(CTI_TOPIC, alert.to_dict())
            n += 1
            path = reports_dir / f"{int(alert.record.ts)}_{alert.record.protocol}_{n}.md"
            path.write_text(alert.cti_report, encoding="utf-8")
            LOG.info("CTI report #%d (%s %s) techniques=%s -> %s",
                     n, alert.record.protocol, alert.record.src,
                     alert.candidate_techniques, path.name)
        time.sleep(poll_s)


if __name__ == "__main__":
    main()
