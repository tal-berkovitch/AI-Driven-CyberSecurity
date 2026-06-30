"""Ops-agent loop: publish container health + execute allowlisted control requests."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import docker

from shared.transport.file_queue import FileQueueConsumer

LOG = logging.getLogger("ops")

CONTROL_DIR = Path(os.getenv("CONTROL_DIR", "/app/control"))
POLL_SECONDS = float(os.getenv("OPS_POLL_SECONDS", "2"))
# Reported in the System panel (status/CPU/RAM)...
REPORTED = {"soc-collector", "soc-defender", "soc-attacker", "soc-cti", "soc-ui",
            "soc-ops", "soc-kafka"}
# ...but only these may be restarted (NOT the broker or the agent itself — restarting
# Kafka would disrupt the whole spine).
RESTARTABLE = {"soc-collector", "soc-defender", "soc-attacker", "soc-cti", "soc-ui"}
APPLY_BACKENDS = {"charae", "isolation_forest"}


def _cpu_pct(stats: dict) -> float:
    try:
        cpu, pre = stats["cpu_stats"], stats["precpu_stats"]
        cd = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sd = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        n = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or [1]) or 1
        return round(cd / sd * n * 100.0, 1) if sd > 0 and cd > 0 else 0.0
    except (KeyError, TypeError, ZeroDivisionError):
        return 0.0


def _mem_mb(stats: dict) -> tuple[float, float]:
    try:
        mem = stats["memory_stats"]
        used = mem.get("usage", 0) - mem.get("stats", {}).get("inactive_file", 0)
        return round(used / 1e6, 1), round(mem.get("limit", 0) / 1e6, 1)
    except (KeyError, TypeError):
        return 0.0, 0.0


def collect_health(client) -> dict:
    rows = []
    for c in client.containers.list(all=True):
        if c.name not in REPORTED:
            continue
        row = {"name": c.name, "status": c.status, "cpu_pct": 0.0, "mem_mb": 0.0, "mem_limit_mb": 0.0}
        if c.status == "running":
            try:
                st = c.stats(stream=False)
                row["cpu_pct"] = _cpu_pct(st)
                row["mem_mb"], row["mem_limit_mb"] = _mem_mb(st)
            except (docker.errors.APIError, KeyError) as exc:
                LOG.debug("stats(%s) failed: %s", c.name, exc)
        rows.append(row)
    rows.sort(key=lambda r: r["name"])
    return {"ts": time.time(), "containers": rows}


def handle_request(client, req: dict) -> None:
    action, target = req.get("action"), req.get("target")
    if target not in RESTARTABLE:
        LOG.warning("rejecting request for non-restartable target: %r", target)
        return
    if action == "apply_backend":
        backend = req.get("backend")
        if backend not in APPLY_BACKENDS:
            LOG.warning("rejecting apply_backend with invalid backend: %r", backend)
            return
        (CONTROL_DIR / "detector_backend").write_text(backend, encoding="utf-8")
        LOG.info("applied detector_backend=%s; restarting %s", backend, target)
    elif action != "restart":
        LOG.warning("unknown action: %r", action)
        return
    try:
        client.containers.get(target).restart(timeout=10)
        LOG.info("restarted %s", target)
    except docker.errors.APIError as exc:
        LOG.error("restart(%s) failed: %s", target, exc)


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    client = docker.from_env()
    requests = FileQueueConsumer(str(CONTROL_DIR))
    requests.poll("requests")  # seek to EOF: ignore stale requests from a previous run
    health_path = CONTROL_DIR / "health.json"
    LOG.info("ops-agent up; control=%s reported=%s restartable=%s",
             CONTROL_DIR, sorted(REPORTED), sorted(RESTARTABLE))

    while True:
        try:
            health_path.write_text(json.dumps(collect_health(client)), encoding="utf-8")
            for req in requests.poll("requests"):
                handle_request(client, req)
        except Exception as exc:  # noqa: BLE001 — keep the agent alive through transient errors
            LOG.warning("ops loop error: %s", exc)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
