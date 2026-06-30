"""Pure dashboard state + builders — no FastAPI, no network, fully unit-testable.

``DashboardState`` is the heart of the SOC board: it ingests capture events and
fully-enriched CTI alerts off the file-queue and keeps only **bounded** rolling
state — ring buffers (``deque(maxlen=…)``) plus small counter dicts and a
fixed-length time-bucket series. Memory stays flat no matter how long the system
runs, and the LLM summary is built from this bounded state (counters + the last
K alerts), never the full history — so the prompt can't bloat over time.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from typing import Any

# Bounded buffers (override via DashboardState ctor for tests).
TRAFFIC_MAX = 100
ALERTS_MAX = 50
BUCKETS = 20          # time-bucket series length for the alerts-over-time chart
BUCKET_SECONDS = 15.0


def _top_features(attrs: dict[str, float], k: int = 5) -> list[tuple[str, float]]:
    return sorted(attrs.items(), key=lambda kv: kv[1], reverse=True)[:k]


def traffic_row(event: dict[str, Any]) -> dict[str, Any]:
    """Compact one capture event for the live-traffic feed."""
    proto = event.get("proto", "?")
    detail = event.get("qname") or ""
    return {
        "ts": event.get("ts", 0.0),
        "proto": proto,
        "src": event.get("src", "?"),
        "dst": event.get("dst", "?"),
        "detail": str(detail)[:80],
        "is_response": bool(event.get("is_response", False)),
    }


def alert_summary(alert: dict[str, Any]) -> dict[str, Any]:
    """Compact a fully-enriched CTI payload (Alert.to_dict w/ cti_report) for display."""
    rec = alert.get("record", {})
    sc = alert.get("score", {})
    top = _top_features(sc.get("feature_attributions", {}))
    return {
        "ts": rec.get("ts", 0.0),
        "proto": rec.get("protocol", "?"),
        "src": rec.get("src", "?"),
        "dst": rec.get("dst", "?"),
        "score": round(float(sc.get("anomaly_score", 0.0)), 4),
        "top_feature": top[0][0] if top else "",
        "top_features": [{"name": n, "value": round(v, 3)} for n, v in top],
        "techniques": list(alert.get("candidate_techniques", []) or []),
        "report": alert.get("cti_report") or "",
    }


class DashboardState:
    """O(1)-memory rolling view of the live SOC pipeline."""

    def __init__(self, traffic_max: int = TRAFFIC_MAX, alerts_max: int = ALERTS_MAX,
                 buckets: int = BUCKETS, bucket_seconds: float = BUCKET_SECONDS) -> None:
        self.traffic: deque[dict] = deque(maxlen=traffic_max)
        self.alerts: deque[dict] = deque(maxlen=alerts_max)
        self.bucket_seconds = bucket_seconds
        self.buckets = buckets
        self.alert_buckets: deque[int] = deque([0] * buckets, maxlen=buckets)
        self._cur_bucket_start = self._now()
        self.total_captures = 0
        self.total_alerts = 0
        self.by_proto: Counter[str] = Counter()       # alerts by protocol
        self.technique_freq: Counter[str] = Counter()  # MITRE technique hits

    # -- ingest ---------------------------------------------------------------

    def add_capture(self, events: list[dict]) -> list[dict]:
        rows = [traffic_row(e) for e in events]
        self.traffic.extend(rows)
        self.total_captures += len(rows)
        return rows

    def add_cti(self, alert: dict) -> dict:
        summary = alert_summary(alert)
        self.alerts.append(summary)
        self.total_alerts += 1
        self.by_proto[summary["proto"]] += 1
        # Count the PRIMARY (top-ranked) technique per alert — its classification —
        # so the frequency chart reflects the attack mix. Counting every loosely
        # related candidate would flatten every alert into the same DNS-exfil family.
        if summary["techniques"]:
            self.technique_freq[summary["techniques"][0]] += 1
        self._roll_buckets()
        self.alert_buckets[-1] += 1
        return summary

    def _roll_buckets(self) -> None:
        """Advance the time-bucket window so the newest bucket is 'now'."""
        elapsed = self._now() - self._cur_bucket_start
        steps = int(elapsed // self.bucket_seconds)
        if steps > 0:
            for _ in range(min(steps, self.buckets)):
                self.alert_buckets.append(0)
            self._cur_bucket_start += steps * self.bucket_seconds

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    # -- views ----------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        self._roll_buckets()
        return {
            "total_captures": self.total_captures,
            "total_alerts": self.total_alerts,
            "by_proto": dict(self.by_proto),
            "technique_freq": dict(self.technique_freq.most_common(8)),
            "alert_buckets": list(self.alert_buckets),
            "bucket_seconds": self.bucket_seconds,
        }

    def snapshot(self) -> dict[str, Any]:
        """Full current state for a freshly-connected client."""
        return {
            "traffic": list(self.traffic),
            "alerts": list(self.alerts),
            "stats": self.stats(),
        }


def build_summary_prompt(state: DashboardState, last_k: int = 15) -> str:
    """Fixed-size prompt: rolling counters + the last K alerts only (never full history)."""
    st = state.stats()
    recent = list(state.alerts)[-last_k:]
    lines = [
        "Current SOC state (live monitor, since UI start):",
        f"- captures observed: {st['total_captures']}",
        f"- anomaly alerts: {st['total_alerts']} (by protocol: {st['by_proto'] or 'none'})",
        f"- top MITRE techniques: {st['technique_freq'] or 'none'}",
        "",
        f"Most recent {len(recent)} alerts:",
    ]
    for a in recent:
        lines.append(
            f"- {a['proto']} from {a['src']} score={a['score']} "
            f"top_feature={a['top_feature']} techniques={a['techniques']}"
        )
    if not recent:
        lines.append("- (none yet)")
    return "\n".join(lines)


def build_ops_payload(health: dict, llm: dict) -> dict:
    """Shape the System-panel SSE event from the ops-agent health file + LLM state."""
    containers = health.get("containers", []) if isinstance(health, dict) else []
    return {"containers": containers, "health_ts": (health or {}).get("ts"), "llm": dict(llm)}


def offline_summary(state: DashboardState) -> str:
    """Deterministic situation report when no LLM is available."""
    st = state.stats()
    if st["total_alerts"] == 0:
        return ("No anomalies yet. Monitoring DNS traffic — "
                f"{st['total_captures']} events observed so far.")
    techs = ", ".join(f"{t} (x{n})" for t, n in st["technique_freq"].items()) or "none"
    protos = ", ".join(f"{p}: {n}" for p, n in st["by_proto"].items())
    return (
        f"{st['total_alerts']} anomaly alerts across {st['total_captures']} observed events "
        f"({protos}). Dominant MITRE techniques: {techs}. "
        "Set GROQ_API_KEY for a synthesized narrative."
    )
