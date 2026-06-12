"""The System-panel SSE payload is built by a pure helper from the ops-agent's
health file + the UI's LLM state — no docker, no network."""

from ui.dashboard import build_ops_payload


def test_build_ops_payload_combines_health_and_llm():
    health = {"ts": 123.0, "containers": [
        {"name": "soc-defender", "status": "running", "cpu_pct": 12.3, "mem_mb": 120.0, "mem_limit_mb": 2048.0},
        {"name": "soc-ui", "status": "running", "cpu_pct": 1.1, "mem_mb": 40.0, "mem_limit_mb": 2048.0},
    ]}
    llm = {"model": "llama-3.1-8b-instant", "status": "online", "used_pct": 42.0}
    out = build_ops_payload(health, llm)

    assert out["health_ts"] == 123.0
    assert [c["name"] for c in out["containers"]] == ["soc-defender", "soc-ui"]
    assert out["containers"][0]["cpu_pct"] == 12.3
    assert out["llm"]["model"] == "llama-3.1-8b-instant" and out["llm"]["used_pct"] == 42.0


def test_build_ops_payload_handles_missing_health():
    out = build_ops_payload({}, {"status": "offline"})
    assert out["containers"] == [] and out["health_ts"] is None
    assert out["llm"]["status"] == "offline"
