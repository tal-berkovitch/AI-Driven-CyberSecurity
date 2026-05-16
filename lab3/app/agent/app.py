"""
Network Security Analyzer Agent
Lab 3 - AI-Enhanced Cybersecurity

A single-agent system that helps analyze network security events.
The agent uses three tools to:
  - Parse and classify raw log entries (detect attack patterns + severity)
  - Check IP addresses against a threat intelligence database
  - Look up CVE severity scores and remediation advice
"""

import asyncio
import os
import re
import json
import time
from typing import Annotated

import chainlit as cl
from autogen import ConversableAgent
from autogen.events.agent_events import ExecuteFunctionEvent, ExecutedFunctionEvent

# ---------------------------------------------------------------------------
# Tool 1 – Log Parser & Classifier
# ---------------------------------------------------------------------------

LOG_PATTERNS = {
    "failed_login": re.compile(
        r"(failed|invalid|bad)\s+(login|password|credentials|auth)", re.IGNORECASE
    ),
    "port_scan": re.compile(
        r"(port.?scan|nmap|masscan|SYN\s+flood|connection refused.*repeated)", re.IGNORECASE
    ),
    "sql_injection": re.compile(
        r"(union\s+select|'\s*or\s+'|drop\s+table|1\s*=\s*1|--|xp_cmdshell)", re.IGNORECASE
    ),
    "xss": re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()", re.IGNORECASE
    ),
    "privilege_escalation": re.compile(
        r"(sudo|su\s+root|privilege|escalat|admin.*attempt)", re.IGNORECASE
    ),
    "data_exfiltration": re.compile(
        r"(large\s+upload|outbound.*mb|curl.*external|wget.*external)", re.IGNORECASE
    ),
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_MAP = {
    "failed_login":        "LOW",
    "port_scan":           "MEDIUM",
    "xss":                 "MEDIUM",
    "sql_injection":       "HIGH",
    "privilege_escalation":"HIGH",
    "data_exfiltration":   "CRITICAL",
}


def parse_log_entry(
    log_line: Annotated[str, "A raw log line or short log snippet to analyze"]
) -> str:
    """
    Parses a raw log entry, detects known attack patterns, and returns
    a JSON string with the classification and severity level.

    Input:  a raw log line string (up to 500 characters)
    Output: JSON with event_types, severity, and detail fields
    """
    detected = [etype for etype, pat in LOG_PATTERNS.items() if pat.search(log_line)]

    if not detected:
        result = {
            "status": "clean",
            "event_types": ["unknown"],
            "severity": "INFO",
            "detail": "No known threat pattern matched.",
        }
    else:
        max_severity = max(
            (SEVERITY_MAP[e] for e in detected),
            key=lambda s: SEVERITY_ORDER.index(s),
        )
        result = {
            "status": "threat_detected",
            "event_types": detected,
            "severity": max_severity,
            "detail": f"Matched pattern(s): {', '.join(detected)}",
        }

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool 2 – IP Reputation Checker
# ---------------------------------------------------------------------------

# Simulated threat-intel database.
# In production this would call an API such as AbuseIPDB or VirusTotal.
_THREAT_DB = {
    "45.33.32.156":  {"reputation": "malicious",  "country": "US", "reports": 47},
    "198.20.69.74":  {"reputation": "scanner",    "country": "US", "reports": 120},
    "80.82.77.33":   {"reputation": "malicious",  "country": "NL", "reports": 88},
    "185.220.101.5": {"reputation": "tor_exit",   "country": "DE", "reports": 210},
    "192.168.1.100": {"reputation": "suspicious", "country": "—",  "reports": 3},
    "10.0.0.55":     {"reputation": "suspicious", "country": "—",  "reports": 1},
}

_IPv4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def check_ip_reputation(
    ip_address: Annotated[str, "IPv4 address to look up in the threat database"]
) -> str:
    """
    Checks an IPv4 address against a local threat-intelligence database.

    Input:  a valid IPv4 address string (e.g. "185.220.101.5")
    Output: JSON with reputation, country, abuse_reports, and recommendation fields
    """
    ip = ip_address.strip()

    if not _IPv4_RE.match(ip):
        return json.dumps({"error": f"'{ip}' is not a valid IPv4 address."})

    if ip in _THREAT_DB:
        data = _THREAT_DB[ip]
        recommendation = "BLOCK" if data["reputation"] in ("malicious", "tor_exit") else "MONITOR"
        return json.dumps({
            "ip": ip,
            "reputation": data["reputation"],
            "country": data["country"],
            "abuse_reports": data["reports"],
            "recommendation": recommendation,
        }, indent=2)

    return json.dumps({
        "ip": ip,
        "reputation": "clean",
        "country": "N/A",
        "abuse_reports": 0,
        "recommendation": "ALLOW",
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool 3 – CVE Lookup
# ---------------------------------------------------------------------------

_CVE_DB = {
    "CVE-2021-44228": {
        "description": "Log4Shell – Apache Log4j2 RCE via JNDI lookup",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected": "Apache Log4j 2.x < 2.15.0",
        "fix": "Upgrade to Log4j 2.15.0 or later",
    },
    "CVE-2022-0778": {
        "description": "OpenSSL infinite loop via malformed certificate (DoS)",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected": "OpenSSL 1.0.2, 1.1.1, 3.0",
        "fix": "Upgrade to OpenSSL 1.1.1n / 3.0.2+",
    },
    "CVE-2023-23397": {
        "description": "Microsoft Outlook NTLM hash leak via crafted email",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected": "Microsoft Outlook (pre-March 2023 patch)",
        "fix": "Apply Microsoft March 2023 security update",
    },
    "CVE-2024-3094": {
        "description": "XZ Utils backdoor enabling unauthorized SSH access",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected": "XZ Utils 5.6.0 and 5.6.1",
        "fix": "Downgrade to XZ Utils 5.4.x",
    },
    "CVE-2023-44487": {
        "description": "HTTP/2 Rapid Reset Attack enabling large-scale DDoS",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "affected": "Multiple HTTP/2 server implementations",
        "fix": "Apply vendor patches; disable HTTP/2 if patch unavailable",
    },
}


def lookup_cve(
    cve_id: Annotated[str, "CVE identifier to look up, e.g. CVE-2021-44228"]
) -> str:
    """
    Returns severity and remediation details for a known CVE.

    Input:  a CVE ID string (e.g. "CVE-2021-44228")
    Output: JSON with description, cvss_score, severity, affected, and fix fields
    """
    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        return json.dumps({"error": f"'{cve_id}' does not look like a valid CVE ID."})

    if cve_id in _CVE_DB:
        return json.dumps({"cve_id": cve_id, **_CVE_DB[cve_id]}, indent=2)

    return json.dumps({
        "cve_id": cve_id,
        "status": "not_found",
        "detail": "CVE not in local database. Check https://nvd.nist.gov for full details.",
    }, indent=2)


# ---------------------------------------------------------------------------
# LLM configuration
# ---------------------------------------------------------------------------

api_base_url = os.getenv("API_BASE_URL")
api_key      = os.getenv("API_KEY")
model        = os.getenv("MODEL")

if not api_key:
    raise RuntimeError(
        "API_KEY is not set. "
        "Set it in your .env file or in compose.yaml."
    )

llm_config = {
    "config_list": [
        {
            "model":       model,
            "api_key":     api_key,
            "base_url":    api_base_url,
            "price":       [0, 0],
            "max_retries": 5,
        }
    ],
}

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are SecAI, a professional network security analyst assistant.

You help security teams triage and understand potential threats using three tools:
- parse_log_entry     → classify a raw log line and determine its severity
- check_ip_reputation → look up whether an IP address is a known threat
- lookup_cve          → retrieve CVSS score and fix advice for a CVE ID

CRITICAL RULES:
1) You MUST call the appropriate tool(s) for every request. Never skip tool calls.
2) If the user provides a log line that contains an IP address, call BOTH parse_log_entry AND check_ip_reputation.
3) If a CVE ID appears in the conversation, call lookup_cve for it.
4) After calling each tool, you MUST use its results in your response. Do not ignore them.
5) Always explain tool results clearly in plain English with specific details from the results.
6) End every security analysis with a "Recommended Actions" section with 2-3 bullet points.
7) Do NOT give generic responses. Always reference specific tool findings.
8) NEVER call the same tool with the same arguments more than once per request. Each tool call returns complete information — repeated identical calls waste resources and must be avoided.

Important: Your analysis is ONLY valid if based on tool results. Always cite tool outputs.
Always answer in English.
"""

WELCOME_MESSAGE = """\
👋 Hello! I am **SecAI**, your network security analyzer.

I can help you with:
- 📋 **Log analysis** – paste a raw log line and I will classify it
- 🌐 **IP reputation** – ask about any IPv4 address
- 🔍 **CVE lookup** – ask about a specific CVE (e.g. `CVE-2021-44228`)

Try something like:
> `Analyze this log: Failed login attempt from 185.220.101.5 for user admin`
> `Is 45.33.32.156 a known threat?`
> `Tell me about CVE-2023-23397`
"""

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _format_content(content: object) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (dict, list, tuple)):
        return json.dumps(content, ensure_ascii=True, indent=2)
    return str(content)

# ---------------------------------------------------------------------------
# Chainlit event handlers
# ---------------------------------------------------------------------------

@cl.on_chat_start
async def on_chat_start():
    """Create the AG2 assistant and store it in the user session."""
    assistant = ConversableAgent(
        name="security_agent",
        system_message=SYSTEM_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
        functions=[parse_log_entry, check_ip_reputation, lookup_cve],
    )

    cl.user_session.set("assistant", assistant)
    await cl.Message(content=WELCOME_MESSAGE, author="security_agent").send()


@cl.on_message
async def on_message(message: cl.Message):
    """Handle each user message using AG2 async single-agent execution."""
    assistant: ConversableAgent = cl.user_session.get("assistant")

    response = await assistant.a_run(
        message=message.content,
        clear_history=False,
        max_turns=6,
        summary_method="last_msg",
        user_input=False,
    )

    # Collect tool inputs so we can pair them with their outputs
    tool_inputs: dict[str, dict[str, str]] = {}

    async for event in response.events:
        # Tool is about to be called – capture the input
        if isinstance(event, ExecuteFunctionEvent):
            event_data = event.content
            tool_key = getattr(event_data, "call_id", None) or event_data.func_name
            tool_inputs[tool_key] = {
                "name":  event_data.func_name,
                "input": _format_content(event_data.arguments) or "(no arguments)",
            }
            continue

        # Tool has returned – display as a Chainlit Step
        if not isinstance(event, ExecutedFunctionEvent):
            continue

        event_data = event.content
        tool_key   = getattr(event_data, "call_id", None) or event_data.func_name
        step_data  = tool_inputs.get(
            tool_key,
            {"name": event_data.func_name, "input": "(no arguments)"},
        )
        async with cl.Step(name=step_data["name"], type="tool") as step:
            step.input  = step_data["input"]
            step.output = _format_content(event_data.content)

    summary = await response.summary
    final_text = _format_content(summary)
    await cl.Message(content=final_text).send()
