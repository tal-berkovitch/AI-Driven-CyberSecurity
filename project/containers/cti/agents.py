"""AG2 multi-agent CTI generation (Phase 4).

A bounded, per-alert group chat that turns one Alert's grounded evidence into a
SOC report. Two agents collaborate:

  * **Threat-Analyst** — assesses severity + confirms which of the *retrieved*
    MITRE techniques the evidence supports (strictly from the provided facts).
  * **Report-Writer** — writes the final structured report, then says TERMINATE.

This runs ONLY on the egress side (the CTI worker), never in the air-gapped
defender. AG2 is a presentation/orchestration layer, never a hard dependency:
``generate_cti`` returns None on a missing key, a missing ``autogen`` install, or
any runtime error, and ``cti.main`` falls back to the deterministic
``offline_report``. Same grounded evidence feeds both paths ("RAG, not free
generation").
"""

from __future__ import annotations

import logging
from typing import Any

from shared.llm import groq_llm_config
from shared.schema import Alert

from .prompts import build_user_prompt

LOG = logging.getLogger("cti.agents")

_ANALYST_SYS = (
    "You are a senior threat analyst. Using ONLY the evidence the user provides "
    "(anomaly score, per-feature reconstruction errors, retrieved MITRE technique "
    "cards, raw context), assess the activity: which of the retrieved techniques the "
    "evidence supports (cite IDs), a severity (low/medium/high) with a one-line "
    "justification, and the 2-3 features that matter most. Do not invent indicators, "
    "IPs, or numbers. Be concise; hand off to the report writer."
)

_WRITER_SYS = (
    "You are a SOC report writer. Turn the analyst's assessment and the original "
    "evidence into a concise CTI report with these sections: Summary (1-2 sentences), "
    "Evidence (bullets citing feature values), MITRE techniques (IDs + names), "
    "Severity (with one-line justification), Recommended actions (2-4 bullets). "
    "Use ONLY provided facts. Output the final report, then on a new line write "
    "exactly: TERMINATE"
)

_MAX_ROUND = 6


def _strip_terminate(text: str) -> str:
    return text.replace("TERMINATE", "").strip()


def generate_cti(alert: Alert, cards: list[dict[str, Any]]) -> str | None:
    """Run the AG2 group chat for one alert. None on unavailability/any error."""
    llm_config = groq_llm_config()
    if llm_config is None:
        return None
    try:
        from autogen import AssistantAgent, GroupChat, GroupChatManager, UserProxyAgent

        evidence = build_user_prompt(alert, cards)

        analyst = AssistantAgent(
            name="Threat_Analyst", system_message=_ANALYST_SYS, llm_config=llm_config)
        writer = AssistantAgent(
            name="Report_Writer", system_message=_WRITER_SYS, llm_config=llm_config)
        # Seeds the conversation and detects the writer's TERMINATE; makes no LLM calls.
        user = UserProxyAgent(
            name="Evidence",
            human_input_mode="NEVER",
            code_execution_config=False,
            max_consecutive_auto_reply=0,
            is_termination_msg=lambda m: "TERMINATE" in (m.get("content") or ""),
        )

        chat = GroupChat(
            agents=[user, analyst, writer],
            messages=[],
            max_round=_MAX_ROUND,
            speaker_selection_method="round_robin",
        )
        manager = GroupChatManager(groupchat=chat, llm_config=llm_config)

        user.initiate_chat(
            manager,
            message=("Produce a CTI report for the following detection.\n\n" + evidence),
        )

        # The report is the Report_Writer's last substantive message.
        for msg in reversed(chat.messages):
            if msg.get("name") == "Report_Writer" and (msg.get("content") or "").strip():
                report = _strip_terminate(msg["content"])
                if report:
                    return report
        LOG.warning("AG2 chat produced no report-writer message; falling back.")
        return None
    except Exception as exc:  # noqa: BLE001 — never let AG2 break the worker loop
        LOG.error("AG2 CTI generation failed (%s) — falling back to template.", exc)
        return None
