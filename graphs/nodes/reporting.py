from __future__ import annotations

import json
import re
import time
from collections import Counter

from config import load_settings
from graphs.state import ThreatIntelState


MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _extract_ids(text: str) -> set[str]:
    return {match.upper() for match in MITRE_ID_RE.findall(text or "")}


def _previously_retrieved_ids(state: ThreatIntelState) -> set[str]:
    ids: set[str] = set()
    for context in state.get("mitre_context", {}).values():
        ids.update(str(item).upper() for item in context.get("retrieved_ids", []))
    prediction = state.get("prediction", {})
    ids.update(str(item).upper() for item in prediction.get("retrieved_ids", []))
    ids.update(str(ioc.get("technique_confirmed", "")).upper() for ioc in state.get("enriched_iocs", []))
    return {item for item in ids if item}


def _sources_summary(report_text: str, state: ThreatIntelState) -> str:
    used_ids = _extract_ids(report_text)
    retrieved_ids = _previously_retrieved_ids(state)
    retrieved_and_used = sorted(used_ids & retrieved_ids)
    beyond_retrieved = sorted(used_ids - retrieved_ids)
    retrieved_not_used = sorted(retrieved_ids - used_ids)
    fmt = lambda values: ", ".join(values) if values else "None"
    return (
        "\n\n---\n"
        "SOURCES SUMMARY (computed automatically, not self-reported by the model)\n"
        f"Retrieved from previous nodes and used in this report: {fmt(retrieved_and_used)}\n"
        "Used in this report but NOT found in previous retrieved context: "
        f"{fmt(beyond_retrieved)}\n"
        f"Retrieved by previous nodes but not used in this report: {fmt(retrieved_not_used)}\n"
        "---"
    )


def _truncate(text: str, max_chars: int = 900) -> str:
    text = str(text or "").strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + "..."


def _strip_source_leakage(text: str) -> str:
    text = str(text or "")
    text = re.sub(
        r"(?ims)^\s*(?:#{1,6}\s*)?sources?\s+summary\b.*\Z",
        "",
        text,
    )
    text = re.sub(
        r"(?ims)^\s*---\s*\n\s*sources?\s+summary\b.*\Z",
        "",
        text,
    )
    cleaned_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            cleaned_lines.append(line)
            continue
        if lowered.startswith(
            (
                "retrieved from database",
                "retrieved from previous nodes",
                "used in this answer",
                "used in this report",
                "retrieved by previous nodes",
                "beyond retrieved data",
            )
        ):
            continue
        if stripped == "---":
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()


def _confirmed_technique_ids(state: ThreatIntelState) -> list[str]:
    scoped_alert_ids = set(state.get("campaign", {}).get("correlated_alert_ids") or [])
    return sorted(
        {
            str(ioc.get("technique_confirmed", "")).upper()
            for ioc in state.get("enriched_iocs", [])
            if ioc.get("technique_confirmed")
            and (not scoped_alert_ids or str(ioc.get("alert_id", "")) in scoped_alert_ids)
        }
    )


def _campaign_stage(campaign: dict) -> str:
    return str(campaign.get("current_stage") or campaign.get("stage") or "Unknown")


def _source_summary(campaign: dict, confidence_score: float) -> str:
    source_ip = campaign.get("attacker_ip", "Unknown")
    target = campaign.get("target_asset", "Unknown")
    actor = str(campaign.get("attributed_actor", "Unknown"))
    is_internal = bool(campaign.get("source_ip_is_internal"))
    is_unattributed = actor in {"Unknown", "Unattributed", "Unattributed Threat Actor"}
    if is_internal:
        return f"The most common source address is {source_ip} (internal or loopback telemetry), targeting {target}. "
    if is_unattributed or confidence_score < 0.5:
        return f"The most common source address is {source_ip}, targeting {target}; it is not yet confirmed as attacker infrastructure. "
    return f"The most common attacker infrastructure is {source_ip}, targeting {target}. "


def _stage_summary(campaign: dict, confidence_score: float) -> str:
    stage = str(campaign.get("current_stage") or "Unknown")
    tactics = campaign.get("confirmed_tactics") or []
    reasoning = str(campaign.get("stage_reasoning") or "").strip()
    if stage in {"Insufficient Evidence", "Unknown"} or not tactics:
        return (
            "Observed Activity: repeated authentication failures or low-confidence telemetry were detected.\n"
            "Confirmed ATT&CK Tactic: None confirmed.\n"
            "Assessment: Unable to determine campaign progression beyond the observed techniques."
        )
    tactic_text = ", ".join(tactics)
    confidence_text = "high" if confidence_score >= 0.7 else "medium" if confidence_score >= 0.4 else "low"
    return (
        f"Observed Activity: evidence currently supports {tactic_text.lower()} activity.\n"
        f"Confirmed ATT&CK Tactic: {stage}\n"
        f"Assessment: {reasoning or 'Evidence supports the observed tactic only.'}\n"
        f"Confidence: {confidence_text}"
    )


def _timeline(state: ThreatIntelState) -> list[dict]:
    scoped_alert_ids = set(state.get("campaign", {}).get("correlated_alert_ids") or [])
    iocs_by_alert = {
        str(ioc.get("alert_id", "")): ioc
        for ioc in state.get("enriched_iocs", [])
        if ioc.get("technique_confirmed")
        and (not scoped_alert_ids or str(ioc.get("alert_id", "")) in scoped_alert_ids)
    }
    seen: set[tuple] = set()
    rows = []
    for alert in sorted(state.get("raw_alerts", []), key=lambda item: item.get("timestamp", "")):
        if scoped_alert_ids and str(alert.get("id", "")) not in scoped_alert_ids:
            continue
        dedup_key = (str(alert.get("timestamp", "")), str(alert.get("event_type", "")))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        ioc = iocs_by_alert.get(str(alert.get("id", "")), {})
        technique = str(ioc.get("technique_confirmed", "")).strip() or "none confirmed"
        rows.append(
            {
                "timestamp": alert.get("timestamp", ""),
                "alert_id": alert.get("id", ""),
                "source_ip": alert.get("source_ip", ""),
                "destination": alert.get("destination", ""),
                "event_type": alert.get("event_type", ""),
                "technique": technique,
                "actor": ioc.get("actor_name", "Unknown"),
                "confidence": ioc.get("confidence", 0.0),
                "actor_confidence": ioc.get("actor_confidence"),
                "data_source": alert.get("data_source", "unknown"),
                "wazuh_rule_id": alert.get("wazuh_rule_id", ""),
                "wazuh_rule_level": alert.get("wazuh_rule_level", ""),
                "agent_name": alert.get("agent_name", ""),
                "risk_score": alert.get("risk_score"),
                "risk_priority": alert.get("risk_priority"),
                "risk_reasons": alert.get("risk_reasons", []),
            }
        )
    return rows


def _technique_catalog(state: ThreatIntelState) -> dict[str, dict]:
    catalog: dict[str, dict] = {}
    for technique_id, context in state.get("mitre_context", {}).items():
        catalog[str(technique_id).upper()] = context
    return catalog


def _format_attack_timeline_section(state: ThreatIntelState) -> str:
    lines = []
    for row in _timeline(state):
        if row.get("risk_score") is None and not row.get("risk_priority"):
            risk_label = "unscored"
        else:
            risk_label = f"{int(row.get('risk_score') or 0)}/{row.get('risk_priority') or 'unknown'}"
        lines.append(
            f"- {row['timestamp']} | {row['source_ip']} -> {row['destination']} | "
            f"{row['event_type']} | {row['technique']} | actor={row['actor']} | "
            f"technique_confidence={float(row['confidence']):.0%} | "
            f"actor_confidence={float(row['actor_confidence'] or 0.0):.0%} | "
            f"risk={risk_label}"
        )
    return "\n".join(lines) if lines else "- No confirmed timeline events available."


def _format_threat_assessment_section(state: ThreatIntelState) -> str:
    campaign = state.get("campaign", {})
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)
    techniques = campaign.get("techniques_confirmed") or _confirmed_technique_ids(state)
    actor_counts = Counter(
        str(ioc.get("actor_name", "Unknown"))
        for ioc in state.get("enriched_iocs", [])
        if not set(campaign.get("correlated_alert_ids") or [])
        or str(ioc.get("alert_id", "")) in set(campaign.get("correlated_alert_ids") or [])
    )
    actor_evidence = ", ".join(f"{name}: {count}" for name, count in actor_counts.most_common()) or "Unknown"
    actor_confidences = [
        f"{ioc.get('actor_name', 'Unknown')}: {float(ioc.get('actor_confidence', 0.0) or 0.0):.0%}"
        for ioc in state.get("enriched_iocs", [])
        if ioc.get("actor_name")
        and (
            not set(campaign.get("correlated_alert_ids") or [])
            or str(ioc.get("alert_id", "")) in set(campaign.get("correlated_alert_ids") or [])
        )
    ]
    actor = campaign.get("attributed_actor", "Unknown")
    campaign_confidence = float(campaign.get("campaign_confidence", 0.0) or 0.0)
    kill_chain_position = campaign.get("kill_chain_position", "Unknown")
    technique_lines = []
    catalog = _technique_catalog(state)
    for technique_id in techniques:
        context = catalog.get(str(technique_id).upper(), {})
        name = context.get("name", technique_id)
        tactic = context.get("tactic", "Unknown")
        technique_lines.append(f"- {technique_id} ({name}) — tactic: {tactic}")
    technique_block = "\n".join(technique_lines) if technique_lines else "- None confirmed"
    return (
        f"Confirmed techniques:\n{technique_block}\n"
        f"Attributed actor: {actor} (campaign confidence {campaign_confidence:.0%}).\n"
        f"Actor evidence counts: {actor_evidence}.\n"
        f"Actor confidence evidence: {', '.join(actor_confidences) if actor_confidences else 'Unknown'}.\n"
        f"Investigation enrichment confidence: {confidence_score:.0%}.\n"
        f"Kill chain position: {kill_chain_position}/7."
    )


def _format_current_attack_stage_section(state: ThreatIntelState) -> str:
    campaign = state.get("campaign", {})
    collection_metadata = state.get("collection_metadata", {})
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)
    is_live = collection_metadata.get("data_source") == "wazuh_live"
    stage = _campaign_stage(campaign)
    reasoning = str(campaign.get("stage_reasoning") or "").strip()
    kill_chain_position = campaign.get("kill_chain_position", "Unknown")
    lines = [
        f"Stage: {stage}",
        f"Kill chain position: {kill_chain_position}/7",
    ]
    if reasoning:
        lines.append(f"Reasoning: {reasoning}")
    if is_live and confidence_score < 0.5:
        lines.append(
            "Guidance: Validate the alert chain before declaring an active incident, but preserve evidence and review affected hosts."
        )
    elif stage not in {"Insufficient Evidence", "Unknown"}:
        lines.append("Guidance: Treat this as active movement requiring containment until validated otherwise.")
    return "\n".join(lines)


def _format_predicted_next_moves_section(state: ThreatIntelState) -> str:
    prediction = state.get("prediction", {})
    predicted = prediction.get("predicted_next_techniques") or prediction.get("predicted_techniques") or []
    details = prediction.get("predicted_next_technique_details") or []
    detail_lines = []
    for item in details:
        technique_id = str(item.get("id", "")).upper()
        name = item.get("name", technique_id)
        if technique_id:
            detail_lines.append(f"- {technique_id} ({name})")
    predicted_text = ", ".join(predicted) if predicted else "None projected"
    detail_block = "\n".join(detail_lines) if detail_lines else "- No detailed technique projections available."
    note = str(prediction.get("note") or "").strip()
    time_to_next = prediction.get("time_to_next_stage", "Unknown")
    confidence = float(prediction.get("prediction_confidence", 0.0) or 0.0)
    lines = [
        f"Predicted techniques: {predicted_text}",
        detail_block,
        f"Estimated time to next stage: {time_to_next}",
        f"Prediction confidence: {confidence:.0%}",
    ]
    if note:
        lines.append(f"Note: {note}")
    return "\n".join(lines)


def _format_recommended_actions_section(state: ThreatIntelState) -> str:
    prediction = state.get("prediction", {})
    recommended = _strip_source_leakage(prediction.get("recommended_immediate_actions") or "")
    if recommended:
        if recommended[0].isdigit():
            return recommended
        numbered = [line.strip() for line in recommended.splitlines() if line.strip()]
        return "\n".join(f"{idx}. {line.lstrip('0123456789.- ')}" for idx, line in enumerate(numbered, start=1))
    return (
        "1. Isolate the suspected pivot host and any affected clinical servers.\n"
        "2. Disable or rotate credentials used from the attacker source IPs.\n"
        "3. Block RDP/SMB lateral movement paths and preserve endpoint evidence."
    )


def _format_detection_rules_section(state: ThreatIntelState) -> str:
    catalog = _technique_catalog(state)
    confirmed = _confirmed_technique_ids(state)
    lines = []
    for technique_id in confirmed:
        context = catalog.get(technique_id, {})
        name = context.get("name", technique_id)
        guidance = _truncate(context.get("detection_guidance", ""), 500)
        if guidance:
            lines.append(f"Detection rule for {technique_id} ({name}): {guidance}")
        else:
            lines.append(f"Detection rule for {technique_id} ({name}): Monitor for telemetry consistent with this technique.")
    if not lines:
        techniques = ", ".join(state.get("campaign", {}).get("techniques_confirmed", []) or []) or "confirmed techniques"
        return (
            f"Prioritize SIEM detections for {techniques}, repeated authentication failures, "
            "successful login after failures, internal scanning, RDP failures, and encoded PowerShell from service accounts."
        )
    return "\n".join(lines)


def _build_deterministic_sections(state: ThreatIntelState) -> dict[str, str]:
    return {
        "attack_timeline": _format_attack_timeline_section(state),
        "threat_assessment": _format_threat_assessment_section(state),
        "current_attack_stage": _format_current_attack_stage_section(state),
        "predicted_next_moves": _format_predicted_next_moves_section(state),
        "recommended_actions": _format_recommended_actions_section(state),
        "detection_rules": _format_detection_rules_section(state),
    }


def _build_condensed_summary(state: ThreatIntelState) -> dict:
    campaign = state.get("campaign", {})
    collection_metadata = state.get("collection_metadata", {})
    catalog = _technique_catalog(state)
    confirmed_ids = _confirmed_technique_ids(state)
    return {
        "data_source": collection_metadata.get("data_source", "unknown"),
        "attack_type": campaign.get("attack_type", "unknown"),
        "current_stage": _campaign_stage(campaign),
        "kill_chain_position": campaign.get("kill_chain_position"),
        "confirmed_technique_ids": confirmed_ids,
        "confirmed_technique_names": {
            technique_id: catalog.get(technique_id, {}).get("name", technique_id)
            for technique_id in confirmed_ids
        },
        "attributed_actor": campaign.get("attributed_actor", "Unknown"),
        "campaign_confidence": campaign.get("campaign_confidence", 0.0),
        "confidence_score": state.get("confidence_score", 0.0),
        "risk_score": state.get("risk_score", 0) or 0,
        "target_asset": campaign.get("target_asset", "Unknown"),
        "potential_patient_impact_hint": _truncate(state.get("prediction", {}).get("business_impact", ""), 400),
    }


def _fallback_narrative(state: ThreatIntelState) -> dict[str, str]:
    campaign = state.get("campaign", {})
    collection_metadata = state.get("collection_metadata", {})
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)
    is_live = collection_metadata.get("data_source") == "wazuh_live"
    stage = _campaign_stage(campaign)
    techniques = ", ".join(campaign.get("techniques_confirmed", []) or _confirmed_technique_ids(state)) or "Unknown"
    actor = campaign.get("attributed_actor", "Unknown")
    campaign_confidence = float(campaign.get("campaign_confidence", 0.0) or 0.0)
    source_sentence = _source_summary(campaign, confidence_score)
    insufficient_evidence = confidence_score < 0.3 or stage == "Insufficient Evidence"

    executive_summary = (
        _stage_summary(campaign, confidence_score)
        + "\n"
        + f"MedFlow is investigating {collection_metadata.get('data_source', 'unknown')} evidence "
        f"with an enrichment confidence of {confidence_score:.0%}. "
        f"{source_sentence}"
        f"Attribution points most strongly to {actor}, with campaign confidence at {campaign_confidence:.0%}. "
        f"Confirmed techniques in scope: {techniques}."
    )
    if is_live and confidence_score < 0.5:
        executive_summary += (
            " Because this is low-confidence live telemetry, treat this as triage evidence rather than a confirmed campaign."
        )

    if insufficient_evidence:
        healthcare_impact = (
            "No specific healthcare-impact scenario can be projected because there is insufficient confirmed evidence. "
            "Continue triage and evidence preservation before assessing patient-care, HIPAA, or operational impact."
        )
    else:
        healthcare_impact = state.get("prediction", {}).get(
            "business_impact",
            "Potential impact on patient data availability, EHR downtime, and patient-care disruption. "
            "Data exfiltration or patient data exposure is unconfirmed unless supported by separate exfiltration evidence.",
        )

    return {
        "executive_summary": executive_summary.strip(),
        "healthcare_impact": str(healthcare_impact).strip(),
    }


def _build_narrative_prompt(state: ThreatIntelState) -> str:
    summary = _build_condensed_summary(state)
    campaign = state.get("campaign", {})
    collection_metadata = state.get("collection_metadata", {})
    is_live = collection_metadata.get("data_source") == "wazuh_live"
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)
    current_stage = _campaign_stage(campaign)
    confirmed_technique_ids = _confirmed_technique_ids(state)
    insufficient_evidence = confidence_score < 0.3 or current_stage == "Insufficient Evidence"
    can_project_healthcare_impact = confidence_score >= 0.5 and bool(confirmed_technique_ids)

    caution = ""
    if is_live:
        caution = (
            "This is live Wazuh telemetry and may be incomplete or noisy. Use cautious wording such as "
            "'preliminary evidence suggests' and do not claim confirmed ransomware unless encryption evidence exists."
        )
    elif float(campaign.get("campaign_confidence", 0.0) or 0.0) < 0.6:
        caution = "Treat this as provisional analysis rather than a confirmed campaign."

    if insufficient_evidence:
        healthcare_instruction = (
            "Write HEALTHCARE IMPACT as a brief statement that no specific healthcare-impact scenario can be projected "
            "given insufficient confirmed evidence."
        )
    elif can_project_healthcare_impact:
        healthcare_instruction = (
            "Write HEALTHCARE IMPACT as a concise narrative on patient-care, HIPAA, and operational risk "
            "based only on the confirmed techniques and stage provided."
        )
    else:
        healthcare_instruction = (
            "Write HEALTHCARE IMPACT cautiously and evidence-bound without inventing exfiltration or PHI exposure."
        )

    return f"""
You are a senior SOC analyst writing narrative prose for a healthcare incident report.

Write ONLY these two sections using the structured investigation summary below.
Do NOT restate timelines, technique lists, attack stage, predictions, actions, or detection rules.

INVESTIGATION SUMMARY:
{json.dumps(summary, indent=2)}

Requirements:
1. EXECUTIVE SUMMARY — 3-4 sentences, non-technical, suitable for hospital leadership.
2. HEALTHCARE IMPACT — 2-4 sentences on patient care, HIPAA, and operational risk.

Use the exact current_stage and confirmed_technique_ids from the summary. Do not contradict them.
Our kill chain uses exactly 7 stages (1-7). Never use X/9.
Do not claim data exfiltration or PHI exposure without explicit exfiltration evidence.
{caution}
{healthcare_instruction}

Return exactly these headings:
EXECUTIVE SUMMARY
<paragraph>

HEALTHCARE IMPACT
<paragraph>
"""


def _has_narrative_sections(report_text: str) -> bool:
    text = report_text.upper()
    return "EXECUTIVE SUMMARY" in text and "HEALTHCARE IMPACT" in text


def _parse_narrative_sections(report_text: str) -> dict[str, str]:
    text = report_text.strip()
    upper = text.upper()
    exec_idx = upper.find("EXECUTIVE SUMMARY")
    health_idx = upper.find("HEALTHCARE IMPACT")
    if exec_idx < 0 or health_idx < 0 or health_idx <= exec_idx:
        raise ValueError("Narrative response missing required sections")
    executive_summary = text[exec_idx + len("EXECUTIVE SUMMARY"):health_idx].strip(":\n ")
    healthcare_impact = text[health_idx + len("HEALTHCARE IMPACT"):].strip(":\n ")
    if not executive_summary or not healthcare_impact:
        raise ValueError("Narrative response sections were empty")
    return {
        "executive_summary": executive_summary,
        "healthcare_impact": healthcare_impact,
    }


def _assemble_report(narrative: dict[str, str], sections: dict[str, str]) -> str:
    return (
        "1. EXECUTIVE SUMMARY\n"
        f"{narrative['executive_summary']}\n\n"
        "2. ATTACK TIMELINE\n"
        f"{sections['attack_timeline']}\n\n"
        "3. THREAT ASSESSMENT\n"
        f"{sections['threat_assessment']}\n\n"
        "4. CURRENT ATTACK STAGE\n"
        f"{sections['current_attack_stage']}\n\n"
        "5. PREDICTED NEXT MOVES\n"
        f"{sections['predicted_next_moves']}\n\n"
        "6. IMMEDIATE RECOMMENDED ACTIONS\n"
        f"{sections['recommended_actions']}\n\n"
        "7. DETECTION RULES\n"
        f"{sections['detection_rules']}\n\n"
        "8. HEALTHCARE IMPACT\n"
        f"{narrative['healthcare_impact']}"
    )


def _is_retryable_reporting_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "429" in text
        or "rate limit" in text
        or "rate_limit" in text
        or "connection" in text
        or "network" in text
        or "timeout" in text
        or "temporarily unavailable" in text
        or "socket" in text
        or "dns" in text
        or "refused" in text
        or "reset" in text
    )


def _generate_narrative_with_retry(
    prompt: str,
    *,
    model: str,
    api_key: str,
    max_attempts: int = 3,
    base_delay: float = 2.0,
) -> dict[str, str]:
    from groq import Groq

    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            client = Groq(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior SOC analyst writing concise narrative sections for a "
                            "healthcare threat intelligence report."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=900,
            )
            report_text = response.choices[0].message.content or ""
            # Strip both closed <think>...</think> blocks and unclosed ones
            # (unclosed blocks occur when a thinking model is truncated at max_tokens)
            report_text = re.sub(r"<think\b[^>]*>.*?</think>", "", report_text, flags=re.DOTALL | re.IGNORECASE)
            report_text = re.sub(r"<think\b[^>]*>.*$", "", report_text, flags=re.DOTALL | re.IGNORECASE)
            report_text = report_text.strip()
            if not _has_narrative_sections(report_text):
                raise ValueError("Model narrative was incomplete")
            return _parse_narrative_sections(report_text)
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_reporting_error(exc) or attempt >= max_attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            print(f"[Reporting] Retryable narrative error on attempt {attempt}/{max_attempts}: {exc}")
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Narrative generation failed without a captured exception")


# Backward-compatible aliases used by tests
_build_report_prompt = _build_narrative_prompt
_generate_report_with_retry = _generate_narrative_with_retry


def _fallback_report(state: ThreatIntelState) -> str:
    sections = _build_deterministic_sections(state)
    narrative = _fallback_narrative(state)
    return _assemble_report(narrative, sections)


def reporting_node(state: ThreatIntelState) -> dict:
    errors = list(state.get("errors", []))
    settings = load_settings()
    campaign = state.get("campaign", {})
    is_live = state.get("collection_metadata", {}).get("data_source") == "wazuh_live"
    has_confirmed_techniques = bool(_confirmed_technique_ids(state))
    sections = _build_deterministic_sections(state)

    if is_live and (_campaign_stage(campaign) == "Insufficient Evidence" or not has_confirmed_techniques):
        report_text = _assemble_report(_fallback_narrative(state), sections)
        print("[Reporting] Report assembled from deterministic template (live low-confidence path; LLM skipped)")
        print(f"[Reporting] Report length: {len(report_text)} characters")
        return {"report": report_text, "errors": errors}

    narrative_source = "llm"
    try:
        time.sleep(2)
        narrative = _generate_narrative_with_retry(
            _build_narrative_prompt(state),
            model=settings.main_model,
            api_key=settings.groq_api_key,
            max_attempts=3,
            base_delay=2.0,
        )
    except Exception as exc:
        narrative_source = "fallback_template"
        if _is_retryable_reporting_error(exc):
            errors.append(f"[Reporting] LLM narrative unavailable after retries: {exc}")
        else:
            errors.append(f"[Reporting] LLM narrative unavailable: {exc}")
        narrative = _fallback_narrative(state)

    report_text = _assemble_report(narrative, sections)

    if narrative_source == "llm":
        print("[Reporting] Report assembled with LLM-generated narrative sections")
    else:
        print("[Reporting] Report assembled from deterministic fallback template (LLM narrative unavailable)")
    print(f"[Reporting] Report length: {len(report_text)} characters")
    return {"report": report_text, "errors": errors}
