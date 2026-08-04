from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from graphs.state import ThreatIntelState


STAGE_BY_POSITION = {
    0: "Insufficient Evidence",
    1: "Reconnaissance",
    2: "Initial Access",
    3: "Execution",
    4: "Credential Access",
    5: "Defense Evasion",
    6: "Lateral Movement",
    7: "Impact",
}

TACTIC_PRIORITY = {
    "reconnaissance": 1,
    "resource development": 1,
    "discovery": 2,
    "initial access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege escalation": 4,
    "credential access": 5,
    "defense evasion": 5,
    "collection": 5,
    "lateral movement": 6,
    "command and control": 6,
    "exfiltration": 7,
    "impact": 7,
}

TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource development": "Resource Development",
    "discovery": "Discovery",
    "initial access": "Initial Access",
    "execution": "Execution",
    "credential access": "Credential Access",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "lateral movement": "Lateral Movement",
    "command and control": "Command and Control",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

DEFAULT_CORRELATION_WINDOW_HOURS = 72


def _alert_by_id(raw_alerts: list[dict]) -> dict[str, dict]:
    return {str(alert.get("id", "")): alert for alert in raw_alerts}


def _parse_alert_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
            text = f"{text[:-2]}:{text[-2:]}"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _alert_timestamp(alert: dict) -> datetime | None:
    return _parse_alert_timestamp(alert.get("timestamp") or alert.get("@timestamp"))


def _rule_groups(alert: dict) -> set[str]:
    groups = alert.get("rule_groups") or alert.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    return {str(group).strip().lower() for group in groups if str(group).strip()}


GENERIC_HOSTNAMES = {
    "unknown",
    "none",
    "n/a",
    "-",
    "::",
    "0.0.0.0",
    "localhost",
    "127.0.0.1",
    "ubuntu",
    "wazuh",
    "wazuh-agent",
    "wazuh.manager",
    "wazuh-manager-01",
    "manager",
    "medflow-network-segment",
}


def _is_wazuh_operational_noise(alert: dict) -> bool:
    groups = _rule_groups(alert)
    text = _alert_text(alert)
    decoder = str(alert.get("decoder", "") or "").lower()

    if "ossec" in groups or "rootcheck" in groups or "syscheck_cleaning" in groups:
        return True
    if decoder in {"ossec", "rootcheck"}:
        return True
    return any(
        token in text
        for token in (
            "rootcheck",
            "ossec",
            "log rotation",
            "log file rotated",
            "logs rotated",
            "wazuh agent started",
            "wazuh agent stopped",
            "vss service is shutting down",
            "service entered the stopped state",
            "service entered the running state",
        )
    )


def _host_key(alert: dict) -> set[str]:
    keys = set()
    for field in ("source_ip", "destination", "agent_name", "agent_ip"):
        value = str(alert.get(field, "") or "").strip().lower()
        if value and value not in GENERIC_HOSTNAMES:
            keys.add(f"{field}:{value}")
    return keys


def _record_is_host_relevant(anchor: dict, candidate: dict) -> bool:
    anchor_source = str(anchor.get("source_ip", "") or "").strip().lower()
    candidate_source = str(candidate.get("source_ip", "") or "").strip().lower()
    if anchor_source and anchor_source not in GENERIC_HOSTNAMES and anchor_source == candidate_source:
        return True
    anchor_keys = _host_key(anchor)
    candidate_keys = _host_key(candidate)
    return bool(anchor_keys & candidate_keys)


def _risk_score(alert: dict) -> int:
    try:
        return int(alert.get("risk_score", 0) or alert.get("wazuh_rule_level", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _select_campaign_scope(
    raw_alerts: list[dict],
    enriched_iocs: list[dict],
    *,
    window_hours: int = DEFAULT_CORRELATION_WINDOW_HOURS,
) -> tuple[list[dict], list[dict], dict]:
    raw_by_id = _alert_by_id(raw_alerts)
    excluded: list[dict] = []
    records: list[dict] = []

    for ioc in enriched_iocs:
        alert_id = str(ioc.get("alert_id", ""))
        alert = raw_by_id.get(alert_id)
        if not alert:
            excluded.append({"alert_id": alert_id, "reason": "missing_raw_alert"})
            continue
        if _is_wazuh_operational_noise(alert):
            excluded.append({"alert_id": alert_id, "reason": "wazuh_operational_noise"})
            continue
        records.append({"ioc": ioc, "alert": alert, "timestamp": _alert_timestamp(alert)})

    if not records:
        return [], [], {
            "correlation_window_hours": window_hours,
            "excluded_alerts": excluded,
            "scope_reason": "no_security_iocs_after_noise_filter",
        }

    window = timedelta(hours=window_hours)
    timed_records = [record for record in records if record["timestamp"] is not None]
    if not timed_records:
        selected = records[:1]
        selected_ids = {str(selected[0]["ioc"].get("alert_id", ""))}
        excluded.extend(
            {"alert_id": str(record["ioc"].get("alert_id", "")), "reason": "missing_timestamp_outside_primary_scope"}
            for record in records[1:]
        )
        return [record["alert"] for record in selected], [record["ioc"] for record in selected], {
            "correlation_window_hours": window_hours,
            "excluded_alerts": excluded,
            "correlated_alert_ids": sorted(selected_ids),
            "scope_reason": "single_alert_fallback_missing_timestamps",
        }

    candidate_clusters: list[list[dict]] = []
    for anchor in timed_records:
        cluster = []
        for record in records:
            candidate_time = record["timestamp"]
            if candidate_time is None:
                continue
            if abs(candidate_time - anchor["timestamp"]) > window:
                continue
            if not _record_is_host_relevant(anchor["alert"], record["alert"]):
                continue
            cluster.append(record)
        candidate_clusters.append(cluster)

    selected = max(
        candidate_clusters,
        key=lambda cluster: (
            max((record["timestamp"] for record in cluster if record["timestamp"] is not None), default=datetime.min.replace(tzinfo=timezone.utc)),
            sum(_risk_score(record["alert"]) for record in cluster),
            len(cluster),
        ),
    )
    selected_ids = {str(record["ioc"].get("alert_id", "")) for record in selected}

    for record in records:
        alert_id = str(record["ioc"].get("alert_id", ""))
        if alert_id in selected_ids:
            continue
        if record["timestamp"] is None:
            reason = "missing_timestamp_outside_primary_scope"
        else:
            reason = "outside_correlation_window_or_host_scope"
        excluded.append({"alert_id": alert_id, "reason": reason})

    return [record["alert"] for record in selected], [record["ioc"] for record in selected], {
        "correlation_window_hours": window_hours,
        "excluded_alerts": excluded,
        "correlated_alert_ids": sorted(selected_ids),
        "scope_reason": "time_and_host_scoped_primary_cluster",
    }


def _most_common(values: list[str], default: str = "Unknown") -> str:
    filtered = [value for value in values if value]
    if not filtered:
        return default
    return Counter(filtered).most_common(1)[0][0]


def _is_internal_or_reserved_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _alert_text(alert: dict) -> str:
    return " ".join(
        str(alert.get(field, ""))
        for field in (
            "event_type",
            "rule_description",
            "raw_log",
            "wazuh_rule_id",
            "decoder",
        )
    ).lower()


def _alert_category(alert: dict) -> str:
    text = _alert_text(alert)
    if any(token in text for token in ("logon failure", "bad password", "authentication failure", "failed login", "5712")):
        return "authentication"
    if any(token in text for token in ("integrity checksum changed", "syscheck", "file modified")):
        return "fim"
    if any(token in text for token in ("powershell", "encodedcommand", "cmd.exe")):
        return "execution"
    if any(token in text for token in ("rdp", "remote desktop", "terminalservices")):
        return "remote_access"
    return "other"


def _effective_kill_chain_position(technique_id: str, mitre_context: dict) -> int:
    technique_id = str(technique_id or "").upper()
    return int(mitre_context.get(technique_id, {}).get("kill_chain_position", 3))


def _tactic_from_context(technique_id: str, mitre_context: dict) -> str:
    tactic = str(mitre_context.get(technique_id, {}).get("tactic", "") or "").strip().lower()
    return tactic or "unknown"


def _stage_reasoning(
    observed_tactics: list[str],
    stage: str,
    kill_chain_position: int,
    highest_techniques: list[str],
) -> str:
    capitalized_tactics = [TACTIC_LABELS.get(t, t.title()) for t in observed_tactics]
    technique_text = ", ".join(highest_techniques) if highest_techniques else "the confirmed evidence"
    return (
        f"Confirmed techniques mapped to ATT&CK tactics: {', '.join(capitalized_tactics)}. "
        f"The highest-position confirmed technique(s) are {technique_text} at kill chain position "
        f"{kill_chain_position}/7, so the campaign is currently assessed at {stage}."
    )


def _derive_stage_from_tactics(techniques: list[str], mitre_context: dict) -> tuple[str, int, str, list[str]]:
    technique_ids = [str(technique_id or "").upper() for technique_id in techniques if technique_id]
    observed_tactics = sorted(
        {
            _tactic_from_context(technique_id, mitre_context)
            for technique_id in technique_ids
            if _tactic_from_context(technique_id, mitre_context) != "unknown"
        },
        key=lambda tactic: TACTIC_PRIORITY.get(tactic, 0),
    )

    if not observed_tactics:
        return "Insufficient Evidence", 0, "No confirmed ATT&CK tactic was available to support a stage assessment.", []

    technique_positions = {
        technique_id: _effective_kill_chain_position(technique_id, mitre_context)
        for technique_id in technique_ids
    }
    kill_chain_position = max(technique_positions.values())
    highest_techniques = sorted(
        technique_id
        for technique_id, position in technique_positions.items()
        if position == kill_chain_position
    )
    stage = STAGE_BY_POSITION.get(kill_chain_position)
    if stage is None:
        highest_tactic = max(observed_tactics, key=lambda tactic: TACTIC_PRIORITY.get(tactic, 0))
        stage = TACTIC_LABELS.get(highest_tactic, highest_tactic.title())
    capitalized_tactics = [TACTIC_LABELS.get(t, t.title()) for t in observed_tactics]
    reasoning = _stage_reasoning(observed_tactics, stage, kill_chain_position, highest_techniques)
    return stage, kill_chain_position, reasoning, capitalized_tactics


def _compromise_confirmed(raw_alerts: list[dict], enriched_iocs: list[dict]) -> bool:
    success_tokens = (
        "successful login",
        "successful logon",
        "login successful",
        "logon successful",
        "session created",
        "session creation",
        "privilege escalation",
        "privileged",
        "elevated",
        "file modified",
        "syscheck",
        "checksum changed",
        "persistence",
        "scheduled task",
        "registry",
        "service installed",
        "ransomware",
        "encrypt",
    )
    for alert in raw_alerts:
        text = _alert_text(alert)
        if any(token in text for token in success_tokens):
            return True
    for ioc in enriched_iocs:
        technique_id = str(ioc.get("technique_confirmed", "")).upper()
        if technique_id in {"T1078", "T1485", "T1486", "T1489", "T1490", "T1491", "T1498", "T1529", "T1561"}:
            return True
    return False


def _attack_type(raw_alerts: list[dict], enriched_iocs: list[dict], source_ip: str, compromise_confirmed: bool) -> str:
    if compromise_confirmed:
        return "confirmed_compromise"

    auth_related = any(
        _alert_category(alert) == "authentication"
        or str(ioc.get("technique_confirmed", "")).upper() in {"T1110", "T1531"}
        for alert in raw_alerts
        for ioc in []
    )
    if not auth_related:
        auth_related = any(
            str(ioc.get("technique_confirmed", "")).upper() in {"T1110", "T1531"}
            for ioc in enriched_iocs
        )
    if auth_related and _is_internal_or_reserved_ip(source_ip):
        return "brute_force_attempt"
    if auth_related:
        return "brute_force_attempt"
    if raw_alerts or enriched_iocs:
        return "intrusion"
    return "reconnaissance"


def _weighted_actor_selection(
    enriched_iocs: list[dict],
    grouped_by_ip: dict[str, list[dict]],
    mitre_context: dict,
) -> tuple[str, dict[str, float]]:
    # Issue 3: pick attribution by weighted evidence, not raw frequency alone.
    most_common_source_ip = ""
    if grouped_by_ip:
        most_common_source_ip = max(grouped_by_ip, key=lambda ip: len(grouped_by_ip[ip]))

    scores: dict[str, float] = defaultdict(float)
    for ioc in enriched_iocs:
        actor_name = str(ioc.get("actor_name", "Unknown")).strip() or "Unknown"
        if actor_name in {"Unknown", "Unattributed", "Unattributed Threat Actor"}:
            continue

        technique_id = str(ioc.get("technique_confirmed", "")).upper()
        scores[actor_name] += 1.0
        if str(ioc.get("source_ip", "")) == most_common_source_ip:
            scores[actor_name] += 0.2
        if technique_id in mitre_context:
            scores[actor_name] += 0.1

    if not scores:
        return "Unattributed", {}
    return max(scores, key=scores.get), dict(scores)


def correlation_node(state: ThreatIntelState) -> dict:
    all_raw_alerts = state.get("raw_alerts", [])
    all_enriched_iocs = state.get("enriched_iocs", [])
    mitre_context = state.get("mitre_context", {})
    raw_alerts, enriched_iocs, scope_metadata = _select_campaign_scope(all_raw_alerts, all_enriched_iocs)
    raw_by_id = _alert_by_id(raw_alerts)

    if not enriched_iocs:
        campaign = {
            "campaign_id": f"CAMP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}",
            "attacker_ip": "Unknown",
            "source_ip_is_internal": False,
            "attributed_actor": "Unattributed",
            "current_stage": "Insufficient Evidence",
            "kill_chain_position": 0,
            "attack_type": "triage",
            "confirmed_tactics": [],
            "stage_reasoning": "No security-relevant, time-scoped IOC evidence remained after correlation filtering.",
            "techniques_confirmed": [],
            "alerts_count": 0,
            "attack_start": "",
            "attack_latest": "",
            "campaign_confidence": 0.0,
            "target_asset": "Unknown",
            "actor_scores": {},
            **scope_metadata,
        }
        print("[Correlation] No security-relevant campaign evidence after time/noise filtering")
        return {"campaign": campaign}

    grouped_by_ip: dict[str, list[dict]] = defaultdict(list)
    for ioc in enriched_iocs:
        grouped_by_ip[str(ioc.get("source_ip", "Unknown"))].append(ioc)

    timeline = sorted(
        enriched_iocs,
        key=lambda ioc: raw_by_id.get(str(ioc.get("alert_id")), {}).get("timestamp", ""),
    )

    compromise_confirmed = _compromise_confirmed(raw_alerts, enriched_iocs)
    most_common_source_ip = _most_common([str(ioc.get("source_ip", "")) for ioc in enriched_iocs])
    attack_type = _attack_type(raw_alerts, enriched_iocs, most_common_source_ip, compromise_confirmed)

    technique_ids = [
        str(ioc.get("technique_confirmed", "")).upper()
        for ioc in enriched_iocs
        if ioc.get("technique_confirmed")
    ]
    stage, kill_chain_position, stage_reasoning, observed_tactics = _derive_stage_from_tactics(technique_ids, mitre_context)
    if compromise_confirmed:
        stage = "Impact" if kill_chain_position >= 7 else stage
        kill_chain_position = max(kill_chain_position, 7) if compromise_confirmed else kill_chain_position
        if kill_chain_position >= 7 and stage != "Impact":
            stage = "Impact"
        if kill_chain_position >= 7 and "Impact" not in stage_reasoning:
            stage_reasoning = _stage_reasoning(
                [str(tactic).lower() for tactic in observed_tactics],
                stage,
                kill_chain_position,
                [
                    technique_id
                    for technique_id in technique_ids
                    if _effective_kill_chain_position(technique_id, mitre_context) == kill_chain_position
                ],
            )
    if stage == "Insufficient Evidence" and attack_type == "brute_force_attempt":
        stage = "Credential Access"
        kill_chain_position = 4
        stage_reasoning = (
            "Observed authentication failures map to ATT&CK Credential Access. "
            "No persistence, privilege escalation, or later-stage activity was confirmed."
        )

    confidence_scores = [float(ioc.get("confidence", 0.0)) for ioc in enriched_iocs]
    campaign_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
    if any(len(items) > 1 for items in grouped_by_ip.values()):
        campaign_confidence += 0.10

    stage = STAGE_BY_POSITION.get(kill_chain_position, stage)

    actor_counts = Counter(
        str(ioc.get("actor_name", "Unknown"))
        for ioc in enriched_iocs
        if str(ioc.get("actor_name", "Unknown")).strip()
    )
    actor, actor_scores = _weighted_actor_selection(enriched_iocs, grouped_by_ip, mitre_context)
    known_actor_count = len(
        {
            actor_name
            for actor_name in actor_counts
            if actor_name and actor_name not in {"Unknown", "Unattributed", "Unattributed Threat Actor"}
        }
    )

    timeline_positions = [
        int(mitre_context.get(str(ioc.get("technique_confirmed", "")).upper(), {}).get("kill_chain_position", 3))
        for ioc in timeline
    ]
    if any(later > earlier for earlier, later in zip(timeline_positions, timeline_positions[1:])):
        campaign_confidence += 0.10
    if actor not in {"Unattributed", "Unattributed Threat Actor"}:
        campaign_confidence += 0.05
    if known_actor_count > 1:
        campaign_confidence -= 0.10
    campaign_confidence = min(1.0, campaign_confidence)

    parsed_timestamps = [_alert_timestamp(alert) for alert in raw_alerts]
    parsed_timestamps = [timestamp for timestamp in parsed_timestamps if timestamp is not None]
    timestamps = [str(alert.get("timestamp", "")) for alert in raw_alerts if alert.get("timestamp")]
    techniques = sorted(
        {
            str(ioc.get("technique_confirmed", "")).upper()
            for ioc in enriched_iocs
            if ioc.get("technique_confirmed")
        }
    )
    campaign = {
        "campaign_id": f"CAMP-{datetime.now().strftime('%Y%m%d-%H%M')}",
        "attacker_ip": most_common_source_ip,
        "source_ip_is_internal": _is_internal_or_reserved_ip(most_common_source_ip),
        "attributed_actor": actor,
        "current_stage": stage,
        "kill_chain_position": kill_chain_position,
        "attack_type": attack_type,
        "confirmed_tactics": observed_tactics,
        "stage_reasoning": stage_reasoning,
        "techniques_confirmed": techniques,
        "alerts_count": len(enriched_iocs),
        "attack_start": min(parsed_timestamps).isoformat().replace("+00:00", "Z") if parsed_timestamps else min(timestamps) if timestamps else "",
        "attack_latest": max(parsed_timestamps).isoformat().replace("+00:00", "Z") if parsed_timestamps else max(timestamps) if timestamps else "",
        "campaign_confidence": campaign_confidence,
        "target_asset": _most_common([str(alert.get("destination", "")) for alert in raw_alerts]),
        "actor_scores": actor_scores,
        **scope_metadata,
    }
    if known_actor_count > 1:
        # Issue 3: preserve attribution ambiguity when multiple ransomware actor signatures appear together.
        campaign["campaign_note"] = (
            "Multiple actor signatures detected - possible shared infrastructure or misattribution. "
            f"Primary attribution: {actor}"
        )

    print(f"[Correlation] Campaign identified: {stage} stage")
    print(f"[Correlation] Actor: {actor} | Techniques: {len(techniques)} confirmed")
    print(f"[Correlation] Kill chain position: {kill_chain_position}/7")
    print(f"[Correlation] Campaign confidence: {campaign_confidence:.0%}")
    if campaign.get("campaign_note"):
        print(f"[Correlation] Note: {campaign['campaign_note']}")
    return {"campaign": campaign}
