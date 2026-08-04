from __future__ import annotations

import json
import os
import re
import time
from copy import deepcopy
from datetime import date, datetime, timedelta
from pathlib import Path

from langchain_groq import ChatGroq
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from config import ROOT_DIR, load_settings
from graphs.nodes.tools.external_tools import (
    check_threat_feeds,
    lookup_actor_profile,
    lookup_cve,
    query_misp,
)
from graphs.nodes.correlation import _is_wazuh_operational_noise
from graphs.state import ThreatIntelState
from graphs.text_utils import strip_model_thinking


_MITRE_TOOL_CACHE: dict[str, str] = {}
_MISP_PREFLIGHT_CACHE: dict[tuple[str, str, bool], tuple[bool, str]] = {}
IOC_CACHE_DIR = ROOT_DIR / ".cache" / "ioc_enrichment"
IOC_CACHE_VERSION = 1


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _misp_preflight() -> tuple[bool, str]:
    misp_url = os.getenv("MISP_URL", "http://localhost").strip().rstrip("/")
    misp_key = os.getenv("MISP_API_KEY", "").strip()
    verify_ssl = _env_flag("MISP_VERIFY_SSL", True)
    cache_key = (misp_url, "configured" if misp_key else "missing", verify_ssl)
    if cache_key in _MISP_PREFLIGHT_CACHE:
        return _MISP_PREFLIGHT_CACHE[cache_key]

    if not misp_key:
        result = (False, "MISP not configured; query_misp disabled for this run.")
        _MISP_PREFLIGHT_CACHE[cache_key] = result
        return result

    try:
        import requests
        import urllib3

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(
            misp_url,
            headers={"Authorization": misp_key, "Accept": "application/json"},
            timeout=3,
            verify=verify_ssl,
        )
        if response.status_code >= 500:
            result = (False, f"MISP preflight failed with HTTP {response.status_code}; query_misp disabled for this run.")
        else:
            result = (True, f"MISP preflight reachable at {misp_url}; query_misp enabled.")
    except Exception as exc:
        result = (False, f"MISP preflight failed for {misp_url}: {exc}; query_misp disabled for this run.")

    _MISP_PREFLIGHT_CACHE[cache_key] = result
    return result


def _today_cache_path(today: date | None = None) -> Path:
    return IOC_CACHE_DIR / f"{(today or date.today()).isoformat()}.json"


def _is_valid_cache_entry(entry: dict) -> bool:
    if not isinstance(entry, dict):
        return False
    confidence = float(entry.get("confidence", 0.0) or 0.0)
    technique_conf = float(entry.get("technique_confidence", 0.0) or 0.0)
    if confidence <= 0.0 and technique_conf <= 0.0:
        return False
    summary = str(entry.get("summary", "") or "").lower()
    if "failed gracefully" in summary or "failed to enrich" in summary:
        return False
    return True


def _load_ioc_cache() -> dict:
    path = _today_cache_path()
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != IOC_CACHE_VERSION:
            return {}
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            return {}
        return {key: val for key, val in entries.items() if _is_valid_cache_entry(val)}
    except Exception:
        return {}


def _save_ioc_cache(entries: dict) -> None:
    IOC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": IOC_CACHE_VERSION,
        "date": date.today().isoformat(),
        "entries": entries,
    }
    _today_cache_path().write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _simulated_cache_enabled(state: ThreatIntelState) -> tuple[bool, str]:
    if not _env_flag("MEDFLOW_SIMULATED_IOC_CACHE", False):
        return False, ""
    collection_metadata = state.get("collection_metadata", {}) or {}
    if collection_metadata.get("data_source") == "wazuh_live" or state.get("live_alerts"):
        return False, ""
    scenario_hash = str(collection_metadata.get("scenario_file_sha256") or "").strip()
    if not scenario_hash:
        return False, ""
    return True, scenario_hash


def _persistent_ioc_cache_key(alert: dict, scenario_hash: str) -> str:
    return f"{scenario_hash}:{alert.get('id', 'unknown')}"


def _extract_json_object(text: str) -> dict:
    text = strip_model_thinking(text)
    match = re.search(r"\{.*\}", text or "", flags=re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def _parse_agent_response(response_text: str) -> tuple[str, str, float, str]:
    response_text = strip_model_thinking(response_text)
    parsed = _extract_json_object(response_text)
    actor_name = str(parsed.get("actor_name") or "Unknown").strip() or "Unknown"
    normalized_actor = actor_name.lower()
    if "insufficient evidence" in normalized_actor or "unattributed" in normalized_actor or normalized_actor in {"unknown", "none", "n/a"}:
        actor_name = "Unattributed"
    malware_associated = str(parsed.get("malware_associated") or "Unknown").strip() or "Unknown"
    summary = str(parsed.get("summary") or response_text).strip()

    try:
        confidence = float(parsed.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    confidence = max(0.0, min(1.0, confidence))
    return actor_name, malware_associated, confidence, summary


def _parse_actor_tool_result(agent_result: dict) -> tuple[str, str, float, str] | None:
    messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
    for message in messages:
        name = getattr(message, "name", None)
        content = strip_model_thinking(getattr(message, "content", "") or "")
        message_type = getattr(message, "type", "")
        if name != "lookup_actor_profile" and message_type != "tool":
            continue
        if "ACTOR ATTRIBUTION:" not in content:
            continue
        parsed = _extract_json_object(content)
        if not parsed:
            continue
        actor_name = str(parsed.get("actor_name") or "Unattributed").strip() or "Unattributed"
        if actor_name.lower() in {"unknown", "none", "n/a", "insufficient evidence"}:
            actor_name = "Unattributed"
        malware_associated = str(parsed.get("malware_associated") or "Unknown").strip() or "Unknown"
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        summary = str(parsed.get("summary") or "").strip()
        return actor_name, malware_associated, max(0.0, min(1.0, confidence)), summary
    return None


def _actor_signature_from_alert(alert: dict, technique_id: str) -> tuple[str, str, float, str] | None:
    if str(technique_id or "").upper() != "T1486":
        return None
    text = " ".join(
        str(alert.get(field, "") or "")
        for field in ("event_type", "rule_description", "full_log", "raw_log")
    ).lower()
    if ".ryukreadme" in text or ".ryk" in text:
        return (
            "Ryuk",
            "Ryuk",
            0.75,
            "Local ransomware signature evidence: the alert log includes a Ryuk-style ransom-note/extension marker.",
        )
    return None


def _response_text(agent_result: dict) -> str:
    messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
    if not messages:
        return str(agent_result)

    final_message = messages[-1]
    content = getattr(final_message, "content", final_message)
    return strip_model_thinking(content if isinstance(content, str) else str(content))


def _tools_used(agent_result: dict) -> list[str]:
    messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
    tools: list[str] = []
    for message in messages:
        name = getattr(message, "name", None)
        if name and name not in tools:
            tools.append(name)
        for tool_call in getattr(message, "tool_calls", []) or []:
            tool_name = tool_call.get("name") if isinstance(tool_call, dict) else getattr(tool_call, "name", None)
            if tool_name and tool_name not in tools:
                tools.append(tool_name)
        additional_kwargs = getattr(message, "additional_kwargs", {}) or {}
        for tool_call in additional_kwargs.get("tool_calls", []) or []:
            function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
            tool_name = function.get("name")
            if tool_name and tool_name not in tools:
                tools.append(tool_name)
    return tools


def _tool_evidence(agent_result: dict) -> list[str]:
    messages = agent_result.get("messages", []) if isinstance(agent_result, dict) else []
    tool_call_names: dict[str, str] = {}
    for message in messages:
        for tool_call in getattr(message, "tool_calls", []) or []:
            if isinstance(tool_call, dict):
                call_id = tool_call.get("id")
                name = tool_call.get("name")
            else:
                call_id = getattr(tool_call, "id", None)
                name = getattr(tool_call, "name", None)
            if call_id and name:
                tool_call_names[str(call_id)] = str(name)
        additional_kwargs = getattr(message, "additional_kwargs", {}) or {}
        for tool_call in additional_kwargs.get("tool_calls", []) or []:
            call_id = tool_call.get("id") if isinstance(tool_call, dict) else None
            function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
            name = function.get("name")
            if call_id and name:
                tool_call_names[str(call_id)] = str(name)

    evidence: list[str] = []
    for message in messages:
        tool_call_id = getattr(message, "tool_call_id", None)
        name = getattr(message, "name", None) or tool_call_names.get(str(tool_call_id))
        content = getattr(message, "content", "")
        message_type = getattr(message, "type", "")
        if message_type != "tool" and not tool_call_id:
            continue
        if not name or not content:
            continue
        snippet = " ".join(strip_model_thinking(content).split())
        if len(snippet) > 220:
            snippet = snippet[:217] + "..."
        evidence.append(f"{name}: {snippet}")
    return evidence


def _is_rate_limit_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "rate_limit" in text or "rate limit" in text or "429" in text


def _is_tool_call_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "tool_use_failed" in text or "failed_generation" in text or "failed to call a function" in text


def _is_connection_error(exc: Exception) -> bool:
    text = str(exc).lower()
    if not text:
        return False
    if type(exc).__name__ in {"ConnectionError", "TimeoutError", "OSError"}:
        return True
    return any(token in text for token in ("connection", "connect", "network", "socket", "timeout", "temporarily unavailable", "dns", "refused", "reset"))


def _invoke_agent_with_retry(agent, prompt: str, max_attempts: int = 3, base_delay: float = 2.0) -> dict:
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return agent.invoke({"messages": [("user", prompt)]})
        except Exception as exc:
            last_exc = exc
            if _is_rate_limit_error(exc):
                if attempt < max_attempts:
                    delay = max(base_delay * (2 ** (attempt - 1)), 6.0)
                    print(f"[IOC Enrichment] Rate limit hit, retrying after {delay:.0f} seconds...")
                    time.sleep(delay)
                    continue
            elif _is_tool_call_error(exc):
                if attempt < max_attempts:
                    print("[IOC Enrichment] Tool call formatting failed, retrying with stricter instructions...")
                    retry_prompt = (
                        prompt
                        + "\n\nTool-call correction: call tools only with complete valid JSON arguments. "
                        "If you cannot call another tool, stop tool use and return the final JSON answer."
                    )
                    time.sleep(base_delay)
                    prompt = retry_prompt
                    continue
            elif _is_connection_error(exc):
                if attempt < max_attempts:
                    delay = base_delay * (2 ** (attempt - 1))
                    print(
                        f"[IOC Enrichment] Connection error on attempt {attempt}/{max_attempts}; "
                        f"retrying after {delay:.0f} seconds..."
                    )
                    time.sleep(delay)
                    continue
            break
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Agent invocation failed without a captured exception")


@tool
def query_mitre_technique(technique_id: str) -> str:
    """
    Retrieves MITRE technique details using the secondary model so
    IOC enrichment does not consume the main reporting model quota.
    """
    from config import ATTACK_DB_DIR

    settings = load_settings()
    normalized = str(technique_id or "").strip().upper()
    if normalized in _MITRE_TOOL_CACHE:
        return _MITRE_TOOL_CACHE[normalized]
    question = (
        f"What is {normalized}, which tactic does it belong to, "
        "and how do attackers use it?"
    )
    system_prompt = (
        "You are a threat intelligence analyst. Explain this MITRE ATT&CK "
        "technique clearly and concisely. Ground your answer strictly in "
        "the retrieved data."
    )
    try:
        try:
            from rag.pipeline import query_rag

            result = query_rag(
                question=question,
                db_path=ATTACK_DB_DIR,
                system_prompt=system_prompt,
                model=settings.secondary_model,
            )
            result = strip_model_thinking(result)
            _MITRE_TOOL_CACHE[normalized] = result
            return result
        except ImportError:
            from rag.pipeline import generate_answer, retrieve

            context = retrieve(ATTACK_DB_DIR, question, settings.embedding_model)
            result = generate_answer(
                system_prompt,
                question,
                context,
                settings.groq_api_key,
                settings.secondary_model,
            )
            result = strip_model_thinking(result)
            _MITRE_TOOL_CACHE[normalized] = result
            return result
    except Exception as exc:
        result = f"MITRE lookup failed for {normalized}: {exc}"
        _MITRE_TOOL_CACHE[normalized] = result
        return result


def _fallback_ioc(
    alert: dict,
    error: Exception,
    technique: str | None = None,
    technique_confidence: float | None = None,
) -> dict:
    if technique is None or technique_confidence is None:
        technique, technique_confidence = _candidate_technique(alert)
    return {
        "alert_id": alert.get("id", "unknown"),
        "source_ip": alert.get("source_ip", ""),
        "technique_confirmed": technique,
        "technique_source": "inferred_from_wazuh",
        "actor_name": "Unattributed",
        "malware_associated": "Unknown",
        "confidence": max(0.0, min(1.0, float(technique_confidence or 0.0))),
        "technique_confidence": max(0.0, min(1.0, float(technique_confidence or 0.0))),
        "actor_confidence": 0.0,
        "summary": f"IOC enrichment failed gracefully: {error}",
        "severity": alert.get("severity", ""),
    }


def _usable_technique_hint(alert: dict) -> str:
    hint = str(alert.get("technique_hint", "") or "").strip()
    if not hint or hint.lower() == "unknown":
        return ""
    return hint


def _structural_technique(alert: dict) -> str:
    """Fast, high-confidence technique mapping grounded in objective Wazuh metadata.

    Keyed exclusively on rule_groups tags, decoder name, and event_type -- all of
    which are set deterministically by Wazuh rules, not inferred from free text.
    Returns an empty string when no structural rule applies, allowing _candidate_technique
    to fall through to semantic similarity search.
    """
    groups = [str(g).lower() for g in (alert.get("rule_groups") or [])]
    decoder = str(alert.get("decoder", "") or "").lower()
    event_type = str(alert.get("event_type", "") or "").lower()
    full_log = str(alert.get("full_log", "") or "").lower()
    rule_desc = str(alert.get("rule_description", "") or "").lower()

    groups_set = set(groups)

    # --- Impact-stage ransomware signals (highest priority) ---
    # FIM decoder + ransomware + impact tags = mass encryption activity
    if decoder == "fim" and "ransomware" in groups_set and "impact" in groups_set:
        return "T1486"  # Data Encrypted for Impact

    # Windows EventChannel + ransomware/impact tag + shadow-copy keywords
    if (
        decoder == "windows_eventchannel"
        and ("ransomware" in groups_set or "impact" in groups_set)
        and any(kw in full_log or kw in rule_desc for kw in ("vssadmin", "shadow", "delete shadows"))
    ):
        return "T1490"  # Inhibit System Recovery

    # --- Network Discovery ---
    # Suricata port scan / sweep signatures
    if "network_scan" in groups_set or "ids" in groups_set and decoder == "suricata":
        return "T1046"  # Network Service Discovery
    if "port_scan" in event_type or "port_sweep" in event_type or "port scan" in event_type:
        return "T1046"

    # --- Medical device access (Modbus / OT protocol) ---
    if "medical_device" in groups_set:
        return "T1210"  # Exploitation of Remote Services

    # --- Lateral Movement via RDP ---
    if "rdp" in groups_set:
        return "T1021.001"  # Remote Desktop Protocol

    # --- PowerShell execution ---
    if "powershell" in groups_set or "process_creation" in groups_set and "powershell" in full_log:
        return "T1059.001"  # Command and Scripting Interpreter: PowerShell

    # --- Credential access: brute force / auth failure ---
    if "authentication_failed" in groups_set and decoder in ("sshd", "windows_eventchannel"):
        return "T1110"  # Brute Force

    # --- Credential access: successful login (valid account use) ---
    if "authentication_success" in groups_set and "authentication_failed" not in groups_set:
        return "T1078"  # Valid Accounts

    return ""


def _wazuh_rule_level(alert: dict) -> int:
    try:
        return int(alert.get("wazuh_rule_level", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _is_wazuh_alert(alert: dict) -> bool:
    return bool(alert.get("wazuh_rule_id") or str(alert.get("source_system", "")).lower() == "wazuh")


def _is_benign_windows_service_message(alert: dict) -> bool:
    text = " ".join(
        str(alert.get(field, ""))
        for field in (
            "event_type",
            "rule_description",
            "decoder",
            "raw_log",
            "full_log",
        )
    ).lower()
    benign_patterns = (
        "vss service is shutting down due to idle timeout",
        "volume shadow copy service is shutting down due to idle timeout",
        "windows update service entered the stopped state",
        "windows update service entered the running state",
        "service entered the stopped state",
        "service entered the running state",
        "service control manager",
    )
    return any(pattern in text for pattern in benign_patterns)


def _is_generic_fim_event(alert: dict) -> bool:
    """True when the alert is a bare FIM/syscheck integrity event with no
    ransomware, impact, or lateral-movement co-indicators.

    Without this guard, the semantic search wrongly maps
    'Integrity checksum changed' to T1495 (Firmware Corruption) at ~60%
    similarity — above the 50% enrichment threshold — because both
    mention 'integrity'.  A generic syscheck event has no actionable
    technique signal; _structural_technique already captures the specific
    case where decoder==fim AND ransomware/impact tags are also present
    (returned as T1486).
    """
    decoder = str(alert.get("decoder", "") or "").lower()
    groups = [str(g).lower() for g in (alert.get("rule_groups") or [])]
    groups_set = set(groups)
    event_type = str(alert.get("event_type", "") or "").lower()
    raw_log = str(alert.get("raw_log", "") or "").lower()

    fim_signals = (
        decoder == "fim"
        or "syscheck" in groups_set
        or "fim" in groups_set
        or "integrity checksum" in event_type
        or "integrity checksum" in raw_log
        or "syscheck" in event_type
        or "syscheck" in raw_log
    )
    if not fim_signals:
        return False

    # If any high-signal co-indicator is present, let _structural_technique handle it.
    impact_signals = (
        "ransomware" in groups_set
        or "impact" in groups_set
        or "mass_encryption" in groups_set
    )
    return not impact_signals


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _is_auth_failure_alert(alert: dict) -> bool:
    text = " ".join(
        str(alert.get(field, ""))
        for field in (
            "event_type",
            "wazuh_rule_id",
            "rule_id",
            "rule_description",
            "decoder",
            "raw_log",
        )
    ).lower()
    return (
        "multiple failed" in text
        or "logon failure" in text
        or "bad password" in text
        or "authentication failure" in text
        or "5712" in text
    )


def _count_recent_auth_failures(alert: dict, raw_alerts: list[dict] | None) -> int:
    if not raw_alerts:
        return 0
    current_ip = str(alert.get("source_ip", "") or "").strip()
    current_time = _parse_timestamp(alert.get("timestamp"))
    if not current_ip or current_ip.lower() == "unknown" or not current_time:
        return 0

    count = 0
    for candidate in raw_alerts:
        if not _is_auth_failure_alert(candidate):
            continue
        candidate_ip = str(candidate.get("source_ip", "") or "").strip()
        if candidate_ip != current_ip:
            continue
        candidate_time = _parse_timestamp(candidate.get("timestamp"))
        if candidate_time is None:
            continue
        if abs((candidate_time - current_time).total_seconds()) <= 600:
            count += 1
    return count


def _candidate_technique(alert: dict, raw_alerts: list[dict] | None = None) -> tuple[str, float]:
    """Return (mitre_id, confidence_score) for a given alert.

    Priority order:
    1. Explicit technique_hint in alert data (score 1.0)
    2. Structural pre-filter: objective Wazuh metadata (rule_groups/decoder) (score 1.0)
    3. Semantic similarity against MITRE ATT&CK vector DB (score = similarity)
    """
    from rag.similarity_search import similarity_search
    from config import ATTACK_DB_DIR

    if _is_benign_windows_service_message(alert):
        return "", 0.0

    # Guard: bare FIM/syscheck events without impact co-indicators are not
    # actionable technique signals. _structural_technique already handles the
    # specific case (decoder==fim + ransomware/impact tags → T1486).
    if _is_generic_fim_event(alert):
        return "", 0.0

    # 1. Explicit hint wins unconditionally
    hint = _usable_technique_hint(alert)
    if hint:
        return hint, 1.0

    # 2. Structural pre-filter (grounded in Wazuh rule metadata)
    structural = _structural_technique(alert)
    if structural:
        return structural, 1.0

    # 3. Semantic fallback for alerts with no structural match
    text = " ".join(
        str(alert.get(field, ""))
        for field in (
            "event_type",
            "rule_description",
            "decoder",
            "full_log",
            "raw_log",
        )
    ).lower().strip()

    if not text:
        return "", 0.0

    try:
        results = similarity_search(text, ATTACK_DB_DIR, n_results=1)
        if not results:
            return "", 0.0
        top_result = results[0]
        mitre_id = str(top_result.metadata.get("mitre_id", ""))
        similarity_score = max(0.0, min(1.0, float(top_result.similarity_percent or 0.0) / 100.0))
        return mitre_id, similarity_score
    except Exception as e:
        print(f"[IOC Enrichment] Semantic search failed: {e}")
        return "", 0.0


def _should_enable_cve_lookup(alert: dict) -> bool:
    text = " ".join(
        str(alert.get(field, ""))
        for field in ("event_type", "rule_description", "raw_log", "full_log")
    ).lower()
    return "exploit" in text or "cve-" in text


def _alert_enrichment_cache_key(alert: dict, technique: str, cve_lookup_enabled: bool) -> tuple[str, ...]:
    return (
        str(technique or "").upper(),
        str(alert.get("source_ip", "") or "").strip(),
        str(alert.get("destination", "") or "").strip(),
        str(alert.get("event_type", "") or "").strip(),
        str(alert.get("wazuh_rule_id", alert.get("rule_id", "")) or "").strip(),
        str(alert.get("decoder", "") or "").strip(),
        str(alert.get("raw_log", "") or "").strip(),
        str(cve_lookup_enabled),
    )


def ioc_enrichment_node(state: ThreatIntelState) -> dict:
    settings = load_settings()
    errors = list(state.get("errors", []))
    enriched_iocs: list[dict] = []
    misp_enabled, misp_status = _misp_preflight()
    print(f"[IOC Enrichment] {misp_status}")
    if not misp_enabled:
        errors.append(f"[IOC Enrichment] {misp_status}")

    persistent_cache_enabled, scenario_hash = _simulated_cache_enabled(state)
    persistent_cache = _load_ioc_cache() if persistent_cache_enabled else {}
    if persistent_cache_enabled:
        print(
            "[IOC Enrichment] Simulated IOC cache enabled "
            f"for scenario hash {scenario_hash[:12]}... ({len(persistent_cache)} entries today)"
        )

    llm = ChatGroq(
        model=settings.secondary_model,
        api_key=settings.groq_api_key,
        temperature=0.2,
        max_tokens=700,
    )
    base_tools = [
        check_threat_feeds,
        query_mitre_technique,
        lookup_actor_profile,
    ]
    if misp_enabled:
        base_tools.insert(1, query_misp)
    base_agent = create_react_agent(llm, base_tools)
    cve_agent = create_react_agent(llm, [*base_tools, lookup_cve])
    enrichment_cache: dict[tuple[str, ...], dict] = {}

    for alert in state.get("raw_alerts", []):
        candidate_technique = ""
        technique_similarity = 0.0
        try:
            if _is_wazuh_operational_noise(alert):
                alert_id = alert.get("id", "unknown")
                message = (
                    f"[IOC Enrichment] Skipped Wazuh operational housekeeping alert {alert_id}; "
                    "not security telemetry for campaign correlation"
                )
                print(message)
                errors.append(message)
                continue

            candidate_technique, technique_similarity = _candidate_technique(alert, state.get("raw_alerts", []))
            
            # Loud failure if no technique is returned or if similarity is below 50%
            if not candidate_technique or technique_similarity < 0.50:
                alert_id = alert.get("id", "unknown")
                rule_id = alert.get("wazuh_rule_id", alert.get("rule_id", "unknown"))
                event_type = alert.get("event_type", alert.get("rule_description", "unknown"))
                reason = "low similarity score" if candidate_technique else "no match found"
                message = (
                    f"[IOC Enrichment] Technique extraction failed for alert {alert_id} "
                    f"(rule {rule_id}, event {event_type}) - {reason} ({technique_similarity:.2f}); skipping enrichment"
                )
                print(message)
                errors.append(message)
                continue

            cve_lookup_enabled = _should_enable_cve_lookup(alert)
            persistent_cache_key = _persistent_ioc_cache_key(alert, scenario_hash) if persistent_cache_enabled else ""
            if persistent_cache_key:
                cached_ioc = persistent_cache.get(persistent_cache_key)
                if isinstance(cached_ioc, dict) and _is_valid_cache_entry(cached_ioc):
                    enriched_ioc = deepcopy(cached_ioc)
                    enriched_ioc["cache_hit"] = True
                    print(
                        f"[IOC Enrichment] Reused persistent simulated cache for alert {alert['id']} "
                        f"({candidate_technique})"
                    )
                    enriched_iocs.append(enriched_ioc)
                    print(
                        f"[IOC Enrichment] {enriched_ioc['technique_confirmed']} | "
                        f"Actor: {enriched_ioc['actor_name']} | "
                        f"Technique confidence: {enriched_ioc['confidence']:.0%} | "
                        f"Actor confidence: {float(enriched_ioc.get('actor_confidence', 0.0)):.0%}"
                    )
                    continue
                elif cached_ioc is not None:
                    print(
                        f"[IOC Enrichment] Invalidated stale 0%-confidence cache entry for alert {alert['id']}"
                    )

            cache_key = _alert_enrichment_cache_key(alert, candidate_technique, cve_lookup_enabled)
            cached_ioc = enrichment_cache.get(cache_key)
            if cached_ioc and _is_valid_cache_entry(cached_ioc):
                enriched_ioc = deepcopy(cached_ioc)
                enriched_ioc["alert_id"] = alert["id"]
                enriched_ioc["severity"] = alert["severity"]
                print(
                    f"[IOC Enrichment] Reused cached enrichment for alert {alert['id']} "
                    f"({candidate_technique}, {alert.get('source_ip', 'unknown')})"
                )
                enriched_iocs.append(enriched_ioc)
                print(
                    f"[IOC Enrichment] {enriched_ioc['technique_confirmed']} | "
                    f"Actor: {enriched_ioc['actor_name']} | "
                    f"Technique confidence: {enriched_ioc['confidence']:.0%} | "
                    f"Actor confidence: {float(enriched_ioc.get('actor_confidence', 0.0)):.0%}"
                )
                continue

            agent = cve_agent if cve_lookup_enabled else base_agent
            misp_instruction = (
                "Also call query_misp for the source IP because MISP passed startup preflight."
                if misp_enabled
                else "MISP lookup was disabled by startup preflight; do not call or rely on query_misp."
            )
            prompt = f"""You are a SOC analyst enriching a security alert.

Alert details:
- Source IP: {alert['source_ip']}
- Candidate MITRE technique inferred from Wazuh/SIEM fields: {candidate_technique}
- Event type: {alert['event_type']}
- Severity: {alert['severity']}
- Risk priority: {alert.get('risk_priority', 'unknown')} ({alert.get('risk_score', 0)}/100)
- Risk reasons: {', '.join(alert.get('risk_reasons', [])) or 'none'}
- Destination: {alert['destination']}
- Wazuh rule: {alert.get('wazuh_rule_id', alert.get('rule_id', 'unknown'))} - {alert.get('event_type', alert.get('rule_description', 'unknown'))}
- Decoder: {alert.get('decoder', 'unknown')}
- Agent: {alert.get('agent_name', 'unknown')} ({alert.get('agent_ip', 'unknown')})
- Raw log: {alert.get('raw_log', '')}

Your task: Investigate this alert by using your available tools. You MUST call at least:
1. check_threat_feeds for the source IP
2. query_mitre_technique for the candidate MITRE technique
3. lookup_actor_profile for the candidate MITRE technique, source IP, and any positive threat-feed/MISP evidence you found

Do not provide your final JSON answer until these required tool calls have completed.

CVE lookup available for this alert: {cve_lookup_enabled}.
Only call lookup_cve when CVE lookup is available. Otherwise do not attempt CVE enrichment.

{misp_instruction}

After calling all relevant tools, synthesize your findings and provide:
- actor_name: the most likely threat actor
- malware_associated: associated malware family
- confidence: a float 0.0-1.0 based on how much evidence you found
- summary: one sentence describing the threat

Respond with ONLY valid JSON in this exact schema:
{{
  "actor_name": "string",
  "malware_associated": "string",
  "confidence": 0.0,
  "summary": "string"
}}"""
            result = _invoke_agent_with_retry(agent, prompt)
            response_text = _response_text(result)
            tools_used = _tools_used(result)
            tool_evidence = _tool_evidence(result)
            actor_name, malware_associated, confidence, summary = _parse_agent_response(response_text)
            actor_confidence = confidence
            actor_tool_result = _parse_actor_tool_result(result)
            if actor_tool_result:
                actor_name, actor_malware, actor_confidence, actor_summary = actor_tool_result
                malware_associated = actor_malware if actor_malware != "Unknown" else malware_associated
                if actor_summary:
                    summary = actor_summary
            signature_actor = _actor_signature_from_alert(alert, candidate_technique)
            if signature_actor and (
                actor_name in {"Unknown", "Unattributed", "Unattributed Threat Actor"}
                or actor_confidence < signature_actor[2]
            ):
                actor_name, signature_malware, actor_confidence, summary = signature_actor
                malware_associated = signature_malware

            technique_confidence = technique_similarity

            enriched_ioc = {
                "alert_id": alert["id"],
                "source_ip": alert["source_ip"],
                "technique_confirmed": candidate_technique,
                "technique_source": "provided_hint" if _usable_technique_hint(alert) else "inferred_from_wazuh",
                "actor_name": actor_name,
                "malware_associated": malware_associated,
                "confidence": technique_confidence,
                "technique_confidence": technique_confidence,
                "actor_confidence": actor_confidence,
                "summary": summary,
                "severity": alert["severity"],
            }
            if tools_used:
                print(f"[IOC Enrichment] Tools used: {', '.join(tools_used)}")
            for evidence in tool_evidence:
                print(f"[IOC Enrichment] Evidence: {evidence}")
        except Exception as exc:
            errors.append(
                f"[IOC Enrichment] Failed to enrich alert {alert.get('id', 'unknown')}: {exc}"
            )
            enriched_ioc = _fallback_ioc(alert, exc, candidate_technique, technique_similarity)

        if enriched_ioc.get("technique_confirmed") and _is_valid_cache_entry(enriched_ioc):
            cache_key = _alert_enrichment_cache_key(
                alert,
                str(enriched_ioc.get("technique_confirmed", "")),
                _should_enable_cve_lookup(alert),
            )
            enrichment_cache.setdefault(cache_key, deepcopy(enriched_ioc))
            if persistent_cache_enabled:
                persistent_entry = deepcopy(enriched_ioc)
                persistent_entry["cache_hit"] = False
                persistent_cache[_persistent_ioc_cache_key(alert, scenario_hash)] = persistent_entry
                try:
                    _save_ioc_cache(persistent_cache)
                except Exception as exc:
                    errors.append(f"[IOC Enrichment] Failed to write simulated IOC cache: {exc}")
        enriched_iocs.append(enriched_ioc)
        print(
            f"[IOC Enrichment] {enriched_ioc['technique_confirmed']} | "
            f"Actor: {enriched_ioc['actor_name']} | "
            f"Technique confidence: {enriched_ioc['confidence']:.0%} | "
            f"Actor confidence: {float(enriched_ioc.get('actor_confidence', 0.0)):.0%}"
        )
        time.sleep(8)

    average_confidence = (
        sum(ioc["confidence"] for ioc in enriched_iocs) / len(enriched_iocs)
        if enriched_iocs
        else 0.0
    )
    if (
        state.get("collection_metadata", {}).get("data_source") == "wazuh_live"
        and enriched_iocs
        and average_confidence < 0.5
    ):
        errors.append(
            "[IOC Enrichment] Live Wazuh confidence below 50%; generating a cautious evidence report."
        )
    print(
        f"[IOC Enrichment] Complete - {len(enriched_iocs)} IOCs enriched | "
        f"Average confidence: {average_confidence:.0%}"
    )
    return {
        "enriched_iocs": enriched_iocs,
        "confidence_score": average_confidence,
        "errors": errors,
    }
