import ipaddress
import json
import os
import re
import urllib3

import requests
from langchain_core.tools import tool


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _is_internal_or_reserved_ip(ip_address: str) -> bool:
    value = str(ip_address or "").strip()
    if not value or value.lower() in {"unknown", "none", "n/a"}:
        return False
    try:
        address = ipaddress.ip_address(value)
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


def _actor_response(
    technique_id: str,
    actor_name: str = "Unattributed",
    malware_associated: str = "Unknown",
    confidence: float = 0.0,
    evidence_count: int = 0,
    summary: str = "No actor attribution: no corroborating actor-specific indicator was provided.",
) -> str:
    return "ACTOR ATTRIBUTION: " + json.dumps(
        {
            "technique_id": technique_id,
            "actor_name": actor_name,
            "malware_associated": malware_associated,
            "confidence": round(max(0.0, min(1.0, confidence)), 2),
            "evidence_count": evidence_count,
            "summary": summary,
        },
        sort_keys=True,
    )


def _extract_checkable_indicators(text: str) -> set[str]:
    indicators: set[str] = set()
    for match in re.findall(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", text):
        indicators.add(match.lower())
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        indicators.add(match)
    for match in re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text):
        indicators.add(match.lower())
    return indicators


def _is_positive_correlated_evidence(text: str) -> bool:
    lowered = text.lower()
    positive_markers = (
        "misp match found",
        "high risk - confirmed malicious",
        "medium risk - suspicious activity reported",
        "confirmed malicious",
        "known malicious",
    )
    negative_markers = (
        "not configured",
        "skipping",
        "no misp correlation",
        "n/a - internal/reserved",
        "clean - no abuse reports found",
        "unreachable",
        "timed out",
    )
    return any(marker in lowered for marker in positive_markers) and not any(
        marker in lowered for marker in negative_markers
    )


@tool
def query_misp(indicator: str) -> str:
    """
    Searches MISP (Malware Information Sharing Platform) for
    any known threat intelligence related to the given indicator.
    The indicator can be an IP address, domain, file hash,
    URL, or MITRE technique ID.
    Use this to find if an IOC has been seen in real attacks.
    """
    misp_url = os.getenv("MISP_URL", "http://localhost").strip().rstrip("/")
    misp_key = os.getenv("MISP_API_KEY", "").strip()
    verify_ssl = _env_flag("MISP_VERIFY_SSL", True)

    if not misp_key:
        return f"MISP not configured. Skipping IOC lookup for {indicator}."

    try:
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        headers = {
            "Authorization": misp_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        payload = {
            "returnFormat": "json",
            "value": indicator,
            "limit": 5
        }
        response = requests.post(
            f"{misp_url}/events/restSearch",
            headers=headers,
            json=payload,
            timeout=10,
            verify=verify_ssl
        )
        if response.status_code == 200:
            data = response.json()
            response_data = data.get("response", [])
            if isinstance(response_data, dict):
                events = response_data.get("Event", [])
            else:
                events = response_data
            if not events:
                return f"No MISP correlation found for {indicator}"
            top = events[0]
            attribute_count = int(top.get("attribute_count", 0) or 0)
            tags = [str(tag.get("name", "")).strip() for tag in top.get("Tag", []) if str(tag.get("name", "")).strip()]
            event_info = str(top.get("info", "") or "").strip()
            threat_level = str(top.get("threat_level_id", "") or "").strip()
            if attribute_count <= 0 and not tags and not event_info and not threat_level:
                return f"No MISP correlation found for {indicator}"
            return (
                f"MISP MATCH FOUND for {indicator}:\n"
                f"Event: {top.get('info', 'unknown')}\n"
                f"Threat level: {top.get('threat_level_id', 'unknown')}\n"
                f"Tags: {tags or ['none']}\n"
                f"Date: {top.get('date', 'unknown')}\n"
                f"Total attributes: {attribute_count}"
            )
        else:
            return f"MISP returned status {response.status_code} for {indicator}"
    except requests.exceptions.SSLError as e:
        return (
            f"MISP TLS verification failed for {indicator}. "
            "Set MISP_VERIFY_SSL=false for a self-signed local MISP certificate, "
            f"or fix the certificate trust chain. Details: {e}"
        )
    except requests.exceptions.ConnectionError as e:
        return f"MISP unreachable at {misp_url}. Skipping lookup for {indicator}. Details: {e}"
    except requests.exceptions.Timeout:
        return f"MISP timed out at {misp_url}. Skipping lookup for {indicator}."
    except Exception as e:
        return f"MISP lookup failed: {str(e)}"


@tool
def check_threat_feeds(ip_address: str) -> str:
    """
    Checks public threat intelligence feeds to determine if an
    IP address is known malicious. Queries AbuseIPDB which
    aggregates reports from the global security community.
    Use this for any suspicious IP address found in an alert.
    Only works for IP addresses, not domains or hashes.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if _is_internal_or_reserved_ip(ip_address):
        return f"N/A - internal/reserved address for {ip_address}"

    if not api_key:
        return f"AbuseIPDB not configured. Skipping feed check for {ip_address}."

    try:
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "unknown")
            isp = data.get("isp", "unknown")
            usage_type = data.get("usageType", "unknown")
            last_reported = data.get("lastReportedAt", "never")
            if abuse_score > 80:
                verdict = "HIGH RISK - confirmed malicious"
            elif abuse_score > 40:
                verdict = "MEDIUM RISK - suspicious activity reported"
            elif abuse_score > 0:
                verdict = "LOW RISK - some reports, monitor closely"
            else:
                verdict = "CLEAN - no abuse reports found"
            return (
                f"THREAT FEED RESULT for {ip_address}:\n"
                f"Verdict: {verdict}\n"
                f"Abuse confidence score: {abuse_score}/100\n"
                f"Total community reports: {total_reports}\n"
                f"Country: {country} | ISP: {isp}\n"
                f"Usage type: {usage_type}\n"
                f"Last reported: {last_reported}"
            )
        else:
            return f"AbuseIPDB returned status {response.status_code}"
    except requests.exceptions.ConnectionError:
        return f"AbuseIPDB unreachable. Skipping for {ip_address}."
    except Exception as e:
        return f"Threat feed check failed: {str(e)}"


@tool
def lookup_cve(search_term: str) -> str:
    """
    Searches the NVD (National Vulnerability Database) for known
    CVEs related to the given search term. Use this when an alert
    involves exploitation of a vulnerability - search by software
    name, CVE ID, or MITRE technique ID to find relevant CVEs.
    Examples: "RDP remote code execution", "T1190",
    "PrintNightmare", "CVE-2021-34527"
    """
    # NVD keyword search is literal and often misses community nicknames.
    # Expand common exploit names to their CVE identifiers before querying.
    alias_map = {
        "printnightmare": "CVE-2021-34527 Windows Print Spooler Remote Code Execution",
    }
    normalized_search = alias_map.get(search_term.strip().lower(), search_term)

    try:
        params = {
            "keywordSearch": normalized_search,
            "resultsPerPage": 3,
            "startIndex": 0
        }
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return f"NVD: No CVEs found for '{search_term}'"
            results = []
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "unknown")
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions
                     if d["lang"] == "en"),
                    "No description available"
                )
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0]
                    .get("cvssData", {})
                )
                severity = cvss_data.get("baseSeverity", "unknown")
                score = cvss_data.get("baseScore", "unknown")
                published = cve.get("published", "unknown")[:10]
                results.append(
                    f"- {cve_id} [{severity} - {score}/10]"
                    f" ({published})\n"
                    f"  {description[:200]}..."
                )
            return (
                f"CVE DATABASE RESULTS for '{search_term}':\n"
                + "\n".join(results)
            )
        else:
            return f"NVD API returned status {response.status_code}"
    except requests.exceptions.ConnectionError:
        return f"NVD API unreachable. Skipping CVE lookup."
    except Exception as e:
        return f"CVE lookup failed: {str(e)}"


@tool
def query_mitre_technique(technique_id: str) -> str:
    """
    Retrieves detailed information about a MITRE ATT&CK
    technique from our local knowledge base including
    description, which tactic it belongs to, how attackers
    use it, and detection guidance.
    Use this for any MITRE technique ID found in an alert
    (e.g. "T1110", "T1566", "T1078").
    """
    from config import ATTACK_DB_DIR, load_settings

    settings = load_settings()
    try:
        from rag.pipeline import query_rag

        return query_rag(
            question=f"What is {technique_id}, which tactic does "
                     f"it belong to, and how do attackers use it?",
            db_path=ATTACK_DB_DIR,
            system_prompt=(
                "You are a threat intelligence analyst. "
                "Explain this MITRE ATT&CK technique clearly "
                "and concisely. Ground your answer strictly in "
                "the retrieved data."
            ),
            model=settings.main_model
        )
    except ImportError:
        from rag.pipeline import generate_answer, retrieve

        context = retrieve(ATTACK_DB_DIR, f"What is {technique_id}?", settings.embedding_model)
        return generate_answer(
            "You are a threat intelligence analyst. Explain this MITRE ATT&CK technique clearly "
            "and concisely. Ground your answer strictly in the retrieved data.",
            f"What is {technique_id}, which tactic does it belong to, and how do attackers use it?",
            context,
            settings.groq_api_key,
            settings.main_model,
        )


@tool
def lookup_actor_profile(
    technique_id: str,
    source_ip: str = "",
    corroborating_evidence: str = "",
) -> str:
    """
    Searches our threat actor database to find which known
    threat actor groups and malware families are associated
    with corroborated indicators in an alert.
    Only returns an actor name when the evidence is explicit and
    corroborated by a checkable indicator. A common technique ID by
    itself is insufficient for actor attribution.
    """
    from config import ACTOR_DB_DIR

    from rag.similarity_search import similarity_search

    normalized = str(technique_id or "").strip().upper()
    if not normalized or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", normalized):
        return _actor_response("unknown", summary="No actor attribution: invalid or missing technique ID.")

    evidence_text = str(corroborating_evidence or "")
    if source_ip:
        evidence_text = f"{evidence_text}\nsource_ip={source_ip}"
    indicators = _extract_checkable_indicators(evidence_text)
    if source_ip and _is_internal_or_reserved_ip(source_ip):
        indicators.discard(str(source_ip).strip())

    if not indicators or not _is_positive_correlated_evidence(evidence_text):
        return _actor_response(
            normalized,
            summary=(
                "No actor attribution: the alert has no positive MISP/threat-feed match "
                "or other checkable actor-specific indicator."
            ),
        )

    results = similarity_search(
        query=f"{normalized} {' '.join(sorted(indicators))} threat actor group malware campaign",
        db_path=ACTOR_DB_DIR,
        n_results=5,
    )
    if not results:
        return _actor_response(normalized)

    actor_scores: dict[str, int] = {}
    actor_docs: dict[str, str] = {}
    actor_pattern = re.compile(
        r"\b(?:APT\d+|FIN\d+|Lazarus|Sandworm|Turla|OilRig|Wizard Spider|Carbanak|Cobalt Group|"
        r"DarkHotel|BitPaymer|Ryuk|INC Ransom|Conti|REvil|BlackMatter|Qilin)\b",
        re.IGNORECASE,
    )
    for result in results:
        document = getattr(result, "document", "") or ""
        if isinstance(result, dict):
            document = str(result.get("document", "") or "")
        normalized_doc = " ".join(str(document).split())
        if not normalized_doc:
            continue
        matched_indicators = {
            indicator
            for indicator in indicators
            if indicator.lower() in normalized_doc.lower()
        }
        if not matched_indicators:
            continue
        actors = actor_pattern.findall(normalized_doc)
        if not actors:
            continue
        for actor in actors:
            canonical_actor = " ".join(actor.split())
            actor_scores[canonical_actor] = actor_scores.get(canonical_actor, 0) + len(matched_indicators)
            actor_docs.setdefault(canonical_actor, normalized_doc)

    if not actor_scores:
        return _actor_response(
            normalized,
            summary="No actor attribution: correlated indicators did not match an actor profile.",
        )

    actor_name = sorted(actor_scores, key=lambda name: (-actor_scores[name], name.lower()))[0]
    evidence_count = actor_scores[actor_name]
    confidence = min(0.85, 0.35 + (0.15 * evidence_count))
    return _actor_response(
        normalized,
        actor_name=actor_name,
        confidence=confidence,
        evidence_count=evidence_count,
        summary=actor_docs[actor_name][:300],
    )
