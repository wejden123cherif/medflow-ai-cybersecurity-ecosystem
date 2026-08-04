from __future__ import annotations

import re
import time
from pathlib import Path

from config import ATTACK_DB_DIR, DETECTION_DB_DIR, REDTEAM_DB_DIR, load_settings
from graphs.nodes.mitre_metadata import get_technique_metadata
from graphs.state import ThreatIntelState
from graphs.text_utils import strip_model_thinking


MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_RAG_CACHE: dict[tuple[str, str, str], str] = {}


# Issue 4: use MedFlow's 7-stage kill-chain mapping, including Discovery at position 2.
RECONNAISSANCE_TECHNIQUES = {
    "T1590", "T1591", "T1592", "T1593", "T1594", "T1595", "T1596",
}
DISCOVERY_TECHNIQUES = {
    "T1007", "T1012", "T1016", "T1018", "T1033", "T1046", "T1049",
    "T1057", "T1069", "T1082", "T1083", "T1087", "T1120", "T1124",
    "T1135", "T1201", "T1217", "T1420", "T1482", "T1497", "T1518",
    "T1538", "T1614", "T1654",
}
INITIAL_ACCESS_TECHNIQUES = {
    "T1078", "T1091", "T1133", "T1190", "T1195", "T1199", "T1200", "T1566",
}
EXECUTION_TECHNIQUES = {
    "T1047", "T1053", "T1059", "T1072", "T1106", "T1129", "T1203", "T1204",
    "T1559", "T1569", "T1610", "T1648",
}
LATERAL_MOVEMENT_TECHNIQUES = {
    "T1021", "T1080", "T1534", "T1550", "T1563", "T1570",
}
IMPACT_EXFILTRATION_TECHNIQUES = {
    "T1485", "T1486", "T1489", "T1490", "T1491", "T1498", "T1529", "T1561",
}
PRE_COMPROMISE_POLICY = {
    "credential_access_attempt": 3,
    "failure_artifact": 3,
}
POSITION_BY_TECHNIQUE = {
    **{technique_id: 1 for technique_id in RECONNAISSANCE_TECHNIQUES},
    **{technique_id: 2 for technique_id in DISCOVERY_TECHNIQUES},
    **{technique_id: 2 for technique_id in INITIAL_ACCESS_TECHNIQUES},
    **{technique_id: 3 for technique_id in EXECUTION_TECHNIQUES},
    **{technique_id: 6 for technique_id in LATERAL_MOVEMENT_TECHNIQUES},
    **{technique_id: 7 for technique_id in IMPACT_EXFILTRATION_TECHNIQUES},
}
POSITION_BY_TACTIC = {
    "reconnaissance": 1,
    "resource development": 1,
    "discovery": 2,
    "initial access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege escalation": 4,
    "defense evasion": 5,
    "credential access": 5,
    "collection": 5,
    "lateral movement": 6,
    "command and control": 6,
    "exfiltration": 7,
    "impact": 7,
}


def _base_technique_id(technique_id: str) -> str:
    return technique_id.split(".", 1)[0].upper()


def _get_parent_id(technique_id: str) -> str:
    return technique_id.split(".", 1)[0].upper()


def _technique_name(text: str, technique_id: str) -> str:
    metadata = get_technique_metadata(technique_id)
    if metadata.get("name") and metadata["name"] != technique_id:
        return str(metadata["name"])
    match = re.search(rf"Technique:\s*([^\n(]+)\s*\({re.escape(technique_id)}\)", text or "", re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return technique_id


def _technique_tactic(text: str, technique_id: str) -> str:
    metadata = get_technique_metadata(technique_id)
    if metadata.get("tactic") and metadata["tactic"] != "Unknown":
        return str(metadata["tactic"])
    match = re.search(r"Tactics?:\s*([^\n]+)", text or "", re.IGNORECASE)
    if match:
        return match.group(1).strip().replace("-", " ").title()
    return "Unknown"


def _extract_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in MITRE_ID_RE.findall(text or "")})


def _split_sources(answer: str) -> tuple[list[str], list[str]]:
    retrieved: set[str] = set()
    beyond: set[str] = set()
    for line in (answer or "").splitlines():
        lowered = line.lower()
        ids = set(_extract_ids(line))
        if "retrieved from database" in lowered:
            retrieved.update(ids)
        elif "not found in retrieved context" in lowered or "beyond retrieved" in lowered:
            beyond.update(ids)
    return sorted(retrieved), sorted(beyond)


def _next_likely_techniques(answer: str, technique_id: str) -> list[str]:
    current = technique_id.upper()
    ids = [mitre_id for mitre_id in _extract_ids(answer) if mitre_id != current]
    return ids[:5]


def _query_rag(question: str, db_path: Path, model: str) -> str:
    cache_key = (str(db_path), model, question)
    if cache_key in _RAG_CACHE:
        return _RAG_CACHE[cache_key]

    system_prompt = (
        "You are a senior healthcare threat intelligence analyst. "
        "Ground your answer in the retrieved MITRE context and be specific."
    )
    try:
        from rag.pipeline import query_rag

        result = query_rag(
            question=question,
            db_path=db_path,
            system_prompt=system_prompt,
            model=model,
        )
        result = strip_model_thinking(result)
        _RAG_CACHE[cache_key] = result
        return result
    except ImportError:
        from rag.pipeline import generate_answer, retrieve

        settings = load_settings()
        context = retrieve(db_path, question, settings.embedding_model)
        result = generate_answer(system_prompt, question, context, settings.groq_api_key, model)
        result = strip_model_thinking(result)
        _RAG_CACHE[cache_key] = result
        return result


def _needs_parent_retry(result: str) -> bool:
    return not result or len(result.strip()) < 50 or "No evidence found" in result


def _query_with_parent_retry(
    technique_id: str,
    db_path: Path,
    model: str,
    question_builder,
) -> str:
    # Issue 2: retry sub-technique lookups with the parent ID when vector search has no direct evidence.
    result = _query_rag(question_builder(technique_id), db_path, model)
    parent_id = _get_parent_id(technique_id)
    if parent_id != technique_id and _needs_parent_retry(result):
        print(f"[MITRE Lookup] Retrying {technique_id} as parent {parent_id}")
        result = _query_rag(question_builder(parent_id), db_path, model)
    return result


def _kill_chain_position(technique_id: str) -> int:
    # Issue 4: sub-techniques inherit their parent position, and tactics fill gaps in explicit ID mapping.
    base_id = _base_technique_id(technique_id)
    if base_id in {"T1110"}:
        return PRE_COMPROMISE_POLICY["credential_access_attempt"]
    if base_id in {"T1531"}:
        return PRE_COMPROMISE_POLICY["failure_artifact"]
    if base_id in POSITION_BY_TECHNIQUE:
        return POSITION_BY_TECHNIQUE[base_id]

    metadata = get_technique_metadata(technique_id)
    for tactic in metadata.get("tactics", []):
        position = POSITION_BY_TACTIC.get(str(tactic).lower())
        if position:
            return position
    return 3


def mitre_lookup_node(state: ThreatIntelState) -> dict:
    errors = list(state.get("errors", []))
    mitre_context: dict[str, dict] = {}
    technique_ids = sorted(
        {
            str(ioc.get("technique_confirmed", "")).upper()
            for ioc in state.get("enriched_iocs", [])
            if ioc.get("technique_confirmed")
        }
    )

    for technique_id in technique_ids:
        try:
            metadata = get_technique_metadata(technique_id)
            name = str(metadata.get("name") or technique_id)
            tactic = str(metadata.get("tactic") or "Unknown")
            position = _kill_chain_position(technique_id)
            attack_description = (
                f"{technique_id} - {name}. Local MITRE metadata maps this technique "
                f"to tactic '{tactic}' and MedFlow kill chain position {position}/7."
            )
            detection_guidance = (
                "Use local detections, Wazuh rule context, endpoint telemetry, file integrity "
                "monitoring, authentication logs, and network indicators associated with the alert."
            )
            procedure_details = (
                "Procedure details are summarized from local technique metadata and incident "
                "evidence; no LLM lookup was used for this deterministic MITRE mapping."
            )
            mitre_context[technique_id] = {
                "name": name,
                "tactic": tactic,
                "kill_chain_position": position,
                "next_likely_techniques": [],
                "attack_description": attack_description,
                "detection_guidance": detection_guidance,
                "procedure_details": procedure_details,
                "retrieved_ids": [technique_id],
                "beyond_retrieved_ids": [],
            }
            print(
                f"[MITRE Lookup] {technique_id} - {name} | "
                f"Tactic: {tactic} | Kill chain: {position}/7"
            )
        except Exception as exc:
            errors.append(f"[MITRE Lookup] Failed lookup for {technique_id}: {exc}")
            continue

    return {"mitre_context": mitre_context, "errors": errors}
