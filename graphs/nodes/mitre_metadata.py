from __future__ import annotations

import json
from functools import lru_cache

from config import ENTERPRISE_ATTACK_JSON


STATIC_FALLBACKS = {
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactics": ["Defense Evasion"],
        "tactic": "Defense Evasion",
    },
}

VALID_ENTERPRISE_TACTICS = {
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
}


def _attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return ""


def _format_tactic(phase_name: str) -> str:
    return str(phase_name or "").replace("-", " ").title()


def _enterprise_tactics(obj: dict) -> list[str]:
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        tactic = _format_tactic(phase.get("phase_name", ""))
        # Some local bundles contain the legacy/non-standard "stealth" phase.
        # Normalize it to the official Enterprise ATT&CK "Defense Evasion" tactic.
        if tactic == "Stealth":
            tactic = "Defense Evasion"
        # Keep only official Enterprise ATT&CK tactic names so reports never inherit invalid labels.
        if tactic in VALID_ENTERPRISE_TACTICS:
            tactics.append(tactic)
    return tactics


@lru_cache(maxsize=1)
def _technique_index() -> dict[str, dict]:
    if not ENTERPRISE_ATTACK_JSON.exists():
        return {}

    bundle = json.loads(ENTERPRISE_ATTACK_JSON.read_text(encoding="utf-8"))
    index: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _attack_id(obj)
        if not technique_id:
            continue

        tactics = _enterprise_tactics(obj)
        metadata = {
            "id": technique_id,
            "name": obj.get("name", technique_id),
            "tactics": tactics,
            "tactic": tactics[0] if tactics else "Unknown",
        }
        index[technique_id] = metadata
    return index


def get_technique_metadata(technique_id: str) -> dict:
    technique_id = str(technique_id or "").upper()
    index = _technique_index()
    if technique_id in index:
        return index[technique_id]

    base_id = technique_id.split(".", 1)[0]
    if base_id in index:
        base = dict(index[base_id])
        base["id"] = technique_id
        return base

    if technique_id in STATIC_FALLBACKS:
        return STATIC_FALLBACKS[technique_id]
    if base_id in STATIC_FALLBACKS:
        base = dict(STATIC_FALLBACKS[base_id])
        base["id"] = technique_id
        return base

    return {
        "id": technique_id,
        "name": technique_id,
        "tactics": [],
        "tactic": "Unknown",
    }
