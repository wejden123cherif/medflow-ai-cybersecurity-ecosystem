from __future__ import annotations

import re
import time
from pathlib import Path

from config import DETECTION_DB_DIR, REDTEAM_DB_DIR, load_settings
from graphs.nodes.mitre_metadata import get_technique_metadata
from graphs.state import ThreatIntelState


MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TIME_RE = re.compile(
    r"\b(?:\d+\s*-\s*\d+|\d+)\s*(?:minutes?|mins?|hours?|hrs?|days?)\b",
    re.IGNORECASE,
)
FALLBACK_NEXT_BY_POSITION = {
    6: ["T1105", "T1562", "T1486", "T1490"],
    5: ["T1021", "T1105", "T1486"],
    4: ["T1562", "T1021", "T1486"],
}
RANSOMWARE_NEXT_STEP_RATIONALE = {
    "T1021": "continue movement across reachable internal systems",
    "T1105": "stage ransomware tooling or follow-on payloads on internal hosts",
    "T1486": "encrypt clinical and business systems for extortion",
    "T1490": "delete or disrupt backups and recovery paths before encryption",
    "T1562": "disable endpoint, logging, or security controls before impact",
}


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


def _query_rag(question: str, db_path: Path, model: str) -> str:
    system_prompt = (
        "You are a senior healthcare ransomware analyst. "
        "Ground your response in the retrieved context and provide actionable guidance."
    )
    try:
        from rag.pipeline import query_rag

        return query_rag(
            question=question,
            db_path=db_path,
            system_prompt=system_prompt,
            model=model,
        )
    except ImportError:
        from rag.pipeline import generate_answer, retrieve

        settings = load_settings()
        context = retrieve(db_path, question, settings.embedding_model)
        return generate_answer(system_prompt, question, context, settings.groq_api_key, model)


def _time_estimate(response: str, position: int) -> str:
    match = TIME_RE.search(response or "")
    if match:
        return match.group(0)
    if position == 6:
        return "1-4 hours"
    if position == 5:
        return "2-8 hours"
    if position == 4:
        return "4-24 hours"
    return "12-48 hours"


def _business_impact(response: str, stage: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", response or "")
    impact_sentences = [
        sentence.strip()
        for sentence in sentences
        if "impact" in sentence.lower() or "patient" in sentence.lower() or "hospital" in sentence.lower()
    ]
    if impact_sentences:
        return " ".join(impact_sentences[:3])
    return (
        f"If the attacker advances beyond {stage}, MedFlow could face clinical downtime, "
        "EHR disruption, PHI exposure, and ransomware-driven interruption to patient care."
    )


def _technique_details(techniques: list[str]) -> list[dict]:
    details = []
    for technique in techniques:
        metadata = get_technique_metadata(technique)
        details.append(
            {
                "id": technique,
                "name": metadata.get("name", "Unknown"),
                "tactic": metadata.get("tactic", "Unknown"),
                "why_likely": RANSOMWARE_NEXT_STEP_RATIONALE.get(
                    technique,
                    "follow-on activity based on the current campaign stage",
                ),
            }
        )
    return details


def prediction_node(state: ThreatIntelState) -> dict:
    errors = list(state.get("errors", []))
    campaign = state.get("campaign", {})
    settings = load_settings()
    current_stage = campaign.get("current_stage") or campaign.get("stage") or "Unknown"
    techniques_confirmed = campaign.get("techniques_confirmed") or campaign.get("confirmed_techniques") or []
    position = int(campaign.get("kill_chain_position", 0) or 0)
    campaign_confidence = float(campaign.get("campaign_confidence", 0.0) or 0.0)
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)

    if len(techniques_confirmed) == 0 or confidence_score == 0.0:
        prediction = {
            "stage": "Insufficient Evidence",
            "predicted_techniques": [],
            "predicted_next_techniques": [],
            "predicted_next_technique_details": [],
            "note": "No prediction possible without at least one confirmed technique",
            "confidence": 0.0,
            "prediction_confidence": 0.0,
            "time_to_next_stage": "Unknown",
            "recommended_immediate_actions": "Continue triage, preserve evidence, and validate alert context before predicting attacker next moves.",
            "business_impact": "No healthcare-impact scenario can be projected without at least one confirmed technique.",
            "based_on_stage": "Insufficient Evidence",
            "retrieved_ids": [],
            "beyond_retrieved_ids": [],
        }
        print("[Prediction] Skipped: insufficient confirmed evidence")
        print(f"[Prediction] Current stage: {current_stage}")
        print("[Prediction] Predicted next techniques: []")
        print("[Prediction] Time estimate: Unknown")
        print("[Prediction] Confidence: 0%")
        return {"prediction": prediction, "errors": errors}

    try:
        time.sleep(2)
        prediction_question = f"""
An attacker has been confirmed at the {current_stage} stage of a ransomware attack against a hospital.
They have used these techniques so far: {techniques_confirmed}.

Based on known Ryuk and hospital ransomware kill chains, what are the NEXT techniques the attacker
will likely use? Give specific MITRE technique IDs, estimated time before execution, and the business
impact if not stopped.
"""
        predictive_response = _query_rag(prediction_question, REDTEAM_DB_DIR, settings.main_model)

        time.sleep(2)
        defense_question = f"""
For a ransomware attack at {current_stage} stage in a hospital environment, what are the TOP 3
immediate defensive actions a SOC team should take RIGHT NOW to prevent the attack from progressing
to the next stage?
"""
        defensive_response = _query_rag(defense_question, DETECTION_DB_DIR, settings.main_model)

        confirmed = {str(technique).upper() for technique in techniques_confirmed}
        predicted_techniques = [
            technique for technique in _extract_ids(predictive_response) if technique not in confirmed
        ]
        if not predicted_techniques:
            predicted_techniques = [
                technique
                for technique in FALLBACK_NEXT_BY_POSITION.get(position, ["T1021", "T1562", "T1486"])
                if technique not in confirmed
            ]
        time_estimate = _time_estimate(predictive_response, position)
        retrieved_prediction, beyond_prediction = _split_sources(predictive_response)
        retrieved_defense, beyond_defense = _split_sources(defensive_response)
        prediction = {
            "predicted_next_techniques": predicted_techniques,
            "predicted_next_technique_details": _technique_details(predicted_techniques),
            "time_to_next_stage": time_estimate,
            "recommended_immediate_actions": defensive_response,
            "business_impact": _business_impact(predictive_response, str(current_stage)),
            "prediction_confidence": campaign_confidence * 0.85,
            "based_on_stage": current_stage,
            "retrieved_ids": sorted(set(retrieved_prediction + retrieved_defense)),
            "beyond_retrieved_ids": sorted(set(beyond_prediction + beyond_defense)),
        }
    except Exception as exc:
        errors.append(f"[Prediction] Failed to generate prediction: {exc}")
        time_estimate = _time_estimate("", position)
        prediction = {
            "predicted_next_techniques": [],
            "predicted_next_technique_details": [],
            "time_to_next_stage": time_estimate,
            "recommended_immediate_actions": "Prediction failed. Isolate affected hosts, disable compromised accounts, and preserve evidence.",
            "business_impact": _business_impact("", str(current_stage)),
            "prediction_confidence": campaign_confidence * 0.5,
            "based_on_stage": current_stage,
            "retrieved_ids": [],
            "beyond_retrieved_ids": [],
        }

    print(f"[Prediction] Current stage: {current_stage}")
    print(f"[Prediction] Predicted next techniques: {prediction['predicted_next_techniques']}")
    print(f"[Prediction] Time estimate: {prediction['time_to_next_stage']}")
    print(f"[Prediction] Confidence: {prediction['prediction_confidence']:.0%}")
    return {"prediction": prediction, "errors": errors}
