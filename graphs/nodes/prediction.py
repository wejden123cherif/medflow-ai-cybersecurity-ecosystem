from __future__ import annotations

import re
import time
from pathlib import Path

from config import DETECTION_DB_DIR, REDTEAM_DB_DIR, load_settings
from graphs.nodes.mitre_metadata import get_technique_metadata
from graphs.state import ThreatIntelState


MITRE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
RANSOMWARE_NEXT_STEP_RATIONALE = {
    "T1021": "continue movement across reachable internal systems",
    "T1105": "stage ransomware tooling or follow-on payloads on internal hosts",
    "T1486": "encrypt clinical and business systems for extortion",
    "T1490": "delete or disrupt backups and recovery paths before encryption",
    "T1685": "disable or modify security tools before impact",
}
TACTIC_ORDER = {
    name.casefold(): index
    for index, name in enumerate((
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command And Control",
        "Exfiltration", "Impact",
    ))
}


def _extract_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in MITRE_ID_RE.findall(text or "")})


def _extract_ids_in_order(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for match in MITRE_ID_RE.findall(text or ""):
        technique = match.upper()
        if technique not in seen:
            seen.add(technique)
            ordered.append(technique)
    return ordered


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


def _query_rag_with_evidence(question: str, db_path: Path, model: str):
    system_prompt = (
        "You are a senior healthcare ransomware analyst. "
        "Ground your response in the retrieved context and provide actionable guidance."
    )
    try:
        from rag.pipeline import query_rag_with_evidence

        return query_rag_with_evidence(
            question=question,
            db_path=db_path,
            system_prompt=system_prompt,
            model=model,
        )
    except ImportError:
        return _query_rag(question, db_path, model), []


def _business_impact(response: str, stage: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", response or "")
    impact_sentences = [
        sentence.strip()
        for sentence in sentences
        if "impact" in sentence.lower() or "patient" in sentence.lower() or "hospital" in sentence.lower()
    ]
    if impact_sentences:
        return " ".join(impact_sentences[:3])
    if stage.strip().lower() == "impact":
        return (
            "Impact-stage activity creates a risk of clinical downtime and EHR disruption. "
            "The available evidence does not establish a service outage or PHI exposure."
        )
    return (
        f"If the attacker advances beyond {stage}, MedFlow could face clinical downtime, "
        "EHR disruption, PHI exposure, and ransomware-driven interruption to patient care."
    )


def _technique_details(techniques: list[str], evidence_results: list | None = None) -> list[dict]:
    evidence_by_id = {
        str(result.metadata.get("mitre_id", "")).upper(): result
        for result in (evidence_results or [])
    }
    details = []
    for technique in techniques:
        metadata = get_technique_metadata(technique)
        result = evidence_by_id.get(technique)
        details.append(
            {
                "id": technique,
                "name": metadata.get("name", "Unknown"),
                "tactic": metadata.get("tactic", "Unknown"),
                "why_likely": RANSOMWARE_NEXT_STEP_RATIONALE.get(
                    technique,
                    "follow-on activity based on the current campaign stage",
                ),
                "retrieval_similarity_percent": round(result.similarity_percent, 1)
                if result and result.similarity_percent is not None else None,
                "retrieved_evidence": result.document[:400]
                if result else "No matching retrieved document evidence.",
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
    campaign_confidence = max(0.0, min(1.0, float(campaign.get("campaign_confidence", 0.0) or 0.0)))
    confidence_score = float(state.get("confidence_score", 0.0) or 0.0)

    if len(techniques_confirmed) == 0 or confidence_score == 0.0:
        prediction = {
            "stage": "Insufficient Evidence",
            "predicted_techniques": [],
            "predicted_next_techniques": [],
            "predicted_next_technique_details": [],
            "note": "No prediction possible without at least one confirmed technique",
            "confidence": 0.0,
            "confidence_basis": "No prediction; confidence is zero.",
            "prediction_confidence": 0.0,
            "time_to_next_stage": "Unknown",
            "recommended_immediate_actions": "Continue triage, preserve evidence, and validate alert context before predicting attacker next moves.",
            "business_impact": "No healthcare-impact scenario can be projected without at least one confirmed technique.",
            "based_on_stage": "Insufficient Evidence",
            "prediction_retrieved_ids": [],
            "prediction_retrieval_evidence": [],
            "defense_retrieved_ids": [],
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
        confirmed_context = ", ".join(
            f"{technique} {get_technique_metadata(str(technique)).get('name', '')}".strip()
            for technique in techniques_confirmed
        )
        prediction_question = (
            f"Next adversary behavior in an enterprise ransomware incident after {current_stage} activity. "
            f"Confirmed ATT&CK techniques: {confirmed_context}. Identify plausible successor techniques "
            "from relevant retrieved intrusion procedures. Only use IDs present in retrieved evidence, "
            "exclude confirmed techniques, and explain the progression. If evidence is insufficient, "
            "say so. Do not estimate timing."
        )
        predictive_response, prediction_evidence = _query_rag_with_evidence(
            prediction_question, REDTEAM_DB_DIR, settings.main_model
        )

        time.sleep(2)
        defense_question = f"""
For a ransomware attack at {current_stage} stage in a hospital environment, what are the TOP 3
immediate defensive actions a SOC team should take RIGHT NOW to prevent the attack from progressing
to the next stage?
"""
        defensive_response = _query_rag(defense_question, DETECTION_DB_DIR, settings.main_model)

        confirmed = {str(technique).upper() for technique in techniques_confirmed}
        retrieved_prediction, beyond_prediction = _split_sources(predictive_response)
        retrieved_defense, beyond_defense = _split_sources(defensive_response)
        # A model-mentioned ID is eligible only when the RAG source summary
        # verifies that it appeared in the retrieved context.
        retrieved_prediction_set = set(retrieved_prediction)
        evidence_ids = {
            str(result.metadata.get("mitre_id", "")).upper()
            for result in prediction_evidence
        }
        current_tactic_order = TACTIC_ORDER.get(str(current_stage).casefold())
        predicted_techniques = [
            technique for technique in _extract_ids_in_order(predictive_response)
            if technique not in confirmed
            and technique in retrieved_prediction_set
            and technique in evidence_ids
            and current_tactic_order is not None
            and any(
                TACTIC_ORDER.get(str(tactic).casefold(), -1) > current_tactic_order
                for tactic in get_technique_metadata(technique).get("tactics", [])
            )
        ]
        predicted_techniques = predicted_techniques[:3]
        # RAG context contains technique behavior, not incident timing evidence.
        time_estimate = "Unknown"
        prediction = {
            "stage": current_stage,
            "predicted_techniques": predicted_techniques,
            "predicted_next_techniques": predicted_techniques,
            "predicted_next_technique_details": _technique_details(predicted_techniques, prediction_evidence),
            "time_to_next_stage": time_estimate,
            "recommended_immediate_actions": defensive_response,
            "business_impact": _business_impact(predictive_response, str(current_stage)),
            "prediction_confidence": campaign_confidence * 0.85 if predicted_techniques else 0.0,
            "confidence": campaign_confidence * 0.85 if predicted_techniques else 0.0,
            "confidence_basis": "Heuristic derived from campaign confidence; not statistically calibrated.",
            "based_on_stage": current_stage,
            "note": (
                "No retrieved technique evidence supports a follow-on prediction at the terminal Impact stage."
                if not predicted_techniques and position >= 7
                else "No retrieved technique evidence supports a follow-on prediction."
                if not predicted_techniques
                else "Predictions are hypotheses supported by retrieved context, not confirmed attacker actions."
            ),
            "retrieved_ids": sorted(set(retrieved_prediction + retrieved_defense)),
            "prediction_retrieved_ids": retrieved_prediction,
            "prediction_retrieval_evidence": [
                {
                    "id": str(result.metadata.get("mitre_id", "")).upper(),
                    "similarity_percent": result.similarity_percent,
                    "document_excerpt": result.document[:400],
                }
                for result in prediction_evidence
            ],
            "defense_retrieved_ids": retrieved_defense,
            "beyond_retrieved_ids": sorted(set(beyond_prediction + beyond_defense)),
        }
    except Exception as exc:
        errors.append(f"[Prediction] Failed to generate prediction: {exc}")
        prediction = {
            "stage": current_stage,
            "predicted_techniques": [],
            "predicted_next_techniques": [],
            "predicted_next_technique_details": [],
            "time_to_next_stage": "Unknown",
            "recommended_immediate_actions": "Prediction failed. Isolate affected hosts, disable compromised accounts, and preserve evidence.",
            "business_impact": _business_impact("", str(current_stage)),
            "prediction_confidence": 0.0,
            "confidence": 0.0,
            "confidence_basis": "Prediction failed; confidence is zero.",
            "based_on_stage": current_stage,
            "prediction_retrieved_ids": [],
            "prediction_retrieval_evidence": [],
            "defense_retrieved_ids": [],
            "retrieved_ids": [],
            "beyond_retrieved_ids": [],
            "note": "Prediction failed; no techniques are asserted.",
        }

    print(f"[Prediction] Current stage: {current_stage}")
    print(f"[Prediction] Predicted next techniques: {prediction['predicted_next_techniques']}")
    print(f"[Prediction] Time estimate: {prediction['time_to_next_stage']}")
    print(f"[Prediction] Confidence: {prediction['prediction_confidence']:.0%}")
    return {"prediction": prediction, "errors": errors}
