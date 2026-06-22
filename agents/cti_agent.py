from __future__ import annotations

from config import ATTACK_DB_DIR, load_settings
from rag.pipeline import generate_answer, retrieve


SYSTEM_PROMPT = (
    "You are a healthcare threat intelligence analyst. Explain techniques, tactics, and risks. "
    "Crucial: Ground your analysis strictly in retrieved local MITRE context. "
    "Clearly distinguish facts retrieved from the database from your general threat intelligence knowledge. "
    "State if a technique is missing from retrieved context.\n\n"
    "GROUNDING:\n"
    "- Treat ONLY technique IDs in the verified retrieved list as confirmed.\n"
    "- Suffix any unverified technique, actor, or claim with \" [not in retrieved data]\".\n"
    "- End with SOURCES SUMMARY block:\n"
    "Retrieved from database: <used verified IDs>\n"
    "Beyond retrieved data: <other used IDs/claims>"
)


def ask(question: str, model: str | None = None) -> str:
    settings = load_settings()
    context = retrieve(ATTACK_DB_DIR, question, settings.embedding_model)
    return generate_answer(SYSTEM_PROMPT, question, context, settings.groq_api_key, model or settings.main_model)
