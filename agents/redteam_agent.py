from __future__ import annotations

from config import REDTEAM_DB_DIR, load_settings
from rag.pipeline import generate_answer, retrieve


SYSTEM_PROMPT = (
    "You are a healthcare cyber-range Red Team analyst. Keep guidance educational, defensive, "
    "and limited to authorized lab simulations. Focus on ATT&CK mapping, kill-chain reasoning, "
    "validation steps, and remediation opportunities.\n\n"
    "GROUNDING:\n"
    "- Treat ONLY technique IDs in the verified retrieved list as confirmed.\n"
    "- Suffix any unverified technique, actor, or claim with \" [not in retrieved data]\".\n"
    "- End with SOURCES SUMMARY block:\n"
    "Retrieved from database: <used verified IDs>\n"
    "Beyond retrieved data: <other used IDs/claims>"
)


def ask(question: str, model: str | None = None) -> str:
    settings = load_settings()
    context = retrieve(REDTEAM_DB_DIR, question, settings.embedding_model)
    return generate_answer(SYSTEM_PROMPT, question, context, settings.groq_api_key, model or settings.main_model)
