from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MITRE_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MODEL_SOURCES_SUMMARY_RE = re.compile(
    r"(?im)^\s*(?:#{1,6}\s*)?(?:[-*]\s*)?(?:[*_~`]+\s*)?"
    r"(?:sources?\s+summary\b.*|retrieved\s+from\s+database\s*:|beyond\s+retrieved\s+data\s*:)"
    r".*\Z",
    re.DOTALL,
)


@dataclass(frozen=True)
class RagDocument:
    doc_id: str
    text: str
    metadata: dict[str, str]


@dataclass(frozen=True)
class SearchResult:
    rank: int
    document: str
    metadata: dict[str, str]
    distance: float | None

    @property
    def similarity_percent(self) -> float | None:
        if self.distance is None:
            return None
        return max(0.0, min(100.0, (1.0 - self.distance) * 100.0))


def _import_chroma():
    try:
        import chromadb
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
    except ImportError as exc:
        raise RuntimeError("Missing RAG dependencies. Run: python -m pip install -r requirements.txt") from exc
    return chromadb, SentenceTransformerEmbeddingFunction


def load_mitre_bundle(bundle_path: Path) -> dict[str, Any]:
    if not bundle_path.exists():
        raise FileNotFoundError(f"Missing MITRE bundle: {bundle_path}. Run python scripts/download_mitre.py first.")
    return json.loads(bundle_path.read_text(encoding="utf-8"))


def active_objects(bundle: dict[str, Any], *types: str) -> list[dict[str, Any]]:
    wanted = set(types)
    return [
        obj
        for obj in bundle.get("objects", [])
        if obj.get("type") in wanted
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]


def attack_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return obj.get("id", "unknown")


def text_block(*parts: str | None) -> str:
    return "\n".join(part.strip() for part in parts if part and part.strip())


def object_by_id(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    wanted = (
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "course-of-action",
        "x-mitre-data-source",
        "x-mitre-data-component",
        "x-mitre-detection-strategy",
        "x-mitre-analytic",
    )
    return {obj["id"]: obj for obj in active_objects(bundle, *wanted)}


def relationships_by_target(bundle: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for rel in active_objects(bundle, "relationship"):
        target = rel.get("target_ref")
        if target:
            index.setdefault(target, []).append(rel)
    return index


def attack_documents(bundle: dict[str, Any]) -> list[RagDocument]:
    docs: list[RagDocument] = []
    for obj in active_objects(bundle, "attack-pattern"):
        tid = attack_id(obj)
        tactics = ", ".join(phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", []))
        docs.append(
            RagDocument(
                doc_id=f"attack::{tid}",
                text=text_block(
                    f"Technique: {obj.get('name', 'Unknown')} ({tid})",
                    f"Tactics: {tactics}",
                    obj.get("description"),
                    f"Detection: {obj.get('x_mitre_detection', '')}",
                ),
                metadata={"mitre_id": tid, "type": "attack-pattern"},
            )
        )
    return docs


def redteam_documents(bundle: dict[str, Any]) -> list[RagDocument]:
    objects = object_by_id(bundle)
    relationships = relationships_by_target(bundle)
    docs: list[RagDocument] = []
    for obj in active_objects(bundle, "attack-pattern"):
        tid = attack_id(obj)
        procedures = []
        for rel in relationships.get(obj["id"], []):
            source = objects.get(rel.get("source_ref", ""))
            if source and rel.get("relationship_type") == "uses":
                procedures.append(f"{source.get('name', source.get('id'))}: {rel.get('description', '')}")
        docs.append(
            RagDocument(
                doc_id=f"redteam::{tid}",
                text=text_block(
                    f"Red Team technique: {obj.get('name', 'Unknown')} ({tid})",
                    obj.get("description"),
                    "Real-world procedure examples:",
                    "\n".join(procedures[:25]),
                ),
                metadata={"mitre_id": tid, "type": "redteam-procedure"},
            )
        )
    return docs


def actor_documents(bundle: dict[str, Any]) -> list[RagDocument]:
    docs: list[RagDocument] = []
    for obj in active_objects(bundle, "intrusion-set", "malware", "tool"):
        oid = obj.get("id", "unknown")
        docs.append(
            RagDocument(
                doc_id=f"actor::{oid}",
                text=text_block(
                    f"{obj.get('type', 'object')}: {obj.get('name', 'Unknown')}",
                    f"Aliases: {', '.join(obj.get('aliases', []))}",
                    obj.get("description"),
                ),
                metadata={"mitre_id": attack_id(obj), "type": obj.get("type", "unknown")},
            )
        )
    return docs


def detection_documents(bundle: dict[str, Any]) -> list[RagDocument]:
    objects = object_by_id(bundle)
    relationships = relationships_by_target(bundle)
    docs: list[RagDocument] = []
    
    for obj in active_objects(bundle, "attack-pattern"):
        tid = attack_id(obj)
        tech_id = obj["id"]
        
        # Build text sections
        sections = [
            f"Technique: {obj.get('name', 'Unknown')} ({tid})",
            f"Description: {obj.get('description', '')}",
            f"Platforms: {', '.join(obj.get('x_mitre_platforms', []))}",
        ]
        
        # 1. Resolve Detection Strategies and Analytics
        detection_sections = []
        rels = relationships.get(tech_id, [])
        
        detect_rels = [r for r in rels if r.get("relationship_type") == "detects"]
        for rel in detect_rels:
            strategy_ref = rel.get("source_ref")
            strategy = objects.get(strategy_ref)
            if not strategy:
                continue
            
            strat_name = strategy.get("name", "Unknown Strategy")
            strat_desc = strategy.get("description", "")
            strat_text = f"Detection Strategy: {strat_name}"
            if strat_desc:
                strat_text += f"\nDescription: {strat_desc}"
            
            # Resolve Analytics
            analytic_texts = []
            analytic_refs = strategy.get("x_mitre_analytic_refs", [])
            for analytic_ref in analytic_refs:
                analytic = objects.get(analytic_ref)
                if not analytic:
                    continue
                
                analytic_name = analytic.get("name", "Unknown Analytic")
                analytic_desc = analytic.get("description", "")
                analytic_text = f"  - Analytic: {analytic_name}"
                if analytic_desc:
                    analytic_text += f"\n    Logic/Description: {analytic_desc}"
                
                # Resolve Log Source References
                log_source_refs = analytic.get("x_mitre_log_source_references", [])
                if log_source_refs:
                    log_texts = []
                    for ls_ref in log_source_refs:
                        ls_name = ls_ref.get("name", "Unknown Log Source")
                        ls_channel = ls_ref.get("channel", "N/A")
                        dc_ref = ls_ref.get("x_mitre_data_component_ref")
                        
                        dc_name = "Unknown Data Component"
                        if dc_ref and dc_ref in objects:
                            dc_name = objects[dc_ref].get("name", "Unknown Data Component")
                        
                        log_texts.append(
                            f"      • Log Source: {ls_name} | Channel/Event: {ls_channel} | Data Component: {dc_name}"
                        )
                    if log_texts:
                        analytic_text += "\n    Log Sources and Components:\n" + "\n".join(log_texts)
                analytic_texts.append(analytic_text)
            
            if analytic_texts:
                strat_text += "\n" + "\n".join(analytic_texts)
            detection_sections.append(strat_text)
            
        if detection_sections:
            sections.append("DETECTION STRATEGIES:\n" + "\n\n".join(detection_sections))
        else:
            # Fallback if no modern detection strategy is linked, use the old standard field
            old_det = obj.get("x_mitre_detection")
            if old_det:
                sections.append(f"Detection Guidance:\n{old_det}")
                
        # 2. Resolve Mitigations (Course of Action)
        mitigation_sections = []
        mitigate_rels = [r for r in rels if r.get("relationship_type") == "mitigates"]
        for rel in mitigate_rels:
            coa_ref = rel.get("source_ref")
            coa = objects.get(coa_ref)
            if not coa:
                continue
            
            coa_name = coa.get("name", "Unknown Mitigation")
            coa_desc = coa.get("description", "")
            rel_desc = rel.get("description", "")
            
            coa_text = f"- Mitigation: {coa_name}"
            if coa_desc:
                coa_text += f"\n  Description: {coa_desc}"
            if rel_desc:
                coa_text += f"\n  Application details: {rel_desc}"
            mitigation_sections.append(coa_text)
            
        if mitigation_sections:
            sections.append("MITIGATIONS:\n" + "\n\n".join(mitigation_sections))
            
        # Compile final text block
        text = text_block(*sections)
        docs.append(
            RagDocument(
                doc_id=f"detection::{tid}",
                text=text,
                metadata={"mitre_id": tid, "type": "detection-guidance"},
            )
        )
        
    return docs


def build_collection(db_path: Path, documents: Iterable[RagDocument], embedding_model: str) -> int:
    chromadb, SentenceTransformerEmbeddingFunction = _import_chroma()
    db_path.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(db_path))
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
    collection = client.get_or_create_collection(name=db_path.name, embedding_function=embedding_fn)

    docs = list(documents)
    if not docs:
        return 0
    batch_size = 64
    for start in range(0, len(docs), batch_size):
        batch = docs[start : start + batch_size]
        collection.upsert(
            ids=[doc.doc_id for doc in batch],
            documents=[doc.text for doc in batch],
            metadatas=[doc.metadata for doc in batch],
        )
        print(f"Indexed {min(start + batch_size, len(docs))}/{len(docs)} documents into {db_path.name}")
    return len(docs)


def retrieve(db_path: Path, question: str, embedding_model: str, n_results: int = 5) -> list[str]:
    chromadb, SentenceTransformerEmbeddingFunction = _import_chroma()
    client = chromadb.PersistentClient(path=str(db_path))
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
    collection = client.get_or_create_collection(name=db_path.name, embedding_function=embedding_fn)
    results = collection.query(query_texts=[question], n_results=n_results)
    documents = results.get("documents", [[]])[0]
    return [doc for doc in documents if doc and doc.strip()]


def search(db_path: Path, question: str, embedding_model: str, n_results: int = 5) -> list[SearchResult]:
    chromadb, SentenceTransformerEmbeddingFunction = _import_chroma()
    client = chromadb.PersistentClient(path=str(db_path))
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
    collection = client.get_or_create_collection(name=db_path.name, embedding_function=embedding_fn)
    results = collection.query(query_texts=[question], n_results=n_results)

    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    return [
        SearchResult(
            rank=index + 1,
            document=document,
            metadata=metadatas[index] if index < len(metadatas) else {},
            distance=distances[index] if index < len(distances) else None,
        )
        for index, document in enumerate(documents)
    ]


def _truncate_context(context: str, max_chars: int = 20000) -> tuple[str, bool]:
    if len(context) <= max_chars:
        return context, False
    truncated = context[:max_chars]
    truncated = truncated.rsplit("\n", 1)[0]
    return truncated + "\n\n[Context truncated to fit model limits.]", True


def _enhance_agent_response(answer: str, question: str, context_truncated: bool) -> str:
    """Enhance the agent response with structured formatting and healthcare context."""
    
    # Add healthcare-specific recommendations based on query content
    healthcare_context = ""
    question_lower = question.lower()
    separator = "─" * 75
    
    if any(word in question_lower for word in ["ransomware", "encryption", "extortion"]):
        healthcare_context = (
            f"\n\n{separator}\n"
            "🏥 HEALTHCARE-SPECIFIC RESPONSE MEASURES\n"
            f"{separator}\n"
            "  • ACTIVATE INCIDENT RESPONSE TEAM: Engage cybersecurity and operations\n"
            "  • PRESERVE SYSTEMS: Isolate affected systems; DO NOT PAY ransom without law enforcement\n"
            "  • PATIENT SAFETY: Maintain continuity of care with manual processes/backups\n"
            "  • REGULATORY REPORTING: Notify HHS if PHI affected; comply with HIPAA Breach Notification\n"
            "  • FORENSICS: Preserve evidence; contact FBI/CISA for federal support\n"
            "  • COMMUNICATION: Inform workforce, patients, and leadership per policy"
        )
    elif any(word in question_lower for word in ["breach", "exfiltration", "data theft"]):
        healthcare_context = (
            f"\n\n{separator}\n"
            "🏥 HEALTHCARE-SPECIFIC RESPONSE MEASURES\n"
            f"{separator}\n"
            "  • INVESTIGATE: Determine scope (what data, how many records, which patients)\n"
            "  • CONTAIN: Revoke compromised credentials; reset affected accounts\n"
            "  • NOTIFY: 60-day notification to affected individuals (HIPAA requirement)\n"
            "  • DOCUMENT: Create detailed incident timeline and forensic report\n"
            "  • IMPROVE: Implement preventive controls to avoid recurrence\n"
            "  • COMMUNICATE: Transparent communication with regulators and stakeholders"
        )
    elif any(word in question_lower for word in ["phis", "pii", "phi", "patient data"]):
        healthcare_context = (
            f"\n\n{separator}\n"
            "🏥 HEALTHCARE-SPECIFIC RESPONSE MEASURES\n"
            f"{separator}\n"
            "  • CLASSIFY DATA: Identify which PHI/PII types are at risk\n"
            "  • ASSESS RISK: Determine likelihood of access/misuse by unauthorized individuals\n"
            "  • MITIGATE: Apply access controls, encryption, and monitoring\n"
            "  • COMPLY: Ensure HIPAA Privacy & Security Rule implementation\n"
            "  • AUDIT: Regular audits and risk assessments of sensitive systems\n"
            "  • TRAIN: Workforce security awareness focused on data protection"
        )
    
    # Add warnings if context was truncated
    truncation_warning = ""
    if context_truncated:
        truncation_warning = (
            f"\n\n{separator}\n"
            "⚠️  IMPORTANT NOTE\n"
            f"{separator}\n"
            "Retrieved context was truncated to fit model token limits.\n"
            "The answer may be incomplete. For comprehensive analysis:\n"
            "  • Use a more specific query to narrow results\n"
            "  • Try the 'search --all' command to see all matching techniques\n"
            "  • Consult official MITRE ATT&CK documentation"
        )
    # Only append the healthcare block if it's useful and not already present in the model answer
    header = "🏥 HEALTHCARE-SPECIFIC RESPONSE MEASURES"
    result = answer
    if healthcare_context and header not in (answer or ""):
        result = result + healthcare_context

    result = result + truncation_warning

    # Collapse accidental repeated header/separator blocks into a single block using line-wise logic
    try:
        lines = result.splitlines()
        new_lines: list[str] = []
        seen_header = False
        last_line = ""

        def normalize_header(s: str) -> str:
            return re.sub(r"[^A-Z0-9 ]+", "", s.upper())

        norm_header = normalize_header(header)

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Detect header variants (with/without emoji or minor differences)
            if normalize_header(stripped).find(norm_header) != -1:
                if not seen_header:
                    new_lines.append(line)
                    seen_header = True
                    last_line = stripped
                # If we've already added a header, skip subsequent header-only blocks
                else:
                    # Peek ahead: if the following lines are only separators or empty, skip them
                    j = i + 1
                    while j < len(lines) and (lines[j].strip() == "" or all(ch in "-─═" for ch in lines[j].strip())):
                        j += 1
                    i = j - 1
                i += 1
                continue

            # Treat long runs of dash/box characters as separators; avoid consecutive duplicates
            if len(stripped) >= 3 and all(ch in "-─═" for ch in stripped):
                if last_line and all(ch in "-─═" for ch in last_line):
                    i += 1
                    continue
                new_lines.append(line)
                last_line = stripped
                seen_header = False
                i += 1
                continue

            # Normal content: include and reset header tracking
            new_lines.append(line)
            last_line = stripped
            seen_header = False
            i += 1

        result = "\n".join(new_lines)
    except Exception:
        # On unexpected failure, leave result unchanged
        pass

    return result


def _extract_mitre_ids(text: str) -> list[str]:
    return [match.upper() for match in MITRE_TECHNIQUE_ID_RE.findall(text or "")]


def _extract_mitre_id_set(text: str) -> set[str]:
    return set(_extract_mitre_ids(text))


def _strip_think_blocks(response_text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", response_text or "", flags=re.DOTALL | re.IGNORECASE).strip()


def _strip_model_sources_summary(response_text: str) -> str:
    return MODEL_SOURCES_SUMMARY_RE.sub("", response_text or "").rstrip()


def _format_id_list(ids: set[str]) -> str:
    return ", ".join(sorted(ids)) if ids else "None"


def compute_sources_summary(verified_ids: set[str], response_text: str) -> str:
    cleaned_response = _strip_model_sources_summary(response_text)
    used_ids = _extract_mitre_id_set(cleaned_response)

    retrieved_and_used = used_ids & verified_ids
    beyond_retrieved = used_ids - verified_ids
    retrieved_not_used = verified_ids - used_ids

    summary = (
        "---\n"
        "SOURCES SUMMARY (computed automatically, not self-reported by the model)\n"
        f"Retrieved from database and used in this answer: {_format_id_list(retrieved_and_used)}\n"
        "Used in this answer but NOT found in retrieved context "
        "(model's own training knowledge, not verified against the database): "
        f"{_format_id_list(beyond_retrieved)}\n"
        f"Retrieved from database but not used in this answer: {_format_id_list(retrieved_not_used)}\n"
        "---"
    )

    return f"{cleaned_response}\n\n{summary}" if cleaned_response else summary


def _has_matching_ids(question: str, docs: list[str]) -> bool:
    query_ids = _extract_mitre_ids(question)
    if not query_ids:
        return False
    joined = "\n".join(docs).upper()
    return any(query_id in joined for query_id in query_ids)


def _no_evidence_response() -> str:
    return "No evidence found for this query in the local MITRE context."


def generate_answer(system_prompt: str, question: str, context_docs: list[str], api_key: str | None, model: str) -> str:
    context_docs = [doc for doc in context_docs if doc and doc.strip()]
    if not context_docs:
        return _no_evidence_response()

    if _extract_mitre_ids(question) and not _has_matching_ids(question, context_docs):
        return _no_evidence_response()

    raw_context_text = "\n\n".join(context_docs)
    verified_ids = _extract_mitre_id_set(raw_context_text)
    verified_ids_str = _format_id_list(verified_ids)

    context = "\n\n---\n\n".join(context_docs)
    context, context_truncated = _truncate_context(context)
    if not api_key:
        return "GROQ_API_KEY is not set. Retrieved local context:\n\n" + (context or "No matching context found.")

    try:
        from groq import Groq
    except ImportError as exc:
        raise RuntimeError("Missing Groq dependency. Run: python -m pip install -r requirements.txt") from exc

    client = Groq(api_key=api_key)
    
    # Inline source labels are readability hints only. The computed summary appended
    # after generation is the single source of truth for technique-ID provenance.
    user_message = (
        "You are a healthcare cybersecurity expert. Provide a comprehensive, structured response.\n\n"
        "INSTRUCTIONS:\n"
        "1. Start with a clear, direct answer to the question\n"
        "2. Use the MITRE ATT&CK framework as your factual basis\n"
        "3. Highlight key threat indicators and attack patterns\n"
        "4. Explain real-world implications for healthcare organizations\n"
        "5. Provide actionable defensive recommendations\n"
        "6. If information is incomplete, explicitly state what is missing\n\n"
        "7. For readability, prefix body sentences that rely on non-retrieved information with "
        "\"Beyond the retrieved data:\"\n\n"
        f"VERIFIED RETRIEVED TECHNIQUE IDs:\n{verified_ids_str}\n\n"
        "RETRIEVED CONTEXT:\n"
        f"{context}\n\n"
        "QUESTION:\n"
        f"{question}\n\n"
        "RESPONSE FORMAT:\n"
        "Structure your response with:\n"
        "  • Summary (concise overview)\n"
        "  • Threat Assessment (risks and implications)\n"
        "  • Key Characteristics (how the threat works)\n"
        "  • Detection Strategies (how to identify it)\n"
        "  • Mitigation Approach (how to defend against it)\n"
        "  • Healthcare Context (specific implications for healthcare)"
    )
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
    )
    
    answer = response.choices[0].message.content or ""
    answer = _strip_think_blocks(answer)
    answer = _strip_model_sources_summary(answer)

    # Enhance response with healthcare-specific context
    answer = _enhance_agent_response(answer, question, context_truncated)

    return compute_sources_summary(verified_ids, answer)
