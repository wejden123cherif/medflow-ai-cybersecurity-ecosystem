from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import config
import rag.pipeline as pipeline
from rag.pipeline import SearchResult


def test_query_rag_uses_document_metadata_for_source_ids(monkeypatch):
    results = [
        SearchResult(
            rank=1,
            document="Technique: Data Encrypted for Impact (T1486). Procedure references unrelated T9000.",
            metadata={"mitre_id": "T1486", "type": "redteam-procedure"},
            distance=0.2,
        ),
        SearchResult(
            rank=2,
            document="Technique: Inhibit System Recovery (T1490).",
            metadata={"mitre_id": "T1490", "type": "redteam-procedure"},
            distance=0.25,
        ),
    ]
    captured = {}

    monkeypatch.setattr(pipeline, "search", lambda *_args, **_kwargs: results)
    monkeypatch.setattr(
        config,
        "load_settings",
        lambda: SimpleNamespace(embedding_model="local-test-model", groq_api_key=None),
    )

    def fake_generate_answer(*args, **kwargs):
        captured["context_docs"] = args[2]
        captured["verified_ids"] = kwargs["verified_ids_override"]
        return "answer"

    monkeypatch.setattr(pipeline, "generate_answer", fake_generate_answer)
    answer = pipeline.query_rag("ransomware technique", Path("redteam_db"), "system", "model")

    assert answer == "answer"
    assert captured["verified_ids"] == {"T1486", "T1490"}
    assert "T9000" in captured["context_docs"][0]


def _fake_chroma(monkeypatch, query_results):
    calls = []

    class Collection:
        def query(self, *, query_texts, n_results):
            query = query_texts[0]
            calls.append(query)
            rows = query_results[query]
            rows = rows[:n_results]
            return {
                "ids": [[item[0] for item in rows]],
                "documents": [[item[1] for item in rows]],
                "metadatas": [[{"mitre_id": item[0].split("::")[-1], "type": "attack-pattern"} for item in rows]],
                "distances": [[item[2] for item in rows]],
            }

    class Client:
        def get_or_create_collection(self, **_kwargs):
            return Collection()

    class Chroma:
        @staticmethod
        def PersistentClient(**_kwargs):
            return Client()

    monkeypatch.setattr(pipeline, "_import_chroma", lambda: (Chroma, lambda **_kwargs: object()))
    return calls


def test_compound_query_decomposition_surfaces_each_behavior(monkeypatch):
    question = "The adversary removes backups and recovery options, then encrypts systems for extortion."
    variants = pipeline._query_variants(question)
    rows = {
        variants[0]: [("attack::T1657", "Technique: Financial Theft (T1657)", 0.31)],
        variants[1]: [("attack::T1490", "Technique: Inhibit System Recovery (T1490)", 0.30)],
        variants[2]: [("attack::T1657", "Technique: Financial Theft (T1657)", 0.32)],
        variants[3]: [
            ("attack::T1679", "Technique: Selective Exclusion (T1679)", 0.25),
            ("attack::T1486", "Technique: Data Encrypted for Impact (T1486)", 0.29),
        ],
    }
    calls = _fake_chroma(monkeypatch, rows)

    results = pipeline.search(Path("attack_db"), question, "local-test-model", n_results=3)

    assert calls == variants
    assert {result.metadata["mitre_id"] for result in results} >= {"T1490", "T1486"}
    assert all(result.similarity_percent >= 62.0 for result in results)


def test_single_encryption_query_does_not_add_expensive_extra_search():
    question = "A ransomware operator encrypts files across enterprise endpoints for impact."
    assert pipeline._query_variants(question) == [question]


def test_broad_ransomware_query_abstains_below_similarity_threshold(monkeypatch):
    question = "A broad hospital ransomware incident is reported, but no specific behavior or telemetry is known."
    rows = {
        question: [
            ("attack::T1679", "Technique: Selective Exclusion (T1679)", 0.39),
            ("attack::T1518.002", "Technique: Software Discovery (T1518.002)", 0.43),
        ]
    }
    _fake_chroma(monkeypatch, rows)

    assert len(pipeline.search(Path("attack_db"), question, "local-test-model", n_results=3)) == 2
    assert pipeline.retrieve(Path("attack_db"), question, "local-test-model", n_results=3) == []


def test_retrieve_accepts_exact_threshold_boundary(monkeypatch):
    question = "concrete behavior"
    rows = {question: [("attack::T1486", "Technique: Data Encrypted for Impact (T1486)", 0.38)]}
    _fake_chroma(monkeypatch, rows)

    assert pipeline.retrieve(Path("attack_db"), question, "local-test-model", n_results=3) == [
        "Technique: Data Encrypted for Impact (T1486)"
    ]

def test_search_ranks_zero_cosine_distance_as_best_match(monkeypatch):
    question = "exact behavior"
    rows = {
        question: [
            ("attack::T1110", "Technique: Brute Force (T1110)", 0.1),
            ("attack::T1486", "Technique: Data Encrypted for Impact (T1486)", 0.0),
        ]
    }
    _fake_chroma(monkeypatch, rows)

    results = pipeline.search(Path("attack_db"), question, "local-test-model", n_results=2)

    assert [result.metadata["mitre_id"] for result in results] == ["T1486", "T1110"]
