from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BUNDLE_SHA256 = "1a1b6d8f926279b6a2eabaf3fc6358080ef8ea59e2645d9b039508bcb6647e96"
sys.path.insert(0, str(ROOT))

from config import ENTERPRISE_ATTACK_JSON, load_settings
from rag.pipeline import (
    actor_documents,
    attack_documents,
    build_collection,
    detection_documents,
    load_mitre_bundle,
    redteam_documents,
    search,
)


def main() -> int:
    started = time.perf_counter()
    parser = argparse.ArgumentParser(description="Build all four MedFlow ATT&CK Chroma collections.")
    parser.add_argument("--source", type=Path, default=ENTERPRISE_ATTACK_JSON, help="Local Enterprise ATT&CK STIX JSON bundle")
    parser.add_argument(
        "--source-sha256",
        default=EXPECTED_BUNDLE_SHA256,
        help="Expected source hash (default pins the audit's Enterprise ATT&CK bundle)",
    )
    parser.add_argument("--allow-unpinned-source", action="store_true", help="Build from a different explicitly supplied source bundle")
    parser.add_argument("--output-root", type=Path, default=ROOT / "vector_dbs", help="Directory for generated collections")
    parser.add_argument("--embedding-model", help="Local model directory or model ID (remote downloads require --allow-model-download)")
    parser.add_argument("--allow-model-download", action="store_true", help="Allow Sentence Transformers to download model weights if absent locally")
    args = parser.parse_args()

    if not args.source.is_file():
        raise SystemExit(f"Missing ATT&CK source bundle: {args.source}. Run scripts/download_mitre.py first or pass --source.")
    if not args.allow_unpinned_source:
        digest = hashlib.sha256(args.source.read_bytes()).hexdigest()
        if digest.lower() != args.source_sha256.lower():
            raise SystemExit(
                f"Source bundle hash mismatch for {args.source}: got {digest}, expected {args.source_sha256}. "
                "Pass --allow-unpinned-source only if you intend to build from a different ATT&CK snapshot."
            )
    settings = load_settings()
    embedding_model = args.embedding_model or settings.embedding_model
    if not Path(embedding_model).exists() and not args.allow_model_download:
        raise SystemExit(
            f"Embedding model is not available locally: {embedding_model}. Check .cache/huggingface or pass "
            "--allow-model-download to explicitly permit retrieval of model weights."
        )

    bundle = load_mitre_bundle(args.source)
    builders = {
        "attack_db": attack_documents,
        "redteam_db": redteam_documents,
        "actor_db": actor_documents,
        "detection_db": detection_documents,
    }
    counts: dict[str, int] = {}
    for name, builder in builders.items():
        documents = builder(bundle)
        if any(not doc.doc_id or not doc.metadata.get("mitre_id") or not doc.metadata.get("type") for doc in documents):
            raise SystemExit(f"Metadata validation failed for {name}; every row requires ID, mitre_id, and type.")
        destination = args.output_root / name
        counts[name] = build_collection(destination, documents, embedding_model)

    settings_embedding = embedding_model
    smoke_queries = {
        "attack_db": ("Data Encrypted for Impact ransomware files", "T1486"),
        "redteam_db": ("Data Encrypted for Impact ransomware files", "T1486"),
        "detection_db": ("Data Encrypted for Impact ransomware detection", "T1486"),
        "actor_db": ("Ryuk ransomware malware", "S0446"),
    }
    for name, (query, expected_id) in smoke_queries.items():
        results = search(args.output_root / name, query, settings_embedding, n_results=5)
        if not results or expected_id not in {hit.metadata.get("mitre_id") for hit in results}:
            raise SystemExit(f"Retrieval smoke test failed for {name}; expected {expected_id} in top five.")
    print(f"Source: {args.source}")
    print(f"Embedding model: {embedding_model}")
    for name, count in counts.items():
        print(f"{name}: {count} documents")
    print("Retrieval smoke test: passed for all four collections")
    print(f"Elapsed seconds: {time.perf_counter() - started:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
