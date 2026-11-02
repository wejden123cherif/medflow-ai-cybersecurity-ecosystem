from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import ACTOR_DB_DIR, ATTACK_DB_DIR, DETECTION_DB_DIR, ENTERPRISE_ATTACK_JSON, REDTEAM_DB_DIR, load_settings
from rag.pipeline import MIN_RETRIEVAL_SIMILARITY, active_objects, attack_id, load_mitre_bundle, search
DEFAULT_DATASET = ROOT / "rag" / "evaluation" / "dataset_v1.json"
DEFAULT_OUTPUT = ROOT / "rag" / "evaluation" / "results"
DBS = {
    "attack_db": ATTACK_DB_DIR,
    "redteam_db": REDTEAM_DB_DIR,
    "detection_db": DETECTION_DB_DIR,
    "actor_db": ACTOR_DB_DIR,
}


def _expected_ids(row: dict) -> list[str]:
    return row.get("expected_technique_ids", []) or row.get("expected_entity_ids", [])


def _metrics(rows: list[dict], collection: str | None) -> dict:
    selected = [row for row in rows if collection is None or collection in row["expected_collections"]]
    rel_total = sum(len(_expected_ids(row)) for row in selected if not row["abstention_required"])
    relevant_at1 = relevant_at3 = accepted_relevant_at1 = accepted_relevant_at3 = reciprocal_rank_sum = 0
    ood = [row for row in selected if row["abstention_required"]]
    ood_rejected = 0
    empty = 0
    latencies = []
    fp_queries = 0
    for row in selected:
        result = next(iter(row["results"].values())) if collection is None else row["results"][collection]
        latencies.append(result["latency_ms"])
        accepted = result["accepted_ids"]
        if not accepted:
            empty += 1
        if row["abstention_required"]:
            if not accepted:
                ood_rejected += 1
            else:
                fp_queries += 1
            continue
        expected = set(_expected_ids(row))
        ranked = result["raw_ids"]
        relevant_at1 += int(bool(ranked) and ranked[0] in expected)
        accepted_relevant_at1 += int(bool(accepted) and accepted[0] in expected)
        relevant_positions = [i + 1 for i, tid in enumerate(ranked[:3]) if tid in expected]
        if relevant_positions:
            reciprocal_rank_sum += 1.0 / relevant_positions[0]
        relevant_at3 += sum(tid in expected for tid in ranked[:3])
        accepted_relevant_at3 += sum(tid in expected for tid in accepted[:3])
    positive = [row for row in selected if not row["abstention_required"]]
    precision_denominator = 3 * len(positive)
    technique_count = sum(len(row.get("expected_technique_ids", [])) for row in positive)
    entity_count = sum(len(row.get("expected_entity_ids", [])) for row in positive)
    return {
        "queries": len(selected),
        "positive_queries": len(positive),
        "ood_queries": len(ood),
        "expected_relevant_technique_count": technique_count,
        "expected_relevant_entity_count": entity_count,
        "expected_relevant_item_count": rel_total,
        "recall_at_1": relevant_at1 / rel_total if rel_total else None,
        "recall_at_3": relevant_at3 / rel_total if rel_total else None,
        "accepted_recall_at_1": accepted_relevant_at1 / rel_total if rel_total else None,
        "accepted_recall_at_3": accepted_relevant_at3 / rel_total if rel_total else None,
        "precision_at_3": relevant_at3 / precision_denominator if precision_denominator else None,
        "accepted_precision_at_3": accepted_relevant_at3 / precision_denominator if precision_denominator else None,
        "mrr": reciprocal_rank_sum / len(positive) if positive else None,
        "ood_rejection_rate": ood_rejected / len(ood) if ood else None,
        "ood_false_positive_query_rate": fp_queries / len(ood) if ood else None,
        "empty_result_rate": empty / len(selected) if selected else None,
        "mean_latency_ms": statistics.mean(latencies) if latencies else None,
        "latency_denominator_queries": len(latencies),
    }


def _threshold_metrics(rows: list[dict], split: str, threshold: float) -> dict:
    selected = [row for row in rows if row["split"] == split]
    relevant = relevant_found = ood = ood_rejected = false_positive = empty = pairs = positive_queries = 0
    for row in selected:
        for result in row["results"].values():
            pairs += 1
            accepted = [
                technique_id for technique_id, score in zip(result["raw_ids"], result["raw_scores_percent"])
                if score is not None and score / 100.0 >= threshold
            ]
            empty += not accepted
            if row["abstention_required"]:
                ood += 1
                ood_rejected += not accepted
                false_positive += bool(accepted)
            else:
                positive_queries += 1
                expected = set(_expected_ids(row))
                relevant += len(expected)
                relevant_found += sum(technique_id in expected for technique_id in accepted[:3])
    return {
        "collection_query_pairs": pairs,
        "positive_collection_query_pairs": positive_queries,
        "expected_relevant_item_count": relevant,
        "accepted_recall_at_3": relevant_found / relevant if relevant else None,
        "ood_cases": ood,
        "ood_rejection_rate": ood_rejected / ood if ood else None,
        "ood_false_positive_query_rate": false_positive / ood if ood else None,
        "empty_result_rate": empty / pairs if pairs else None,
    }


def _write_result(path: Path, output: dict) -> None:
    """Create an evaluation artifact without replacing an earlier result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(output, handle, indent=2)
        handle.write("\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate local Chroma retrieval against a versioned query set.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--split", choices=("all", "dev", "heldout"), default="all")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--label", default="baseline", help="Output label, e.g. baseline or after")
    parser.add_argument("--threshold", type=float, default=MIN_RETRIEVAL_SIMILARITY, help="Cosine-similarity cutoff in [0, 1]")
    args = parser.parse_args()
    if args.top_k < 3:
        raise SystemExit("--top-k must be at least 3 so Precision@3 and Recall@3 are fully evaluated.")
    if not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("--threshold must be between 0 and 1.")
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    bundle = load_mitre_bundle(ENTERPRISE_ATTACK_JSON)
    valid_techniques = {attack_id(obj) for obj in active_objects(bundle, "attack-pattern")}
    valid_entities = {attack_id(obj) for obj in active_objects(bundle, "intrusion-set", "malware", "tool")}
    for query in dataset["queries"]:
        unknown_techniques = set(query.get("expected_technique_ids", [])) - valid_techniques
        unknown_entities = set(query.get("expected_entity_ids", [])) - valid_entities
        if unknown_techniques or unknown_entities:
            raise SystemExit(f"Evaluation labels not found in local ATT&CK data for {query['id']}.")
    ids = set(dataset["splits"][args.split]) if args.split != "all" else {q["id"] for q in dataset["queries"]}
    queries = [q for q in dataset["queries"] if q["id"] in ids]
    settings = load_settings()
    rows = []
    for query in queries:
        row = {**query, "results": {}}
        for name in query["expected_collections"]:
            start = time.perf_counter()
            found = search(DBS[name], query["query"], settings.embedding_model, n_results=args.top_k)
            elapsed = (time.perf_counter() - start) * 1000
            raw_ids = [str(hit.metadata.get("mitre_id", "")) for hit in found]
            accepted_ids = [
                str(hit.metadata.get("mitre_id", "")) for hit in found
                if hit.similarity_percent is not None and hit.similarity_percent / 100 >= args.threshold
            ]
            row["results"][name] = {
                "latency_ms": elapsed,
                "raw_ids": raw_ids,
                "accepted_ids": accepted_ids,
                "raw_scores_percent": [hit.similarity_percent for hit in found],
            }
        rows.append(row)
    summary = {name: _metrics(rows, name) for name in DBS if any(name in r["expected_collections"] for r in rows)}
    # Aggregate across all evaluated query/collection pairs (including all-target collections).
    flattened = []
    for row in rows:
        for name, result in row["results"].items():
            flattened.append({**row, "expected_collections": [name], "results": {name: result}})
    aggregate = _metrics(flattened, None)
    output = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset["version"],
        "label": args.label,
        "split": args.split,
        "embedding_model": settings.embedding_model,
        "similarity_threshold": args.threshold,
        "top_k": args.top_k,
        "metric_notes": {
            "recall_at_k": "Relevant ATT&CK IDs hit in raw top-k / all expected IDs; technique and actor entity cases are ID-weighted.",
            "precision_at_3": "Relevant IDs in the raw top three / (3 * positive query count); empty slots count as non-relevant.",
            "accepted_precision_at_3": "Relevant IDs in threshold-accepted top three / (3 * positive query count); empty slots count as non-relevant.",
            "mrr": "Mean reciprocal rank of first expected ID among positive queries.",
            "ood_rejection_rate": "OOD cases with no accepted result / OOD cases.",
            "ood_false_positive_query_rate": "OOD cases with at least one accepted result / OOD cases.",
            "latency": "Per-query local search wall time including client/model initialization; first query may be cold.",
        },
        "collection_metrics": summary,
        "aggregate_metrics": aggregate,
        "threshold_sweep": {
            split: {
                f"{threshold:.2f}": _threshold_metrics(rows, split, threshold)
                for threshold in (0.60, 0.61, 0.62, 0.65, 0.70, 0.75)
            }
            for split in ("dev", "heldout")
        },
        "queries": rows,
    }
    output_path = args.output_dir / f"{args.label}_v{dataset['version'].replace('.', '_')}_{args.split}.json"
    try:
        _write_result(output_path, output)
    except FileExistsError:
        raise SystemExit(f"Refusing to overwrite existing evaluation result: {output_path.name}")
    print(json.dumps({"output": output_path.name, "queries": len(rows), "metrics": summary, "aggregate": aggregate}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
