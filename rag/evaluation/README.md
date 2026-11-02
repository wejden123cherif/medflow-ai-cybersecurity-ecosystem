# Phase 2.7 RAG evaluation

`dataset_v1.json` contains 39 labeled queries in development and held-out
splits. Development was used during tuning; held-out results were recorded
after selecting the implementation. Evaluation reads the existing four local
ChromaDB collections and does not rebuild them. Keep those collections local.

For a fresh run, choose a new output directory name under the ignored temporary
area so machine-specific model paths and query results remain local:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_rag.py --split dev --label run --output-dir .pytest-tmp\rag-eval-run-01
```

The evaluator refuses to overwrite an existing result and prints only the
artifact filename. Do not tune on the held-out split.

## Accepted prototype results

Phase 2.7 is accepted for the prototype at similarity threshold **0.62**.
Combining the saved development and held-out denominators gives raw Recall@3
**78.85%**, accepted Recall@3 **76.92%**, raw Precision@3 **30.71%**, accepted
Precision@3 **29.96%**, MRR **75.84%**, and OOD rejection **10/10**. The target
of 85% raw Recall@3 was not reached.

The sanitized snapshots are
[`phase27_final_v1_0_1_dev.json`](published/phase27_final_v1_0_1_dev.json) and
[`phase27_final_v1_0_1_heldout.json`](published/phase27_final_v1_0_1_heldout.json).
They preserve the recorded labels, scores, and metrics; only the absolute local
embedding-cache path was replaced by the model repository and revision. The
original snapshots remain local under the ignored `results/` directory.

Raw Recall@3 by collection was attack **85.29%**, red-team **79.41%**,
detection **70.59%**, and actor **100%** (two entity-label cases). Remaining
misses include exfiltration, system discovery, and recovery inhibition;
detection-collection ranking is also weaker. Broad OOD queries remained below
the acceptance threshold and were rejected.

## Evaluation model

The recorded embedding model was `BAAI/bge-base-en-v1.5`, snapshot revision
`a5beb1e3e68b9ab74eb54cfd186867f64f240e1a`. Evaluation scores are cosine-derived
ranking scores, not calibrated probabilities. The dataset and result snapshots
are documentation evidence; local ChromaDB stores and model weights are not
part of this checkpoint.

Database rebuild tooling is excluded from this checkpoint because its current
default output points at the working `vector_dbs/` collections. Do not run a
rebuild against those collections.
