# MedFlow AI Cybersecurity Ecosystem

AI-powered Red Team and Threat Intelligence lab for healthcare cybersecurity simulations.

This project follows the setup from the provided presentation:

- Red Team agent using MITRE ATT&CK knowledge.
- Threat Intelligence agents for technique lookup, attribution, detection, and response.
- Four local Chroma vector database folders: `attack_db`, `redteam_db`, `actor_db`, and `detection_db`.
- Healthcare scenarios such as MFA fatigue, API abuse, phishing, ransomware staging, and smart-contract permission abuse.

## Requirements

- Python 3.10 or higher
- Git
- 16 GB RAM recommended
- Groq API key for LLM answers

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Add your Groq key to `.env`:

```env
GROQ_API_KEY=your_key_here
```

Download MITRE CTI data:

```powershell
python scripts/download_mitre.py
```

Build the four vector databases:

```powershell
python scripts/build_attack_db.py
python scripts/build_redteam_db.py
python scripts/build_actor_db.py
python scripts/build_detection_db.py
```

Check setup status:

```powershell
python app.py status
```

Ask validation questions:

```powershell
python app.py ask --agent redteam "Give me a full kill chain for a Ryuk attack on a hospital."
python app.py ask --agent detection "What SIEM rules detect MFA fatigue attacks against hospital portals?"
python app.py ask --agent cti "What is T9999?"
```

Run raw similarity search without any LLM:

```powershell
python app.py search --db detection "MFA fatigue hospital portal"
python -m rag.similarity_search --db redteam "Ryuk ransomware hospital kill chain"
```

Compare the configured main and secondary Groq models:

```powershell
python app.py compare --agent redteam "Give me a full kill chain for a Ryuk attack on a hospital."
```

## Project Layout

```text
data/
  mitre-cti/           MITRE CTI repository clone
.cache/
  huggingface/         local embedding model cache
vector_dbs/
  attack_db/
  redteam_db/
  actor_db/
  detection_db/
agents/
  redteam_agent.py
  cti_agent.py
  attribution_agent.py
  detection_agent.py
rag/
  pipeline.py          shared RAG logic used by all agents
  similarity_search.py raw ChromaDB search without Groq/LLM
scripts/
  download_mitre.py
  build_attack_db.py
  build_redteam_db.py
  build_actor_db.py
  build_detection_db.py
app.py
docs/
  model_comparison.md
```

## Safety Note

This repository is designed for defensive education, authorized testing, and simulated healthcare cyber-range work. Red Team output should stay inside approved lab systems.
