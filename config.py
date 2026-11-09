from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
MITRE_CTI_DIR = DATA_DIR / "mitre-cti"
VECTOR_DB_DIR = ROOT_DIR / "vector_dbs"
MODEL_CACHE_DIR = ROOT_DIR / ".cache" / "huggingface"

ATTACK_DB_DIR = VECTOR_DB_DIR / "attack_db"
REDTEAM_DB_DIR = VECTOR_DB_DIR / "redteam_db"
ACTOR_DB_DIR = VECTOR_DB_DIR / "actor_db"
DETECTION_DB_DIR = VECTOR_DB_DIR / "detection_db"

ENTERPRISE_ATTACK_JSON = MITRE_CTI_DIR / "enterprise-attack" / "enterprise-attack.json"

os.environ.setdefault("HF_HOME", str(MODEL_CACHE_DIR))
os.environ.setdefault("SENTENCE_TRANSFORMERS_HOME", str(MODEL_CACHE_DIR / "sentence-transformers"))


@dataclass(frozen=True)
class Settings:
    groq_api_key: str | None
    main_model: str
    secondary_model: str
    embedding_model: str
    smtp_host: str
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_from: str
    soc_email: str
    email_mode: str  # "gmail" for real delivery, "mock" for localhost:1025 CI fallback
    protected_ips: list[str]
    target_vm_host: str | None
    target_vm_ssh_user: str | None
    target_vm_ssh_key_path: str | None
    soc_email_allowlist: list[str] = field(default_factory=list)
    email_min_severity: int = 8
    email_max_evidence_age_minutes: int = 15


def resolve_embedding_model(model_name: str) -> str:
    cache_repo = MODEL_CACHE_DIR / "sentence-transformers" / f"models--{model_name.replace('/', '--')}"
    snapshots_dir = cache_repo / "snapshots"
    if snapshots_dir.exists():
        snapshots = [path for path in snapshots_dir.iterdir() if path.is_dir()]
        if snapshots:
            return str(sorted(snapshots, key=lambda path: path.stat().st_mtime, reverse=True)[0])
    return model_name


def load_settings() -> Settings:
    load_dotenv(ROOT_DIR / ".env")
    embedding_model = os.getenv("MEDFLOW_EMBEDDING_MODEL", "BAAI/bge-base-en-v1.5")
    protected_ips_raw = os.getenv("PROTECTED_IPS", "127.0.0.1,::1,10.0.2.2,192.168.1.1")
    protected_ips = [ip.strip() for ip in protected_ips_raw.split(",") if ip.strip()]
    return Settings(
        groq_api_key=os.getenv("GROQ_API_KEY") or None,
        main_model=os.getenv("GROQ_MAIN_MODEL", "openai/gpt-oss-120b"),
        secondary_model=os.getenv("GROQ_SECONDARY_MODEL", "openai/gpt-oss-20b"),
        embedding_model=resolve_embedding_model(embedding_model),
        smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER") or None,
        smtp_password=os.getenv("SMTP_PASSWORD") or None,
        smtp_from=os.getenv("SMTP_FROM", "medflow-ai-soc@gmail.com"),
        # No personal recipient is enabled by default; dispatch also requires an
        # explicit match in SOC_EMAIL_ALLOWLIST.
        soc_email=os.getenv("SOC_EMAIL", ""),
        soc_email_allowlist=[address.strip().casefold() for address in os.getenv("SOC_EMAIL_ALLOWLIST", "").split(",") if address.strip()],
        email_mode=os.getenv("EMAIL_MODE", "gmail"),
        protected_ips=protected_ips,
        target_vm_host=os.getenv("TARGET_VM_HOST") or None,
        target_vm_ssh_user=os.getenv("TARGET_VM_SSH_USER") or None,
        target_vm_ssh_key_path=os.getenv("TARGET_VM_SSH_KEY_PATH") or None,
        email_min_severity=max(0, min(15, int(os.getenv("MEDFLOW_EMAIL_MIN_SEVERITY", "8")))),
        email_max_evidence_age_minutes=max(1, min(1440, int(os.getenv("MEDFLOW_EMAIL_MAX_EVIDENCE_AGE_MINUTES", "15")))),
    )


def ensure_project_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    VECTOR_DB_DIR.mkdir(exist_ok=True)
    MODEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for db_dir in (ATTACK_DB_DIR, REDTEAM_DB_DIR, ACTOR_DB_DIR, DETECTION_DB_DIR):
        db_dir.mkdir(parents=True, exist_ok=True)
