from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from config import MITRE_CTI_DIR


REPO_URL = "https://github.com/mitre/cti.git"


def main() -> None:
    MITRE_CTI_DIR.parent.mkdir(parents=True, exist_ok=True)
    if (MITRE_CTI_DIR / ".git").exists():
        print("MITRE CTI repository already exists. Pulling latest changes...")
        subprocess.run(["git", "-C", str(MITRE_CTI_DIR), "pull", "--ff-only"], check=True)
        return
    if MITRE_CTI_DIR.exists() and any(MITRE_CTI_DIR.iterdir()):
        raise SystemExit(f"{MITRE_CTI_DIR} exists and is not empty. Move it or remove it before cloning.")
    subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(MITRE_CTI_DIR)], check=True)
    print(f"Downloaded MITRE CTI data to {MITRE_CTI_DIR}")


if __name__ == "__main__":
    main()
