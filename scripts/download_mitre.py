from __future__ import annotations

import subprocess
import sys
import argparse
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from config import MITRE_CTI_DIR


REPO_URL = "https://github.com/mitre/cti.git"
PINNED_COMMIT = "ea1adfe1a68ca3dcfe2dd883180b8cf10a988824"


def main() -> None:
    parser = argparse.ArgumentParser(description="Get the pinned MITRE CTI source used to build MedFlow's ATT&CK indexes.")
    parser.add_argument("--ref", default=PINNED_COMMIT, help="MITRE CTI commit to use; defaults to the documented audit snapshot")
    args = parser.parse_args()
    MITRE_CTI_DIR.parent.mkdir(parents=True, exist_ok=True)
    if (MITRE_CTI_DIR / ".git").exists():
        current = subprocess.run(
            ["git", "-C", str(MITRE_CTI_DIR), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if current != args.ref:
            raise SystemExit(
                f"Existing MITRE CTI checkout is at {current}, requested pinned ref is {args.ref}. "
                "It was left unchanged; inspect it and check out the requested commit manually if desired."
            )
        print(f"MITRE CTI repository already matches pinned ref {args.ref}; no network update needed.")
        return
    if MITRE_CTI_DIR.exists() and any(MITRE_CTI_DIR.iterdir()):
        raise SystemExit(f"{MITRE_CTI_DIR} exists and is not empty. Move it or remove it before cloning.")
    subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", REPO_URL, str(MITRE_CTI_DIR)], check=True)
    subprocess.run(["git", "-C", str(MITRE_CTI_DIR), "fetch", "--depth", "1", "origin", args.ref], check=True)
    subprocess.run(["git", "-C", str(MITRE_CTI_DIR), "checkout", "--detach", "FETCH_HEAD"], check=True)
    print(f"Downloaded MITRE CTI ref {args.ref} to {MITRE_CTI_DIR}")


if __name__ == "__main__":
    main()
