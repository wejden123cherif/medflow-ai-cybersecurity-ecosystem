from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

EXTERNAL_REPOS = {
    "wazuh-docker": "https://github.com/wazuh/wazuh-docker.git",
    "misp-docker": "https://github.com/MISP/misp-docker.git",
}


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def clone_if_missing(repo_name: str, repo_url: str, *, dry_run: bool = False) -> None:
    target = ROOT_DIR / repo_name
    if target.exists():
        print(f"{repo_name}: already present at {target}")
        return

    print(f"{repo_name}: missing, cloning from {repo_url}")
    if dry_run:
        print(f"[dry-run] git clone --depth 1 {repo_url} {target}")
        return

    subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target)], cwd=ROOT_DIR, check=True)
    print(f"{repo_name}: clone complete")


def ensure_suricata_dirs(*, dry_run: bool = False) -> None:
    suricata_dir = ROOT_DIR / "suricata"
    required = [
        suricata_dir / "logs",
        suricata_dir / "pcap",
        suricata_dir / "rules",
    ]
    for path in required:
        if path.exists():
            print(f"suricata: {path.relative_to(ROOT_DIR)} already present")
            continue
        print(f"suricata: creating {path.relative_to(ROOT_DIR)}")
        if not dry_run:
            path.mkdir(parents=True, exist_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap local external service directories used by MedFlow.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created without cloning or modifying files.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.dry_run:
        print("Bootstrap check only (no clone, no directory creation)")

    for repo_name, repo_url in EXTERNAL_REPOS.items():
        clone_if_missing(repo_name, repo_url, dry_run=args.dry_run)

    ensure_suricata_dirs(dry_run=args.dry_run)
    print("External service bootstrap complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
