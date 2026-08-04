#!/usr/bin/env python3
"""Extract only the MedFlow-specific Wazuh customizations from a local Wazuh Docker clone.

Why this exists:
    We do not commit the upstream `wazuh-docker` repository because it is a large external
    dependency with its own lifecycle. We only keep the files that MedFlow actually needs to
    override: the manager config, custom MedFlow integration logic, and Wazuh active-response
    hooks. This keeps the repository small, reproducible, and portable.

Docker Compose usage:
    The MedFlow project keeps the official Wazuh images and mounts the project-owned config
    files into the manager container. This means a fresh VM can run:

        git clone <medflow-repo>
        cd <medflow-repo>
        docker compose up -d --build

    without needing a full `wazuh-docker` repository checked into Git.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "wazuh" / "wazuh-docker"
DEFAULT_BACKUP = ROOT / "wazuh-medflow-custom.patch"

TARGET_DIRS = {
    "config": ROOT / "wazuh" / "config",
    "integrations": ROOT / "wazuh" / "integrations",
    "active_response": ROOT / "wazuh" / "active-response",
    "suricata": ROOT / "suricata",
}

CUSTOM_GLOBS = {
    "config": [
        "single-node/config/wazuh_cluster/wazuh_manager.conf",
        "multi-node/config/wazuh_cluster/wazuh_manager.conf",
    ],
    "integrations": [
        "**/custom-medflow*",
        "**/*medflow*",
        "**/*suricata*",
    ],
    "active_response": [
        "**/firewall-drop-ssh.sh",
        "**/*firewall*drop*",
        "**/*active-response*",
    ],
    "rules": [
        "**/*suricata*.rules",
        "**/*suricata*",
        "**/*medflow*rules*",
    ],
}

ALLOWED_SUFFIXES = {".conf", ".py", ".sh", ".yaml", ".yml", ".json", ".rules", ".txt"}
BLOCKED_SUFFIXES = {".pem", ".crt", ".key", ".env", ".pub", ".p12", ".pfx"}


def log(msg: str) -> None:
    print(msg)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract only the MedFlow-specific Wazuh customizations from a local wazuh-docker "
            "clone into the MedFlow repository."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Path to the local wazuh-docker clone to inspect (default: ./wazuh/wazuh-docker)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="MedFlow repo root. Defaults to the current repository.",
    )
    parser.add_argument(
        "--backup-path",
        type=Path,
        default=DEFAULT_BACKUP,
        help="Where to store the Wazuh custom patch backup.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display actions without creating or copying files.",
    )
    return parser.parse_args()


def ensure_target_layout(repo_root: Path, dry_run: bool) -> None:
    for target in TARGET_DIRS.values():
        rel = target.relative_to(repo_root)
        if dry_run:
            log(f"[dry-run] would create directory: {rel}")
        else:
            target.mkdir(parents=True, exist_ok=True)
            log(f"created directory: {rel}")


def is_safe_file(path: Path) -> bool:
    if path.name.startswith("."):
        return False
    if path.suffix.lower() in BLOCKED_SUFFIXES:
        return False
    if path.suffix.lower() not in ALLOWED_SUFFIXES and path.name not in {"README", "README.md"}:
        return False
    return True


def collect_source_matches(source_root: Path, patterns: list[str]) -> list[Path]:
    matches: list[Path] = []
    for pattern in patterns:
        matches.extend(source_root.glob(pattern))
    unique: list[Path] = []
    seen: set[Path] = set()
    for match in matches:
        if match.is_file() and match not in seen:
            if is_safe_file(match):
                unique.append(match)
                seen.add(match)
    return sorted(unique, key=lambda p: str(p))


def find_required_files(source_root: Path) -> dict[str, list[Path]]:
    discovered: dict[str, list[Path]] = {}
    for category, patterns in CUSTOM_GLOBS.items():
        files = collect_source_matches(source_root, patterns)
        discovered[category] = files
    return discovered


def validate_source(source_root: Path) -> None:
    if not source_root.exists():
        raise FileNotFoundError(f"Wazuh source directory does not exist: {source_root}")

    if not (source_root / ".git").exists():
        log("warning: source directory is not a git checkout; continuing because the script is for local export only.")

    # The exact file we need for manager configuration should be present in a Wazuh single-node
    # or multi-node setup. We intentionally limit the export to config files, not the whole repo.
    needed = [
        source_root / "single-node" / "config" / "wazuh_cluster" / "wazuh_manager.conf",
        source_root / "multi-node" / "config" / "wazuh_cluster" / "wazuh_manager.conf",
    ]
    present = [path for path in needed if path.exists()]
    if not present:
        raise FileNotFoundError(
            "No Wazuh manager config was found in the source clone. "
            "Expected one of: single-node/config/wazuh_cluster/wazuh_manager.conf or "
            "multi-node/config/wazuh_cluster/wazuh_manager.conf"
        )

    # Ensure no secret-bearing certificate or env file is being blindly copied.
    env_files = list(source_root.rglob("*.env"))
    if env_files:
        log("warning: environment files are present in the source. They will not be exported.")

    cert_files = list(source_root.rglob("*.pem")) + list(source_root.rglob("*.key")) + list(source_root.rglob("*.crt"))
    if cert_files:
        log("warning: certificate/key files were detected in the source clone; they are excluded from export.")


def make_backup_patch(source_root: Path, backup_path: Path, dry_run: bool) -> None:
    if not source_root.exists():
        raise FileNotFoundError(f"Cannot create patch because source path does not exist: {source_root}")

    git_cmd = ["git", "-C", str(source_root), "diff", "--binary"]
    if dry_run:
        log(f"[dry-run] would create patch at: {backup_path}")
        log(f"[dry-run] command: {' '.join(git_cmd)} > {backup_path}")
        return

    result = subprocess.run(git_cmd, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git diff failed in source repository: {result.stderr}")

    backup_path.write_text(result.stdout, encoding="utf-8")
    log(f"created patch backup: {backup_path}")


def copy_file(src: Path, dst: Path, dry_run: bool) -> None:
    if dry_run:
        log(f"[dry-run] would copy: {src} -> {dst}")
        return

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    log(f"copied: {src} -> {dst}")


def export_customizations(source_root: Path, repo_root: Path, dry_run: bool) -> None:
    discovered = find_required_files(source_root)

    config_candidates = discovered.get("config", [])
    if not config_candidates:
        raise FileNotFoundError("No Wazuh manager custom config found in the source clone.")

    chosen_config = config_candidates[0]
    target_config = repo_root / "wazuh" / "config" / "wazuh_manager.conf"
    copy_file(chosen_config, target_config, dry_run)

    integration_files = discovered.get("integrations", [])
    for file_path in integration_files:
        if "custom-medflow" in file_path.name.lower() or "medflow" in file_path.name.lower():
            target = repo_root / "wazuh" / "integrations" / file_path.name
            copy_file(file_path, target, dry_run)

    active_files = discovered.get("active_response", [])
    for file_path in active_files:
        if file_path.suffix.lower() in {".sh", ".py"}:
            target = repo_root / "wazuh" / "active-response" / file_path.name
            copy_file(file_path, target, dry_run)

    rule_files = collect_source_matches(source_root, ["**/*.rules", "**/*suricata*", "**/*medflow*rules*"])
    for file_path in rule_files:
        if file_path.is_file() and file_path.suffix.lower() in {".rules", ".yaml", ".yml", ".json"}:
            target = repo_root / "wazuh" / "config" / file_path.name
            copy_file(file_path, target, dry_run)

    # Suricata project directory is kept locally and is intentionally not copied from the Wazuh repo.
    # We only ensure the project directory exists and is ready for Docker bind mounts.
    if dry_run:
        log("[dry-run] would ensure Suricata directories exist under ./suricata")
    else:
        for rel in ("suricata/logs", "suricata/rules", "suricata/pcap"):
            (repo_root / rel).mkdir(parents=True, exist_ok=True)
        log("ensured Suricata local directories exist")


def patch_compose_file(repo_root: Path, dry_run: bool) -> None:
    compose_path = repo_root / "docker-compose.yml"
    if not compose_path.exists():
        raise FileNotFoundError(f"docker-compose.yml not found at {compose_path}")

    text = compose_path.read_text(encoding="utf-8")

    required_snippets = {
        "suricata_mount": "      - ./suricata/logs:/var/log/suricata:ro",
        "wazuh_config_mount": "      - ./wazuh/config/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf",
        "wazuh_integration_mount": "      - ./wazuh/integrations:/var/ossec/integrations",
        "wazuh_active_response_mount": "      - ./wazuh/active-response:/var/ossec/active-response/bin",
    }

    if dry_run:
        log("[dry-run] would update docker-compose.yml with MedFlow-owned Wazuh custom mounts.")
        for key, value in required_snippets.items():
            if value in text:
                log(f"[dry-run] already present in compose: {value}")
            else:
                log(f"[dry-run] would add to compose: {value}")
        return

    for key, value in required_snippets.items():
        if value not in text:
            marker = "      - ./suricata/logs:/var/log/suricata:ro"
            if marker in text and key == "wazuh_config_mount":
                text = text.replace(marker, value + "\n" + marker)
            elif marker in text and key in {"wazuh_integration_mount", "wazuh_active_response_mount"}:
                text = text.replace(marker, marker + "\n" + value)
            else:
                # This fallback appends the mount near the Wazuh manager volumes block.
                anchor = "      - wazuh_wodles:/var/ossec/wodles\n"
                if anchor in text:
                    insertion = value + "\n"
                    text = text.replace(anchor, anchor + "      - " + value.split("- ", 1)[1] + "\n")
                    # Note: This branch is defensive and not used by the normal path.

    compose_path.write_text(text, encoding="utf-8")
    log(f"updated: {compose_path}")


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    source_root = args.source.resolve()
    backup_path = args.backup_path.resolve()

    try:
        validate_source(source_root)
        ensure_target_layout(repo_root, args.dry_run)
        make_backup_patch(source_root, backup_path, args.dry_run)
        export_customizations(source_root, repo_root, args.dry_run)
        patch_compose_file(repo_root, args.dry_run)

        log("")
        log("Wazuh custom extraction plan complete.")
        log("Summary:")
        log("- Upstream wazuh-docker remains external and is not copied wholesale.")
        log("- Only MedFlow-specific config and scripts are exported into ./wazuh and ./suricata.")
        log("- Docker Compose will mount local MedFlow-owned files, not the external upstream repo.")
        log("- No .env files or certificate/key material are copied by the export logic.")
        return 0
    except Exception as exc:  # pragma: no cover - this is a CLI safety guard.
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
