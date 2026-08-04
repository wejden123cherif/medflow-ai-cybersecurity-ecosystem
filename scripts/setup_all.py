from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run_step(name: str, command: list[str]) -> None:
    print(f"\n=== {name} ===")
    subprocess.run(command, cwd=ROOT_DIR, check=True)


def main() -> None:
    steps = [
        ("Install Python packages", [PYTHON, "-m", "pip", "install", "-r", "requirements.txt"]),
        ("Bootstrap external service directories", [PYTHON, "scripts/bootstrap_external_services.py"]),
        ("Download or update MITRE CTI", [PYTHON, "scripts/download_mitre.py"]),
        ("Build attack_db", [PYTHON, "scripts/build_attack_db.py"]),
        ("Build redteam_db", [PYTHON, "scripts/build_redteam_db.py"]),
        ("Build actor_db", [PYTHON, "scripts/build_actor_db.py"]),
        ("Build detection_db", [PYTHON, "scripts/build_detection_db.py"]),
        ("Show final status", [PYTHON, "app.py", "status"]),
    ]

    for name, command in steps:
        run_step(name, command)

    print("\nSetup complete. You can now use:")
    print('  python app.py search --db attack "ransomware encryption hospital"')
    print('  python app.py ask --agent redteam "Give me a full kill chain for a Ryuk attack on a hospital."')


if __name__ == "__main__":
    main()
