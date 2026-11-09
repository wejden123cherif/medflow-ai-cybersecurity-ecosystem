from __future__ import annotations

import subprocess
from typing import Any

from config import load_settings


SSH_CONNECT_FAILURE_RETURN_CODE = 255


def _build_ssh_command(command: list[str], timeout: int) -> list[str]:
    settings = load_settings()
    missing = [
        name
        for name, value in (
            ("TARGET_VM_HOST", settings.target_vm_host),
            ("TARGET_VM_SSH_USER", settings.target_vm_ssh_user),
            ("TARGET_VM_SSH_KEY_PATH", settings.target_vm_ssh_key_path),
        )
        if not value
    ]
    if missing:
        raise ValueError(f"Missing remote execution config: {', '.join(missing)}")

    return [
        "ssh",
        "-i",
        str(settings.target_vm_ssh_key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{settings.target_vm_ssh_user}@{settings.target_vm_host}",
        "--",
        *command,
    ]


def run_remote_command(command: list[str], timeout: int = 10) -> dict[str, Any]:
    if not command:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Remote command cannot be empty.",
            "returncode": -1,
            "error": "empty_command",
            "connection_failed": False,
        }

    try:
        ssh_command = _build_ssh_command(command, timeout)
    except ValueError as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "error": "ssh_config_missing",
            "connection_failed": True,
        }

    try:
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "stdout": exc.stdout or "",
            "stderr": (exc.stderr or f"SSH command timed out after {timeout} seconds."),
            "returncode": -1,
            "error": "timeout",
            "connection_failed": True,
        }
    except OSError as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "returncode": -1,
            "error": "ssh_invocation_failed",
            "connection_failed": True,
        }

    connection_failed = result.returncode == SSH_CONNECT_FAILURE_RETURN_CODE
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "error": "ssh_connection_failed" if connection_failed else ("remote_command_failed" if result.returncode != 0 else None),
        "connection_failed": connection_failed,
    }
