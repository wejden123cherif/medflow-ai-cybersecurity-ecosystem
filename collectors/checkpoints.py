from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_PENDING_LIMIT = 10000


class PendingQueueFull(ValueError):
    """The durable pending queue is full; do not advance a source cursor."""


class CheckpointIOError(OSError):
    """Sanitized checkpoint filesystem failure with the failing operation."""

    def __init__(self, operation: str, cause: OSError, cleanup_errors: list[OSError] | None = None):
        self.operation = operation
        self.error_number = getattr(cause, "errno", None)
        self.windows_error_number = getattr(cause, "winerror", None)
        self.cleanup_errors = [
            (getattr(error, "errno", None), getattr(error, "winerror", None))
            for error in (cleanup_errors or [])
        ]
        details = [f"operation={operation}"]
        if self.error_number is not None:
            details.append(f"errno={self.error_number}")
        if self.windows_error_number is not None:
            details.append(f"winerror={self.windows_error_number}")
        for error_number, winerror in self.cleanup_errors:
            cleanup = "cleanup"
            if error_number is not None:
                cleanup += f"_errno={error_number}"
            if winerror is not None:
                cleanup += f"_winerror={winerror}"
            details.append(cleanup)
        message = "checkpoint persistence failed (" + ", ".join(details) + ")"
        if self.error_number is None:
            super().__init__(message)
        else:
            super().__init__(self.error_number, message)


def checkpoint_failure_details(exc: OSError) -> dict[str, Any]:
    if isinstance(exc, CheckpointIOError):
        operation = exc.operation
        error_number = exc.error_number
        winerror = exc.windows_error_number
        cleanup_errors = exc.cleanup_errors
    else:
        operation = "unknown"
        error_number = getattr(exc, "errno", None)
        winerror = getattr(exc, "winerror", None)
        cleanup_errors = []
    reason_parts = [f"operation={operation}"]
    if error_number is not None:
        reason_parts.append(f"errno={error_number}")
    if winerror is not None:
        reason_parts.append(f"winerror={winerror}")
    for cleanup_errno, cleanup_winerror in cleanup_errors:
        cleanup = "cleanup"
        if cleanup_errno is not None:
            cleanup += f"_errno={cleanup_errno}"
        if cleanup_winerror is not None:
            cleanup += f"_winerror={cleanup_winerror}"
        reason_parts.append(cleanup)
    details: dict[str, Any] = {
        "failure_code": "checkpoint_io_error",
        "failure_reason": "Checkpoint persistence failed (" + ", ".join(reason_parts) + ").",
        "checkpoint_operation": operation,
    }
    if error_number is not None:
        details["checkpoint_errno"] = error_number
    if winerror is not None:
        details["checkpoint_winerror"] = winerror
    if cleanup_errors:
        details["checkpoint_cleanup_failed"] = True
    return details


def load_checkpoint(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise CheckpointIOError("read", exc) from exc
    except json.JSONDecodeError as exc:
        raise ValueError("checkpoint_invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("checkpoint_invalid")
    pending = value.get("pending_events", [])
    seen = value.get("seen_event_ids", [])
    if not isinstance(pending, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("event_id"), str) or not item["event_id"]
        for item in pending
    ):
        raise ValueError("checkpoint_invalid")
    if not isinstance(seen, list) or any(not isinstance(item, str) for item in seen):
        raise ValueError("checkpoint_invalid")
    return value


def _cleanup_temporary(handle: Any, temporary: Path | None) -> list[OSError]:
    errors: list[OSError] = []
    if handle is not None:
        try:
            if not handle.closed:
                handle.close()
        except OSError as exc:
            errors.append(exc)
    if temporary is not None:
        try:
            temporary.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(exc)
    return errors


def write_checkpoint(path: Path, value: dict[str, Any]) -> None:
    handle = None
    temporary: Path | None = None
    operation = "create_parent_directory"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        operation = "create_temporary_file"
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=f".{path.name}.", suffix=".tmp",
            dir=path.parent, delete=False,
        )
        temporary = Path(handle.name)
        operation = "write"
        json.dump(value, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        operation = "flush"
        handle.flush()
        operation = "fsync"
        os.fsync(handle.fileno())
        operation = "close"
        handle.close()
        handle = None
        operation = "atomic_replace"
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        cleanup_errors = _cleanup_temporary(handle, temporary)
        raise CheckpointIOError(operation, exc, cleanup_errors) from exc
    except Exception as exc:
        cleanup_errors = _cleanup_temporary(handle, temporary)
        if cleanup_errors and hasattr(exc, "add_note"):
            exc.add_note("Checkpoint temporary cleanup also failed.")
        raise


def merge_seen_ids(previous: object, new_ids: list[str], limit: int = 20000) -> list[str]:
    seen = list(dict.fromkeys(str(item) for item in previous if item)) if isinstance(previous, list) else []
    known = set(seen)
    for item in new_ids:
        if item not in known:
            seen.append(item)
            known.add(item)
    return seen[-limit:]


def append_pending_events(
    checkpoint: dict[str, Any], events: list[dict[str, Any]], limit: int = DEFAULT_PENDING_LIMIT
) -> list[dict[str, Any]]:
    previous = checkpoint.get("pending_events", [])
    if not isinstance(previous, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("event_id"), str) or not item["event_id"]
        for item in previous
    ):
        raise ValueError("checkpoint_invalid")
    pending = list(previous)
    by_id = {str(item.get("event_id")): item for item in pending if item.get("event_id")}
    for event in events:
        event_id = str(event.get("event_id") or "")
        if event_id and event_id not in by_id:
            by_id[event_id] = event
    if len(by_id) > limit:
        raise PendingQueueFull("pending_queue_full")
    checkpoint["pending_events"] = list(by_id.values())
    return checkpoint["pending_events"]


def acknowledge_pending_events(
    checkpoint: dict[str, Any], event_ids: list[str], seen_limit: int = 20000
) -> int:
    requested = {str(item) for item in event_ids if item}
    previous = checkpoint.get("pending_events", [])
    if not isinstance(previous, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("event_id"), str) or not item["event_id"]
        for item in previous
    ):
        raise ValueError("checkpoint_invalid")
    pending = list(previous)
    acknowledged = [item for item in pending if str(item.get("event_id") or "") in requested]
    acknowledged_ids = {str(item.get("event_id")) for item in acknowledged if item.get("event_id")}
    checkpoint["pending_events"] = [
        item for item in pending if str(item.get("event_id") or "") not in acknowledged_ids
    ]
    checkpoint["seen_event_ids"] = merge_seen_ids(
        checkpoint.get("seen_event_ids", []),
        [str(item["event_id"]) for item in acknowledged if item.get("event_id")],
        limit=seen_limit,
    )
    return len(acknowledged)
