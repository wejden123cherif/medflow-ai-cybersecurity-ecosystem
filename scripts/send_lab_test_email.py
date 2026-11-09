"""Validate email configuration or explicitly send one harmless MedFlow lab email."""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from email.utils import parseaddr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import DATA_DIR, load_settings

TEST_ID_RE = re.compile(r"^MEDFLOW-LAB-TEST-[A-Fa-f0-9]{32}$")


def _valid_address(value: str) -> bool:
    if not value or any(character in value for character in "\r\n,;"):
        return False
    return parseaddr(value)[1] == value and "@" in value


def _configuration_issues(settings, recipient: str | None) -> list[str]:
    issues: list[str] = []
    if str(settings.email_mode or "").strip().casefold() != "gmail":
        issues.append("EMAIL_MODE must be gmail for real delivery")
    if not str(settings.smtp_host or "").strip():
        issues.append("SMTP_HOST is missing")
    if settings.smtp_port not in {465, 587}:
        issues.append("SMTP_PORT must be 465 (implicit TLS) or 587 (STARTTLS)")
    if not str(settings.smtp_user or "").strip():
        issues.append("SMTP_USER is missing")
    if not str(settings.smtp_password or "").strip():
        issues.append("SMTP_PASSWORD is missing")
    if not _valid_address(str(settings.smtp_from or "").strip()):
        issues.append("SMTP_FROM must be one valid sender address")
    allowlist = {str(item).strip().casefold() for item in settings.soc_email_allowlist if str(item).strip()}
    if not allowlist:
        issues.append("SOC_EMAIL_ALLOWLIST is empty")
    if recipient is not None:
        clean_recipient = recipient.strip()
        if not _valid_address(clean_recipient):
            issues.append("recipient must be exactly one valid email address")
        elif clean_recipient.casefold() not in allowlist:
            issues.append("recipient is not in SOC_EMAIL_ALLOWLIST")
    return issues


def _notification_status(incident_id: str, recipient: str) -> str:
    database = DATA_DIR / "incidents.db"
    if not database.is_file():
        return "not_recorded"
    uri = database.resolve().as_uri() + "?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=2) as connection:
            row = connection.execute(
                "SELECT status FROM email_notifications WHERE incident_id=? AND recipient=?",
                (incident_id, recipient.casefold()),
            ).fetchone()
    except sqlite3.OperationalError:
        return "not_recorded"
    return str(row[0]) if row else "not_recorded"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-test", action="store_true", required=True, help="explicitly mark this operation as a lab test")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true", help="check local SMTP settings and allowlist; send nothing")
    mode.add_argument("--send", action="store_true", help="send one fixed harmless test email through MedFlow EmailConnector")
    mode.add_argument("--status", action="store_true", help="query local duplicate-suppression delivery record without sending")
    parser.add_argument("--recipient", help="one exact recipient address; must be allowlisted")
    parser.add_argument("--incident-id", help="unique MEDFLOW-LAB-TEST-<32 hex chars> identifier")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = load_settings()

    if args.validate_only:
        issues = _configuration_issues(settings, args.recipient)
        print("Email configuration: " + ("READY (local checks only; no SMTP connection or email sent)" if not issues else "NOT READY"))
        for issue in issues:
            print(f"- {issue}")
        print(f"Allowlisted recipient count: {len(settings.soc_email_allowlist)}")
        return 0 if not issues else 2

    if not args.recipient or not args.incident_id:
        print("--send and --status require both --recipient and --incident-id.")
        return 2
    incident_id = args.incident_id.strip()
    if not TEST_ID_RE.fullmatch(incident_id):
        print("incident ID must be MEDFLOW-LAB-TEST- followed by a fresh 32-character hexadecimal UUID.")
        return 2

    issues = _configuration_issues(settings, args.recipient)
    if issues:
        print("Email configuration: NOT READY")
        for issue in issues:
            print(f"- {issue}")
        return 2

    if args.status:
        status = _notification_status(incident_id, args.recipient)
        print(f"Notification record status: {status}")
        return 0 if status in {"sent", "sending", "not_recorded"} else 1

    from integrations.email.connector import EmailConnector

    result = EmailConnector().execute_action(
        {"action_type": "NOTIFY_SOC", "target": args.recipient.strip()},
        {"incident_id": incident_id, "notification_kind": "lab_test"},
    )
    if result.get("already_sent"):
        print("Duplicate suppressed; no email was sent for this incident ID.")
        print(f"Notification record status: {_notification_status(incident_id, args.recipient)}")
        return 0
    print(f"Email connector result: {result.get('status', 'unknown')} ({result.get('error') or 'no_error_code'})")
    print(f"Notification record status: {_notification_status(incident_id, args.recipient)}")
    if result.get("status") == "success":
        print("SMTP accepted the test notification; independently confirm receipt in the recipient mailbox.")
        return 0
    print("No delivery success was recorded. Check SMTP configuration and retry using a fresh test incident ID.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
