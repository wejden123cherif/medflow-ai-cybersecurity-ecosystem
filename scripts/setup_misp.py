from __future__ import annotations

import sys
from typing import Any


TEST_IOC = "185.220.101.45"


def parse_verify_ssl(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def result_count(result: Any) -> int:
    if isinstance(result, list):
        return len(result)

    if isinstance(result, dict):
        response = result.get("response")
        if isinstance(response, list):
            return len(response)
        if isinstance(response, dict):
            return len(response)

    return 0


def print_feed_hint() -> None:
    print()
    print("No MISP feed data was returned.")
    print("In the MISP UI, go to Sync Actions -> Feeds, enable CIRCL OSINT Feed")
    print("and Botvrij.eu Data, then click 'Fetch and store all feed data'.")


def main() -> int:
    try:
        from dotenv import load_dotenv
        from pymisp import PyMISP
    except ImportError as exc:
        print("Missing required Python dependency.")
        print(f"Error: {exc}")
        print("Install project dependencies with:")
        print("python -m pip install -r requirements.txt")
        return 1

    load_dotenv()

    import os

    misp_url = os.getenv("MISP_URL", "https://localhost").strip()
    misp_api_key = os.getenv("MISP_API_KEY", "").strip()
    verify_ssl = parse_verify_ssl(os.getenv("MISP_VERIFY_SSL", "false"))

    if not misp_api_key:
        print("MISP_API_KEY is missing.")
        print("Create an API key in MISP, then add it to your .env file:")
        print("MISP_API_KEY=your_key_here")
        return 1

    print(f"Connecting to MISP at {misp_url}")
    print(f"SSL verification: {'enabled' if verify_ssl else 'disabled'}")

    try:
        misp = PyMISP(misp_url, misp_api_key, ssl=verify_ssl)
        misp_version = misp.misp_instance_version
        version_text = misp_version.get("version") if isinstance(misp_version, dict) else misp_version
        print(f"Connection succeeded. MISP version: {version_text}")
    except Exception as exc:
        print("Could not connect to MISP.")
        print(f"Error: {exc}")
        print()
        print("Troubleshooting:")
        print("- Confirm MISP is running in Docker.")
        print("- For MedFlow on the Windows host, use MISP_URL=https://localhost.")
        print("- For MedFlow inside the same Docker network, use MISP_URL=https://misp-core.")
        print("- For local self-signed certificates, use MISP_VERIFY_SSL=false.")
        print("- Confirm MISP_API_KEY is valid.")
        return 1

    try:
        events = misp.search(controller="events", limit=5)
        attributes = misp.search(controller="attributes", limit=5)

        event_count = result_count(events)
        attribute_count = result_count(attributes)

        print(f"Events returned: {event_count}")
        print(f"Attributes returned: {attribute_count}")

        if event_count == 0 or attribute_count == 0:
            print_feed_hint()
    except Exception as exc:
        print("Connected to MISP, but search validation failed.")
        print(f"Error: {exc}")
        print("Confirm your API key has permission to search events and attributes.")
        return 1

    try:
        ioc_result = misp.search(controller="attributes", value=TEST_IOC, limit=5)
        ioc_count = result_count(ioc_result)
        if ioc_count:
            print(f"IOC lookup for {TEST_IOC}: found {ioc_count} matching attribute(s).")
        else:
            print(f"IOC lookup for {TEST_IOC}: no matching attributes returned.")
    except Exception as exc:
        print(f"Optional IOC lookup for {TEST_IOC} failed.")
        print(f"Error: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
