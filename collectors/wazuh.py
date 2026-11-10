from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import requests

from collectors.base import BaseCollector
from collectors.checkpoints import (
    PendingQueueFull,
    acknowledge_pending_events,
    append_pending_events,
    load_checkpoint,
    write_checkpoint,
)
from config import ROOT_DIR
from models.alert import normalize_alert, stable_event_id

DEFAULT_WAZUH_LIMIT = 100
DEFAULT_WAZUH_MAX_PAGES = 10
DEFAULT_WAZUH_TIMEOUT = 10
DEFAULT_WAZUH_RECENT_HOURS = 24
DEFAULT_WAZUH_LOOKBACK_DAYS = 7


class CollectorError(RuntimeError):
    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


class WazuhCollector(BaseCollector):
    name = "wazuh"

    def __init__(self, *, checkpoint_path: str | Path | None = None) -> None:
        self.url = os.getenv("WAZUH_URL", "").strip().rstrip("/")
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "").strip().rstrip("/")
        self.user = os.getenv("WAZUH_USER", "").strip()
        self.password = os.getenv("WAZUH_PASSWORD", "")
        # Prefer the dedicated MedFlow reader credentials. Keep the generic
        # Wazuh variables as a compatibility fallback for existing setups.
        self.indexer_user = (
            os.getenv("MEDFLOW_WAZUH_INDEXER_USER", "").strip()
            or os.getenv("WAZUH_INDEXER_USER", "").strip()
        )
        self.indexer_password = (
            os.getenv("MEDFLOW_WAZUH_INDEXER_PASSWORD", "")
            or os.getenv("WAZUH_INDEXER_PASSWORD", "")
        )
        ca_bundle = os.getenv("WAZUH_CA_BUNDLE", "").strip()
        tls_value = os.getenv("WAZUH_VERIFY_TLS", "true").strip().lower()
        self.verify: bool | str = ca_bundle or tls_value not in {"0", "false", "no", "off"}
        self.timeout = _bounded_int("WAZUH_API_TIMEOUT", DEFAULT_WAZUH_TIMEOUT, 1, 60)
        self.page_size = _bounded_int("WAZUH_PAGE_SIZE", DEFAULT_WAZUH_LIMIT, 1, 500)
        self.max_pages = _bounded_int("WAZUH_MAX_PAGES", DEFAULT_WAZUH_MAX_PAGES, 1, 100)
        self.retries = _bounded_int("WAZUH_MAX_RETRIES", 2, 0, 5)
        self.lookback_days = _bounded_int("WAZUH_LOOKBACK_DAYS", DEFAULT_WAZUH_LOOKBACK_DAYS, 1, 365)
        self.alerts_path = os.getenv("WAZUH_ALERTS_PATH", "/alerts").strip() or "/alerts"
        self.checkpoint_path = Path(checkpoint_path or os.getenv(
            "WAZUH_CHECKPOINT_PATH", str(ROOT_DIR / "data" / "collector-checkpoints" / "wazuh.json")
        )).expanduser()

    def collect(self) -> tuple[list[dict] | None, dict]:
        manager_alerts, manager_meta = self.collect_manager()
        if manager_alerts:
            return manager_alerts, manager_meta
        indexer_alerts, indexer_meta = self.collect_indexer()
        if indexer_alerts:
            if manager_meta.get("failure_code"):
                indexer_meta["manager_failure_code"] = manager_meta["failure_code"]
            return indexer_alerts, indexer_meta
        if manager_alerts is not None and not manager_meta.get("failure_code"):
            return [], {**manager_meta, "indexer_failure_code": indexer_meta.get("failure_code")}
        return None, {
            "source_system": "wazuh", "data_source": "wazuh_live",
            "failure_code": manager_meta.get("failure_code") or indexer_meta.get("failure_code") or "no_alerts",
            "manager_failure_code": manager_meta.get("failure_code"),
            "indexer_failure_code": indexer_meta.get("failure_code"),
        }

    def collect_manager(self) -> tuple[list[dict] | None, dict]:
        metadata: dict[str, Any] = {"source_system": "wazuh", "data_source": "wazuh_live", "collector": "manager"}
        if not self.url:
            metadata["failure_code"] = "manager_url_missing"
            return None, metadata
        if not self.user or not self.password:
            metadata["failure_code"] = "manager_credentials_missing"
            return None, metadata
        try:
            token = self.authenticate()
            raw_alerts: list[dict] = []
            page_limit_reached = False
            for page in range(self.max_pages):
                response = self._request(
                    "get", f"{self.url}{self.alerts_path}",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": self.page_size, "offset": page * self.page_size, "sort": "-timestamp"},
                    verify=self.verify, timeout=self.timeout,
                )
                payload = response.json()
                data = payload.get("data", {}) if isinstance(payload, dict) else {}
                batch = data.get("affected_items", []) if isinstance(data, dict) else None
                if not isinstance(batch, list):
                    raise CollectorError("invalid_manager_response")
                raw_alerts.extend(item for item in batch if isinstance(item, dict))
                if len(batch) < self.page_size:
                    break
                if page == self.max_pages - 1:
                    page_limit_reached = True
            normalized, checkpoint, newly_queued, duplicate_count, malformed_count = self._normalize_and_checkpoint(raw_alerts)
            metadata.update(
                success=True,
                pages_fetched=min(self.max_pages, (len(raw_alerts) + self.page_size - 1) // self.page_size),
                page_limit_reached=page_limit_reached,
                new_events_queued=newly_queued,
                pending_event_count=len(normalized),
                duplicate_count=duplicate_count,
                malformed_records=malformed_count,
            )
            write_checkpoint(self.checkpoint_path, checkpoint)
            return normalized, metadata
        except PendingQueueFull as exc:
            metadata["failure_code"] = str(exc)
            return None, metadata
        except CollectorError as exc:
            metadata["failure_code"] = exc.code
            if exc.status is not None:
                metadata["http_status"] = exc.status
            return None, metadata
        except ValueError as exc:
            metadata["failure_code"] = "checkpoint_invalid" if str(exc) == "checkpoint_invalid" else "invalid_manager_response"
            return None, metadata
        except (TypeError, KeyError):
            metadata["failure_code"] = "invalid_manager_response"
            return None, metadata
        except OSError:
            metadata["failure_code"] = "checkpoint_io_error"
            return None, metadata

    def authenticate(self) -> str:
        response = self._request(
            "post", f"{self.url}/security/user/authenticate",
            auth=(self.user, self.password), verify=self.verify, timeout=self.timeout,
        )
        try:
            token = response.json().get("data", {}).get("token")
        except (ValueError, AttributeError):
            token = None
        if not isinstance(token, str) or not token:
            raise CollectorError("invalid_auth_response")
        return token

    def collect_indexer(self) -> tuple[list[dict] | None, dict]:
        metadata: dict[str, Any] = {"source_system": "wazuh", "data_source": "wazuh_live", "collector": "indexer"}
        if not self.indexer_url:
            metadata["failure_code"] = "indexer_url_missing"
            return None, metadata
        if not self.indexer_user or not self.indexer_password:
            metadata["failure_code"] = "indexer_credentials_missing"
            return None, metadata
        try:
            raw_alerts: list[dict] = []
            page_limit_reached = False
            for page in range(self.max_pages):
                query = {
                    "size": self.page_size,
                    "from": page * self.page_size,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {"range": {"@timestamp": {"gte": f"now-{self.lookback_days}d"}}},
                }
                response = self._request(
                    "post", f"{self.indexer_url}/wazuh-alerts-*/_search",
                    auth=(self.indexer_user, self.indexer_password), json=query,
                    verify=self.verify, timeout=self.timeout,
                )
                payload = response.json()
                hits_data = payload.get("hits", {}) if isinstance(payload, dict) else {}
                hits = hits_data.get("hits", []) if isinstance(hits_data, dict) else None
                if not isinstance(hits, list):
                    raise CollectorError("invalid_indexer_response")
                batch = []
                for hit in hits:
                    if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                        continue
                    source = dict(hit["_source"])
                    source["_id"] = hit.get("_id")
                    source["_index"] = hit.get("_index")
                    batch.append(source)
                raw_alerts.extend(batch)
                if len(hits) < self.page_size:
                    break
                if page == self.max_pages - 1:
                    page_limit_reached = True
            normalized, checkpoint, newly_queued, duplicate_count, malformed_count = self._normalize_and_checkpoint(raw_alerts)
            metadata.update(
                success=True,
                pages_fetched=min(self.max_pages, (len(raw_alerts) + self.page_size - 1) // self.page_size),
                page_limit_reached=page_limit_reached,
                new_events_queued=newly_queued,
                pending_event_count=len(normalized),
                duplicate_count=duplicate_count,
                malformed_records=malformed_count,
            )
            write_checkpoint(self.checkpoint_path, checkpoint)
            return normalized, metadata
        except PendingQueueFull as exc:
            metadata["failure_code"] = str(exc)
            return None, metadata
        except CollectorError as exc:
            metadata["failure_code"] = exc.code
            if exc.status is not None:
                metadata["http_status"] = exc.status
            return None, metadata
        except ValueError as exc:
            metadata["failure_code"] = "checkpoint_invalid" if str(exc) == "checkpoint_invalid" else "invalid_indexer_response"
            return None, metadata
        except (TypeError, KeyError):
            metadata["failure_code"] = "invalid_indexer_response"
            return None, metadata
        except OSError:
            metadata["failure_code"] = "checkpoint_io_error"
            return None, metadata

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        request = requests.post if method.lower() == "post" else requests.get
        last_code = "request_failed"
        for attempt in range(self.retries + 1):
            try:
                response = request(url, **kwargs)
            except requests.exceptions.SSLError as exc:
                raise CollectorError("tls_verification_failed") from exc
            except requests.exceptions.Timeout as exc:
                last_code = "request_timeout"
                if attempt >= self.retries:
                    raise CollectorError(last_code) from exc
                time.sleep(min(0.25 * (2 ** attempt), 2.0))
                continue
            except requests.exceptions.ConnectionError as exc:
                last_code = "connection_failed"
                if attempt >= self.retries:
                    raise CollectorError(last_code) from exc
                time.sleep(min(0.25 * (2 ** attempt), 2.0))
                continue
            except requests.exceptions.RequestException as exc:
                raise CollectorError("request_failed") from exc

            if response.status_code in (401, 403):
                raise CollectorError("authentication_failed", response.status_code)
            if response.status_code == 429 or response.status_code >= 500:
                last_code = "rate_limited" if response.status_code == 429 else "upstream_server_error"
                if attempt >= self.retries:
                    raise CollectorError(last_code, response.status_code)
                retry_after = response.headers.get("Retry-After", "")
                try:
                    delay = min(max(float(retry_after), 0.0), 2.0)
                except ValueError:
                    delay = min(0.25 * (2 ** attempt), 2.0)
                time.sleep(delay)
                continue
            if response.status_code < 200 or response.status_code >= 300:
                raise CollectorError("upstream_http_error", response.status_code)
            return response
        raise CollectorError(last_code)

    def acknowledge_event_ids(self, event_ids: list[str]) -> int:
        checkpoint = load_checkpoint(self.checkpoint_path)
        acknowledged = acknowledge_pending_events(checkpoint, event_ids)
        if acknowledged:
            write_checkpoint(self.checkpoint_path, checkpoint)
        return acknowledged

    def _normalize_and_checkpoint(self, alerts: list[dict]) -> tuple[list[dict], dict[str, Any], int, int, int]:
        checkpoint = load_checkpoint(self.checkpoint_path)
        old_ids = checkpoint.get("seen_event_ids", [])
        seen = set(str(item) for item in old_ids) if isinstance(old_ids, list) else set()
        pending = checkpoint.get("pending_events", [])
        queued = {
            str(item.get("event_id")) for item in pending
            if isinstance(item, dict) and item.get("event_id")
        } if isinstance(pending, list) else set()
        normalized: list[dict] = []
        new_ids: list[str] = []
        duplicate_count = malformed_count = 0
        for alert in alerts:
            if not isinstance(alert, dict):
                malformed_count += 1
                continue
            rule = alert.get("rule") or {}
            agent = alert.get("agent") or {}
            data = alert.get("data") or {}
            if not all(isinstance(value, dict) for value in (rule, agent, data)):
                malformed_count += 1
                continue
            mitre = rule.get("mitre") or {}
            if not isinstance(mitre, dict):
                mitre = {}
            mitre_ids = mitre.get("id") or []
            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids]
            if not isinstance(mitre_ids, list):
                mitre_ids = []
            level_raw = rule.get("level", alert.get("rule_level"))
            try:
                level = int(level_raw) if level_raw is not None else None
            except (ValueError, TypeError):
                malformed_count += 1
                continue
            timestamp = alert.get("timestamp") or alert.get("@timestamp")
            if not timestamp:
                malformed_count += 1
                continue
            identity = alert.get("_id") or alert.get("id")
            event_id = stable_event_id("wazuh", identity, alert)
            if event_id in seen or event_id in queued:
                duplicate_count += 1
                continue
            level_for_map = level if level is not None else 0
            severity = _wazuh_severity(level_for_map)
            manager = alert.get("manager") or {}
            if not isinstance(manager, dict):
                manager = {}
            predecoder = alert.get("predecoder") or {}
            if not isinstance(predecoder, dict):
                predecoder = {}
            sensor = manager.get("name") or agent.get("name")
            rule_id = rule.get("id") or alert.get("rule_id")
            raw_log = alert.get("full_log") or alert.get("raw_log")
            additional = {
                "data_source": "wazuh_live",
                "agent_name": agent.get("name"),
                "agent_id": agent.get("id"),
                "agent_ip": agent.get("ip"),
                "wazuh_rule_id": str(rule_id) if rule_id is not None else None,
                "wazuh_rule_level": level,
                "wazuh_rule_groups": rule.get("groups", alert.get("rule_groups", [])),
                "technique_hint": (mitre_ids[0] if mitre_ids else "unknown"),
                "source_log_timestamp": predecoder.get("timestamp"),
                "indexed_timestamp": timestamp,
                "target_host": predecoder.get("hostname") or agent.get("name"),
                "destination_user": data.get("dstuser") or data.get("user"),
                "source_port": data.get("srcport") or data.get("src_port"),
                "target_ip": data.get("dstip") or data.get("dst_ip"),
                "risk_score": min(100, max(0, level_for_map * 6)),
                "risk_priority": _wazuh_priority(level_for_map),
            }
            try:
                record = normalize_alert(
                    source_type="wazuh", event_id=event_id, source_event_timestamp=timestamp,
                    severity=severity, severity_level=level, rule_id=rule_id,
                    source_ip=data.get("srcip") or data.get("src_ip") or alert.get("source_ip"),
                    destination_ip=data.get("dstip") or data.get("dst_ip") or alert.get("destination_ip"),
                    destination=agent.get("name") or alert.get("destination"), source_sensor=sensor,
                    event_type=rule.get("description") or alert.get("rule_description"),
                    evidence=alert, raw_log=raw_log, attributes=additional,
                )
            except ValueError:
                malformed_count += 1
                continue
            normalized.append(record)
            new_ids.append(event_id)
            queued.add(event_id)
        checkpoint["version"] = 1
        checkpoint["source"] = "wazuh"
        all_pending = append_pending_events(checkpoint, normalized)
        if new_ids:
            new_id_set = set(new_ids)
            latest = max((item for item in all_pending if item.get("event_id") in new_id_set), key=lambda item: item["source_event_timestamp"])
            checkpoint["last_event_id"] = latest["event_id"]
            checkpoint["last_event_timestamp"] = latest["source_event_timestamp"]
        return all_pending, checkpoint, len(new_ids), duplicate_count, malformed_count


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


def _wazuh_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _wazuh_priority(level: int) -> str:
    return "high" if level >= 12 else "medium" if level >= 8 else "low"
