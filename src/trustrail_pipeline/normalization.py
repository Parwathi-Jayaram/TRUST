"""Source-aware event normalization and conservative relationship extraction."""

from __future__ import annotations

import hashlib
import ipaddress
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


AUTH_EVENT_IDS = {4624, 4625, 4647, 4648, 4768, 4769, 4770, 4774, 4776}
PROCESS_START_EVENT_IDS = {4688}


@dataclass(frozen=True)
class SourceInfo:
    dataset_id: str
    source_system: str
    version: str = "unknown"
    source_url: str | None = None
    license: str | None = None
    evidence_status: str = "observed"


@dataclass(frozen=True)
class NormalizationResult:
    event: dict[str, Any]
    entities: tuple[dict[str, Any], ...]
    relationship: dict[str, Any] | None
    evidence: dict[str, Any]
    warnings: tuple[str, ...] = ()


def _lookup(record: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).strip().lower(): value for key, value in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip() != "":
            return value
    return None


def stable_id(namespace: str, *parts: Any) -> str:
    digest = hashlib.sha256(
        "\0".join([namespace, *(str(part) for part in parts)]).encode("utf-8")
    ).hexdigest()
    return f"{namespace}:{digest}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> tuple[str | None, str | None, str]:
    """Return UTC time, original representation, and explicit source-time semantics."""
    if value is None or str(value).strip() == "":
        return None, None, "missing"

    original = str(value).strip()
    try:
        numeric = float(original)
    except ValueError:
        numeric = math.nan

    if math.isfinite(numeric):
        if numeric >= 946684800 and numeric <= 4102444800:
            normalized = datetime.fromtimestamp(numeric, timezone.utc)
            return normalized.isoformat(timespec="seconds").replace("+00:00", "Z"), original, "unix_seconds"
        return None, original, "source_numeric_time_unresolved"

    parsed_text = original[:-1] + "+00:00" if original.endswith(("Z", "z")) else original
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError:
        return None, original, "unparseable"
    if parsed.tzinfo is None:
        return None, original, "timezone_missing"
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return normalized, original, "iso8601"


def _entity(
    entity_type: str,
    value: Any,
    source: SourceInfo,
    *,
    identity_parts: tuple[Any, ...] | None = None,
    extra_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    name = str(value).strip()
    parts = identity_parts or (name.casefold(),)
    entity_id = stable_id(f"entity:{source.dataset_id}:{entity_type.lower()}", *parts)
    entity = {
        "id": entity_id,
        "name": name,
        "entity_type": entity_type,
        "source": source.dataset_id,
        "source_system": source.source_system,
        "environment": source.evidence_status,
        "status": "synthetic" if source.evidence_status == "synthetic" else "observed",
    }
    if extra_properties:
        entity.update(extra_properties)
    return entity


def _endpoint(value: Any, source: SourceInfo) -> dict[str, Any] | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        normalized_ip = str(ipaddress.ip_address(text))
    except ValueError:
        return _entity("Host", text, source)
    return _entity("IPAddress", normalized_ip, source)


def _relationship(
    source_entity: dict[str, Any] | None,
    target_entity: dict[str, Any] | None,
    relationship_type: str | None,
    event: dict[str, Any],
) -> dict[str, Any] | None:
    if not source_entity or not target_entity or not relationship_type:
        return None
    relationship_id = stable_id(
        "relationship",
        event["event_id"],
        source_entity["id"],
        relationship_type,
        target_entity["id"],
    )
    return {
        "id": relationship_id,
        "source_entity_id": source_entity["id"],
        "target_entity_id": target_entity["id"],
        "relationship": relationship_type,
        "event_time": event["event_time"],
        "source_system": event["source_system"],
        "evidence_id": event["evidence_id"],
        "evidence_status": event["evidence_status"],
        "properties": {"event_id": event["event_id"]},
    }


def normalize_record(
    record: dict[str, Any],
    *,
    source: SourceInfo,
    source_record_id: str,
    ingested_at: str | None = None,
) -> NormalizationResult:
    if not isinstance(record, dict):
        raise ValueError("record must be a JSON object or CSV row")

    ingested_at = ingested_at or _utc_now()
    raw_time = _lookup(record, "Time", "timestamp", "event_time", "eventTime")
    timestamp_utc, timestamp_original, timestamp_semantics = normalize_timestamp(raw_time)
    event_time = timestamp_utc or timestamp_original
    if event_time is None:
        raise ValueError("record is missing a usable source timestamp")
    event_id = stable_id("event", source.dataset_id, source_record_id)
    evidence_id = stable_id("evidence", source.dataset_id, source_record_id)
    event_id_value = _lookup(record, "EventID", "event_id", "eventId")
    try:
        event_code = int(event_id_value) if event_id_value is not None else None
    except (TypeError, ValueError):
        event_code = None

    src_device = _lookup(record, "SrcDevice", "src_device", "source_host", "source_ip")
    dst_device = _lookup(record, "DstDevice", "dst_device", "target_host", "destination_ip")
    is_network_flow = src_device is not None and dst_device is not None
    user_name = _lookup(record, "UserName", "username", "user", "account")
    host_name = _lookup(record, "LogHost", "Computer", "host", "hostname", "Destination")
    process_name = _lookup(record, "ProcessName", "process_name", "process")
    process_id = _lookup(record, "ProcessID", "process_id")
    domain_name = _lookup(record, "DomainName", "domain")
    severity = _lookup(record, "severity", "Severity")
    warnings: list[str] = []
    event_attributes: dict[str, Any] = {}

    entities: list[dict[str, Any]] = []
    relationship_type: str | None = None
    source_entity: dict[str, Any] | None = None
    target_entity: dict[str, Any] | None = None
    if is_network_flow:
        event_type = "network_flow"
        source_entity = _endpoint(src_device, source)
        target_entity = _endpoint(dst_device, source)
        relationship_type = "COMMUNICATES_WITH"
        for item in (source_entity, target_entity):
            if item:
                entities.append(item)
    elif event_code in AUTH_EVENT_IDS:
        event_type = "authentication"
        user_identity = (
            (str(domain_name).casefold(), str(user_name).casefold())
            if domain_name
            else (str(user_name).casefold(),)
        )
        source_entity = (
            _entity(
                "User",
                f"{domain_name}\\{user_name}" if domain_name else user_name,
                source,
                identity_parts=user_identity,
                extra_properties={"username": str(user_name), "domain": str(domain_name)} if domain_name else {"username": str(user_name)},
            )
            if user_name
            else None
        )
        target_entity = _endpoint(host_name, source)
        status = _lookup(record, "Status", "status")
        status_succeeded = status is None or str(status).strip().lower() in {"0", "0x0", "success", "succeeded"}
        if (event_code == 4624 and status_succeeded) or (
            event_code in {4768, 4769, 4770, 4776}
            and status is not None
            and status_succeeded
        ):
            relationship_type = "AUTHENTICATED_TO"
        for item in (source_entity, target_entity):
            if item:
                entities.append(item)
        if not source_entity or not target_entity:
            relationship_type = None
            warnings.append("authentication relationship omitted: user or target host is missing")
    elif event_code in PROCESS_START_EVENT_IDS:
        event_type = "process"
        target_entity = _endpoint(host_name, source)
        process_entity = (
            _entity(
                "Process",
                process_name,
                source,
                identity_parts=(
                    target_entity["id"] if target_entity else "",
                    str(process_id) if process_id is not None else "unknown-pid",
                    source_record_id,
                ),
                extra_properties={"process_id": str(process_id)} if process_id is not None else None,
            )
            if process_name
            else None
        )
        source_entity = target_entity
        target_entity = process_entity
        relationship_type = "RUNS"
        for item in (source_entity, target_entity):
            if item:
                entities.append(item)
        if not source_entity or not target_entity:
            relationship_type = None
            warnings.append("process relationship omitted: host or process name is missing")
    else:
        event_type = "host_event" if event_code is not None or host_name else ""
        if not event_type:
            raise ValueError("record does not match a supported network-flow or host-event shape")
        host_entity = _endpoint(host_name, source)
        if host_entity:
            entities.append(host_entity)
            target_entity = host_entity

    for key in (
        "Protocol",
        "SrcPort",
        "DstPort",
        "Duration",
        "SrcPackets",
        "DstPackets",
        "SrcBytes",
        "DstBytes",
        "Status",
        "LogonType",
        "LogonTypeDescription",
        "AuthenticationPackage",
        "ServiceName",
        "ProcessID",
        "ParentProcessName",
        "ParentProcessID",
        "EventID",
    ):
        value = _lookup(record, key)
        if isinstance(value, str):
            value = value.strip()
        if value is not None:
            event_attributes[key] = value

    if severity is not None:
        event_attributes["severity"] = str(severity).strip()

    event = {
        "event_id": event_id,
        "event_type": event_type,
        "event_time": event_time,
        "event_time_utc": timestamp_utc,
        "event_time_original": timestamp_original,
        "timestamp_semantics": timestamp_semantics,
        "ingestion_time": ingested_at,
        "severity": str(severity).strip() if severity is not None else None,
        "source_system": source.source_system,
        "source_record_id": source_record_id,
        "source_entity_id": source_entity["id"] if source_entity else None,
        "target_entity_id": target_entity["id"] if target_entity else None,
        "relationship": relationship_type,
        "evidence_id": evidence_id,
        "evidence_status": source.evidence_status,
        "attributes": event_attributes,
    }
    relationship = _relationship(source_entity, target_entity, relationship_type, event)
    evidence = {
        "evidence_id": evidence_id,
        "source_record_id": source_record_id,
        "source_system": source.source_system,
        "source_dataset_id": source.dataset_id,
        "source_version": source.version,
        "source_url": source.source_url,
        "license": source.license,
        "observed_at": timestamp_utc or timestamp_original,
        "ingested_at": ingested_at,
        "evidence_type": event_type,
        "evidence_status": source.evidence_status,
    }
    return NormalizationResult(
        event=event,
        entities=tuple(entities),
        relationship=relationship,
        evidence=evidence,
        warnings=tuple(warnings),
    )
