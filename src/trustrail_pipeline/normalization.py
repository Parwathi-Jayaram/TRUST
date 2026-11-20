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
DOMAIN_RELATIONSHIP_TYPES = {
    "AUTHENTICATED_TO",
    "COMMUNICATES_WITH",
    "RUNS",
    "DEPENDS_ON",
    "HAS_VULNERABILITY",
    "INVOLVES",
}
RELATIONSHIP_ENDPOINT_TYPES = {
    "AUTHENTICATED_TO": ({"user"}, {"host"}),
    "COMMUNICATES_WITH": ({"host", "server"}, {"ip", "server"}),
    "RUNS": ({"host"}, {"process"}),
    "DEPENDS_ON": ({"server"}, {"application"}),
    "HAS_VULNERABILITY": ({"server"}, {"vulnerability"}),
    "INVOLVES": ({"incident"}, {"host", "user"}),
}


@dataclass(frozen=True)
class SourceInfo:
    dataset_id: str
    source_system: str
    version: str = "unknown"
    source_url: str | None = None
    license: str | None = None
    evidence_status: str = "observed"
    is_synthetic: bool = False


@dataclass(frozen=True)
class NormalizationResult:
    event: dict[str, Any]
    entities: tuple[dict[str, Any], ...]
    relationship: dict[str, Any] | None
    trace_relationships: tuple[dict[str, Any], ...]
    evidence: dict[str, Any]
    warnings: tuple[str, ...] = ()


def _lookup(record: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).strip().lower(): value for key, value in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip() != "":
            return value
    return None


def _lookup_exact(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return None


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    raise ValueError(f"expected a boolean value, got {value!r}")


def _entity_type(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized in {"ip", "ipaddress", "ip_address"}:
        return "ip"
    return normalized


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
    entity_id: Any = None,
    is_synthetic: bool | None = None,
    identity_parts: tuple[Any, ...] | None = None,
    extra_properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    name = value
    parts = identity_parts or (str(name).strip().casefold(),)
    stable_entity_id = (
        str(entity_id)
        if entity_id is not None
        else stable_id(f"entity:{source.dataset_id}:{entity_type.lower()}", *parts)
    )
    entity = {
        "id": stable_entity_id,
        "type": _entity_type(entity_type),
        "synthetic": source.is_synthetic if is_synthetic is None else is_synthetic,
    }
    if name is not None:
        entity["name"] = name
    if extra_properties:
        for key, property_value in extra_properties.items():
            if property_value is not None:
                entity[key] = property_value
    return entity


def _endpoint(
    value: Any,
    source: SourceInfo,
    *,
    entity_id: Any = None,
    is_synthetic: bool | None = None,
    entity_type: str | None = None,
    criticality: Any = None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    text = value.strip() if isinstance(value, str) else str(value)
    if not text.strip():
        return None
    if entity_type is None:
        try:
            normalized_ip = str(ipaddress.ip_address(text))
        except ValueError:
            entity_type = "host"
        else:
            return _entity(
                "ip",
                normalized_ip,
                source,
                entity_id=entity_id,
                is_synthetic=is_synthetic,
                extra_properties={"criticality": criticality},
            )
    return _entity(
        entity_type,
        text,
        source,
        entity_id=entity_id,
        is_synthetic=is_synthetic,
        extra_properties={"criticality": criticality},
    )


def _relationship(
    source_entity: dict[str, Any] | None,
    target_entity: dict[str, Any] | None,
    relationship_type: str | None,
    event: dict[str, Any],
    *,
    relationship_id: Any = None,
) -> dict[str, Any] | None:
    if not source_entity or not target_entity or not relationship_type:
        return None
    stable_relationship_id = (
        str(relationship_id)
        if relationship_id is not None
        else stable_id(
            "relationship",
            event["event_id"],
            source_entity["id"],
            relationship_type,
            target_entity["id"],
        )
    )
    return {
        "relationship_id": stable_relationship_id,
        "source_id": source_entity["id"],
        "target_id": target_entity["id"],
        "relationship_type": relationship_type,
        "evidence_status": event["evidence_status"],
        "event_id": event["event_id"],
        "is_synthetic": event["is_synthetic"],
    }


def _valid_relationship_endpoints(
    source_entity: dict[str, Any],
    target_entity: dict[str, Any],
    relationship_type: str,
) -> bool:
    allowed_source_types, allowed_target_types = RELATIONSHIP_ENDPOINT_TYPES[relationship_type]
    return (
        source_entity["type"] in allowed_source_types
        and target_entity["type"] in allowed_target_types
    )


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
    raw_time = _lookup(record, "event_time", "Time", "timestamp", "eventTime")
    timestamp_utc, timestamp_original, timestamp_semantics = normalize_timestamp(raw_time)
    event_id = str(
        _lookup_exact(record, "event_id", "eventId")
        or stable_id("event", source.dataset_id, source_record_id)
    )
    evidence_id = str(
        _lookup_exact(record, "evidence_id")
        or stable_id("evidence", source.dataset_id, source_record_id)
    )
    evidence_status = _lookup(record, "evidence_status") or source.evidence_status
    if evidence_status not in {"observed", "derived", "unconfirmed"}:
        raise ValueError("evidence_status must be observed, derived, or unconfirmed")
    is_synthetic = _as_bool(
        _lookup(record, "is_synthetic", "synthetic"),
        source.is_synthetic,
    )
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
    if timestamp_utc is None:
        warnings.append(f"event timestamp requires validation: {timestamp_semantics}")

    entities: list[dict[str, Any]] = []
    relationship_type: str | None = None
    source_entity: dict[str, Any] | None = None
    target_entity: dict[str, Any] | None = None
    provided_relationship_type = _lookup(record, "relationship_type")
    explicit_relationship_id = _lookup(record, "relationship_id")
    if provided_relationship_type is not None:
        if provided_relationship_type not in DOMAIN_RELATIONSHIP_TYPES:
            raise ValueError(f"unsupported relationship type: {provided_relationship_type}")
        source_id = _lookup(record, "source_id")
        target_id = _lookup(record, "target_id")
        source_type = _lookup(record, "source_type", "source_entity_type")
        target_type = _lookup(record, "target_type", "target_entity_type")
        if not source_id or not target_id:
            raise ValueError("explicit relationship is missing source_id or target_id")
        if not source_type or not target_type:
            raise ValueError("explicit relationship is missing source_type or target_type")
        source_entity = _entity(
            str(source_type),
            _lookup(record, "source_name"),
            source,
            entity_id=source_id,
            is_synthetic=is_synthetic,
            extra_properties={"criticality": _lookup(record, "source_criticality")},
        )
        target_entity = _entity(
            str(target_type),
            _lookup(record, "target_name"),
            source,
            entity_id=target_id,
            is_synthetic=is_synthetic,
            extra_properties={"criticality": _lookup(record, "target_criticality")},
        )
        if not _valid_relationship_endpoints(source_entity, target_entity, str(provided_relationship_type)):
            raise ValueError(
                f"{provided_relationship_type} has unsupported endpoint types "
                f"{source_entity['type']} -> {target_entity['type']}"
            )
        entities.extend((source_entity, target_entity))
        relationship_type = str(provided_relationship_type)
        event_type = str(_lookup(record, "event_type") or "security_event")
    elif is_network_flow:
        event_type = "network_flow"
        source_entity = _endpoint(
            src_device,
            source,
            entity_id=_lookup(record, "source_entity_id", "source_id", "src_id"),
            is_synthetic=is_synthetic,
            entity_type=_lookup(record, "source_type", "source_entity_type"),
            criticality=_lookup(record, "source_criticality"),
        )
        target_entity = _endpoint(
            dst_device,
            source,
            entity_id=_lookup(record, "target_entity_id", "target_id", "dst_id"),
            is_synthetic=is_synthetic,
            entity_type=_lookup(record, "target_type", "target_entity_type"),
            criticality=_lookup(record, "target_criticality"),
        )
        relationship_type = "COMMUNICATES_WITH"
        for item in (source_entity, target_entity):
            if item:
                entities.append(item)
        if source_entity and target_entity and not _valid_relationship_endpoints(
            source_entity,
            target_entity,
            relationship_type,
        ):
            relationship_type = None
            warnings.append("network relationship omitted: endpoint types do not match the import contract")
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
                entity_id=_lookup(record, "user_id"),
                is_synthetic=is_synthetic,
                identity_parts=user_identity,
                extra_properties={"username": str(user_name), "domain": str(domain_name)} if domain_name else {"username": str(user_name)},
            )
            if user_name
            else None
        )
        target_entity = _endpoint(
            host_name,
            source,
            entity_id=_lookup(record, "host_id"),
            is_synthetic=is_synthetic,
            entity_type=_lookup(record, "host_type"),
        )
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
        target_entity = _endpoint(host_name, source, is_synthetic=is_synthetic)
        process_entity = (
            _entity(
                "Process",
                process_name,
                source,
                entity_id=_lookup(record, "process_entity_id"),
                is_synthetic=is_synthetic,
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
        host_entity = _endpoint(host_name, source, is_synthetic=is_synthetic)
        if host_entity:
            entities.append(host_entity)
            target_entity = host_entity

    if relationship_type and source_entity and target_entity and not _valid_relationship_endpoints(
        source_entity,
        target_entity,
        relationship_type,
    ):
        relationship_type = None
        warnings.append("relationship omitted: endpoint types do not match the import contract")

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

    description = _lookup(record, "description", "EventDescription")
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "event_time": timestamp_utc,
        "event_time_original": timestamp_original,
        "timestamp_semantics": timestamp_semantics,
        "ingested_at": ingested_at,
        "severity": severity,
        "description": description,
        "source_system": source.source_system,
        "source_record_id": source_record_id,
        "evidence_id": evidence_id,
        "evidence_status": evidence_status,
        "is_synthetic": is_synthetic,
    }
    if event_attributes:
        event["attributes"] = event_attributes
    relationship = _relationship(
        source_entity,
        target_entity,
        relationship_type,
        event,
        relationship_id=explicit_relationship_id,
    )
    unique_entities = {entity["id"]: entity for entity in entities if entity is not None}
    trace_relationships = [
        _relationship(
            {"id": event_id},
            {"id": evidence_id},
            "SUPPORTED_BY",
            event,
        )
    ]
    trace_relationships.extend(
        _relationship({"id": event_id}, entity, "OBSERVED_ON", event)
        for entity in unique_entities.values()
    )
    evidence = {
        "evidence_id": evidence_id,
        "event_id": event_id,
        "source_record_id": source_record_id,
        "source_system": source.source_system,
        "source_dataset_id": source.dataset_id,
        "source_version": source.version,
        "source_url": source.source_url,
        "license": source.license,
        "observed_at": timestamp_utc,
        "observed_at_original": timestamp_original,
        "ingested_at": ingested_at,
        "evidence_type": event_type,
        "description": description,
        "evidence_status": evidence_status,
        "is_synthetic": is_synthetic,
    }
    return NormalizationResult(
        event=event,
        entities=tuple(unique_entities.values()),
        relationship=relationship,
        trace_relationships=tuple(
            item for item in trace_relationships if item is not None
        ),
        evidence=evidence,
        warnings=tuple(warnings),
    )
