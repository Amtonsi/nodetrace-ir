from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import ipaddress
import ntpath
from pathlib import Path
import re
from typing import Any, Iterable
import xml.etree.ElementTree as ET

from nodetrace_ir.contracts import (
    CollectorResult,
    EvidenceDraft,
    GapDraft,
    RelationDraft,
    canonical_sha256,
    utc_now,
)


class AVZImportError(ValueError):
    """Raised when an AVZ report is malformed or exceeds parser limits."""


@dataclass(frozen=True, slots=True)
class AVZImportLimits:
    """Hard limits for untrusted reports copied from an investigated host."""

    max_bytes: int = 32 * 1024 * 1024
    max_depth: int = 64
    max_elements: int = 200_000
    max_attributes: int = 128
    max_text_per_element: int = 1024 * 1024
    max_total_text: int = 8 * 1024 * 1024
    max_lines: int = 500_000
    max_line_length: int = 1024 * 1024

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            if int(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")


DEFAULT_IMPORT_LIMITS = AVZImportLimits()

_SOURCE_XML = "AVZ XML report"
_SOURCE_TEXT = "AVZ text report"
_DTD_OR_ENTITY = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_NORMALIZE_NAME = re.compile(r"[^a-z0-9]+", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_SAFE_ISO_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$"
)

_SECTION_KINDS = {
    "detections": "detection",
    "detectionlist": "detection",
    "infectedfiles": "detection",
    "suspiciousfiles": "detection",
    "scanresults": "detection",
    "threats": "detection",
    "malware": "detection",
    "processes": "process",
    "processmanager": "process",
    "processlist": "process",
    "runningprocesses": "process",
    "files": "file",
    "filelist": "file",
    "filesystem": "file",
    "services": "service",
    "servicelist": "service",
    "drivers": "service",
    "autoruns": "autorun",
    "autorun": "autorun",
    "autostart": "autorun",
    "startup": "autorun",
    "network": "network",
    "connections": "network",
    "networkconnections": "network",
    "tcpudp": "network",
    "ports": "network",
    "sockets": "network",
}

_RECORD_KINDS = {
    "detection": "detection",
    "threat": "detection",
    "infected": "detection",
    "infectedfile": "detection",
    "suspicious": "detection",
    "suspiciousfile": "detection",
    "scanresult": "detection",
    "verdict": "detection",
    "process": "process",
    "processinfo": "process",
    "file": "file",
    "fileinfo": "file",
    "module": "file",
    "service": "service",
    "driver": "service",
    "startupitem": "autorun",
    "autostartitem": "autorun",
    "runkey": "autorun",
    "connection": "network",
    "networkconnection": "network",
    "tcp": "network",
    "udp": "network",
    "socket": "network",
}

_GENERIC_RECORD_NAMES = {"item", "row", "record", "entry", "object"}
_SUSPICIOUS_TERMS = (
    "suspicious",
    "suspicion",
    "heuristic",
    "подозр",
    "эврист",
)
_NEGATIVE_TERMS = (
    "not infected",
    "not detected",
    "no threat",
    "clean",
    "не зараж",
    "не обнаруж",
    "угроз не",
    "чистый",
)


def _name(value: str) -> str:
    local = value.rsplit("}", 1)[-1].split(":", 1)[-1]
    return _NORMALIZE_NAME.sub("", local).casefold()


def _stable(prefix: str, identity: Any, length: int = 32) -> str:
    return f"{prefix}:{canonical_sha256(identity)[:length]}"


def _normalized_windows_path(value: str) -> str:
    value = str(value or "").strip().strip('"').strip()
    value = re.sub(r"^\\\\\?\\", "", value)
    return ntpath.normcase(ntpath.normpath(value)) if value else ""


def _path_from_command(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        if end > 1:
            return value[1:end]
    match = re.match(
        r"(.+?\.(?:exe|dll|sys|com|scr|ps1|bat|cmd|vbs|js|msi))(?:\s|,|$)",
        value,
        re.IGNORECASE,
    )
    return match.group(1).strip('"') if match else value.split(" ", 1)[0].strip('"')


def _first(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(_name(name), "").strip()
        if value:
            return value
    return ""


def _integer(value: str) -> int | None:
    value = str(value or "").strip()
    try:
        return int(value, 16) if value.casefold().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return None


def _safe_observed_at(fields: dict[str, str], fallback: str) -> str:
    value = _first(
        fields,
        "timestamp",
        "timeutc",
        "datetimeutc",
        "createdutc",
        "starttimeutc",
        "observedat",
    )
    if not _SAFE_ISO_TIME.fullmatch(value):
        return fallback
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return value


def _hashes(fields: dict[str, str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for algorithm, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
        value = _first(fields, algorithm, f"hash{algorithm}").strip().casefold()
        if re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
            found[algorithm] = value
    combined = _first(fields, "hash", "hashes")
    for part in re.split(r"[,;\s]+", combined):
        if "=" not in part:
            continue
        algorithm, value = part.split("=", 1)
        algorithm = algorithm.strip().casefold()
        value = value.strip().casefold()
        expected = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
        if expected and re.fullmatch(rf"[0-9a-f]{{{expected}}}", value):
            found[algorithm] = value
    return found


def _file_key(path: str, hashes: dict[str, str] | None = None) -> str:
    digest = (hashes or {}).get("sha256", "").casefold()
    if _SHA256.fullmatch(digest):
        return f"file:sha256:{digest}"
    return _stable("file:path", _normalized_windows_path(path))


def _process_key(report_sha256: str, pid: int | None, image: str = "") -> str:
    # An AVZ report is a snapshot, so PID plus report identity is a conservative
    # process-instance key.  It deliberately does not join a PID across reports.
    if pid is not None:
        return _stable("process:avz", {"report": report_sha256, "pid": pid})
    return _stable(
        "process:avz",
        {"report": report_sha256, "image": _normalized_windows_path(image)},
    )


def _flatten(element: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}

    def add(key: str, value: Any) -> None:
        normalized = _name(key)
        text = str(value or "").strip()
        if not normalized or not text:
            return
        if normalized in fields and text not in fields[normalized].split(" | "):
            fields[normalized] = f"{fields[normalized]} | {text}"
        else:
            fields.setdefault(normalized, text)

    for key, value in element.attrib.items():
        add(key, value)
    if not list(element):
        add(_name(element.tag) or "value", element.text)
    for child in element.iter():
        if child is element:
            continue
        for key, value in child.attrib.items():
            add(key, value)
        if not list(child):
            add(child.tag, child.text)
    return fields


def decode_avz_text(
    data: bytes,
    *,
    limits: AVZImportLimits = DEFAULT_IMPORT_LIMITS,
) -> tuple[str, str]:
    """Decode AVZ output without locale-dependent implicit fallbacks."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) > limits.max_bytes:
        raise AVZImportError(
            f"AVZ report exceeds the {limits.max_bytes}-byte import limit"
        )
    if data.startswith(b"\xef\xbb\xbf"):
        candidates = (("utf-8-sig", "utf-8-sig"),)
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates = (("utf-16", "utf-16"),)
    else:
        odd_nuls = data[1::2].count(0)
        even_nuls = data[0::2].count(0)
        pairs = max(1, len(data) // 2)
        if odd_nuls / pairs > 0.25:
            candidates = (("utf-16-le", "utf-16-le"),)
        elif even_nuls / pairs > 0.25:
            candidates = (("utf-16-be", "utf-16-be"),)
        else:
            candidates = (("utf-8", "utf-8"), ("cp1251", "cp1251"))
    last_error: UnicodeDecodeError | None = None
    for codec, label in candidates:
        try:
            return data.decode(codec, errors="strict"), label
        except UnicodeDecodeError as exc:
            last_error = exc
    raise AVZImportError("AVZ report is not valid UTF-8, UTF-16, or CP1251") from last_error


def _validate_xml_tree(root: ET.Element, limits: AVZImportLimits) -> dict[str, int]:
    element_count = 0
    total_text = 0
    maximum_depth = 0
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        element_count += 1
        maximum_depth = max(maximum_depth, depth)
        if element_count > limits.max_elements:
            raise AVZImportError("AVZ XML exceeds the element-count limit")
        if depth > limits.max_depth:
            raise AVZImportError("AVZ XML exceeds the nesting-depth limit")
        if len(element.attrib) > limits.max_attributes:
            raise AVZImportError("AVZ XML element has too many attributes")
        pieces = [element.text or "", element.tail or "", *element.attrib.values()]
        for piece in pieces:
            if len(piece) > limits.max_text_per_element:
                raise AVZImportError("AVZ XML element text exceeds the per-element limit")
            total_text += len(piece)
            if total_text > limits.max_total_text:
                raise AVZImportError("AVZ XML exceeds the total-text limit")
        for child in reversed(list(element)):
            stack.append((child, depth + 1))
    return {
        "element_count": element_count,
        "maximum_depth": maximum_depth,
        "text_characters": total_text,
    }


def _is_leaf_record(element: ET.Element) -> bool:
    children = list(element)
    if not children:
        return bool(element.attrib or (element.text or "").strip())
    if any(
        _name(child.tag) in _RECORD_KINDS or _name(child.tag) in _SECTION_KINDS
        for child in children
    ):
        return False
    return all(not list(child) for child in children)


def _iter_xml_records(
    root: ET.Element,
) -> Iterable[tuple[str, ET.Element, str, str]]:
    """Yield (kind, element, source_ref, tag) without treating field nodes as records."""

    def walk(
        parent: ET.Element,
        path: str,
        context: str | None,
        parent_is_section: bool,
    ) -> Iterable[tuple[str, ET.Element, str, str]]:
        counters: dict[str, int] = {}
        for child in list(parent):
            tag = _name(child.tag) or "node"
            counters[tag] = counters.get(tag, 0) + 1
            child_path = f"{path}/{tag}[{counters[tag]}]"
            section_kind = _SECTION_KINDS.get(tag)
            direct_kind = _RECORD_KINDS.get(tag)
            if section_kind:
                yield from walk(child, child_path, section_kind, True)
                continue
            effective_kind = direct_kind or context
            generic = tag in _GENERIC_RECORD_NAMES
            should_emit = bool(
                effective_kind
                and (
                    direct_kind
                    or (parent_is_section and _is_leaf_record(child))
                    or (generic and _is_leaf_record(child))
                )
            )
            if should_emit:
                yield effective_kind, child, child_path, tag  # type: ignore[misc]
            else:
                yield from walk(child, child_path, effective_kind, False)

    root_name = _name(root.tag) or "report"
    root_record = _RECORD_KINDS.get(root_name)
    if root_record:
        yield root_record, root, f"/{root_name}[1]", root_name
        return
    root_section = _SECTION_KINDS.get(root_name)
    yield from walk(root, f"/{root_name}[1]", root_section, bool(root_section))


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class _Accumulator:
    def __init__(self) -> None:
        self.evidence: list[EvidenceDraft] = []
        self.relations: list[RelationDraft] = []
        self._evidence_by_key: dict[str, EvidenceDraft] = {}
        self._relation_keys: set[tuple[str, str, str]] = set()

    def evidence_item(self, item: EvidenceDraft) -> str:
        key = item.key()
        existing = self._evidence_by_key.get(key)
        if existing is None:
            self._evidence_by_key[key] = item
            self.evidence.append(item)
            return key
        existing.properties.update(
            {name: value for name, value in item.properties.items() if value not in (None, "", {})}
        )
        existing.raw.update(item.raw)
        if existing.label.startswith("PID ") and not item.label.startswith("PID "):
            existing.label = item.label
        if _CONFIDENCE_RANK.get(item.confidence, 0) > _CONFIDENCE_RANK.get(
            existing.confidence, 0
        ):
            existing.confidence = item.confidence
        if _SEVERITY_RANK.get(item.severity, 0) > _SEVERITY_RANK.get(
            existing.severity, 0
        ):
            existing.severity = item.severity
        return key

    def relation(self, item: RelationDraft) -> None:
        key = (item.source_key, item.target_key, item.relation_type)
        if key not in self._relation_keys:
            self._relation_keys.add(key)
            self.relations.append(item)


def _raw_fields(fields: dict[str, str], tag: str) -> dict[str, Any]:
    return {"avz_tag": tag, "fields": dict(sorted(fields.items()))}


def _add_file(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    path: str,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
    severity: str = "info",
    confidence: str = "high",
) -> str:
    hashes = _hashes(fields)
    normalized = _normalized_windows_path(path)
    key = _file_key(normalized, hashes)
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="file",
            label=ntpath.basename(normalized) or normalized or "Неизвестный файл",
            observed_at=observed_at,
            source=source,
            stable_key=key,
            source_ref=source_ref,
            confidence=confidence,
            severity=severity,
            properties={"path": path, "normalized_path": normalized, "hashes": hashes},
            raw=_raw_fields(fields, tag),
        )
    )
    return key


def _emit_detection(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    report_sha256: str,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> bool:
    joined = " ".join([tag, *fields.values()]).casefold()
    if any(term in joined for term in _NEGATIVE_TERMS):
        return False
    suspicious = tag.startswith("suspicious") or any(
        term in joined for term in _SUSPICIOUS_TERMS
    )
    path = _first(
        fields,
        "path",
        "filepath",
        "fullpath",
        "file",
        "filename",
        "object",
        "target",
        "image",
    )
    threat = _first(
        fields,
        "threat",
        "threatname",
        "malware",
        "malwarename",
        "virus",
        "virusname",
        "name",
        "verdict",
        "diagnosis",
        "result",
        "reason",
    )
    if threat.casefold() in {"infected", "suspicious", "detected"}:
        threat = ""
    threat = threat or ("Подозрительный объект AVZ" if suspicious else "Обнаружение AVZ")
    confidence = "medium" if suspicious else "high"
    severity = "medium" if suspicious else "high"
    identity = {
        "report": report_sha256,
        "path": _normalized_windows_path(path),
        "threat": threat.casefold(),
        "suspicious": suspicious,
        "source_ref": source_ref,
    }
    detection_key = _stable("detection:avz", identity)
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="malware_detection",
            label=f"{'Подозрение' if suspicious else 'Обнаружение'}: {threat}",
            observed_at=observed_at,
            source=source,
            stable_key=detection_key,
            source_ref=source_ref,
            confidence=confidence,
            severity=severity,
            properties={
                "classification": threat,
                "verdict": "suspicious" if suspicious else "malware",
                "confirmed_malware": not suspicious,
                "path": path,
                "scanner": "AVZ",
                "interpretation": (
                    "heuristic suspicion; requires analyst validation"
                    if suspicious
                    else "AVZ reported a malware detection"
                ),
            },
            raw=_raw_fields(fields, tag),
        )
    )
    if path:
        file_key = _add_file(
            accumulator,
            fields,
            path=path,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
            severity=severity,
            confidence=confidence,
        )
        accumulator.relation(
            RelationDraft(
                source_key=file_key,
                target_key=detection_key,
                relation_type="detected_as",
                confidence=confidence,
                rationale=(
                    "AVZ associated this file with a heuristic suspicion; this is not proof of malware"
                    if suspicious
                    else "AVZ directly associated this file with the reported detection"
                ),
                observed_at=observed_at,
            )
        )
    return True


def _emit_process(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    report_sha256: str,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> str:
    pid = _integer(_first(fields, "pid", "processid", "process_id"))
    image = _first(
        fields,
        "image",
        "imagepath",
        "executable",
        "executablepath",
        "path",
        "filename",
    )
    command_line = _first(fields, "commandline", "command", "cmdline")
    if not image and command_line:
        image = _path_from_command(command_line)
    key = _process_key(report_sha256, pid, image)
    label = ntpath.basename(image) or _first(fields, "name") or (
        f"PID {pid}" if pid is not None else "Неизвестный процесс"
    )
    if pid is not None and not label.startswith("PID "):
        label = f"{label} (PID {pid})"
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="process",
            label=label,
            observed_at=observed_at,
            source=source,
            stable_key=key,
            source_ref=source_ref,
            confidence="high",
            severity="info",
            properties={
                "pid": pid,
                "parent_pid": _integer(_first(fields, "ppid", "parentpid", "parentprocessid")),
                "image": image,
                "command_line": command_line,
                "user": _first(fields, "user", "username", "account"),
                "avz_snapshot": True,
            },
            raw=_raw_fields(fields, tag),
        )
    )
    if image:
        file_key = _add_file(
            accumulator,
            fields,
            path=image,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
        accumulator.relation(
            RelationDraft(
                source_key=file_key,
                target_key=key,
                relation_type="executed_as",
                confidence="high",
                rationale="The AVZ process snapshot directly reported this executable image",
                observed_at=observed_at,
            )
        )
    return key


def _emit_service(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> None:
    name = _first(fields, "servicename", "name", "displayname", "drivername")
    command = _first(fields, "imagepath", "binarypath", "path", "command", "filename")
    image = _path_from_command(command)
    key = _stable(
        "service:avz",
        {"name": name.casefold(), "image": _normalized_windows_path(image)},
    )
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="service",
            label=name or ntpath.basename(image) or "Неизвестная служба",
            observed_at=observed_at,
            source=source,
            stable_key=key,
            source_ref=source_ref,
            confidence="high",
            severity="info",
            properties={
                "name": name,
                "display_name": _first(fields, "displayname"),
                "image_path": command,
                "start_type": _first(fields, "starttype", "startup", "start"),
                "state": _first(fields, "state", "status"),
                "account": _first(fields, "account", "user", "startname"),
            },
            raw=_raw_fields(fields, tag),
        )
    )
    if image:
        file_key = _add_file(
            accumulator,
            fields,
            path=image,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
        accumulator.relation(
            RelationDraft(
                source_key=file_key,
                target_key=key,
                relation_type="configured_as_service",
                confidence="high",
                rationale="The AVZ service record directly referenced this executable path",
                observed_at=observed_at,
            )
        )


def _emit_autorun(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> None:
    location = _first(fields, "location", "registry", "registrykey", "key", "source")
    name = _first(fields, "name", "valuename", "entry")
    command = _first(fields, "command", "commandline", "value", "imagepath", "path")
    image = _path_from_command(command)
    key = _stable(
        "autorun:avz",
        {"location": location.casefold(), "name": name.casefold(), "command": command},
    )
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="autorun",
            label=name or location or ntpath.basename(image) or "Элемент автозапуска",
            observed_at=observed_at,
            source=source,
            stable_key=key,
            source_ref=source_ref,
            confidence="high",
            severity="info",
            properties={"location": location, "name": name, "command": command},
            raw=_raw_fields(fields, tag),
        )
    )
    if image:
        file_key = _add_file(
            accumulator,
            fields,
            path=image,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
        accumulator.relation(
            RelationDraft(
                source_key=file_key,
                target_key=key,
                relation_type="possible_persistence_reference",
                confidence="medium",
                rationale=(
                    "The AVZ autorun record referenced this command; the snapshot does not prove who created it"
                ),
                observed_at=observed_at,
            )
        )


def _split_endpoint(value: str) -> tuple[str, int | None]:
    value = str(value or "").strip()
    if not value:
        return "", None
    if value.startswith("[") and "]" in value:
        address, _, remainder = value[1:].partition("]")
        return address, _integer(remainder.lstrip(":"))
    if value.count(":") == 1:
        address, port = value.rsplit(":", 1)
        return address, _integer(port)
    try:
        ipaddress.ip_address(value)
        return value, None
    except ValueError:
        return value, None


def _emit_network(
    accumulator: _Accumulator,
    fields: dict[str, str],
    *,
    report_sha256: str,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> None:
    protocol = (_first(fields, "protocol", "proto") or tag or "tcp").casefold()
    local_address = _first(fields, "localaddress", "localip", "sourceaddress", "src")
    local_port = _integer(_first(fields, "localport", "sourceport", "srcport"))
    remote_address = _first(
        fields, "remoteaddress", "remoteip", "destinationaddress", "dst", "destination"
    )
    remote_port = _integer(
        _first(fields, "remoteport", "destinationport", "dstport")
    )
    if not local_address:
        local_address, combined_port = _split_endpoint(_first(fields, "local"))
        local_port = local_port if local_port is not None else combined_port
    if not remote_address:
        remote_address, combined_port = _split_endpoint(_first(fields, "remote"))
        remote_port = remote_port if remote_port is not None else combined_port
    pid = _integer(_first(fields, "pid", "processid", "ownerpid"))
    state = _first(fields, "state", "status")
    identity = {
        "report": report_sha256,
        "protocol": protocol,
        "pid": pid,
        "local_address": local_address,
        "local_port": local_port,
        "remote_address": remote_address,
        "remote_port": remote_port,
        "state": state,
    }
    connection_key = _stable("connection:avz", identity)
    accumulator.evidence_item(
        EvidenceDraft(
            entity_type="network_connection",
            label=(
                f"{protocol.upper()} {local_address or '*'}:{local_port or '*'} -> "
                f"{remote_address or '*'}:{remote_port or '*'}"
            ),
            observed_at=observed_at,
            source=source,
            stable_key=connection_key,
            source_ref=source_ref,
            confidence="high",
            severity="info",
            properties={**identity, "process_name": _first(fields, "process", "processname")},
            raw=_raw_fields(fields, tag),
        )
    )
    if pid is not None:
        image = _first(fields, "image", "processpath", "executable")
        process_key = _emit_process(
            accumulator,
            {**fields, "pid": str(pid), "image": image},
            report_sha256=report_sha256,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag="network-owner",
        )
        accumulator.relation(
            RelationDraft(
                source_key=process_key,
                target_key=connection_key,
                relation_type="owns_connection",
                confidence="high",
                rationale="The AVZ connection record directly reported the owning PID",
                observed_at=observed_at,
            )
        )
    if remote_address and remote_address not in {"0.0.0.0", "::", "*"}:
        endpoint_key = _stable(
            "network:endpoint",
            {"protocol": protocol, "address": remote_address.casefold(), "port": remote_port},
        )
        accumulator.evidence_item(
            EvidenceDraft(
                entity_type="network_endpoint",
                label=f"{remote_address}:{remote_port or '*'}",
                observed_at=observed_at,
                source=source,
                stable_key=endpoint_key,
                source_ref=source_ref,
                confidence="high",
                severity="info",
                properties={"protocol": protocol, "address": remote_address, "port": remote_port},
                raw={},
            )
        )
        accumulator.relation(
            RelationDraft(
                source_key=connection_key,
                target_key=endpoint_key,
                relation_type="remote_endpoint",
                confidence="high",
                rationale="The remote endpoint was directly present in the AVZ connection record",
                observed_at=observed_at,
            )
        )


def _emit_record(
    accumulator: _Accumulator,
    kind: str,
    fields: dict[str, str],
    *,
    report_sha256: str,
    observed_at: str,
    source: str,
    source_ref: str,
    tag: str,
) -> bool:
    if kind == "detection":
        if not _first(
            fields,
            "path",
            "filepath",
            "fullpath",
            "file",
            "filename",
            "threat",
            "threatname",
            "malware",
            "virus",
            "verdict",
            "result",
        ):
            return False
        return _emit_detection(
            accumulator,
            fields,
            report_sha256=report_sha256,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    if kind == "process":
        if not _first(
            fields,
            "pid",
            "processid",
            "image",
            "imagepath",
            "executable",
            "path",
            "filename",
            "name",
            "commandline",
        ):
            return False
        _emit_process(
            accumulator,
            fields,
            report_sha256=report_sha256,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    elif kind == "file":
        path = _first(fields, "path", "filepath", "fullpath", "filename", "name", "file")
        if not path:
            return False
        _add_file(
            accumulator,
            fields,
            path=path,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    elif kind == "service":
        if not _first(
            fields,
            "servicename",
            "name",
            "displayname",
            "drivername",
            "imagepath",
            "binarypath",
            "path",
            "command",
        ):
            return False
        _emit_service(
            accumulator,
            fields,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    elif kind == "autorun":
        if not _first(
            fields,
            "location",
            "registry",
            "registrykey",
            "key",
            "name",
            "valuename",
            "command",
            "value",
            "path",
        ):
            return False
        _emit_autorun(
            accumulator,
            fields,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    elif kind == "network":
        if not _first(
            fields,
            "pid",
            "processid",
            "local",
            "localaddress",
            "remote",
            "remoteaddress",
            "destination",
        ):
            return False
        _emit_network(
            accumulator,
            fields,
            report_sha256=report_sha256,
            observed_at=observed_at,
            source=source,
            source_ref=source_ref,
            tag=tag,
        )
    else:
        return False
    return True


def _xml_metadata(root: ET.Element) -> dict[str, str]:
    metadata = {_name(key): str(value) for key, value in root.attrib.items()}
    for element in root.iter():
        tag = _name(element.tag)
        if tag not in {"metadata", "database", "signaturebase", "antivirusbase", "report"}:
            continue
        prefix = "database" if tag in {"database", "signaturebase", "antivirusbase"} else ""
        for key, value in element.attrib.items():
            metadata[f"{prefix}{_name(key)}"] = str(value)
        for child in list(element):
            if not list(child) and (child.text or "").strip():
                metadata[f"{prefix}{_name(child.tag)}"] = (child.text or "").strip()
    return dict(sorted(metadata.items()))


def _unsafe_removal_metadata(metadata: dict[str, str]) -> bool:
    safe = {"n", "no", "false", "0", "disabled", "off", "readonly", "read-only"}
    for key, value in metadata.items():
        if any(token in key for token in ("removalmode", "delvir", "useinfected", "usequarantine")):
            if value.strip().casefold() not in safe:
                return True
    return False


def _parse_xml_report(
    data: bytes,
    *,
    report_sha256: str,
    source_name: str,
    observed_at: str,
    limits: AVZImportLimits,
) -> tuple[_Accumulator, list[GapDraft], dict[str, Any]]:
    text, encoding = decode_avz_text(data, limits=limits)
    if _DTD_OR_ENTITY.search(text):
        raise AVZImportError("DTD and ENTITY declarations are forbidden in AVZ XML")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AVZImportError(f"Malformed AVZ XML: {exc}") from exc
    statistics = _validate_xml_tree(root, limits)
    metadata = _xml_metadata(root)
    accumulator = _Accumulator()
    records = 0
    detections = 0
    for kind, element, location, tag in _iter_xml_records(root):
        fields = _flatten(element)
        record_time = _safe_observed_at(fields, observed_at)
        if _emit_record(
            accumulator,
            kind,
            fields,
            report_sha256=report_sha256,
            observed_at=record_time,
            source=_SOURCE_XML,
            source_ref=f"{source_name}#{location}",
            tag=tag,
        ):
            records += 1
            detections += int(kind == "detection")
    gaps: list[GapDraft] = []
    if records == 0:
        gaps.append(
            GapDraft(
                collector="avz_import",
                source=source_name,
                reason="The XML report contained no supported AVZ records",
                impact="No detection, process, file, service, autorun, or network evidence was imported",
                recommendation="Export an AVZ XML system-analysis report or import the text log separately",
            )
        )
    if _unsafe_removal_metadata(metadata):
        gaps.append(
            GapDraft(
                collector="avz_import",
                source=source_name,
                reason="Report metadata indicates that AVZ remediation or quarantine was enabled",
                impact="The investigated host may have been changed before evidence was imported",
                recommendation="Treat the report as post-change evidence and record the operator action",
            )
        )
    payload = {
        "format": "xml",
        "encoding": encoding,
        "source_name": source_name,
        "sha256": report_sha256,
        "metadata": metadata,
        "record_count": records,
        "detection_count": detections,
        "evidence_count": len(accumulator.evidence),
        "relation_count": len(accumulator.relations),
        **statistics,
    }
    return accumulator, gaps, payload


_TEXT_RECORD = re.compile(
    r"^\s*(?P<kind>Process|Процесс|Service|Служба|Autorun|Автозапуск|TCP|UDP)\s*:\s*(?P<body>.+)$",
    re.IGNORECASE,
)
_TEXT_FILE_VERDICT = re.compile(
    r"(?P<path>(?:[A-Za-z]:\\|\\\\)[^\r\n<>|]*?\.(?:exe|dll|sys|com|scr|ps1|bat|cmd|vbs|js|msi))"
    r"\s*(?:>>>|-->|\s+-\s+|\s*:\s*)\s*(?P<verdict>.+)$",
    re.IGNORECASE,
)
_TEXT_METADATA = {
    "version": re.compile(r"\bAVZ(?:\s+version|\s+версия|\s+v\.?|\s+)([\d.]+)", re.I),
    "database_date": re.compile(r"(?:database|баз[аы])(?:\s+date|\s+от|\s*:)\s*([^;\r\n]+)", re.I),
    "removal_mode": re.compile(r"(?:removal\s*mode|режим\s+лечения)\s*[:=]\s*([^;\r\n]+)", re.I),
}


def _parse_key_values(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in body.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.strip() and value.strip():
            result[_name(key)] = value.strip()
    return result


def _threat_from_text(verdict: str, suspicious: bool) -> str:
    value = verdict.strip()
    patterns = (
        r"(?:обнаружен[ао]?|detected|infected(?:\s+with)?|malware)\s*[:=-]?\s*(.+)$",
        r"(?:подозрение\s+на|suspicion(?:\s+of)?|suspicious(?:\s+for)?)\s*[:=-]?\s*(.+)$",
    )
    for pattern in patterns:
        match = re.search(pattern, value, re.IGNORECASE)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return value or ("Подозрительный объект AVZ" if suspicious else "Обнаружение AVZ")


def _parse_text_report(
    data: bytes,
    *,
    report_sha256: str,
    source_name: str,
    observed_at: str,
    limits: AVZImportLimits,
) -> tuple[_Accumulator, list[GapDraft], dict[str, Any]]:
    text, encoding = decode_avz_text(data, limits=limits)
    if len(text) > limits.max_total_text:
        raise AVZImportError("AVZ text report exceeds the total-text limit")
    lines = text.splitlines()
    if len(lines) > limits.max_lines:
        raise AVZImportError("AVZ text report exceeds the line-count limit")
    if any(len(line) > limits.max_line_length for line in lines):
        raise AVZImportError("AVZ text report contains a line over the length limit")
    metadata: dict[str, str] = {}
    for key, pattern in _TEXT_METADATA.items():
        match = pattern.search(text[: min(len(text), 256 * 1024)])
        if match:
            metadata[key] = match.group(1).strip()
    accumulator = _Accumulator()
    records = 0
    detections = 0
    for number, line in enumerate(lines, 1):
        source_ref = f"{source_name}#line:{number}"
        structured = _TEXT_RECORD.match(line)
        if structured:
            source_kind = structured.group("kind").casefold()
            fields = _parse_key_values(structured.group("body"))
            kind = (
                "process"
                if source_kind in {"process", "процесс"}
                else "service"
                if source_kind in {"service", "служба"}
                else "autorun"
                if source_kind in {"autorun", "автозапуск"}
                else "network"
            )
            fields.setdefault("protocol", source_kind if kind == "network" else "")
            if fields and _emit_record(
                accumulator,
                kind,
                fields,
                report_sha256=report_sha256,
                observed_at=observed_at,
                source=_SOURCE_TEXT,
                source_ref=source_ref,
                tag=source_kind,
            ):
                records += 1
            continue
        match = _TEXT_FILE_VERDICT.search(line)
        if not match:
            continue
        verdict = match.group("verdict").strip()
        joined = verdict.casefold()
        suspicious = any(term in joined for term in _SUSPICIOUS_TERMS)
        detected = suspicious or any(
            term in joined
            for term in ("обнаруж", "detected", "infected", "malware", "virus", "trojan")
        )
        if not detected or any(term in joined for term in _NEGATIVE_TERMS):
            continue
        fields = {
            "path": match.group("path").strip(),
            "threat": _threat_from_text(verdict, suspicious),
            "verdict": "suspicious" if suspicious else "detected",
            "message": verdict,
        }
        if _emit_detection(
            accumulator,
            fields,
            report_sha256=report_sha256,
            observed_at=observed_at,
            source=_SOURCE_TEXT,
            source_ref=source_ref,
            tag="suspiciousfile" if suspicious else "infectedfile",
        ):
            records += 1
            detections += 1
    gaps = [
        GapDraft(
            collector="avz_import",
            source=source_name,
            reason="A presentation-oriented AVZ text log was imported instead of structured XML",
            impact="Fields and relationships absent from the text cannot be reconstructed reliably",
            recommendation="Preserve and import the corresponding AVZ XML system-analysis report",
        )
    ]
    if records == 0:
        gaps.append(
            GapDraft(
                collector="avz_import",
                source=source_name,
                reason="The text report contained no supported AVZ records",
                impact="No structured investigation evidence was imported",
                recommendation="Verify that this is an AVZ scan log and export the XML report",
            )
        )
    if _unsafe_removal_metadata(metadata):
        gaps.append(
            GapDraft(
                collector="avz_import",
                source=source_name,
                reason="The text log says that AVZ treatment/removal mode was enabled",
                impact="The investigated host may have been changed during the scan",
                recommendation="Document the intervention and prefer evidence acquired before treatment",
            )
        )
    payload = {
        "format": "text",
        "encoding": encoding,
        "source_name": source_name,
        "sha256": report_sha256,
        "metadata": metadata,
        "line_count": len(lines),
        "record_count": records,
        "detection_count": detections,
        "evidence_count": len(accumulator.evidence),
        "relation_count": len(accumulator.relations),
    }
    return accumulator, gaps, payload


def _read_source(
    source: str | Path | bytes | bytearray,
    *,
    filename: str | None,
    limits: AVZImportLimits,
) -> tuple[bytes, str]:
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        source_name = Path(filename or "avz_report").name
    else:
        path = Path(source)
        source_name = Path(filename).name if filename else path.name
        try:
            with path.open("rb") as handle:
                data = handle.read(limits.max_bytes + 1)
        except OSError as exc:
            raise AVZImportError(f"Unable to read AVZ report: {exc}") from exc
    if not source_name:
        source_name = "avz_report"
    if len(data) > limits.max_bytes:
        raise AVZImportError(
            f"AVZ report exceeds the {limits.max_bytes}-byte import limit"
        )
    if not data:
        raise AVZImportError("AVZ report is empty")
    return data, source_name


class AVZImporter:
    """Parse untrusted AVZ reports into NodeTrace evidence drafts.

    Parsing is deliberately separate from AVZ execution.  No report content is
    executed, no referenced file is opened, and no path from the report is used
    for host access.
    """

    name = "avz_import"

    def __init__(self, *, limits: AVZImportLimits = DEFAULT_IMPORT_LIMITS) -> None:
        self.limits = limits

    def import_report(
        self,
        source: str | Path | bytes | bytearray,
        *,
        filename: str | None = None,
        collected_at: str | None = None,
    ) -> CollectorResult:
        started_at = utc_now()
        observed_at = collected_at or started_at
        data, source_name = _read_source(
            source, filename=filename, limits=self.limits
        )
        report_sha256 = sha256(data).hexdigest()
        probe, _ = decode_avz_text(data[: min(len(data), 64 * 1024)], limits=self.limits)
        xml_report = probe.lstrip("\ufeff \t\r\n").startswith("<")
        if xml_report:
            accumulator, gaps, raw_payload = _parse_xml_report(
                data,
                report_sha256=report_sha256,
                source_name=source_name,
                observed_at=observed_at,
                limits=self.limits,
            )
        else:
            accumulator, gaps, raw_payload = _parse_text_report(
                data,
                report_sha256=report_sha256,
                source_name=source_name,
                observed_at=observed_at,
                limits=self.limits,
            )
        return CollectorResult(
            collector=self.name,
            started_at=started_at,
            finished_at=utc_now(),
            status="partial" if gaps else "completed",
            evidence=accumulator.evidence,
            relations=accumulator.relations,
            gaps=gaps,
            raw_payload=raw_payload,
        )

    parse = import_report


def import_avz_report(
    source: str | Path | bytes | bytearray,
    *,
    filename: str | None = None,
    collected_at: str | None = None,
    limits: AVZImportLimits = DEFAULT_IMPORT_LIMITS,
) -> CollectorResult:
    return AVZImporter(limits=limits).import_report(
        source, filename=filename, collected_at=collected_at
    )


__all__ = [
    "AVZImportError",
    "AVZImportLimits",
    "AVZImporter",
    "DEFAULT_IMPORT_LIMITS",
    "decode_avz_text",
    "import_avz_report",
]
