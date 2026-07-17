from __future__ import annotations

from hashlib import sha256
import ntpath
import os
import re
from typing import Any

from nodetrace_ir.contracts import EvidenceDraft, RelationDraft

from ._common import stable_hash, text


def _fields(event: dict[str, Any]) -> dict[str, str]:
    value = event.get("EventData") or event.get("event_data") or {}
    if not isinstance(value, dict):
        return {}
    return {str(key).casefold(): text(item) for key, item in value.items()}


def _get(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name.casefold(), "")
        if value:
            return value
    return ""


def _path(value: str) -> str:
    value = value.strip().strip('"').strip()
    value = re.sub(r"^\\\?\\", "", value)
    return ntpath.normcase(ntpath.normpath(value)) if value else ""


def _path_from_command(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end > 1 else value.strip('"')
    match = re.match(r"(.+?\.(?:exe|dll|sys|com|scr|ps1|bat|cmd|vbs|js))(?:\s|,|$)", value, re.I)
    return match.group(1) if match else value.split(" ", 1)[0]


def _pid(value: str) -> int | None:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return None


def _hashes(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in re.split(r"[,;]", value or ""):
        if "=" not in part:
            continue
        name, digest = part.split("=", 1)
        name = name.strip().lower()
        digest = digest.strip().lower()
        if name and digest:
            result[name] = digest
    return result


def _process_key(guid: str, pid: int | None, observed_at: str, image: str = "") -> str:
    if guid and guid not in {"{00000000-0000-0000-0000-000000000000}", "-"}:
        return f"process:guid:{guid.strip('{}').casefold()}"
    return stable_hash("process:event", {"pid": pid, "time": observed_at, "image": _path(image)})


def _file_key(path: str, hashes: dict[str, str] | None = None) -> str:
    digest = (hashes or {}).get("sha256", "")
    if digest:
        return f"file:sha256:{digest.casefold()}"
    return stable_hash("file:path", _path(path))


def _file(
    path: str,
    observed_at: str,
    source: str,
    source_ref: str,
    *,
    hashes: dict[str, str] | None = None,
    confidence: str = "high",
    severity: str = "info",
    action: str = "observed",
) -> EvidenceDraft:
    return EvidenceDraft(
        entity_type="file",
        label=ntpath.basename(path) or path or "Неизвестный файл",
        observed_at=observed_at,
        source=source,
        stable_key=_file_key(path, hashes),
        source_ref=source_ref,
        confidence=confidence,
        severity=severity,
        properties={"path": path, "hashes": hashes or {}, "event_action": action},
        raw={},
    )


def _process(
    key: str,
    image: str,
    pid: int | None,
    observed_at: str,
    source: str,
    source_ref: str,
    fields: dict[str, str],
    *,
    severity: str = "info",
) -> EvidenceDraft:
    name = ntpath.basename(image) or "Процесс"
    pid_suffix = f" (PID {pid})" if pid is not None else ""
    return EvidenceDraft(
        entity_type="process",
        label=f"{name}{pid_suffix}",
        observed_at=observed_at,
        source=source,
        stable_key=key,
        source_ref=source_ref,
        confidence="high",
        severity=severity,
        properties={
            "pid": pid,
            "image": image,
            "command_line": _get(fields, "CommandLine", "ProcessCommandLine"),
            "process_guid": _get(fields, "ProcessGuid"),
            "user": _get(fields, "User", "SubjectUserName", "TargetUserName"),
        },
        raw={},
    )


def normalize_windows_event(
    event: dict[str, Any],
    stream_key: str,
    observed_at: str,
    source: str,
    source_ref: str,
    *,
    suspect_path: str = "",
    seed_key: str = "",
) -> tuple[list[EvidenceDraft], list[RelationDraft]]:
    """Create typed entities/edges from structured event data.

    The function intentionally emits only direct-source relations as high
    confidence. It never turns timestamp proximity into causal attribution.
    """
    fields = _fields(event)
    event_id = int(event.get("Id") or 0)
    evidence: list[EvidenceDraft] = []
    relations: list[RelationDraft] = []
    suspect = _path(suspect_path)

    if stream_key == "sysmon":
        process_guid = _get(fields, "ProcessGuid", "SourceProcessGuid")
        process_id = _pid(_get(fields, "ProcessId", "SourceProcessId"))
        image = _get(fields, "Image", "SourceImage")
        process_key = _process_key(process_guid, process_id, observed_at, image)

        if event_id == 1:
            image_hashes = _hashes(_get(fields, "Hashes"))
            process_severity = "high" if suspect and _path(image) == suspect else "info"
            evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields, severity=process_severity))
            if image:
                image_file = _file(image, observed_at, source, source_ref, hashes=image_hashes, severity=process_severity, action="executed")
                image_key = image_file.key()
                if image_key != seed_key:
                    evidence.append(image_file)
                relations.append(RelationDraft(image_key, process_key, "executed_as", "high", "Sysmon Event 1 directly records Image, ProcessGuid and hashes for process creation.", observed_at))
                if seed_key and suspect and _path(image) == suspect and image_key != seed_key:
                    relations.append(RelationDraft(seed_key, process_key, "executed_as", "high", "Sysmon Event 1 Image exactly matches the case seed path.", observed_at))
            parent_guid = _get(fields, "ParentProcessGuid")
            parent_pid = _pid(_get(fields, "ParentProcessId"))
            parent_image = _get(fields, "ParentImage")
            if parent_guid or parent_pid is not None:
                parent_key = _process_key(parent_guid, parent_pid, observed_at, parent_image)
                evidence.append(_process(parent_key, parent_image, parent_pid, observed_at, source, source_ref, {}, severity="info"))
                relations.append(RelationDraft(parent_key, process_key, "spawned", "high", "Sysmon Event 1 directly records ParentProcessGuid and ProcessGuid.", observed_at))
            user = _get(fields, "User")
            if user:
                user_key = f"user:{user.casefold()}"
                evidence.append(EvidenceDraft("user", user, observed_at, source, user_key, source_ref, "high", "info", {"account": user}, {}))
                relations.append(RelationDraft(user_key, process_key, "started", "high", "Sysmon Event 1 records the user security context.", observed_at))

        elif event_id == 3:
            evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields))
            destination_ip = _get(fields, "DestinationIp")
            destination_port = _get(fields, "DestinationPort")
            hostname = _get(fields, "DestinationHostname")
            if destination_ip:
                endpoint_key = f"ip:{destination_ip.casefold()}:{destination_port or '0'}"
                label = f"{destination_ip}:{destination_port}" if destination_port else destination_ip
                evidence.append(EvidenceDraft("ip", label, observed_at, source, endpoint_key, source_ref, "high", "info", {"ip": destination_ip, "port": destination_port, "hostname": hostname, "protocol": _get(fields, "Protocol")}, {}))
                relations.append(RelationDraft(process_key, endpoint_key, "connected_to", "high", "Sysmon Event 3 directly associates ProcessGuid with the destination endpoint.", observed_at))

        elif event_id == 7:
            loaded = _get(fields, "ImageLoaded")
            if loaded:
                hashes = _hashes(_get(fields, "Hashes"))
                evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields))
                module = _file(loaded, observed_at, source, source_ref, hashes=hashes, action="loaded")
                evidence.append(module)
                relations.append(RelationDraft(process_key, module.key(), "loaded", "high", "Sysmon Event 7 directly associates ProcessGuid with ImageLoaded.", observed_at))

        elif event_id in {11, 23, 26}:
            target = _get(fields, "TargetFilename")
            if target:
                action = "created" if event_id == 11 else "deleted"
                evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields))
                target_file = _file(target, observed_at, source, source_ref, action=action, severity="medium")
                evidence.append(target_file)
                relations.append(RelationDraft(process_key, target_file.key(), action, "high", f"Sysmon Event {event_id} directly associates ProcessGuid with TargetFilename.", observed_at))

        elif event_id in {12, 13, 14}:
            target = _get(fields, "TargetObject")
            if target:
                action = {12: "created_registry", 13: "modified_registry", 14: "renamed_registry"}[event_id]
                registry_key = stable_hash("registry", target.casefold())
                evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields))
                evidence.append(EvidenceDraft("registry", target, observed_at, source, registry_key, source_ref, "high", "medium", {"target": target, "details": _get(fields, "Details"), "event_action": action}, {}))
                relations.append(RelationDraft(process_key, registry_key, action, "high", f"Sysmon Event {event_id} directly associates ProcessGuid with TargetObject.", observed_at))

        elif event_id == 22:
            query_name = _get(fields, "QueryName")
            if query_name:
                domain_key = f"domain:{query_name.rstrip('.').casefold()}"
                evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields))
                evidence.append(EvidenceDraft("domain", query_name, observed_at, source, domain_key, source_ref, "high", "info", {"query": query_name, "result": _get(fields, "QueryResults")}, {}))
                relations.append(RelationDraft(process_key, domain_key, "resolved", "high", "Sysmon Event 22 directly associates ProcessGuid with QueryName.", observed_at))

    elif stream_key == "security_4688" and event_id == 4688:
        image = _get(fields, "NewProcessName")
        process_id = _pid(_get(fields, "NewProcessId"))
        process_key = stable_hash("process:security4688", {"record": event.get("RecordId"), "time": observed_at, "pid": process_id})
        severity = "high" if suspect and _path(image) == suspect else "info"
        evidence.append(_process(process_key, image, process_id, observed_at, source, source_ref, fields, severity=severity))
        if seed_key and suspect and _path(image) == suspect:
            relations.append(RelationDraft(seed_key, process_key, "executed_as", "high", "Security Event 4688 NewProcessName exactly matches the case seed path.", observed_at))
        user = "\\".join(part for part in (_get(fields, "SubjectDomainName"), _get(fields, "SubjectUserName")) if part and part != "-")
        if user:
            user_key = f"user:{user.casefold()}"
            evidence.append(EvidenceDraft("user", user, observed_at, source, user_key, source_ref, "high", "info", {"account": user}, {}))
            relations.append(RelationDraft(user_key, process_key, "started", "high", "Security Event 4688 records the subject account that created the process.", observed_at))

    elif stream_key == "defender" and event_id in {1006, 1007, 1008, 1116, 1117, 1118, 1119, 1120}:
        threat = _get(fields, "Threat Name", "ThreatName", "Name") or "Microsoft Defender detection"
        alert_key = stable_hash("alert:defender", {"record": event.get("RecordId"), "threat": threat})
        evidence.append(EvidenceDraft("alert", threat, observed_at, source, alert_key, source_ref, "high", "critical" if event_id == 1116 else "high", {"event_id": event_id, "action": _get(fields, "Action Name", "ActionName"), "path": _get(fields, "Path")}, {}))
        path_value = _get(fields, "Path")
        if path_value:
            candidate = re.split(r"[;|]", path_value, maxsplit=1)[0].strip()
            candidate = re.sub(r"^(?:file|containerfile):_?", "", candidate, flags=re.I)
            target_key = seed_key if seed_key and suspect and _path(candidate) == suspect else _file_key(candidate)
            if target_key != seed_key or not seed_key:
                evidence.append(_file(candidate, observed_at, source, source_ref, severity="high", action="detected"))
            relations.append(RelationDraft(target_key, alert_key, "detected_as", "high", "Microsoft Defender event directly names the affected path and threat.", observed_at))

    elif stream_key == "powershell_4104" and event_id == 4104:
        script_text = _get(fields, "ScriptBlockText")
        script_id = _get(fields, "ScriptBlockId")
        script_key = f"powershell:scriptblock:{script_id.casefold()}" if script_id else stable_hash("powershell:scriptblock", {"record": event.get("RecordId"), "text": script_text})
        suspicious_terms = [term for term in ("downloadstring", "invoke-expression", "frombase64string", "-enc ") if term in script_text.casefold()]
        evidence.append(EvidenceDraft("event", "PowerShell ScriptBlock 4104", observed_at, source, script_key, source_ref, "high", "high" if suspicious_terms else "info", {"script_block_id": script_id, "path": _get(fields, "Path"), "suspicious_terms": suspicious_terms, "script_block_text": script_text}, {}))
        if seed_key and suspect_path and suspect_path.casefold() in script_text.casefold():
            relations.append(RelationDraft(seed_key, script_key, "referenced_by", "high", "PowerShell 4104 ScriptBlockText directly contains the full case seed path.", observed_at))

    elif stream_key == "system_7045" and event_id == 7045:
        service_name = _get(fields, "ServiceName", "Service Name")
        if not service_name:
            return evidence, relations
        image_path = _get(fields, "ImagePath", "Image Path")
        service_key = stable_hash("service", service_name.casefold())
        evidence.append(EvidenceDraft("service", service_name, observed_at, source, service_key, source_ref, "high", "high", {"image_path": image_path, "service_type": _get(fields, "ServiceType", "Service Type"), "start_type": _get(fields, "StartType", "Start Type"), "account": _get(fields, "AccountName", "Account Name")}, {}))
        executable = _path_from_command(image_path)
        if executable:
            target_key = seed_key if seed_key and suspect and _path(executable) == suspect else _file_key(executable)
            if target_key != seed_key or not seed_key:
                evidence.append(_file(executable, observed_at, source, source_ref, severity="medium", action="installed_service"))
            relations.append(RelationDraft(target_key, service_key, "installed_as_service", "high", "System Event 7045 directly records the service ImagePath.", observed_at))

    elif stream_key == "task_scheduler":
        task_name = _get(fields, "TaskName", "TaskNameString")
        if task_name:
            task_key = stable_hash("scheduled_task", task_name.casefold())
            evidence.append(EvidenceDraft("scheduled_task", task_name, observed_at, source, task_key, source_ref, "high", "medium", {"event_id": event_id, "user": _get(fields, "UserName", "UserContext"), "result_code": _get(fields, "ResultCode")}, {}))

    return evidence, relations
