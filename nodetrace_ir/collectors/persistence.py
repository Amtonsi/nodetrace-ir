from __future__ import annotations

import ntpath
from pathlib import Path
import re

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, RelationDraft, utc_now

from . import helpers
from ._common import (
    as_dict,
    as_list,
    cancelled_gap,
    content_file_key,
    finish,
    new_result,
    normalized_path,
    powershell_gap,
    stable_hash,
    text,
)


def _normalized_windows_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value.strip().strip('"'))) if value.strip() else ""


def _command_path_tokens(value: str) -> list[str]:
    """Extract explicit Windows path tokens without treating substrings as paths."""
    tokens = [match for match in re.findall(r'"([^"\r\n]+)"', value) if match]
    tokens.extend(
        match.group(0)
        for match in re.finditer(
            r"(?i)(?<![\w.])(?:[A-Z]:\\|\\\\)[^\r\n\t\"',;]*?\.(?:exe|com|scr|dll|sys|ps1|bat|cmd|vbs|js)(?=$|\s|,|;)",
            value,
        )
    )
    stripped = value.strip().strip('"')
    if re.search(r"(?i)\.(?:exe|com|scr|dll|sys|ps1|bat|cmd|vbs|js)$", stripped):
        tokens.append(stripped)
    return list(dict.fromkeys(tokens))


def _contains_filename_token(value: str, filename: str) -> bool:
    if not filename:
        return False
    pattern = rf"(?<![A-Za-z0-9_.-]){re.escape(filename)}(?![A-Za-z0-9_.-])"
    return re.search(pattern, value, flags=re.I) is not None


class PersistenceCollector:
    name = "persistence"
    display_name = "Persistence inventory"

    _SCRIPT = r"""
$sectionErrors = @()
$runValues = @()
$services = @()
$tasks = @()
$startupItems = @()

$runPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($runPath in $runPaths) {
    try {
        if (Test-Path -LiteralPath $runPath) {
            $item = Get-ItemProperty -LiteralPath $runPath -ErrorAction Stop
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                    $runValues += [ordered]@{
                        RegistryPath = $runPath
                        ValueName = $property.Name
                        Command = [string]$property.Value
                    }
                }
            }
        }
    } catch {
        $sectionErrors += [ordered]@{ Source = "Run key: $runPath"; Error = $_.Exception.Message }
    }
}

try {
    $services = @(
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                State = $_.State
                StartMode = $_.StartMode
                PathName = $_.PathName
                StartName = $_.StartName
                ProcessId = $_.ProcessId
                ServiceType = $_.ServiceType
            }
        }
    )
} catch {
    $sectionErrors += [ordered]@{ Source = 'Win32_Service'; Error = $_.Exception.Message }
}

try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = @(
            Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
                $taskActions = @(
                    $_.Actions | ForEach-Object {
                        [ordered]@{
                            Execute = $_.Execute
                            Arguments = $_.Arguments
                            WorkingDirectory = $_.WorkingDirectory
                            ClassId = $_.ClassId
                        }
                    }
                )
                [ordered]@{
                    TaskPath = $_.TaskPath
                    TaskName = $_.TaskName
                    State = [string]$_.State
                    Author = $_.Author
                    Description = $_.Description
                    Actions = $taskActions
                }
            }
        )
    } else {
        $sectionErrors += [ordered]@{ Source = 'Get-ScheduledTask'; Error = 'Cmdlet is unavailable' }
    }
} catch {
    $sectionErrors += [ordered]@{ Source = 'Get-ScheduledTask'; Error = $_.Exception.Message }
}

$startupPaths = @(
    $env:NODETRACE_USER_STARTUP,
    $env:NODETRACE_COMMON_STARTUP
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
foreach ($startupPath in $startupPaths) {
    try {
        if (Test-Path -LiteralPath $startupPath) {
            $startupItems += @(
                Get-ChildItem -LiteralPath $startupPath -File -Force -ErrorAction Stop | ForEach-Object {
                    [ordered]@{
                        FullName = $_.FullName
                        Name = $_.Name
                        Length = $_.Length
                        CreationTimeUtc = $_.CreationTimeUtc.ToString('o')
                        LastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')
                    }
                }
            )
        }
    } catch {
        $sectionErrors += [ordered]@{ Source = "Startup folder: $startupPath"; Error = $_.Exception.Message }
    }
}

[ordered]@{
    RunValues = $runValues
    Services = $services
    ScheduledTasks = $tasks
    StartupItems = $startupItems
    Errors = $sectionErrors
} | ConvertTo-Json -Depth 8 -Compress
"""

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)
        if not helpers.is_windows():
            result.gaps.append(
                powershell_gap(
                    self.name,
                    "Windows persistence sources",
                    "Registry, Windows services and Scheduled Tasks are unavailable on this OS",
                )
            )
            return finish(result)

        query = helpers.run_powershell_json(
            self._SCRIPT,
            timeout=60,
            env={
                "NODETRACE_USER_STARTUP": helpers.known_folder_path("startup"),
                "NODETRACE_COMMON_STARTUP": helpers.known_folder_path("common_startup"),
            },
        )
        if not query.ok:
            result.gaps.append(powershell_gap(self.name, "Windows persistence sources", query.error))
            return finish(result, failed=True)
        payload = as_dict(query.data)
        observed_at = utc_now()
        suspect_value = context.suspect_path.strip()
        suspect = Path(suspect_value).expanduser() if suspect_value else Path()
        suspect_path = _normalized_windows_path(suspect_value)
        suspect_name = ntpath.basename(suspect_value).casefold()
        suspect_key: str | None = None

        def link_if_matching(evidence_key: str, candidate: str, source_label: str) -> None:
            nonlocal suspect_key
            candidate_paths = {_normalized_windows_path(item) for item in _command_path_tokens(candidate)}
            if suspect_path and suspect_path in candidate_paths:
                confidence = "high"
                rationale = f"{source_label} contains an exact executable path token equal to the suspect path"
            elif suspect_name and _contains_filename_token(candidate, suspect_name):
                confidence = "medium"
                rationale = f"{source_label} contains the suspect filename; another file with the same name is possible"
            else:
                return
            if suspect_key is None:
                suspect_key = content_file_key(suspect)
            result.relations.append(
                RelationDraft(
                    source_key=suspect_key,
                    target_key=evidence_key,
                    relation_type="possible_persistence_reference",
                    confidence=confidence,
                    rationale=rationale,
                    observed_at=observed_at,
                )
            )

        for item in as_list(payload.get("RunValues")):
            row = as_dict(item)
            if not row:
                continue
            registry_path = text(row.get("RegistryPath"))
            value_name = text(row.get("ValueName"))
            command = text(row.get("Command"))
            key = stable_hash("persistence:run", {"path": registry_path.casefold(), "name": value_name.casefold()})
            result.evidence.append(
                EvidenceDraft(
                    entity_type="run_key_value",
                    label=f"{value_name} ({registry_path})",
                    observed_at=observed_at,
                    source="Windows Run/RunOnce registry",
                    stable_key=key,
                    source_ref=f"{registry_path}::{value_name}",
                    confidence="high",
                    properties={"registry_path": registry_path, "value_name": value_name, "command": command},
                    raw=row,
                )
            )
            link_if_matching(key, command, "Run/RunOnce command")

        for item in as_list(payload.get("Services")):
            row = as_dict(item)
            if not row:
                continue
            service_name = text(row.get("Name"))
            path_name = text(row.get("PathName"))
            key = f"service:{service_name.casefold()}" if service_name else stable_hash("service", row)
            result.evidence.append(
                EvidenceDraft(
                    entity_type="windows_service",
                    label=text(row.get("DisplayName")) or service_name or "Unnamed service",
                    observed_at=observed_at,
                    source="Win32_Service",
                    stable_key=key,
                    source_ref=service_name,
                    confidence="high",
                    properties={
                        "name": service_name,
                        "display_name": text(row.get("DisplayName")),
                        "state": text(row.get("State")),
                        "start_mode": text(row.get("StartMode")),
                        "path_name": path_name,
                        "start_name": text(row.get("StartName")),
                        "process_id": row.get("ProcessId"),
                        "service_type": text(row.get("ServiceType")),
                    },
                    raw=row,
                )
            )
            link_if_matching(key, path_name, "Service ImagePath")

        for item in as_list(payload.get("ScheduledTasks")):
            row = as_dict(item)
            if not row:
                continue
            task_path = text(row.get("TaskPath"))
            task_name = text(row.get("TaskName"))
            actions = [as_dict(action) for action in as_list(row.get("Actions")) if isinstance(action, dict)]
            action_text = " ".join(
                " ".join(
                    filter(
                        None,
                        [text(action.get("Execute")), text(action.get("Arguments")), text(action.get("WorkingDirectory"))],
                    )
                )
                for action in actions
            )
            key = stable_hash("task", {"path": task_path.casefold(), "name": task_name.casefold()})
            result.evidence.append(
                EvidenceDraft(
                    entity_type="scheduled_task",
                    label=f"{task_path}{task_name}",
                    observed_at=observed_at,
                    source="Get-ScheduledTask",
                    stable_key=key,
                    source_ref=f"{task_path}{task_name}",
                    confidence="high",
                    properties={
                        "task_path": task_path,
                        "task_name": task_name,
                        "state": text(row.get("State")),
                        "author": text(row.get("Author")),
                        "description": text(row.get("Description")),
                        "actions": actions,
                    },
                    raw=row,
                )
            )
            link_if_matching(key, action_text, "Scheduled Task action")

        for item in as_list(payload.get("StartupItems")):
            row = as_dict(item)
            if not row:
                continue
            full_name = text(row.get("FullName"))
            key = stable_hash("startup:item", normalized_path(full_name).casefold() if full_name else row)
            result.evidence.append(
                EvidenceDraft(
                    entity_type="startup_item",
                    label=text(row.get("Name")) or Path(full_name).name or "Startup item",
                    observed_at=text(row.get("LastWriteTimeUtc")) or observed_at,
                    source="Windows Startup folders",
                    stable_key=key,
                    source_ref=full_name,
                    confidence="high",
                    properties={
                        "path": full_name,
                        "size": row.get("Length"),
                        "created_utc": text(row.get("CreationTimeUtc")),
                        "modified_utc": text(row.get("LastWriteTimeUtc")),
                    },
                    raw=row,
                )
            )
            link_if_matching(key, full_name, "Startup folder path")

        for item in as_list(payload.get("Errors")):
            error = as_dict(item)
            result.gaps.append(
                powershell_gap(
                    self.name,
                    text(error.get("Source")) or "Windows persistence source",
                    text(error.get("Error")),
                )
            )

        result.raw_payload = {
            "run_value_count": len(as_list(payload.get("RunValues"))),
            "service_count": len(as_list(payload.get("Services"))),
            "scheduled_task_count": len(as_list(payload.get("ScheduledTasks"))),
            "startup_item_count": len(as_list(payload.get("StartupItems"))),
            "errors": as_list(payload.get("Errors")),
        }
        return finish(result)
