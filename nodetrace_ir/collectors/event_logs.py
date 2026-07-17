from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, GapDraft, utc_now

from . import helpers
from ._common import (
    as_dict,
    as_list,
    cancelled_gap,
    finish,
    int_option,
    integer,
    new_result,
    powershell_gap,
    stable_hash,
    text,
)
from .event_normalization import normalize_windows_event
from .evtx_native import NativeEvtxError, query_file as query_evtx_file


class EventLogCollector:
    name = "event_logs"
    display_name = "Windows event timeline"
    supports_offline = True

    _OFFLINE_SPECS = (
        ("sysmon", "Sysmon", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon%4Operational.evtx", (1, 3, 7, 11, 12, 13, 14, 22, 23, 26)),
        ("security_4688", "Security process creation", "Security", "Security.evtx", (4688,)),
        ("defender", "Microsoft Defender", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender%4Operational.evtx", (1006, 1007, 1008, 1116, 1117, 1118, 1119, 1120, 5007, 5010, 5012)),
        ("powershell_4104", "PowerShell script blocks", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell%4Operational.evtx", (4104,)),
        ("system_7045", "Service installation", "System", "System.evtx", (7045,)),
        ("task_scheduler", "Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler%4Operational.evtx", (106, 129, 140, 141, 142, 200, 201)),
    )

    _SCRIPT = r"""
$lookbackDays = [Math]::Max(1, [Math]::Min(3650, [int]$env:NODETRACE_LOOKBACK_DAYS))
$maxEvents = [Math]::Max(1, [Math]::Min(5000, [int]$env:NODETRACE_EVENT_MAX))
$endTime = [DateTimeOffset]::Parse($env:NODETRACE_END_UTC).UtcDateTime
$startTime = $endTime.AddDays(-$lookbackDays)
$specs = @(
    [ordered]@{ Key='sysmon'; Label='Sysmon'; LogName='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,3,7,11,12,13,14,22,23,26) },
    [ordered]@{ Key='security_4688'; Label='Security process creation'; LogName='Security'; Ids=@(4688) },
    [ordered]@{ Key='defender'; Label='Microsoft Defender'; LogName='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1006,1007,1008,1116,1117,1118,1119,1120,5007,5010,5012) },
    [ordered]@{ Key='powershell_4104'; Label='PowerShell script blocks'; LogName='Microsoft-Windows-PowerShell/Operational'; Ids=@(4104) },
    [ordered]@{ Key='system_7045'; Label='Service installation'; LogName='System'; Ids=@(7045) },
    [ordered]@{ Key='task_scheduler'; Label='Task Scheduler'; LogName='Microsoft-Windows-TaskScheduler/Operational'; Ids=@(106,129,140,141,142,200,201) }
)
$streams = @()
foreach ($spec in $specs) {
    $stream = [ordered]@{
        Key = $spec.Key
        Label = $spec.Label
        LogName = $spec.LogName
        Ids = $spec.Ids
        Available = $false
        Enabled = $null
        QueryError = $null
        Truncated = $false
        Events = @()
    }
    try {
        $logInfo = Get-WinEvent -ListLog $spec.LogName -ErrorAction Stop
        $stream.Available = $true
        $stream.Enabled = $logInfo.IsEnabled
        if ($logInfo.IsEnabled) {
            try {
                $filter = @{ LogName=$spec.LogName; Id=$spec.Ids; StartTime=$startTime; EndTime=$endTime }
                $queriedEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ($maxEvents + 1) -ErrorAction Stop)
                if ($queriedEvents.Count -gt $maxEvents) { $stream.Truncated = $true }
                $stream.Events = @(
                    $queriedEvents | Select-Object -First $maxEvents | ForEach-Object {
                        $message = $_.Message
                        $messageTruncated = $false
                        if ($message -and $message.Length -gt 20000) {
                            $message = $message.Substring(0, 20000)
                            $messageTruncated = $true
                        }
                        $eventData = [ordered]@{}
                        try {
                            [xml]$eventXml = $_.ToXml()
                            $fieldIndex = 0
                            foreach ($field in @($eventXml.Event.EventData.Data)) {
                                $fieldName = [string]$field.Name
                                if ([string]::IsNullOrWhiteSpace($fieldName)) { $fieldName = "Field$fieldIndex" }
                                $eventData[$fieldName] = [string]$field.'#text'
                                $fieldIndex++
                            }
                        } catch {
                            $eventData['_ParseError'] = $_.Exception.Message
                        }
                        [ordered]@{
                            LogName = $_.LogName
                            Id = $_.Id
                            RecordId = $_.RecordId
                            TimeCreatedUtc = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                            ProviderName = $_.ProviderName
                            LevelDisplayName = $_.LevelDisplayName
                            MachineName = $_.MachineName
                            ProcessId = $_.ProcessId
                            ThreadId = $_.ThreadId
                            Message = $message
                            MessageTruncated = $messageTruncated
                            EventData = $eventData
                        }
                    }
                )
            } catch {
                # No matching events is a valid result. Other failures are an evidence gap.
                if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                    $stream.QueryError = $_.Exception.Message
                }
            }
        }
    } catch {
        $stream.QueryError = $_.Exception.Message
    }
    $streams += $stream
}
[ordered]@{ StartTimeUtc=$startTime.ToString('o'); EndTimeUtc=$endTime.ToString('o'); MaxEventsPerStream=$maxEvents; Streams=$streams } |
    ConvertTo-Json -Depth 8 -Compress
"""

    _OFFLINE_SCRIPT = r"""
$lookbackDays = [Math]::Max(1, [Math]::Min(3650, [int]$env:NODETRACE_LOOKBACK_DAYS))
$maxEvents = [Math]::Max(1, [Math]::Min(5000, [int]$env:NODETRACE_EVENT_MAX))
$endTime = [DateTimeOffset]::Parse($env:NODETRACE_END_UTC).UtcDateTime
$startTime = $endTime.AddDays(-$lookbackDays)
$evtxDirectory = [IO.Path]::GetFullPath($env:NODETRACE_OFFLINE_EVTX_DIR)
$specs = @(
    [ordered]@{ Key='sysmon'; Label='Sysmon'; LogName='Microsoft-Windows-Sysmon/Operational'; FileName='Microsoft-Windows-Sysmon%4Operational.evtx'; Ids=@(1,3,7,11,12,13,14,22,23,26) },
    [ordered]@{ Key='security_4688'; Label='Security process creation'; LogName='Security'; FileName='Security.evtx'; Ids=@(4688) },
    [ordered]@{ Key='defender'; Label='Microsoft Defender'; LogName='Microsoft-Windows-Windows Defender/Operational'; FileName='Microsoft-Windows-Windows Defender%4Operational.evtx'; Ids=@(1006,1007,1008,1116,1117,1118,1119,1120,5007,5010,5012) },
    [ordered]@{ Key='powershell_4104'; Label='PowerShell script blocks'; LogName='Microsoft-Windows-PowerShell/Operational'; FileName='Microsoft-Windows-PowerShell%4Operational.evtx'; Ids=@(4104) },
    [ordered]@{ Key='system_7045'; Label='Service installation'; LogName='System'; FileName='System.evtx'; Ids=@(7045) },
    [ordered]@{ Key='task_scheduler'; Label='Task Scheduler'; LogName='Microsoft-Windows-TaskScheduler/Operational'; FileName='Microsoft-Windows-TaskScheduler%4Operational.evtx'; Ids=@(106,129,140,141,142,200,201) }
)
$streams = @()
foreach ($spec in $specs) {
    $evtxPath = Join-Path -Path $evtxDirectory -ChildPath $spec.FileName
    $stream = [ordered]@{
        Key = $spec.Key
        Label = $spec.Label
        LogName = $spec.LogName
        Path = $evtxPath
        Ids = $spec.Ids
        Available = $false
        Enabled = $true
        QueryError = $null
        Truncated = $false
        Events = @()
    }
    if (-not (Test-Path -LiteralPath $evtxPath -PathType Leaf)) {
        $stream.QueryError = 'Offline EVTX file is absent'
        $streams += $stream
        continue
    }
    $stream.Available = $true
    try {
        $idExpression = @($spec.Ids | ForEach-Object { "EventID=$_" }) -join ' or '
        $startIso = $startTime.ToString('o')
        $endIso = $endTime.ToString('o')
        $xpath = "*[System[(" + $idExpression + ") and TimeCreated[@SystemTime >= '" + $startIso + "' and @SystemTime <= '" + $endIso + "']]]"
        $queriedEvents = @(Get-WinEvent -Path $evtxPath -FilterXPath $xpath -MaxEvents ($maxEvents + 1) -ErrorAction Stop)
        if ($queriedEvents.Count -gt $maxEvents) { $stream.Truncated = $true }
        $stream.Events = @(
            $queriedEvents | Select-Object -First $maxEvents | ForEach-Object {
                $message = $_.Message
                $messageTruncated = $false
                if ($message -and $message.Length -gt 20000) {
                    $message = $message.Substring(0, 20000)
                    $messageTruncated = $true
                }
                $eventData = [ordered]@{}
                try {
                    [xml]$eventXml = $_.ToXml()
                    $fieldIndex = 0
                    foreach ($field in @($eventXml.Event.EventData.Data)) {
                        $fieldName = [string]$field.Name
                        if ([string]::IsNullOrWhiteSpace($fieldName)) { $fieldName = "Field$fieldIndex" }
                        $eventData[$fieldName] = [string]$field.'#text'
                        $fieldIndex++
                    }
                } catch {
                    $eventData['_ParseError'] = $_.Exception.Message
                }
                [ordered]@{
                    LogName = $_.LogName
                    Id = $_.Id
                    RecordId = $_.RecordId
                    TimeCreatedUtc = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                    ProviderName = $_.ProviderName
                    LevelDisplayName = $_.LevelDisplayName
                    MachineName = $_.MachineName
                    ProcessId = $_.ProcessId
                    ThreadId = $_.ThreadId
                    Message = $message
                    MessageTruncated = $messageTruncated
                    EventData = $eventData
                }
            }
        )
    } catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
            $stream.QueryError = $_.Exception.Message
        }
    }
    $streams += $stream
}
[ordered]@{
    TargetMode='offline'
    EvtxDirectory=$evtxDirectory
    StartTimeUtc=$startTime.ToString('o')
    EndTimeUtc=$endTime.ToString('o')
    MaxEventsPerStream=$maxEvents
    Streams=$streams
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
                powershell_gap(self.name, "Windows Event Logs", "Windows Event Logs are unavailable on this OS")
            )
            return finish(result)

        target_mode = str(context.options.get("target_mode") or "live").strip().casefold()
        offline_mode = target_mode == "offline"
        offline_root = Path(str(context.options.get("offline_root") or "")).expanduser()
        lookback_days = max(1, min(3650, int(context.lookback_days or 1)))
        max_events = int_option(context.options, "event_max_per_log", 500, 1, 5000)
        timeout = int_option(context.options, "event_timeout_seconds", 120, 10, 600)
        script = self._SCRIPT
        query_env = {
            "NODETRACE_LOOKBACK_DAYS": str(lookback_days),
            "NODETRACE_EVENT_MAX": str(max_events),
            "NODETRACE_END_UTC": context.started_at,
        }
        if offline_mode:
            if not str(context.options.get("offline_root") or "").strip():
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source="Offline Windows Event Logs",
                        reason="offline_root was not provided for the offline target",
                        impact="No preserved EVTX files were queried",
                        recommendation="Set offline_root to the mounted Windows volume root",
                    )
                )
                return finish(result, failed=True)
            evtx_directory = offline_root / "Windows" / "System32" / "winevt" / "Logs"
            if not evtx_directory.is_dir():
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=str(evtx_directory),
                        reason="The offline Windows EVTX directory does not exist or is inaccessible",
                        impact="No preserved Windows event timeline was collected",
                        recommendation="Mount the affected Windows volume and verify read access to its EVTX files",
                    )
                )
                return finish(result, failed=True)
            script = self._OFFLINE_SCRIPT
            query_env["NODETRACE_OFFLINE_EVTX_DIR"] = str(evtx_directory)
        payload: dict | None = None
        native_error = ""
        backend = "powershell"
        if offline_mode:
            try:
                payload = self._native_offline_payload(
                    evtx_directory,
                    end_time=context.started_at,
                    lookback_days=lookback_days,
                    max_events=max_events,
                    cancelled=context.cancel_event.is_set,
                )
                backend = "native-wevtapi"
            except NativeEvtxError as exc:
                native_error = str(exc)

        query = None
        if payload is None:
            query = helpers.run_powershell_json(
                script,
                timeout=timeout,
                env=query_env,
            )
            if query.ok:
                payload = as_dict(query.data)
                backend = "powershell-fallback" if native_error else "powershell"
        if payload is None:
            assert query is not None
            source = "Offline Windows EVTX files" if offline_mode else "Windows Event Logs"
            if offline_mode and bool(context.options.get("winpe")):
                combined_error = query.error
                if native_error:
                    combined_error = f"native wevtapi: {native_error}; PowerShell fallback: {query.error}"
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=source,
                        reason=(
                            f"Offline EVTX query failed in WinPE: {combined_error}. "
                            "Microsoft documents Get-WinEvent as unsupported in Windows PE"
                        ),
                        impact="No events from the mounted target EVTX files were added to the timeline",
                        recommendation=(
                            "Verify that wevtapi.dll can render the preserved EVTX files, or run offline "
                            "mode from a supported full Windows technician host. Adding the PowerShell "
                            "optional components alone does not make Get-WinEvent supported in WinPE"
                        ),
                    )
                )
            else:
                result.gaps.append(powershell_gap(self.name, source, query.error))
            return finish(result, failed=True)

        stream_summaries: list[dict] = []
        normalized_count = 0
        seed_key = text(context.options.get("seed_key"))
        for item in as_list(payload.get("Streams")):
            stream = as_dict(item)
            if not stream:
                continue
            label = text(stream.get("Label")) or text(stream.get("Key")) or "Event stream"
            log_name = text(stream.get("LogName"))
            evtx_path = text(stream.get("Path"))
            stream_source = evtx_path if offline_mode and evtx_path else (log_name or label)
            available = bool(stream.get("Available"))
            enabled = stream.get("Enabled") is not False
            query_error = text(stream.get("QueryError"))
            truncated = bool(stream.get("Truncated"))
            events = [as_dict(event) for event in as_list(stream.get("Events")) if isinstance(event, dict)]

            if not available:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=stream_source,
                        reason=query_error or "The event log is not installed or could not be enumerated",
                        impact=f"{label} evidence is absent from the reconstructed timeline",
                        recommendation="Enable and preserve this log before future incidents; acquire an EVTX copy if available",
                    )
                )
            elif not enabled:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=log_name or label,
                        reason="The event log exists but is disabled",
                        impact=f"{label} activity may not have been recorded",
                        recommendation="Enable this operational log and configure adequate retention",
                    )
                )
            elif query_error:
                result.gaps.append(powershell_gap(self.name, stream_source, query_error))
            if truncated:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=stream_source,
                        reason=f"Выборка достигла лимита {max_events} событий и была усечена",
                        impact="Более старые подходящие события этого канала не включены в таймлайн",
                        recommendation="Увеличьте event_max_per_log или сохраните и исследуйте полный EVTX отдельно",
                    )
                )

            message_was_truncated = False

            for event in events:
                event_id = integer(event.get("Id"), 0)
                record_id = integer(event.get("RecordId"), 0)
                event_log = text(event.get("LogName")) or log_name
                observed_at = text(event.get("TimeCreatedUtc")) or started_at
                evidence_source = (
                    f"Offline EVTX: {evtx_path}" if offline_mode and evtx_path else f"Windows Event Log: {event_log}"
                )
                evidence_ref = (
                    f"{evtx_path}#{record_id}" if offline_mode and evtx_path and record_id
                    else evtx_path if offline_mode and evtx_path
                    else f"{event_log}#{record_id}" if record_id
                    else event_log
                )
                if record_id:
                    key = stable_hash("eventlog", {"log": event_log.casefold(), "record_id": record_id})
                else:
                    key = stable_hash(
                        "eventlog",
                        {
                            "log": event_log.casefold(),
                            "event_id": event_id,
                            "time": observed_at,
                            "message": text(event.get("Message")),
                        },
                    )
                level = text(event.get("LevelDisplayName"))
                severity = "info"
                message = text(event.get("Message"))
                message_was_truncated = message_was_truncated or bool(event.get("MessageTruncated"))
                first_line = next((line.strip() for line in message.splitlines() if line.strip()), "")
                label_suffix = f": {first_line[:160]}" if first_line else ""
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="event",
                        label=f"{label} / {event_id}{label_suffix}",
                        observed_at=observed_at,
                        source=evidence_source,
                        stable_key=key,
                        source_ref=evidence_ref,
                        confidence="high",
                        severity=severity,
                        properties={
                            "stream_key": text(stream.get("Key")),
                            "log_name": event_log,
                            "event_id": event_id,
                            "record_id": record_id or None,
                            "provider": text(event.get("ProviderName")),
                            "level": level,
                            "machine_name": text(event.get("MachineName")),
                            "process_id": event.get("ProcessId"),
                            "thread_id": event.get("ThreadId"),
                            "message": message,
                        },
                        raw=event,
                    )
                )
                typed_evidence, typed_relations = normalize_windows_event(
                    event,
                    text(stream.get("Key")),
                    observed_at,
                    evidence_source,
                    evidence_ref,
                    suspect_path=context.suspect_path,
                    seed_key=seed_key,
                )
                result.evidence.extend(typed_evidence)
                result.relations.extend(typed_relations)
                normalized_count += len(typed_evidence)

            if message_was_truncated:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=stream_source,
                        reason="Одно или несколько текстовых сообщений длиннее 20 000 символов сохранены частично",
                        impact="Хвост исходного Message отсутствует; структурированные EventData сохранены отдельно",
                        recommendation="Проверьте исходную запись в EVTX по RecordId",
                    )
                )

            stream_summaries.append(
                {
                    "key": text(stream.get("Key")),
                    "log_name": log_name,
                    "path": evtx_path,
                    "available": available,
                    "enabled": enabled,
                    "event_count": len(events),
                    "query_error": query_error,
                    "truncated": truncated,
                    "message_truncated": message_was_truncated,
                }
            )

        result.raw_payload = {
            "target_mode": "offline" if offline_mode else "live",
            "offline_root": str(offline_root) if offline_mode else "",
            "start_time_utc": text(payload.get("StartTimeUtc")),
            "end_time_utc": text(payload.get("EndTimeUtc")) or context.started_at,
            "lookback_days": lookback_days,
            "max_events_per_stream": max_events,
            "streams": stream_summaries,
            "normalized_entity_count": normalized_count,
            "backend": backend,
            "native_fallback_error": native_error,
        }
        return finish(result)

    @classmethod
    def _native_offline_payload(
        cls,
        evtx_directory: Path,
        *,
        end_time: str,
        lookback_days: int,
        max_events: int,
        cancelled,
    ) -> dict:
        raw_end = str(end_time or "").strip()
        if raw_end.endswith("Z"):
            raw_end = raw_end[:-1] + "+00:00"
        try:
            end = datetime.fromisoformat(raw_end)
        except ValueError as exc:
            raise NativeEvtxError(f"invalid collection end timestamp: {end_time}") from exc
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        end = end.astimezone(timezone.utc)
        start = end - timedelta(days=lookback_days)
        start_text = start.isoformat()
        end_text = end.isoformat()
        streams: list[dict] = []
        existing = 0
        successful = 0
        errors: list[str] = []

        for key, label, log_name, file_name, ids in cls._OFFLINE_SPECS:
            path = evtx_directory / file_name
            stream = {
                "Key": key,
                "Label": label,
                "LogName": log_name,
                "Path": str(path),
                "Ids": list(ids),
                "Available": False,
                "Enabled": True,
                "QueryError": None,
                "Truncated": False,
                "Events": [],
            }
            if not path.is_file():
                stream["QueryError"] = "Offline EVTX file is absent"
                streams.append(stream)
                continue
            existing += 1
            stream["Available"] = True
            try:
                events, truncated = query_evtx_file(
                    path,
                    event_ids=ids,
                    start_time_utc=start_text,
                    end_time_utc=end_text,
                    max_events=max_events,
                    log_name=log_name,
                    cancelled=cancelled,
                )
                stream["Events"] = events
                stream["Truncated"] = truncated
                successful += 1
            except NativeEvtxError as exc:
                stream["QueryError"] = str(exc)
                errors.append(f"{file_name}: {exc}")
            streams.append(stream)

        # An invalid fixture, missing API, or uniformly unreadable media gets a
        # chance to use the full-Windows PowerShell backend. Missing files are
        # not an API failure and remain explicit per-stream gaps.
        if existing and not successful:
            raise NativeEvtxError("; ".join(errors) or "all existing EVTX files failed")
        return {
            "TargetMode": "offline",
            "EvtxDirectory": str(evtx_directory),
            "StartTimeUtc": start_text,
            "EndTimeUtc": end_text,
            "MaxEventsPerStream": max_events,
            "Streams": streams,
        }
