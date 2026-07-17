from __future__ import annotations

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, GapDraft, RelationDraft, utc_now

from . import helpers
from ._common import (
    as_dict,
    as_list,
    cancelled_gap,
    finish,
    integer,
    new_result,
    powershell_gap,
    process_instance_key,
    stable_hash,
    text,
)


class NetworkCollector:
    name = "network"
    display_name = "TCP connections and DNS cache"

    _SCRIPT = r"""
$sectionErrors = @()
$tcp = @()
$processes = @()
$dns = @()

try {
    $tcp = @(
        Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = [string]$_.State
                OwningProcess = $_.OwningProcess
                AppliedSetting = [string]$_.AppliedSetting
                CreationTimeUtc = if ($_.CreationTime) { $_.CreationTime.ToUniversalTime().ToString('o') } else { $null }
            }
        }
    )
} catch {
    $sectionErrors += [ordered]@{ Source = 'Get-NetTCPConnection'; Error = $_.Exception.Message }
}

try {
    $processes = @(
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                ProcessId = $_.ProcessId
                Name = $_.Name
                ExecutablePath = $_.ExecutablePath
                CommandLine = $_.CommandLine
                CreationDateUtc = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
            }
        }
    )
} catch {
    $sectionErrors += [ordered]@{ Source = 'Win32_Process mapping'; Error = $_.Exception.Message }
}

try {
    if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        $dns = @(
            Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    Entry = $_.Entry
                    Name = $_.Name
                    Data = $_.Data
                    Type = [string]$_.Type
                    Status = [string]$_.Status
                    Section = [string]$_.Section
                    TimeToLive = $_.TimeToLive
                }
            }
        )
    } else {
        $sectionErrors += [ordered]@{ Source = 'Get-DnsClientCache'; Error = 'Cmdlet is unavailable' }
    }
} catch {
    $sectionErrors += [ordered]@{ Source = 'Get-DnsClientCache'; Error = $_.Exception.Message }
}

[ordered]@{ Tcp = $tcp; Processes = $processes; Dns = $dns; Errors = $sectionErrors } |
    ConvertTo-Json -Depth 6 -Compress
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
                    "Get-NetTCPConnection and Get-DnsClientCache",
                    "Windows network inventory cmdlets are unavailable on this OS",
                )
            )
            return finish(result)

        query = helpers.run_powershell_json(self._SCRIPT, timeout=45)
        if not query.ok:
            result.gaps.append(powershell_gap(self.name, "Windows network snapshot", query.error))
            return finish(result, failed=True)

        payload = as_dict(query.data)
        process_map: dict[int, dict] = {}
        for item in as_list(payload.get("Processes")):
            row = as_dict(item)
            pid = integer(row.get("ProcessId"), -1)
            if pid >= 0:
                process_map[pid] = row

        observed_at = utc_now()
        for item in as_list(payload.get("Tcp")):
            row = as_dict(item)
            if not row:
                continue
            pid = integer(row.get("OwningProcess"), 0)
            local_address = text(row.get("LocalAddress"))
            local_port = integer(row.get("LocalPort"), 0)
            remote_address = text(row.get("RemoteAddress"))
            remote_port = integer(row.get("RemotePort"), 0)
            state = text(row.get("State")) or "Unknown"
            connection_identity = {
                "protocol": "tcp",
                "pid": pid,
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_address,
                "remote_port": remote_port,
                "state": state,
            }
            connection_key = stable_hash("connection:tcp", connection_identity)
            process = process_map.get(pid, {})
            created = text(row.get("CreationTimeUtc")) or observed_at
            properties = {
                **connection_identity,
                "process_name": text(process.get("Name")),
                "process_path": text(process.get("ExecutablePath")),
                "process_command_line": text(process.get("CommandLine")),
                "creation_time_utc": text(row.get("CreationTimeUtc")),
                "applied_setting": text(row.get("AppliedSetting")),
            }
            result.evidence.append(
                EvidenceDraft(
                    entity_type="network_connection",
                    label=f"TCP {local_address}:{local_port} -> {remote_address}:{remote_port} ({state})",
                    observed_at=created,
                    source="Get-NetTCPConnection",
                    stable_key=connection_key,
                    source_ref=f"tcp:{local_address}:{local_port}-{remote_address}:{remote_port}",
                    confidence="high",
                    properties=properties,
                    raw=row,
                )
            )
            if pid > 0:
                process_key = process_instance_key(
                    pid,
                    text(process.get("CreationDateUtc")),
                    context.started_at,
                )
                result.relations.append(
                    RelationDraft(
                        source_key=process_key,
                        target_key=connection_key,
                        relation_type="owns_connection",
                        confidence="high",
                        rationale="Get-NetTCPConnection directly reported the owning process ID",
                        observed_at=created,
                    )
                )

            if remote_address and remote_address not in {"0.0.0.0", "::", "*"} and remote_port > 0:
                endpoint_key = stable_hash(
                    "network:endpoint", {"protocol": "tcp", "address": remote_address, "port": remote_port}
                )
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="network_endpoint",
                        label=f"{remote_address}:{remote_port}",
                        observed_at=created,
                        source="Get-NetTCPConnection",
                        stable_key=endpoint_key,
                        source_ref=remote_address,
                        confidence="high",
                        properties={"protocol": "tcp", "address": remote_address, "port": remote_port},
                        raw={},
                    )
                )
                result.relations.append(
                    RelationDraft(
                        source_key=connection_key,
                        target_key=endpoint_key,
                        relation_type="remote_endpoint",
                        confidence="high",
                        rationale="The remote endpoint was present in the live TCP connection snapshot",
                        observed_at=created,
                    )
                )

        for item in as_list(payload.get("Dns")):
            row = as_dict(item)
            if not row:
                continue
            record_name = text(row.get("Entry")) or text(row.get("Name")) or "unnamed DNS record"
            record_data = text(row.get("Data"))
            record_type = text(row.get("Type"))
            dns_key = stable_hash(
                "dns:cache", {"name": record_name.casefold(), "data": record_data, "type": record_type}
            )
            result.evidence.append(
                EvidenceDraft(
                    entity_type="dns_cache_record",
                    label=f"{record_name} -> {record_data or '(negative/cache metadata)'}",
                    observed_at=observed_at,
                    source="Get-DnsClientCache",
                    stable_key=dns_key,
                    source_ref=record_name,
                    confidence="high",
                    properties={
                        "name": record_name,
                        "data": record_data,
                        "record_type": record_type,
                        "status": text(row.get("Status")),
                        "section": text(row.get("Section")),
                        "ttl_seconds": row.get("TimeToLive"),
                    },
                    raw=row,
                )
            )

        for item in as_list(payload.get("Errors")):
            error = as_dict(item)
            result.gaps.append(
                powershell_gap(
                    self.name,
                    text(error.get("Source")) or "Windows network snapshot",
                    text(error.get("Error")),
                )
            )

        result.raw_payload = {
            "tcp_count": len(as_list(payload.get("Tcp"))),
            "process_map_count": len(process_map),
            "dns_count": len(as_list(payload.get("Dns"))),
            "errors": as_list(payload.get("Errors")),
        }
        return finish(result)
