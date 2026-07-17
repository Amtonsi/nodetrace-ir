from __future__ import annotations

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, RelationDraft, utc_now

from . import helpers
from ._common import as_dict, as_list, cancelled_gap, finish, integer, new_result, powershell_gap, process_instance_key, text


class LiveProcessCollector:
    name = "live_processes"
    display_name = "Live processes"

    _SCRIPT = r"""
@(
    Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine,
            @{Name='CreationDateUtc';Expression={ if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null } }},
            SessionId, HandleCount, ThreadCount, WorkingSetSize
) | ConvertTo-Json -Depth 5 -Compress
"""

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)
        if not helpers.is_windows():
            result.gaps.append(
                powershell_gap(self.name, "Win32_Process", "Win32_Process is available only on Windows")
            )
            return finish(result)

        query = helpers.run_powershell_json(self._SCRIPT, timeout=30)
        if not query.ok:
            result.gaps.append(powershell_gap(self.name, "Win32_Process", query.error))
            return finish(result, failed=True)

        rows = [as_dict(item) for item in as_list(query.data) if isinstance(item, dict)]
        observed_at = utc_now()
        known_pids: set[int] = set()
        process_keys: dict[int, str] = {}
        parent_links: list[tuple[int, int, str]] = []
        for row in rows:
            pid = integer(row.get("ProcessId"), -1)
            if pid < 0:
                continue
            ppid = integer(row.get("ParentProcessId"), -1)
            known_pids.add(pid)
            created = text(row.get("CreationDateUtc")) or observed_at
            label = text(row.get("Name")) or f"PID {pid}"
            process_key = process_instance_key(pid, created, context.started_at)
            process_keys[pid] = process_key
            properties = {
                "pid": pid,
                "parent_pid": ppid if ppid >= 0 else None,
                "name": label,
                "executable_path": text(row.get("ExecutablePath")),
                "command_line": text(row.get("CommandLine")),
                "creation_time_utc": text(row.get("CreationDateUtc")),
                "session_id": row.get("SessionId"),
                "handle_count": row.get("HandleCount"),
                "thread_count": row.get("ThreadCount"),
                "working_set_size": row.get("WorkingSetSize"),
            }
            result.evidence.append(
                EvidenceDraft(
                    entity_type="process",
                    label=f"{label} (PID {pid})",
                    observed_at=created,
                    source="Win32_Process",
                    stable_key=process_key,
                    source_ref=f"pid:{pid}",
                    confidence="high",
                    properties=properties,
                    raw=row,
                )
            )
            if ppid >= 0 and ppid != pid:
                parent_links.append((ppid, pid, created))

        for ppid, pid, created in parent_links:
            if ppid not in known_pids:
                continue
            result.relations.append(
                RelationDraft(
                    source_key=process_keys[ppid],
                    target_key=process_keys[pid],
                    relation_type="reported_parent_of",
                    confidence="medium",
                    rationale="Win32_Process reported this parent PID; PID reuse means the snapshot alone does not prove process creation",
                    observed_at=created,
                )
            )

        result.raw_payload = {"process_count": len(result.evidence)}
        return finish(result)
