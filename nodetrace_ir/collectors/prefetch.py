from __future__ import annotations

import os
from pathlib import Path

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, GapDraft, RelationDraft, utc_now

from . import helpers
from ._common import (
    cancelled_gap,
    content_file_key,
    finish,
    int_option,
    iso_from_timestamp,
    new_result,
    stable_hash,
)


class PrefetchCollector:
    name = "prefetch"
    display_name = "Windows Prefetch metadata"
    supports_offline = True

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)
        if not helpers.is_windows():
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Windows Prefetch",
                    reason="Windows Prefetch is unavailable on this OS",
                    impact="Name-based possible-execution traces were not collected",
                    recommendation="Collect metadata from the affected host's Windows\\Prefetch directory",
                )
            )
            return finish(result)

        suspect = Path(context.suspect_path).expanduser()
        executable_name = suspect.name.upper()
        if not executable_name:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=context.suspect_path,
                    reason="The suspect path has no filename to match against Prefetch",
                    impact="Prefetch matching was skipped",
                    recommendation="Provide the original executable filename",
                )
            )
            return finish(result, failed=True)

        target_mode = str(context.options.get("target_mode") or "live").strip().casefold()
        offline_mode = target_mode == "offline"
        offline_root_value = str(context.options.get("offline_root") or "").strip()
        if offline_mode:
            if not offline_root_value:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source="Offline Windows Prefetch",
                        reason="offline_root was not provided for the offline target",
                        impact="Possible execution evidence from Prefetch was not checked",
                        recommendation="Set offline_root to the mounted Windows volume root",
                    )
                )
                return finish(result, failed=True)
            prefetch_dir = Path(offline_root_value).expanduser() / "Windows" / "Prefetch"
        else:
            configured = context.options.get("prefetch_directory")
            if configured:
                prefetch_dir = Path(str(configured)).expanduser()
            else:
                windows_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
                prefetch_dir = Path(windows_root) / "Prefetch"
        max_entries = int_option(context.options, "prefetch_max_entries", 20000, 100, 100000)

        if not prefetch_dir.is_dir():
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(prefetch_dir),
                    reason="Prefetch directory does not exist or is not accessible as a directory",
                    impact="Possible execution evidence cannot be checked by filename",
                    recommendation="Acquire the Prefetch directory from the affected system, preserving timestamps",
                )
            )
            return finish(result)

        prefix = f"{executable_name}-"
        exact = f"{executable_name}.PF"
        scanned = 0
        matched = 0
        truncated = False
        scan_errors: list[str] = []
        suspect_key: str | None = None
        try:
            with os.scandir(prefetch_dir) as iterator:
                for entry in iterator:
                    if scanned >= max_entries:
                        truncated = True
                        break
                    scanned += 1
                    if context.cancel_event.is_set():
                        result.gaps.append(cancelled_gap(self.name))
                        break
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        name_upper = entry.name.upper()
                        if not name_upper.endswith(".PF"):
                            continue
                        if not (name_upper.startswith(prefix) or name_upper == exact):
                            continue
                        stat = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        scan_errors.append(f"{entry.path}: {exc}")
                        continue

                    path = Path(entry.path)
                    key = stable_hash("prefetch:metadata", os.path.normcase(os.path.abspath(entry.path)).casefold())
                    observed_at = iso_from_timestamp(stat.st_mtime)
                    matched += 1
                    result.evidence.append(
                        EvidenceDraft(
                            entity_type="prefetch_metadata",
                            label=entry.name,
                            observed_at=observed_at,
                            source=(
                                "Offline Windows Prefetch directory metadata"
                                if offline_mode
                                else "Windows Prefetch directory metadata"
                            ),
                            stable_key=key,
                            source_ref=str(path),
                            confidence="high",
                            properties={
                                "path": str(path),
                                "filename": entry.name,
                                "matched_executable_name": executable_name,
                                "size": stat.st_size,
                                "created_utc": iso_from_timestamp(stat.st_ctime),
                                "modified_utc": observed_at,
                                "accessed_utc": iso_from_timestamp(stat.st_atime),
                                "content_parsed": False,
                                "match_basis": "executable filename only",
                            },
                            raw={"stat_mode": stat.st_mode},
                        )
                    )
                    if suspect_key is None:
                        suspect_key = content_file_key(suspect)
                    result.relations.append(
                        RelationDraft(
                            source_key=suspect_key,
                            target_key=key,
                            relation_type="possible_prefetch_name_match",
                            confidence="medium",
                            rationale=(
                                "The Prefetch filename matches the suspect executable name, which is consistent with execution; "
                                "Prefetch metadata alone does not prove the full path or that the file contents were identical"
                            ),
                            observed_at=observed_at,
                        )
                    )
        except OSError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(prefetch_dir),
                    reason=f"Prefetch directory could not be enumerated: {exc}",
                    impact="Possible execution evidence is unavailable",
                    recommendation="Retry with read access or analyze a preserved disk image",
                )
            )
            return finish(result, failed=True)

        if truncated:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(prefetch_dir),
                    reason=f"Prefetch enumeration reached the limit of {max_entries} entries",
                    impact="A later matching entry may not have been inspected",
                    recommendation="Increase prefetch_max_entries for the offline evidence set",
                )
            )
        if scan_errors:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(prefetch_dir),
                    reason=f"{len(scan_errors)} matching candidate(s) could not be read. Sample: {scan_errors[0]}",
                    impact="Some Prefetch metadata may be missing",
                    recommendation="Retry with read access or analyze a preserved disk image",
                )
            )

        result.raw_payload = {
            "target_mode": "offline" if offline_mode else "live",
            "offline_root": offline_root_value if offline_mode else "",
            "prefetch_directory": str(prefetch_dir),
            "matched_executable_name": executable_name,
            "scanned_entries": scanned,
            "matched_entries": matched,
            "truncated": truncated,
            "content_parsed": False,
        }
        return finish(result)
