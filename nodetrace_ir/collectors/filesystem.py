from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any

from nodetrace_ir.contracts import CollectionContext, EvidenceDraft, GapDraft, RelationDraft, utc_now

from . import helpers
from ._common import (
    cancelled_gap,
    content_file_key,
    finish,
    float_option,
    int_option,
    iso_from_timestamp,
    new_result,
    normalized_path,
    path_file_key,
    unique_paths,
)


class FilesystemContextCollector:
    name = "filesystem_context"
    display_name = "Time-adjacent filesystem context"

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)

        suspect = Path(context.suspect_path).expanduser()
        try:
            suspect_stat = suspect.stat()
        except OSError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(suspect),
                    reason=f"Temporal anchor metadata is unavailable: {exc}",
                    impact="Nearby files cannot be selected by time distance from the suspect file",
                    recommendation="Provide a preserved suspect file with original timestamps",
                )
            )
            return finish(result, failed=True)
        if not suspect.is_file():
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(suspect),
                    reason="Temporal anchor is not a regular file",
                    impact="Filesystem context collection was skipped",
                    recommendation="Select a regular suspect file",
                )
            )
            return finish(result, failed=True)

        max_entries = int_option(context.options, "filesystem_max_entries", 3000, 10, 50000)
        max_depth = int_option(context.options, "filesystem_max_depth", 2, 0, 5)
        window_hours = float_option(context.options, "filesystem_time_window_hours", 24.0, 0.1, 24 * 30)
        window_seconds = window_hours * 3600.0
        anchor_time = suspect_stat.st_mtime
        suspect_normalized = normalized_path(suspect).casefold()

        roots: list[tuple[Path, str]] = [
            (suspect.parent, "suspect_directory"),
            (Path(tempfile.gettempdir()), "temporary_directory"),
        ]
        if helpers.is_windows():
            appdata = os.environ.get("APPDATA")
            programdata = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
            if appdata:
                roots.append(
                    (Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", "user_startup")
                )
            else:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source="User Startup folder",
                        reason="APPDATA is not defined",
                        impact="Per-user Startup items were not included in the temporal scan",
                        recommendation="Collect in the affected user's session or provide that profile path",
                    )
                )
            if programdata:
                roots.append(
                    (
                        Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
                        "machine_startup",
                    )
                )
            else:
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source="Machine Startup folder",
                        reason="ProgramData is not defined",
                        impact="All-users Startup items were not included in the temporal scan",
                        recommendation="Provide the Windows ProgramData path",
                    )
                )
        else:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Windows Startup folders",
                    reason="Windows Startup locations are unavailable on this OS",
                    impact="The scan includes only the suspect directory and temporary directory",
                    recommendation="Run on the affected Windows host or mount its profile and ProgramData evidence",
                )
            )

        roots = unique_paths(roots)
        suspect_key = content_file_key(suspect)
        scanned_entries = 0
        matched_files = 0
        truncated = False
        scan_errors: list[tuple[str, str]] = []

        for root, role in roots:
            if context.cancel_event.is_set():
                result.gaps.append(cancelled_gap(self.name))
                break
            if scanned_entries >= max_entries:
                truncated = True
                break
            if not root.exists():
                result.gaps.append(
                    GapDraft(
                        collector=self.name,
                        source=str(root),
                        reason=f"Configured {role} location does not exist",
                        impact=f"No time-adjacent files were collected from {role}",
                        recommendation="Acquire this location separately if it existed at incident time",
                    )
                )
                continue

            files, used, root_truncated, errors = self._scan_root(
                root,
                max_depth=max_depth,
                remaining=max_entries - scanned_entries,
            )
            scanned_entries += used
            truncated = truncated or root_truncated
            scan_errors.extend(errors)
            for path, stat in files:
                normalized = normalized_path(path).casefold()
                if normalized == suspect_normalized:
                    continue
                modified_delta = abs(stat.st_mtime - anchor_time)
                created_delta = abs(stat.st_ctime - anchor_time)
                delta = min(modified_delta, created_delta)
                if delta > window_seconds:
                    continue
                basis = "modified" if modified_delta <= created_delta else "created_or_metadata_changed"
                target_key = path_file_key(path)
                observed_at = iso_from_timestamp(stat.st_mtime)
                matched_files += 1
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="filesystem_context_file",
                        label=path.name,
                        observed_at=observed_at,
                        source=f"bounded filesystem scan: {role}",
                        stable_key=target_key,
                        source_ref=str(path),
                        confidence="low",
                        properties={
                            "path": str(path),
                            "location_role": role,
                            "size": stat.st_size,
                            "created_or_changed_utc": iso_from_timestamp(stat.st_ctime),
                            "modified_utc": observed_at,
                            "time_delta_seconds": round(delta, 3),
                            "nearest_time_basis": basis,
                            "content_not_read": True,
                        },
                        raw={"stat_mode": stat.st_mode},
                    )
                )
                result.relations.append(
                    RelationDraft(
                        source_key=suspect_key,
                        target_key=target_key,
                        relation_type="temporally_adjacent_file",
                        confidence="low",
                        rationale=(
                            f"A file timestamp is within {delta:.0f} seconds of the suspect file's modification time; "
                            "temporal proximity alone does not prove causation"
                        ),
                        observed_at=observed_at,
                    )
                )

        if truncated:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="bounded filesystem scan",
                    reason=f"The scan reached its configured limit of {max_entries} directory entries",
                    impact="Additional time-adjacent files may exist outside the collected subset",
                    recommendation="Increase filesystem_max_entries or acquire a forensic filesystem image for offline analysis",
                )
            )
        if scan_errors:
            sample = "; ".join(f"{path}: {error}" for path, error in scan_errors[:5])
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="bounded filesystem scan",
                    reason=f"{len(scan_errors)} path(s) could not be read. Sample: {sample}",
                    impact="The temporal file context is incomplete in inaccessible locations",
                    recommendation="Retry with read access or analyze a forensic image",
                )
            )

        result.raw_payload = {
            "anchor_modified_utc": iso_from_timestamp(anchor_time),
            "time_window_hours": window_hours,
            "max_entries": max_entries,
            "max_depth": max_depth,
            "scanned_entries": scanned_entries,
            "matched_files": matched_files,
            "truncated": truncated,
            "roots": [{"path": str(path), "role": role} for path, role in roots],
        }
        return finish(result)

    @staticmethod
    def _scan_root(
        root: Path,
        *,
        max_depth: int,
        remaining: int,
    ) -> tuple[list[tuple[Path, os.stat_result]], int, bool, list[tuple[str, str]]]:
        files: list[tuple[Path, os.stat_result]] = []
        errors: list[tuple[str, str]] = []
        stack: list[tuple[Path, int]] = [(root, 0)]
        used = 0
        truncated = False
        while stack:
            directory, depth = stack.pop()
            try:
                with os.scandir(directory) as iterator:
                    for entry in iterator:
                        if used >= remaining:
                            truncated = True
                            return files, used, truncated, errors
                        used += 1
                        try:
                            if entry.is_file(follow_symlinks=False):
                                files.append((Path(entry.path), entry.stat(follow_symlinks=False)))
                            elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                                stack.append((Path(entry.path), depth + 1))
                        except OSError as exc:
                            errors.append((entry.path, str(exc)))
            except OSError as exc:
                errors.append((str(directory), str(exc)))
        return files, used, truncated, errors
