from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path, PureWindowsPath
import re
import sqlite3
import stat
from typing import Any, Iterable

from nodetrace_ir.contracts import (
    CollectionContext,
    EvidenceDraft,
    GapDraft,
    RelationDraft,
    utc_now,
)

from ._common import (
    cancelled_gap,
    content_file_key,
    finish,
    int_option,
    iso_from_timestamp,
    new_result,
    stable_hash,
)


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_SETUPAPI_SECTION = re.compile(
    r"^>>>\s*\[(?P<event>[^\]\r\n]*?)\s+-\s+"
    r"(?P<instance>(?:USBSTOR|USB)\\[^\]\r\n]+)\]\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SETUPAPI_START = re.compile(
    r"^>>>\s*Section start\s+(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
    re.IGNORECASE | re.MULTILINE,
)


def _is_reparse_or_link(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _safe_existing_path(path: Path, root: Path, *, directory: bool) -> bool:
    """Accept only a direct, non-reparse descendant of the mounted target."""

    try:
        root = root.absolute()
        candidate = path.absolute()
        relative = candidate.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            if _is_reparse_or_link(current):
                return False
        return candidate.is_dir() if directory else candidate.is_file()
    except (OSError, ValueError):
        return False


def _safe_child_directories(path: Path, root: Path) -> Iterable[Path]:
    if not _safe_existing_path(path, root, directory=True):
        return ()
    output: list[Path] = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    child = Path(entry.path)
                    if _safe_existing_path(child, root, directory=True):
                        output.append(child)
                except OSError:
                    continue
    except OSError:
        return ()
    return tuple(sorted(output, key=lambda value: value.name.casefold()))


def _offline_context_root(context: CollectionContext, collector: str) -> tuple[Path | None, GapDraft | None]:
    if str(context.options.get("target_mode") or "").strip().casefold() != "offline":
        return None, GapDraft(
            collector=collector,
            source="Offline Windows source attribution",
            reason="This collector is restricted to an explicitly mounted offline target",
            impact="No live-host browser or USB data was queried",
            recommendation="Run with target_mode=offline and an explicit offline_root",
        )
    value = str(context.options.get("offline_root") or "").strip()
    if not value:
        return None, GapDraft(
            collector=collector,
            source="Offline Windows source attribution",
            reason="offline_root was not provided",
            impact="Persistent source-attribution artifacts could not be located",
            recommendation="Set offline_root to the mounted Windows volume root",
        )
    root = Path(value).expanduser().absolute()
    if not root.is_dir():
        return None, GapDraft(
            collector=collector,
            source=str(root),
            reason="The offline target root is unavailable or is not a directory",
            impact="Persistent source-attribution artifacts could not be read",
            recommendation="Mount the affected Windows volume read-only and retry",
        )
    return root, None


def _drive_neutral_windows_path(value: str) -> str:
    """Normalize a Windows path while discarding its drive-letter assignment."""

    rendered = str(value or "").strip().strip('"').replace("/", "\\")
    if not rendered:
        return ""
    try:
        parsed = PureWindowsPath(rendered)
        parts = list(parsed.parts)
    except (TypeError, ValueError):
        return ""
    if parts and (parts[0].endswith(":\\") or parts[0].startswith("\\\\")):
        parts = parts[1:]
    normalized = "\\" + "\\".join(part.strip("\\") for part in parts if part.strip("\\"))
    return normalized.casefold()


def _suspect_target_path(suspect: Path, offline_root: Path) -> str:
    try:
        relative = suspect.absolute().relative_to(offline_root.absolute())
    except ValueError:
        return ""
    return ("\\" + "\\".join(relative.parts)).casefold()


def _safe_url(value: Any) -> str:
    rendered = str(value or "").strip()
    if not rendered or len(rendered) > 8192 or _CONTROL_CHARACTERS.search(rendered):
        return ""
    return rendered


def _chrome_time(value: Any) -> str:
    try:
        micros = int(value)
        if micros <= 0:
            return ""
        moment = _CHROMIUM_EPOCH + timedelta(microseconds=micros)
        if moment.year < 1970 or moment.year > 9998:
            return ""
        return moment.replace(microsecond=0).isoformat()
    except (OverflowError, TypeError, ValueError):
        return ""


def _like_escape(value: str) -> str:
    return value.replace("!", "!!").replace("%", "!%").replace("_", "!_")


@dataclass(frozen=True, slots=True)
class _HistoryLocation:
    path: Path
    browser: str
    user: str
    profile: str


class OfflineBrowserDownloadCollector:
    """Correlate a mounted file with persistent Chromium download records.

    History databases are opened through SQLite ``mode=ro&immutable=1``.  This
    prevents lock files, journals, or WAL side effects on the investigated
    volume.  A non-empty pre-existing WAL is reported as a coverage gap because
    immutable mode intentionally ignores uncheckpointed records.
    """

    name = "offline_browser_downloads"
    display_name = "Offline Edge/Chrome download history"
    supports_offline = True

    _BROWSERS = (
        ("Google Chrome", ("Google", "Chrome", "User Data")),
        ("Microsoft Edge", ("Microsoft", "Edge", "User Data")),
    )
    _DOWNLOAD_FIELDS = (
        "id",
        "current_path",
        "target_path",
        "start_time",
        "end_time",
        "received_bytes",
        "total_bytes",
        "state",
        "danger_type",
        "interrupt_reason",
        "referrer",
        "tab_url",
        "tab_referrer_url",
        "mime_type",
        "original_mime_type",
        "guid",
    )

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)

        offline_root, root_gap = _offline_context_root(context, self.name)
        if root_gap is not None or offline_root is None:
            result.gaps.append(root_gap)  # type: ignore[arg-type]
            return finish(result, failed=True)

        suspect = Path(context.suspect_path).expanduser().absolute()
        suspect_name = suspect.name
        suspect_relative = _suspect_target_path(suspect, offline_root)
        if not suspect_name:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=context.suspect_path,
                    reason="The suspect path has no filename for browser-history correlation",
                    impact="Download rows could not be matched to the investigated artifact",
                    recommendation="Provide the original file path within the mounted Windows target",
                )
            )
            return finish(result, failed=True)

        max_databases = int_option(
            context.options, "offline_browser_max_databases", 64, 1, 512
        )
        max_rows = int_option(
            context.options, "offline_browser_max_rows_per_database", 500, 1, 5000
        )
        max_chain = int_option(
            context.options, "offline_browser_max_url_chain", 32, 1, 128
        )
        max_database_bytes = int_option(
            context.options,
            "offline_browser_max_database_bytes",
            2 * 1024 * 1024 * 1024,
            1024 * 1024,
            8 * 1024 * 1024 * 1024,
        )
        locations, enumeration_truncated = self._history_locations(
            offline_root, max_databases
        )
        suspect_key: str | None = None
        databases_queried = 0
        rows_matched = 0
        query_errors: list[str] = []
        wal_databases: list[str] = []
        oversized: list[str] = []
        row_limited_databases: list[str] = []

        for location in locations:
            if context.cancel_event.is_set():
                result.gaps.append(cancelled_gap(self.name))
                break
            try:
                size = location.path.stat().st_size
            except OSError as exc:
                query_errors.append(f"{location.path}: {exc}")
                continue
            if size > max_database_bytes:
                oversized.append(str(location.path))
                continue
            wal = location.path.with_name(f"{location.path.name}-wal")
            try:
                if _safe_existing_path(wal, offline_root, directory=False) and wal.stat().st_size:
                    wal_databases.append(str(location.path))
            except OSError:
                pass
            try:
                rows, rows_truncated = self._query_history(
                    location.path,
                    suspect_name=suspect_name,
                    max_rows=max_rows,
                    max_chain=max_chain,
                    cancel_event=context.cancel_event,
                )
                databases_queried += 1
                if rows_truncated:
                    row_limited_databases.append(str(location.path))
            except (OSError, sqlite3.Error, ValueError) as exc:
                query_errors.append(f"{location.path}: {exc}")
                continue

            for row in rows:
                target_path = str(row.get("target_path") or row.get("current_path") or "")
                normalized_target = _drive_neutral_windows_path(target_path)
                exact_path = bool(suspect_relative and normalized_target == suspect_relative)
                filename_match = PureWindowsPath(target_path).name.casefold() == suspect_name.casefold()
                if not filename_match:
                    continue
                chain = [url for url in row.pop("_url_chain", []) if _safe_url(url)]
                chain_truncated = bool(row.pop("_url_chain_truncated", False))
                chain_initial_url = _safe_url(row.pop("_url_chain_initial", ""))
                chain_final_url = _safe_url(row.pop("_url_chain_final", ""))
                direct_url = chain_final_url
                url_role = "final_url_chain_entry"
                if not direct_url:
                    direct_url = _safe_url(row.get("tab_url"))
                    url_role = "tab_url_context"
                if not direct_url:
                    direct_url = _safe_url(row.get("referrer") or row.get("tab_referrer_url"))
                    url_role = "referrer_context"
                if not direct_url:
                    continue

                rows_matched += 1
                observed_at = _chrome_time(row.get("start_time")) or started_at
                source_ref = f"{location.path}#downloads:{row.get('id', '')}"
                origin_key = stable_hash(
                    "download_origin:chromium",
                    {
                        "database": str(location.path.relative_to(offline_root)).casefold(),
                        "download_id": row.get("id"),
                        "url": direct_url,
                    },
                    64,
                )
                match_basis = "exact_drive_neutral_target_path" if exact_path else "filename_only"
                evidence_confidence = "high" if url_role == "final_url_chain_entry" else "medium"
                properties = {
                    "url": direct_url,
                    "download_url": direct_url if url_role == "final_url_chain_entry" else "",
                    "url_role": url_role,
                    "initial_url": chain_initial_url,
                    "redirect_chain": chain,
                    "redirect_chain_truncated": chain_truncated,
                    "browser": location.browser,
                    "windows_user": location.user,
                    "browser_profile": location.profile,
                    "history_database": str(location.path),
                    "download_id": row.get("id"),
                    "target_path": row.get("target_path") or "",
                    "current_path": row.get("current_path") or "",
                    "start_time_utc": _chrome_time(row.get("start_time")),
                    "end_time_utc": _chrome_time(row.get("end_time")),
                    "received_bytes": row.get("received_bytes"),
                    "total_bytes": row.get("total_bytes"),
                    "state": row.get("state"),
                    "danger_type": row.get("danger_type"),
                    "interrupt_reason": row.get("interrupt_reason"),
                    "referrer_url": _safe_url(row.get("referrer")),
                    "tab_url": _safe_url(row.get("tab_url")),
                    "tab_referrer_url": _safe_url(row.get("tab_referrer_url")),
                    "mime_type": row.get("mime_type") or "",
                    "original_mime_type": row.get("original_mime_type") or "",
                    "guid": row.get("guid") or "",
                    "match_basis": match_basis,
                    "browser_recorded_download": url_role == "final_url_chain_entry",
                    "content_identity_proven": False,
                    "database_open_mode": "mode=ro&immutable=1",
                }
                result.evidence.append(
                    EvidenceDraft(
                        entity_type="download_origin",
                        label=direct_url,
                        observed_at=observed_at,
                        source=f"Offline {location.browser} History database",
                        stable_key=origin_key,
                        source_ref=source_ref,
                        confidence=evidence_confidence,
                        properties=properties,
                        raw={
                            key: value
                            for key, value in row.items()
                            if key in self._DOWNLOAD_FIELDS
                        },
                    )
                )
                if suspect_key is None:
                    suspect_key = content_file_key(suspect)
                relation_confidence = (
                    "medium"
                    if exact_path and url_role == "final_url_chain_entry"
                    else "low"
                )
                result.relations.append(
                    RelationDraft(
                        source_key=origin_key,
                        target_key=suspect_key,
                        relation_type="reported_download_source",
                        confidence=relation_confidence,
                        rationale=(
                            "The offline Chromium downloads row records this URL and the exact drive-neutral "
                            "target path of the suspect file. The mutable browser database does not prove "
                            "that the current file bytes are identical to the downloaded bytes."
                            if relation_confidence == "medium"
                            else
                            "The offline Chromium record shares only the suspect filename or page context. "
                            "This is a hypothesis, not proof that this URL delivered the investigated file."
                        ),
                        observed_at=observed_at,
                    )
                )

        if enumeration_truncated:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(offline_root / "Users"),
                    reason=f"Browser History enumeration reached the limit of {max_databases} databases",
                    impact="A later user profile or browser profile may not have been inspected",
                    recommendation="Increase offline_browser_max_databases for the preserved target",
                )
            )
        if wal_databases:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Chromium History WAL",
                    reason=(
                        f"{len(wal_databases)} database(s) had a non-empty WAL; immutable read-only mode "
                        "did not replay it"
                    ),
                    impact="The newest uncheckpointed download records may be absent",
                    recommendation=(
                        "Preserve History together with its -wal and -shm files, then analyze a forensic copy "
                        "with a WAL-aware tool"
                    ),
                )
            )
        if oversized:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Chromium History databases",
                    reason=f"{len(oversized)} database(s) exceeded the {max_database_bytes}-byte safety limit",
                    impact="Those browser download records were not queried",
                    recommendation="Raise offline_browser_max_database_bytes after preserving a forensic copy",
                )
            )
        if row_limited_databases:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Chromium downloads rows",
                    reason=(
                        f"{len(row_limited_databases)} database(s) reached the per-database limit "
                        f"of {max_rows} filename matches"
                    ),
                    impact="An older download record with the same filename may not have been inspected",
                    recommendation="Increase offline_browser_max_rows_per_database for the preserved target",
                )
            )
        if query_errors:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source="Chromium History databases",
                    reason=f"{len(query_errors)} database(s) could not be queried. Sample: {query_errors[0]}",
                    impact="Browser source attribution may be incomplete",
                    recommendation="Verify database integrity and read permissions on a forensic copy",
                )
            )

        result.raw_payload = {
            "target_mode": "offline",
            "offline_root": str(offline_root),
            "suspect_relative_path": suspect_relative,
            "history_databases_found": len(locations),
            "history_databases_queried": databases_queried,
            "matching_rows_with_url": rows_matched,
            "enumeration_truncated": enumeration_truncated,
            "read_only_immutable": True,
            "wal_databases_ignored": wal_databases,
            "row_limited_databases": row_limited_databases,
        }
        return finish(result)

    @classmethod
    def _history_locations(
        cls, offline_root: Path, max_databases: int
    ) -> tuple[list[_HistoryLocation], bool]:
        users = offline_root / "Users"
        locations: list[_HistoryLocation] = []
        truncated = False
        for user_dir in _safe_child_directories(users, offline_root):
            local = user_dir / "AppData" / "Local"
            for browser, parts in cls._BROWSERS:
                user_data = local.joinpath(*parts)
                for profile_dir in _safe_child_directories(user_data, offline_root):
                    history = profile_dir / "History"
                    if not _safe_existing_path(history, offline_root, directory=False):
                        continue
                    if len(locations) >= max_databases:
                        truncated = True
                        return locations, truncated
                    locations.append(
                        _HistoryLocation(
                            path=history,
                            browser=browser,
                            user=user_dir.name,
                            profile=profile_dir.name,
                        )
                    )
        return locations, truncated

    @classmethod
    def _query_history(
        cls,
        path: Path,
        *,
        suspect_name: str,
        max_rows: int,
        max_chain: int,
        cancel_event: Any,
    ) -> tuple[list[dict[str, Any]], bool]:
        uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, timeout=0.25)
        connection.row_factory = sqlite3.Row
        try:
            connection.enable_load_extension(False)
            connection.execute("PRAGMA query_only=ON")
            # Abort pathological/corrupt databases and promptly honor cancellation.
            progress_calls = 0

            def progress() -> int:
                nonlocal progress_calls
                progress_calls += 1
                return int(bool(cancel_event.is_set()) or progress_calls > 20_000)

            connection.set_progress_handler(progress, 1000)
            available = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(downloads)").fetchall()
            }
            selected = [field for field in cls._DOWNLOAD_FIELDS if field in available]
            if "id" not in selected or not ({"target_path", "current_path"} & set(selected)):
                raise ValueError("downloads table lacks the required id and path columns")
            path_fields = [field for field in ("target_path", "current_path") if field in available]
            escaped_name = _like_escape(suspect_name)
            parameters: list[Any] = []
            clauses: list[str] = []
            for field in path_fields:
                clauses.extend(
                    [
                        f'"{field}" LIKE ? ESCAPE \'!\'',
                        f'"{field}" LIKE ? ESCAPE \'!\'',
                    ]
                )
                parameters.extend([f"%\\{escaped_name}", f"%/{escaped_name}"])
            order = '"start_time" DESC, "id" DESC' if "start_time" in available else '"id" DESC'
            selected_sql = ", ".join(f'"{field}"' for field in selected)
            sql = (
                f"SELECT {selected_sql} FROM downloads "
                f"WHERE {' OR '.join(clauses)} ORDER BY {order} LIMIT ?"
            )
            parameters.append(max_rows + 1)
            rows = [dict(row) for row in connection.execute(sql, parameters).fetchall()]
            rows_truncated = len(rows) > max_rows
            rows = rows[:max_rows]

            chain_available = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(downloads_url_chains)").fetchall()
            }
            if {"id", "url"}.issubset(chain_available):
                chain_order = '"chain_index" ASC' if "chain_index" in chain_available else "rowid ASC"
                for row in rows:
                    if cancel_event.is_set():
                        break
                    chain_rows = connection.execute(
                        f"SELECT \"url\" FROM downloads_url_chains WHERE \"id\" = ? "
                        f"ORDER BY {chain_order} LIMIT ?",
                        (row.get("id"), max_chain + 1),
                    ).fetchall()
                    chain_truncated = len(chain_rows) > max_chain
                    chain = [value[0] for value in chain_rows[:max_chain]]
                    initial_url = chain_rows[0][0] if chain_rows else ""
                    final_url = chain[-1] if chain else ""
                    if chain_truncated:
                        final_row = connection.execute(
                            f"SELECT \"url\" FROM downloads_url_chains WHERE \"id\" = ? "
                            f"ORDER BY {chain_order.replace('ASC', 'DESC')} LIMIT 1",
                            (row.get("id"),),
                        ).fetchone()
                        if final_row is not None:
                            final_url = final_row[0]
                            if max_chain == 1:
                                chain = [final_url]
                            elif chain and chain[-1] != final_url:
                                chain = chain[: max_chain - 1] + [final_url]
                    row["_url_chain_truncated"] = chain_truncated
                    row["_url_chain"] = chain
                    row["_url_chain_initial"] = initial_url
                    row["_url_chain_final"] = final_url
            return rows, rows_truncated
        finally:
            connection.close()


def _decode_setupapi(raw: bytes, *, started_mid_file: bool) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw[:256].count(b"\x00") > 16:
        # A tail read can begin after the UTF-16 BOM.  Aligning the seek offset
        # keeps code units intact; a replacement character at the boundary is benign.
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _setupapi_local_timestamp(value: str) -> str:
    rendered = value.strip()
    for pattern in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(rendered, pattern).isoformat()
        except ValueError:
            continue
    return ""


def _component(instance_id: str, name: str) -> str:
    match = re.search(
        rf"(?:^|[&\\]){re.escape(name)}_([^&\\]+)",
        instance_id,
        re.IGNORECASE,
    )
    return match.group(1).replace("_", " ").strip() if match else ""


def _usb_properties(instance_id: str) -> dict[str, Any]:
    normalized = instance_id.strip().rstrip(" .")
    upper = normalized.upper()
    bus = upper.partition("\\")[0]
    tail = normalized.rpartition("\\")[2]
    serial = tail
    if bus == "USBSTOR" and re.fullmatch(r"[^&\\]+&\d+", tail):
        serial = tail.rsplit("&", 1)[0]
    elif bus != "USBSTOR":
        serial = ""
    vid = _component(normalized, "VID")
    pid = _component(normalized, "PID")
    return {
        "instance_id": normalized,
        "pnp_device_id": normalized,
        "bus_type": "USB",
        "device_class": bus,
        "vendor": _component(normalized, "VEN"),
        "product": _component(normalized, "PROD"),
        "revision": _component(normalized, "REV"),
        "vendor_id": vid,
        "product_id": pid,
        "vid": vid,
        "pid": pid,
        "device_serial_number": serial,
        "historical_delivery_proven": False,
        "setupapi_observation_only": True,
    }


class OfflineUsbHistoryCollector:
    """Extract exact USB instance identifiers from the offline SetupAPI log.

    SetupAPI records device installation, not file-copy activity.  Consequently
    this collector emits no USB-to-file relation merely because a device and a
    suspect filename coexist on the same host.
    """

    name = "offline_usb_history"
    display_name = "Offline USB device-install history"
    supports_offline = True

    def collect(self, context: CollectionContext):
        started_at = utc_now()
        result = new_result(self.name, started_at)
        if context.cancel_event.is_set():
            result.gaps.append(cancelled_gap(self.name))
            return finish(result)

        offline_root, root_gap = _offline_context_root(context, self.name)
        if root_gap is not None or offline_root is None:
            result.gaps.append(root_gap)  # type: ignore[arg-type]
            return finish(result, failed=True)

        log_path = offline_root / "Windows" / "INF" / "setupapi.dev.log"
        if not _safe_existing_path(log_path, offline_root, directory=False):
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(log_path),
                    reason="The offline SetupAPI device-install log is absent, inaccessible, or a reparse path",
                    impact="Historical USB instance identifiers could not be enumerated from SetupAPI",
                    recommendation="Preserve Windows\\INF\\setupapi.dev.log from the affected installation",
                )
            )
            return finish(result)

        max_bytes = int_option(
            context.options,
            "offline_setupapi_max_bytes",
            32 * 1024 * 1024,
            1024 * 1024,
            256 * 1024 * 1024,
        )
        max_devices = int_option(
            context.options, "offline_usb_max_devices", 512, 1, 5000
        )
        try:
            size = log_path.stat().st_size
            offset = max(0, size - max_bytes)
            if offset % 2:
                offset += 1
            with log_path.open("rb") as stream:
                stream.seek(offset)
                raw = stream.read(max_bytes)
            modified_at = iso_from_timestamp(log_path.stat().st_mtime)
        except OSError as exc:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(log_path),
                    reason=f"The SetupAPI log could not be read: {exc}",
                    impact="Historical USB identifiers are unavailable",
                    recommendation="Retry with read access against a forensic copy",
                )
            )
            return finish(result, failed=True)

        text = _decode_setupapi(raw, started_mid_file=offset > 0)
        sections = list(_SETUPAPI_SECTION.finditer(text))
        observations: dict[str, dict[str, Any]] = {}
        for index, match in enumerate(sections):
            if context.cancel_event.is_set():
                result.gaps.append(cancelled_gap(self.name))
                break
            instance_id = match.group("instance").strip()
            identity = instance_id.casefold()
            end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
            section_tail = text[match.end() : min(end, match.end() + 65536)]
            timestamp_match = _SETUPAPI_START.search(section_tail)
            local_timestamp = (
                _setupapi_local_timestamp(timestamp_match.group("timestamp"))
                if timestamp_match
                else ""
            )
            current = observations.get(identity)
            if current is None:
                current = {
                    **_usb_properties(instance_id),
                    "setupapi_event": match.group("event").strip(),
                    "first_section_start_local": local_timestamp,
                    "last_section_start_local": local_timestamp,
                    "occurrence_count": 1,
                }
                observations[identity] = current
            else:
                current["occurrence_count"] = int(current["occurrence_count"]) + 1
                if local_timestamp:
                    if not current.get("first_section_start_local"):
                        current["first_section_start_local"] = local_timestamp
                    current["last_section_start_local"] = local_timestamp

        truncated_devices = len(observations) > max_devices
        ordered = sorted(
            observations.values(),
            key=lambda item: (
                str(item.get("last_section_start_local") or ""),
                str(item.get("instance_id") or "").casefold(),
            ),
            reverse=True,
        )[:max_devices]
        for properties in ordered:
            identifier = (
                str(properties.get("device_serial_number") or "")
                or ":".join(
                    value
                    for value in (
                        str(properties.get("vid") or ""),
                        str(properties.get("pid") or ""),
                    )
                    if value
                )
                or str(properties["instance_id"])
            )
            model = " ".join(
                value
                for value in (
                    str(properties.get("vendor") or ""),
                    str(properties.get("product") or ""),
                )
                if value
            )
            label = f"USB {identifier}" + (f" · {model}" if model else "")
            result.evidence.append(
                EvidenceDraft(
                    entity_type="removable_media",
                    label=label,
                    observed_at=str(properties.get("last_section_start_local") or modified_at),
                    source="Offline Windows SetupAPI device-install log",
                    stable_key=stable_hash(
                        "removable_media:setupapi", str(properties["instance_id"]).casefold(), 64
                    ),
                    source_ref=f"{log_path}#{properties['instance_id']}",
                    confidence="high",
                    properties={
                        **properties,
                        "setupapi_log": str(log_path),
                        "timestamp_timezone": "offline host local time; offset unavailable",
                        "relation_to_suspect_file": "not established",
                    },
                    raw={
                        "instance_id": properties["instance_id"],
                        "setupapi_event": properties["setupapi_event"],
                    },
                )
            )

        if offset > 0:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(log_path),
                    reason=f"Only the newest {max_bytes} bytes of the SetupAPI log were inspected",
                    impact="Older USB device-install sections may be absent",
                    recommendation="Increase offline_setupapi_max_bytes for the preserved log",
                )
            )
        if truncated_devices:
            result.gaps.append(
                GapDraft(
                    collector=self.name,
                    source=str(log_path),
                    reason=f"USB output reached the safety limit of {max_devices} unique devices",
                    impact="Older or lower-sorted device identifiers may be absent",
                    recommendation="Increase offline_usb_max_devices after preserving the source log",
                )
            )

        result.raw_payload = {
            "target_mode": "offline",
            "offline_root": str(offline_root),
            "setupapi_log": str(log_path),
            "setupapi_log_size": size,
            "bytes_read": len(raw),
            "tail_offset": offset,
            "sections_parsed": len(sections),
            "unique_usb_devices": len(observations),
            "devices_emitted": len(result.evidence),
            "usb_file_relations_emitted": 0,
            "causation_claimed": False,
        }
        return finish(result)


__all__ = ["OfflineBrowserDownloadCollector", "OfflineUsbHistoryCollector"]
