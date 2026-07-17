from __future__ import annotations

"""Read preserved EVTX files through the native Windows Event Log API.

This backend needs neither PowerShell nor Get-WinEvent, which Microsoft marks
unsupported in WinPE.  It only opens explicit EVTX paths and renders event XML;
it does not subscribe to or modify the running WinPE event service.
"""

from ctypes import (
    POINTER,
    WinDLL,
    byref,
    c_bool,
    c_uint32,
    c_void_p,
    c_wchar,
    c_wchar_p,
    create_unicode_buffer,
    get_last_error,
    sizeof,
)
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Callable, Iterable
from xml.etree import ElementTree


EVT_QUERY_FILE_PATH = 0x2
EVT_QUERY_REVERSE_DIRECTION = 0x200
EVT_RENDER_EVENT_XML = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259


class NativeEvtxError(RuntimeError):
    pass


def _windows_error(code: int) -> str:
    try:
        import ctypes

        rendered = ctypes.FormatError(code).strip()
    except Exception:
        rendered = ""
    return f"Windows error {code}" + (f": {rendered}" if rendered else "")


def _parse_utc(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def parse_event_xml(xml_text: str, *, fallback_log_name: str = "") -> dict[str, object]:
    """Convert rendered event XML to the collector's stable event dictionary."""

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NativeEvtxError(f"EvtRender returned malformed event XML: {exc}") from exc

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    system = next((child for child in root if local(child.tag) == "System"), None)
    if system is None:
        raise NativeEvtxError("rendered event XML has no System element")
    system_items = {local(item.tag): item for item in system}
    event_id_node = system_items.get("EventID")
    time_node = system_items.get("TimeCreated")
    provider_node = system_items.get("Provider")
    execution_node = system_items.get("Execution")
    channel_node = system_items.get("Channel")
    record_node = system_items.get("EventRecordID")
    computer_node = system_items.get("Computer")
    level_node = system_items.get("Level")

    event_data: dict[str, str] = {}
    field_index = 0
    for section in root:
        section_name = local(section.tag)
        if section_name not in {"EventData", "UserData"}:
            continue
        for node in section.iter():
            if node is section:
                continue
            name = str(node.attrib.get("Name") or local(node.tag) or f"Field{field_index}")
            value = str(node.text or "")
            if name in event_data:
                name = f"{name}_{field_index}"
            event_data[name] = value
            field_index += 1

    def integer(value: object) -> int | None:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None

    event_id = integer(event_id_node.text if event_id_node is not None else None) or 0
    record_id = integer(record_node.text if record_node is not None else None)
    process_id = integer(
        execution_node.attrib.get("ProcessID") if execution_node is not None else None
    )
    thread_id = integer(
        execution_node.attrib.get("ThreadID") if execution_node is not None else None
    )
    time_created = str(
        time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    )
    log_name = str(channel_node.text or "") if channel_node is not None else fallback_log_name
    provider = str(provider_node.attrib.get("Name", "")) if provider_node is not None else ""
    level = integer(level_node.text if level_node is not None else None)

    return {
        "LogName": log_name or fallback_log_name,
        "Id": event_id,
        "RecordId": record_id,
        "TimeCreatedUtc": time_created,
        "ProviderName": provider,
        "LevelDisplayName": str(level) if level is not None else "",
        "MachineName": str(computer_node.text or "") if computer_node is not None else "",
        "ProcessId": process_id,
        "ThreadId": thread_id,
        # Offline message formatting would load provider DLLs from a target OS
        # and is intentionally avoided. EventData retains the exact fields used
        # for source/process/file normalization.
        "Message": "",
        "MessageTruncated": False,
        "EventData": event_data,
    }


class _WevtApi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise NativeEvtxError("the native EVTX backend is available only on Windows")
        try:
            self.dll = WinDLL("wevtapi.dll", use_last_error=True)
        except OSError as exc:
            raise NativeEvtxError(f"wevtapi.dll is unavailable: {exc}") from exc

        self.query = self.dll.EvtQuery
        self.query.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_uint32]
        self.query.restype = c_void_p
        self.next = self.dll.EvtNext
        self.next.argtypes = [
            c_void_p,
            c_uint32,
            POINTER(c_void_p),
            c_uint32,
            c_uint32,
            POINTER(c_uint32),
        ]
        self.next.restype = c_bool
        self.render = self.dll.EvtRender
        self.render.argtypes = [
            c_void_p,
            c_void_p,
            c_uint32,
            c_uint32,
            c_void_p,
            POINTER(c_uint32),
            POINTER(c_uint32),
        ]
        self.render.restype = c_bool
        self.close = self.dll.EvtClose
        self.close.argtypes = [c_void_p]
        self.close.restype = c_bool

    def event_xml(self, handle: c_void_p) -> str:
        used = c_uint32(0)
        properties = c_uint32(0)
        if self.render(
            None,
            handle,
            EVT_RENDER_EVENT_XML,
            0,
            None,
            byref(used),
            byref(properties),
        ):
            raise NativeEvtxError("EvtRender unexpectedly succeeded without a buffer")
        error = get_last_error()
        if error != ERROR_INSUFFICIENT_BUFFER or used.value < sizeof(c_uint32):
            raise NativeEvtxError(f"EvtRender sizing failed: {_windows_error(error)}")
        buffer = create_unicode_buffer((used.value + sizeof(c_wchar) - 1) // sizeof(c_wchar))
        if not self.render(
            None,
            handle,
            EVT_RENDER_EVENT_XML,
            used.value,
            buffer,
            byref(used),
            byref(properties),
        ):
            raise NativeEvtxError(f"EvtRender failed: {_windows_error(get_last_error())}")
        return buffer.value


def query_file(
    path: str | Path,
    *,
    event_ids: Iterable[int],
    start_time_utc: str,
    end_time_utc: str,
    max_events: int,
    log_name: str,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[list[dict[str, object]], bool]:
    """Read newest matching events from one explicit EVTX file."""

    source = Path(path).expanduser().absolute()
    if not source.is_file():
        raise NativeEvtxError(f"EVTX file is absent: {source}")
    ids = sorted({int(value) for value in event_ids if int(value) >= 0})
    if not ids:
        raise NativeEvtxError("no event IDs were supplied")
    limit = max(1, min(5000, int(max_events)))
    expression = " or ".join(f"EventID={value}" for value in ids)
    xpath = f"*[System[({expression})]]"
    api = _WevtApi()
    query_handle = api.query(
        None,
        str(source),
        xpath,
        EVT_QUERY_FILE_PATH | EVT_QUERY_REVERSE_DIRECTION,
    )
    if not query_handle:
        raise NativeEvtxError(f"EvtQuery failed for {source}: {_windows_error(get_last_error())}")

    start = _parse_utc(start_time_utc)
    end = _parse_utc(end_time_utc)
    results: list[dict[str, object]] = []
    truncated = False
    batch_size = 32
    handles = (c_void_p * batch_size)()
    scanned = 0
    scan_ceiling = max(10_000, limit * 100)
    try:
        while scanned < scan_ceiling:
            if cancelled and cancelled():
                break
            returned = c_uint32(0)
            ok = api.next(query_handle, batch_size, handles, 0, 0, byref(returned))
            if not ok:
                error = get_last_error()
                if error == ERROR_NO_MORE_ITEMS:
                    break
                raise NativeEvtxError(f"EvtNext failed for {source}: {_windows_error(error)}")
            for index in range(returned.value):
                handle = handles[index]
                try:
                    if len(results) >= limit:
                        truncated = True
                        continue
                    event = parse_event_xml(api.event_xml(handle), fallback_log_name=log_name)
                    scanned += 1
                    observed = _parse_utc(str(event.get("TimeCreatedUtc") or ""))
                    if observed is not None and end is not None and observed > end:
                        continue
                    if observed is not None and start is not None and observed < start:
                        continue
                    results.append(event)
                finally:
                    if handle:
                        api.close(handle)
                        handles[index] = None
            if truncated:
                return results, True
    finally:
        api.close(query_handle)
    return results, truncated


__all__ = ["NativeEvtxError", "parse_event_xml", "query_file"]
