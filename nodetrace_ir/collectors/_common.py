from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
from typing import Any, Iterable

from nodetrace_ir.contracts import CollectorResult, GapDraft, canonical_json, utc_now

from .helpers import hash_file


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def text(value: Any) -> str:
    return "" if value is None else str(value)


def integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def float_option(options: dict[str, Any], name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(options.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def int_option(options: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(options.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(prefix: str, value: Any, length: int = 32) -> str:
    digest = sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:length]}"


def normalized_path(path: str | os.PathLike[str]) -> str:
    value = os.path.abspath(os.fspath(path))
    return os.path.normcase(os.path.normpath(value))


def path_file_key(path: str | os.PathLike[str]) -> str:
    return stable_hash("file:path", normalized_path(path).casefold())


def content_file_key(path: str | os.PathLike[str]) -> str:
    """Return the same content key as FileSeedCollector, falling back to path."""

    try:
        return f"file:sha256:{hash_file(path)['sha256']}"
    except (OSError, ValueError):
        return path_file_key(path)


def process_instance_key(pid: int, creation_time: str, snapshot_started_at: str) -> str:
    """Identify a process instance without conflating later PID reuse."""
    anchor = creation_time or snapshot_started_at
    return stable_hash("process:instance", {"pid": int(pid), "created": anchor})


def new_result(name: str, started_at: str) -> CollectorResult:
    return CollectorResult(
        collector=name,
        started_at=started_at,
        finished_at=utc_now(),
        status="completed",
    )


def finish(result: CollectorResult, *, failed: bool = False) -> CollectorResult:
    result.finished_at = utc_now()
    if failed:
        result.status = "failed"
    elif result.gaps:
        result.status = "partial"
    else:
        result.status = "completed"
    return result


def cancelled_gap(name: str) -> GapDraft:
    return GapDraft(
        collector=name,
        source="collection control",
        reason="Collection was cancelled before this source was queried",
        impact="No evidence was collected from this source",
        recommendation="Resume collection if it is safe to continue",
    )


def powershell_gap(name: str, source: str, error: str) -> GapDraft:
    return GapDraft(
        collector=name,
        source=source,
        reason=error or "PowerShell query failed",
        impact="Evidence from this source may be incomplete",
        recommendation="Run as an administrator on the affected Windows host and preserve the original logs",
    )


def unique_paths(items: Iterable[tuple[Path, str]]) -> list[tuple[Path, str]]:
    output: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for path, role in items:
        key = normalized_path(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        output.append((path, role))
    return output
