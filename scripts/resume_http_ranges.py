#!/usr/bin/env python3
"""Resume an exact HTTP payload split across stable byte-range part files.

The downloader deliberately never truncates or removes an existing part.  Each
missing tail is fetched into a separate file with curl, its final 206 response,
Content-Range and byte count are verified, and only then is it appended and
fsynced.  The completed payload is published only after its pinned digest has
been checked.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse
import uuid


CONTENT_RANGE_RE = re.compile(
    rb"(?im)^content-range:\s*bytes\s+(\d+)-(\d+)/(\d+|\*)\s*$"
)
STATUS_RE = re.compile(rb"(?im)^HTTP/(?:1(?:\.\d)?|2)\s+(\d{3})(?:\s|$)")
PRINT_LOCK = threading.Lock()


class DownloadError(RuntimeError):
    """Raised when a range cannot be proved complete and exact."""


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def part_ranges(total_size: int, part_count: int) -> list[tuple[int, int]]:
    if total_size <= 0:
        raise ValueError("total_size must be positive")
    if part_count <= 0:
        raise ValueError("part_count must be positive")
    chunk = math.ceil(total_size / part_count)
    ranges: list[tuple[int, int]] = []
    for index in range(part_count):
        start = index * chunk
        if start >= total_size:
            raise ValueError("part_count exceeds total_size")
        ranges.append((start, min(total_size - 1, start + chunk - 1)))
    return ranges


def sha_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def retain(path: Path, label: str) -> Path:
    retained = path.with_name(
        f"{path.name}.{label}.retained-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
    )
    path.replace(retained)
    return retained


def validate_headers(
    header_path: Path,
    request_start: int,
    request_end: int,
    total_size: int,
) -> None:
    raw = header_path.read_bytes()
    statuses = STATUS_RE.findall(raw)
    if not statuses or int(statuses[-1]) != 206:
        rendered = statuses[-1].decode("ascii") if statuses else "missing"
        raise DownloadError(f"final HTTP status is {rendered}, expected 206")
    ranges = CONTENT_RANGE_RE.findall(raw)
    if not ranges:
        raise DownloadError("the final response has no Content-Range header")
    start_raw, end_raw, total_raw = ranges[-1]
    actual_start = int(start_raw)
    actual_end = int(end_raw)
    if total_raw == b"*":
        raise DownloadError("Content-Range total is unknown")
    actual_total = int(total_raw)
    if (actual_start, actual_end, actual_total) != (
        request_start,
        request_end,
        total_size,
    ):
        raise DownloadError(
            "unexpected Content-Range "
            f"{actual_start}-{actual_end}/{actual_total}; expected "
            f"{request_start}-{request_end}/{total_size}"
        )


def resume_one(
    *,
    index: int,
    part_path: Path,
    range_start: int,
    range_end: int,
    total_size: int,
    url: str,
    curl: str,
    retry: int,
    connect_timeout: int,
    chunk_size: int | None = None,
) -> dict[str, object]:
    expected_part_size = range_end - range_start + 1
    current_size = part_path.stat().st_size if part_path.exists() else 0
    if current_size > expected_part_size:
        raise DownloadError(
            f"{part_path.name} is {current_size} bytes, larger than its exact "
            f"{expected_part_size}-byte range"
        )
    if current_size == expected_part_size:
        log(f"[{index:02d}] already complete: {part_path.name} ({current_size} bytes)")
        return {"index": index, "path": str(part_path), "bytes": current_size, "reused": True}
    if chunk_size is not None and chunk_size <= 0:
        raise DownloadError("chunk_size must be positive")

    applied_chunks: list[str] = []
    reused = current_size > 0
    while current_size < expected_part_size:
        request_start = range_start + current_size
        request_end = range_end
        if chunk_size is not None:
            request_end = min(request_end, request_start + chunk_size - 1)
        request_size = request_end - request_start + 1
        scratch = part_path.with_name(
            f"{part_path.name}.resume-{request_start}-{request_end}.download"
        )
        headers = scratch.with_suffix(scratch.suffix + ".headers")
        curl_log = scratch.with_suffix(scratch.suffix + ".curl.log")
        for old in (scratch, headers, curl_log):
            if old.exists():
                retained = retain(old, "preexisting")
                log(f"[{index:02d}] retained prior scratch as {retained.name}")

        command = [
            curl,
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry-all-errors",
            "--retry",
            str(retry),
            "--connect-timeout",
            str(connect_timeout),
            "--range",
            f"{request_start}-{request_end}",
            "--dump-header",
            str(headers),
            "--output",
            str(scratch),
            url,
        ]
        log(
            f"[{index:02d}] curl bytes {request_start}-{request_end} "
            f"({request_size}-byte verified chunk)"
        )
        with curl_log.open("ab") as error_stream:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=error_stream,
                check=False,
            )
            error_stream.flush()
            os.fsync(error_stream.fileno())
        if result.returncode != 0:
            raise DownloadError(
                f"curl failed for part {index:02d} with exit {result.returncode}; "
                f"retained {scratch.name} and {curl_log.name}"
            )
        if not scratch.is_file() or scratch.stat().st_size != request_size:
            actual = scratch.stat().st_size if scratch.exists() else -1
            raise DownloadError(
                f"part {index:02d} range body is {actual} bytes, expected {request_size}"
            )
        if not headers.is_file():
            raise DownloadError(f"curl did not write headers for part {index:02d}")
        validate_headers(headers, request_start, request_end, total_size)

        observed_size = part_path.stat().st_size if part_path.exists() else 0
        if observed_size != current_size:
            raise DownloadError(
                f"{part_path.name} changed concurrently ({current_size} -> {observed_size}); "
                "the verified scratch file was retained but not appended"
            )
        part_path.parent.mkdir(parents=True, exist_ok=True)
        with part_path.open("ab") as output, scratch.open("rb") as source:
            shutil.copyfileobj(source, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        final_size = part_path.stat().st_size
        expected_after_append = current_size + request_size
        if final_size != expected_after_append:
            raise DownloadError(
                f"{part_path.name} is {final_size} bytes after append, expected "
                f"{expected_after_append}; no data was removed"
            )
        applied = scratch.with_suffix(scratch.suffix + ".applied")
        scratch.replace(applied)
        applied_chunks.append(str(applied))
        current_size = final_size
        log(
            f"[{index:02d}] verified {current_size}/{expected_part_size} bytes "
            f"in {part_path.name}"
        )

    log(f"[{index:02d}] complete: {part_path.name} ({current_size} bytes)")
    return {
        "index": index,
        "path": str(part_path),
        "bytes": current_size,
        "range_start": range_start,
        "range_end": range_end,
        "verified_chunks": applied_chunks,
        "reused": reused,
    }


def aggregate_progress(parts: list[Path], ranges: list[tuple[int, int]]) -> tuple[int, int]:
    complete = 0
    downloaded = 0
    for part, (start, end) in zip(parts, ranges):
        expected = end - start + 1
        size = part.stat().st_size if part.exists() else 0
        downloaded += min(size, expected)
        if size == expected:
            complete += 1
    return complete, downloaded


def assemble(
    parts: list[Path],
    output: Path,
    total_size: int,
    expected_sha1: str,
) -> dict[str, object]:
    expected_sha1 = expected_sha1.upper()
    if output.exists():
        if output.stat().st_size == total_size and sha_file(output, "sha1") == expected_sha1:
            log(f"Verified existing final payload: {output}")
            return {
                "path": str(output),
                "size": total_size,
                "sha1": expected_sha1,
                "sha256": sha_file(output, "sha256"),
                "reused": True,
            }
        raise DownloadError(
            f"refusing to replace existing unverified output: {output}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(output.name + ".assembling")
    if staging.exists():
        retained = retain(staging, "incomplete")
        log(f"Retained prior assembly as {retained.name}")

    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    written = 0
    with staging.open("xb") as destination:
        for part in parts:
            with part.open("rb") as source:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    destination.write(block)
                    sha1.update(block)
                    sha256.update(block)
                    written += len(block)
        destination.flush()
        os.fsync(destination.fileno())
    actual_sha1 = sha1.hexdigest().upper()
    if written != total_size or actual_sha1 != expected_sha1:
        raise DownloadError(
            f"assembled payload failed identity verification: size {written}/{total_size}, "
            f"SHA-1 {actual_sha1}/{expected_sha1}; retained {staging}"
        )
    staging.replace(output)
    result = {
        "path": str(output),
        "size": written,
        "sha1": actual_sha1,
        "sha256": sha256.hexdigest().upper(),
        "reused": False,
    }
    log(
        f"Published verified payload: {output} ({written} bytes, SHA-1 {actual_sha1})"
    )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--total-size", required=True, type=int)
    parser.add_argument("--part-count", required=True, type=int)
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--part-prefix", default="part-")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sha1", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--curl", default="curl.exe")
    parser.add_argument("--retry", type=int, default=20)
    parser.add_argument("--connect-timeout", type=int, default=30)
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1024 * 1024,
        help="maximum independently verified range size (default: 1 MiB)",
    )
    parser.add_argument("--progress-interval", type=int, default=60)
    parser.add_argument(
        "--indices",
        help="optional comma/range selection such as 0-3,12-15",
    )
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="verify selected part files but do not require/assemble every part",
    )
    parser.add_argument("--plan", action="store_true")
    return parser.parse_args(argv)


def parse_indices(value: str | None, part_count: int) -> list[int]:
    if value is None:
        return list(range(part_count))
    selected: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise DownloadError("--indices contains an empty item")
        if "-" in item:
            first_text, separator, last_text = item.partition("-")
            if not separator or not first_text or not last_text:
                raise DownloadError(f"invalid index range: {item!r}")
            first, last = int(first_text, 10), int(last_text, 10)
            if last < first:
                raise DownloadError(f"descending index range: {item!r}")
            selected.update(range(first, last + 1))
        else:
            selected.add(int(item, 10))
    if not selected or min(selected) < 0 or max(selected) >= part_count:
        raise DownloadError("--indices selects a part outside --part-count")
    return sorted(selected)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    parsed = urlparse(args.url)
    if parsed.scheme != "https" or parsed.hostname != "download.microsoft.com":
        raise DownloadError("only official HTTPS download.microsoft.com URLs are accepted")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", args.sha1):
        raise DownloadError("--sha1 must be exactly 40 hexadecimal characters")
    if not 1 <= args.workers <= 16:
        raise DownloadError("--workers must be between 1 and 16")
    if args.retry < 0 or args.connect_timeout <= 0 or args.chunk_size <= 0:
        raise DownloadError("retry and timeout values are invalid")
    if shutil.which(args.curl) is None:
        raise DownloadError(f"curl executable not found: {args.curl}")

    ranges = part_ranges(args.total_size, args.part_count)
    selected_indices = parse_indices(args.indices, args.part_count)
    width = max(2, len(str(args.part_count - 1)))
    parts = [
        args.parts_dir / f"{args.part_prefix}{index:0{width}d}"
        for index in range(args.part_count)
    ]
    plan = [
        {
            "index": index,
            "path": str(part),
            "start": start,
            "end": end,
            "size": end - start + 1,
            "existing": part.stat().st_size if part.exists() else 0,
        }
        for index, (part, (start, end)) in enumerate(zip(parts, ranges))
    ]
    if args.plan:
        print(json.dumps(plan, indent=2))
        return 0

    args.parts_dir.mkdir(parents=True, exist_ok=True)
    jobs: list[dict[str, object]] = []
    failures: list[BaseException] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        pending = {
            executor.submit(
                resume_one,
                index=index,
                part_path=part,
                range_start=start,
                range_end=end,
                total_size=args.total_size,
                url=args.url,
                curl=args.curl,
                retry=args.retry,
                connect_timeout=args.connect_timeout,
                chunk_size=args.chunk_size,
            ): index
            for index, (part, (start, end)) in enumerate(zip(parts, ranges))
            if index in selected_indices
        }
        while pending:
            done, _ = concurrent.futures.wait(
                pending,
                timeout=args.progress_interval,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                complete, downloaded = aggregate_progress(parts, ranges)
                percent = downloaded * 100.0 / args.total_size
                log(
                    f"Progress: {downloaded}/{args.total_size} bytes "
                    f"({percent:.2f}%), {complete}/{args.part_count} parts complete"
                )
                continue
            for future in done:
                index = pending.pop(future)
                try:
                    jobs.append(future.result())
                except BaseException as exc:  # retain all completed transfer evidence
                    failures.append(exc)
                    log(f"[{index:02d}] ERROR: {exc}")
        if failures:
            raise DownloadError(
                f"{len(failures)} range job(s) failed; all original and scratch files were retained"
            ) from failures[0]

    audited_indices = selected_indices if args.download_only else list(range(args.part_count))
    for index in audited_indices:
        part = parts[index]
        start, end = ranges[index]
        expected = end - start + 1
        if not part.is_file() or part.stat().st_size != expected:
            raise DownloadError(
                f"part failed final size audit: {part} (expected {expected})"
            )
    if args.download_only:
        log(
            "Verified selected part files without assembly: "
            + ",".join(str(index) for index in selected_indices)
        )
        return 0
    payload = assemble(parts, args.output, args.total_size, args.sha1)
    summary = {
        "schema": "nodetrace-exact-range-download/v1",
        "url": args.url,
        "total_size": args.total_size,
        "part_count": args.part_count,
        "workers": args.workers,
        "curl_retry": args.retry,
        "curl_connect_timeout": args.connect_timeout,
        "verified_chunk_size": args.chunk_size,
        "parts": sorted(jobs, key=lambda item: int(item["index"])),
        "payload": payload,
        "verified_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest = args.output.with_name(args.output.name + ".download-manifest.json")
    manifest.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    log(f"Download manifest: {manifest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DownloadError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
