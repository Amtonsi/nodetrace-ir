#!/usr/bin/env python3
"""Fetch, audit and explicitly re-pin the mutable official AVZ base archive.

The boot media itself never updates over the network.  Run this utility on a
trusted build workstation, review the candidate metadata, and then rebuild the
ISO.  The official full-base URL is mutable and does not publish a strong
signature, so a newly downloaded archive is never silently trusted merely
because it came over HTTPS.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from hashlib import md5, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile


OFFICIAL_BASE_URL = "https://z-oleg.com/secur/avz_up/avzbase.zip"
OFFICIAL_HOSTS = {"z-oleg.com", "www.z-oleg.com"}
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_ENTRY_COUNT = 2_048
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


class BaseUpdateError(RuntimeError):
    """Raised when a candidate base cannot be safely accepted for review."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_entry_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise BaseUpdateError(f"unsafe ZIP entry name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BaseUpdateError(f"unsafe ZIP entry path: {name!r}")
    if re.match(r"^[A-Za-z]:", name):
        raise BaseUpdateError(f"drive-qualified ZIP entry path: {name!r}")
    if len(path.parts) != 1 or path.suffix.casefold() != ".avz":
        raise BaseUpdateError(
            f"unexpected AVZ base entry (only flat *.avz files are accepted): {name!r}"
        )
    return path.as_posix()


def inspect_base_archive(path: Path) -> dict[str, object]:
    """Return deterministic archive metadata after bounded full-content checks."""

    if not path.is_file() or path.stat().st_size <= 0:
        raise BaseUpdateError(f"candidate archive is missing or empty: {path}")
    if path.stat().st_size > MAX_DOWNLOAD_BYTES:
        raise BaseUpdateError("candidate archive exceeds the compressed-size limit")

    outer_sha = sha256()
    outer_md5 = md5(usedforsecurity=False)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            outer_sha.update(block)
            outer_md5.update(block)

    try:
        with ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ENTRY_COUNT:
                raise BaseUpdateError("candidate ZIP has an invalid entry count")
            seen: set[str] = set()
            total = 0
            entries: list[dict[str, object]] = []
            for info in infos:
                if info.is_dir():
                    raise BaseUpdateError("candidate ZIP must not contain directories")
                name = _safe_entry_name(info.filename)
                folded = name.casefold()
                if folded in seen:
                    raise BaseUpdateError(f"duplicate ZIP entry: {name}")
                seen.add(folded)
                if info.flag_bits & 0x1:
                    raise BaseUpdateError(f"encrypted ZIP entry is not accepted: {name}")
                if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES:
                    raise BaseUpdateError(f"ZIP entry exceeds the size limit: {name}")
                total += info.file_size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise BaseUpdateError("candidate ZIP exceeds the expansion-size limit")

                digest = sha256()
                with archive.open(info, "r") as entry:
                    for block in iter(lambda: entry.read(1024 * 1024), b""):
                        digest.update(block)
                entries.append(
                    {
                        "path": name,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "crc32": f"{info.CRC:08X}",
                        "sha256": digest.hexdigest(),
                    }
                )
    except BadZipFile as exc:
        raise BaseUpdateError(f"candidate is not a valid ZIP archive: {exc}") from exc

    return {
        "name": "avzbase.zip",
        "url": OFFICIAL_BASE_URL,
        "size": path.stat().st_size,
        "sha256": outer_sha.hexdigest(),
        "md5": outer_md5.hexdigest(),
        "upstream_md5_published": False,
        "zip": {
            "entry_count": len(entries),
            "uncompressed_size": total,
            "entries": entries,
        },
    }


def candidate_manifest(
    current: dict[str, object],
    base_metadata: dict[str, object],
    *,
    retrieved_at: str,
    last_modified: str,
) -> dict[str, object]:
    if int(current.get("schema_version", 0)) != 1:
        raise BaseUpdateError("unsupported AVZ manifest schema")
    archives = current.get("archives")
    if not isinstance(archives, list):
        raise BaseUpdateError("AVZ manifest has no archive list")
    names = {str(item.get("name")) for item in archives if isinstance(item, dict)}
    if names != {"avz4.zip", "avzbase.zip"}:
        raise BaseUpdateError("AVZ manifest must contain exactly avz4.zip and avzbase.zip")

    updated = json.loads(json.dumps(current))
    replacement = dict(base_metadata)
    replacement["last_modified_utc"] = last_modified
    replacement["retrieved_at_utc"] = retrieved_at
    updated["pinned_at_utc"] = retrieved_at
    updated["mutable_upstream_warning"] = (
        "Official URLs are mutable and the full base has no published strong signature. "
        "This hash is a locally reviewed provenance pin; future changes require another explicit re-pin."
    )
    updated["archives"] = [
        replacement if item.get("name") == "avzbase.zip" else item
        for item in updated["archives"]
    ]
    return updated


def _download(destination: Path) -> tuple[str, str]:
    request = Request(
        OFFICIAL_BASE_URL,
        headers={"User-Agent": "NodeTrace-IR-base-updater/0.3"},
    )
    final_url = ""
    with urlopen(request, timeout=120) as response, destination.open("xb") as output:
        final_url = response.geturl()
        final = urlparse(response.geturl())
        if final.scheme != "https" or (final.hostname or "").casefold() not in OFFICIAL_HOSTS:
            raise BaseUpdateError(f"official download redirected to an unapproved URL: {response.geturl()}")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > MAX_DOWNLOAD_BYTES:
            raise BaseUpdateError("official response exceeds the download-size limit")
        size = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_DOWNLOAD_BYTES:
                raise BaseUpdateError("official response exceeded the download-size limit")
            output.write(block)
        if size == 0:
            raise BaseUpdateError("official response was empty")
        last_modified = response.headers.get("Last-Modified", "")

    normalized_last_modified = ""
    if last_modified:
        try:
            normalized_last_modified = parsedate_to_datetime(last_modified).astimezone(
                timezone.utc
            ).replace(microsecond=0).isoformat()
        except (TypeError, ValueError, OverflowError):
            normalized_last_modified = last_modified
    return final_url, normalized_last_modified


def _copy_local_candidate(source: Path, destination: Path) -> None:
    """Copy a separately downloaded candidate without trusting its filename.

    This fallback is useful on build networks where Python's TLS trust store is
    unavailable but an enterprise-approved downloader can fetch the official
    URL. The same full ZIP and per-entry validation still runs afterwards.
    """

    if source.is_symlink() or not source.is_file():
        raise BaseUpdateError(f"local candidate is not a regular file: {source}")
    declared = source.stat().st_size
    if declared <= 0 or declared > MAX_DOWNLOAD_BYTES:
        raise BaseUpdateError("local candidate has an invalid compressed size")
    copied = 0
    with source.open("rb") as input_stream, destination.open("xb") as output:
        while True:
            block = input_stream.read(1024 * 1024)
            if not block:
                break
            copied += len(block)
            if copied > MAX_DOWNLOAD_BYTES:
                raise BaseUpdateError("local candidate exceeded the download-size limit")
            output.write(block)
    if copied != declared:
        raise BaseUpdateError("local candidate changed while it was copied")


def _archive_by_name(manifest: dict[str, object], name: str) -> dict[str, object]:
    archives = manifest.get("archives")
    if not isinstance(archives, list):
        raise BaseUpdateError("AVZ manifest has no archive list")
    matches = [item for item in archives if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise BaseUpdateError(f"AVZ manifest must contain exactly one {name} entry")
    return matches[0]


def _normalized_sha256(value: str, *, label: str) -> str:
    normalized = value.strip().casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise BaseUpdateError(f"{label} must be exactly 64 hexadecimal characters")
    return normalized


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def approve_existing_candidate(
    manifest_path: Path,
    cache_dir: Path,
    *,
    expected_base_sha256: str,
    expected_manifest_sha256: str,
) -> Path:
    """Validate and install an already reviewed candidate pair fail-closed."""

    candidate_zip = cache_dir / "avzbase.candidate.zip"
    candidate_json = manifest_path.with_name("avz-manifest.candidate.json")
    if not candidate_zip.is_file() or not candidate_json.is_file():
        raise BaseUpdateError(
            "no complete candidate pair exists; run once without --approve-repin first"
        )
    reviewed_base_sha256 = _normalized_sha256(
        expected_base_sha256, label="reviewed candidate ZIP SHA-256"
    )
    reviewed_manifest_sha256 = _normalized_sha256(
        expected_manifest_sha256, label="reviewed candidate manifest SHA-256"
    )
    if _file_sha256(candidate_json) != reviewed_manifest_sha256:
        raise BaseUpdateError(
            "candidate manifest changed after review (SHA-256 does not match approval)"
        )
    current = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_json.read_text(encoding="utf-8"))
    if int(candidate.get("schema_version", 0)) != 1:
        raise BaseUpdateError("candidate manifest has an unsupported schema")
    if _archive_by_name(candidate, "avz4.zip") != _archive_by_name(current, "avz4.zip"):
        raise BaseUpdateError("candidate unexpectedly changes the pinned avz4.zip runtime")

    inspected = inspect_base_archive(candidate_zip)
    if inspected.get("sha256") != reviewed_base_sha256:
        raise BaseUpdateError(
            "candidate ZIP changed after review (SHA-256 does not match approval)"
        )
    proposed_base = _archive_by_name(candidate, "avzbase.zip")
    if proposed_base.get("url") != OFFICIAL_BASE_URL:
        raise BaseUpdateError("candidate base URL is not the pinned official URL")
    for field in ("name", "size", "sha256", "md5", "zip"):
        if proposed_base.get(field) != inspected.get(field):
            raise BaseUpdateError(f"candidate manifest does not match candidate ZIP: {field}")

    current_base = cache_dir / "avzbase.zip"
    if not current_base.is_file():
        raise BaseUpdateError("current pinned avzbase.zip is missing")
    current_inspected = inspect_base_archive(current_base)
    current_base_metadata = _archive_by_name(current, "avzbase.zip")
    if current_base_metadata.get("sha256") != current_inspected.get("sha256"):
        raise BaseUpdateError("current avzbase.zip no longer matches the pinned manifest")

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    history = manifest_path.parent / "history" / stamp
    history.mkdir(parents=True, exist_ok=False)
    shutil.copy2(current_base, history / "avzbase.zip")
    shutil.copy2(manifest_path, history / manifest_path.name)
    # Re-check the exact reviewed bytes immediately before publishing either
    # member.  A crash between the two os.replace calls can leave a mismatched
    # pair, but all consumers verify the pair and therefore fail closed; the
    # previous complete pair remains available in history for recovery.
    if _file_sha256(candidate_zip) != reviewed_base_sha256:
        raise BaseUpdateError("candidate ZIP changed during approval")
    if _file_sha256(candidate_json) != reviewed_manifest_sha256:
        raise BaseUpdateError("candidate manifest changed during approval")
    os.replace(candidate_zip, current_base)
    os.replace(candidate_json, manifest_path)
    return history


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download and explicitly re-pin the official mutable AVZ full base"
    )
    parser.add_argument("--accept-noncommercial-license", action="store_true")
    parser.add_argument("--approve-repin", action="store_true")
    parser.add_argument(
        "--expected-base-sha256",
        help="SHA-256 of the candidate ZIP recorded during operator review",
    )
    parser.add_argument(
        "--expected-manifest-sha256",
        help="SHA-256 of the candidate manifest recorded during operator review",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "cache",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent / "avz-manifest.json",
    )
    parser.add_argument(
        "--source-archive",
        type=Path,
        help=(
            "Use a separately downloaded avzbase.zip instead of Python HTTPS; "
            "the input is still treated only as an unapproved candidate"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.accept_noncommercial_license:
        raise SystemExit(
            "AVZ update requires explicit acknowledgement: --accept-noncommercial-license"
        )
    manifest_path = args.manifest.expanduser().resolve()
    cache_dir = args.cache_dir.expanduser().resolve()
    if not manifest_path.is_file():
        raise SystemExit(f"manifest was not found: {manifest_path}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    retrieved = utc_now()

    candidate_zip = cache_dir / "avzbase.candidate.zip"
    candidate_json = manifest_path.with_name("avz-manifest.candidate.json")
    if args.approve_repin:
        if not args.expected_base_sha256 or not args.expected_manifest_sha256:
            raise SystemExit(
                "--approve-repin requires both --expected-base-sha256 and "
                "--expected-manifest-sha256 from the completed review"
            )
        try:
            history = approve_existing_candidate(
                manifest_path,
                cache_dir,
                expected_base_sha256=args.expected_base_sha256,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
        except (BaseUpdateError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"AVZ candidate approval failed: {exc}") from exc
        print(f"Re-pin approved. Previous inputs were preserved in: {history}")
        print("Rebuild the WinPE ISO so the read-only boot media contains this pinned base.")
        return 0
    if args.expected_base_sha256 or args.expected_manifest_sha256:
        raise SystemExit("expected SHA-256 arguments are valid only with --approve-repin")
    if candidate_zip.exists() or candidate_json.exists():
        raise SystemExit(
            "candidate outputs already exist; review them and run --approve-repin, "
            "or remove both before downloading another candidate"
        )

    handle = tempfile.NamedTemporaryFile(
        prefix="avzbase-", suffix=".download", dir=cache_dir, delete=False
    )
    download_path = Path(handle.name)
    handle.close()
    download_path.unlink(missing_ok=True)
    try:
        if args.source_archive is not None:
            source_archive = args.source_archive.expanduser().resolve()
            _copy_local_candidate(source_archive, download_path)
            final_url, last_modified = OFFICIAL_BASE_URL, ""
            retrieval_method = "operator_supplied_candidate"
        else:
            final_url, last_modified = _download(download_path)
            retrieval_method = "official_https"
        if final_url != OFFICIAL_BASE_URL:
            # Same approved host redirects are allowed but recorded through the
            # immutable URL field and this diagnostic output.
            print(f"Official redirect accepted: {final_url}")
        metadata = inspect_base_archive(download_path)
        metadata["retrieval_method"] = retrieval_method
        current = json.loads(manifest_path.read_text(encoding="utf-8"))
        candidate = candidate_manifest(
            current,
            metadata,
            retrieved_at=retrieved,
            last_modified=last_modified,
        )
        os.replace(download_path, candidate_zip)
        candidate_json.write_text(
            json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        print(f"Candidate base:     {candidate_zip}")
        print(f"Candidate manifest: {candidate_json}")
        print(f"Base SHA-256:       {metadata['sha256']}")
        print(f"Manifest SHA-256:   {_file_sha256(candidate_json)}")
        print(f"Entries:            {metadata['zip']['entry_count']}")
        print("Candidate only; current pinned build inputs were not changed.")
        return 0
    finally:
        download_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
