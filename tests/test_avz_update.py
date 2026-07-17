from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile

import pytest

from tools.update_avz_base import (
    BaseUpdateError,
    _copy_local_candidate,
    main,
    candidate_manifest,
    inspect_base_archive,
)


def _base(path: Path, entries: dict[str, bytes]) -> Path:
    with ZipFile(path, "w", ZIP_STORED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return path


def test_base_candidate_is_fully_hashed_and_bounded(tmp_path: Path) -> None:
    archive = _base(
        tmp_path / "avzbase.zip",
        {"main.avz": b"main", "signf001.avz": b"signatures"},
    )

    result = inspect_base_archive(archive)

    assert result["sha256"] == sha256(archive.read_bytes()).hexdigest()
    assert result["zip"]["entry_count"] == 2
    entries = {item["path"]: item for item in result["zip"]["entries"]}
    assert entries["main.avz"]["sha256"] == sha256(b"main").hexdigest()
    assert entries["signf001.avz"]["crc32"]


@pytest.mark.parametrize(
    "name",
    ["../escape.avz", "/absolute.avz", "Base/main.avz", "payload.exe"],
)
def test_base_candidate_rejects_unexpected_paths(tmp_path: Path, name: str) -> None:
    archive = _base(tmp_path / "bad.zip", {name: b"data"})

    with pytest.raises(BaseUpdateError):
        inspect_base_archive(archive)


def test_candidate_manifest_replaces_only_mutable_base() -> None:
    current = {
        "schema_version": 1,
        "pinned_at_utc": "old",
        "archives": [
            {"name": "avz4.zip", "sha256": "exe-pin"},
            {"name": "avzbase.zip", "sha256": "old-base"},
        ],
    }
    base = {
        "name": "avzbase.zip",
        "url": "https://z-oleg.com/secur/avz_up/avzbase.zip",
        "sha256": "new-base",
        "zip": {"entry_count": 1, "entries": []},
    }

    result = candidate_manifest(
        current,
        base,
        retrieved_at="2026-07-16T00:00:00+00:00",
        last_modified="2026-07-16T00:00:00+00:00",
    )

    by_name = {item["name"]: item for item in result["archives"]}
    assert by_name["avz4.zip"]["sha256"] == "exe-pin"
    assert by_name["avzbase.zip"]["sha256"] == "new-base"
    assert by_name["avzbase.zip"]["retrieved_at_utc"] == "2026-07-16T00:00:00+00:00"
    assert json.loads(json.dumps(result)) == result


def test_separately_downloaded_candidate_is_bounded_copied_then_inspected(
    tmp_path: Path,
) -> None:
    source = _base(tmp_path / "downloaded.zip", {"main.avz": b"verified content"})
    destination = tmp_path / "candidate.download"

    _copy_local_candidate(source, destination)
    metadata = inspect_base_archive(destination)

    assert destination.read_bytes() == source.read_bytes()
    assert metadata["sha256"] == sha256(source.read_bytes()).hexdigest()


def test_review_then_approve_repin_uses_existing_candidate_pair(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    current_base = _base(cache / "avzbase.zip", {"main.avz": b"old"})
    current_metadata = inspect_base_archive(current_base)
    manifest_path = tmp_path / "avz-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pinned_at_utc": "2026-07-15T00:00:00+00:00",
                "archives": [
                    {"name": "avz4.zip", "sha256": "runtime-pin"},
                    current_metadata,
                ],
            }
        ),
        encoding="utf-8",
    )
    downloaded = _base(tmp_path / "official-download.zip", {"main.avz": b"new"})

    assert main(
        [
            "--accept-noncommercial-license",
            "--source-archive",
            str(downloaded),
            "--cache-dir",
            str(cache),
            "--manifest",
            str(manifest_path),
        ]
    ) == 0
    assert current_base.read_bytes() != downloaded.read_bytes()
    assert (cache / "avzbase.candidate.zip").is_file()
    candidate_zip = cache / "avzbase.candidate.zip"
    candidate_manifest = tmp_path / "avz-manifest.candidate.json"

    assert main(
        [
            "--accept-noncommercial-license",
            "--approve-repin",
            "--expected-base-sha256",
            sha256(candidate_zip.read_bytes()).hexdigest(),
            "--expected-manifest-sha256",
            sha256(candidate_manifest.read_bytes()).hexdigest(),
            "--cache-dir",
            str(cache),
            "--manifest",
            str(manifest_path),
        ]
    ) == 0
    assert current_base.read_bytes() == downloaded.read_bytes()
    assert not (cache / "avzbase.candidate.zip").exists()
    assert len(list((tmp_path / "history").glob("*/avzbase.zip"))) == 1


def test_approve_requires_hashes_from_completed_review(tmp_path: Path) -> None:
    manifest_path = tmp_path / "avz-manifest.json"
    manifest_path.write_text('{"schema_version": 1, "archives": []}', encoding="utf-8")

    with pytest.raises(SystemExit, match="requires both"):
        main(
            [
                "--accept-noncommercial-license",
                "--approve-repin",
                "--cache-dir",
                str(tmp_path / "cache"),
                "--manifest",
                str(manifest_path),
            ]
        )


def test_approve_rejects_candidate_pair_changed_after_review(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    current_base = _base(cache / "avzbase.zip", {"main.avz": b"old"})
    current_metadata = inspect_base_archive(current_base)
    manifest_path = tmp_path / "avz-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "archives": [
                    {"name": "avz4.zip", "sha256": "runtime-pin"},
                    current_metadata,
                ],
            }
        ),
        encoding="utf-8",
    )
    downloaded = _base(tmp_path / "downloaded.zip", {"main.avz": b"reviewed"})
    assert main(
        [
            "--accept-noncommercial-license",
            "--source-archive",
            str(downloaded),
            "--cache-dir",
            str(cache),
            "--manifest",
            str(manifest_path),
        ]
    ) == 0
    candidate_zip = cache / "avzbase.candidate.zip"
    candidate_manifest = tmp_path / "avz-manifest.candidate.json"
    reviewed_base_hash = sha256(candidate_zip.read_bytes()).hexdigest()
    reviewed_manifest_hash = sha256(candidate_manifest.read_bytes()).hexdigest()

    changed = json.loads(candidate_manifest.read_text(encoding="utf-8"))
    changed["pinned_at_utc"] = "changed-after-review"
    candidate_manifest.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(SystemExit, match="manifest changed after review"):
        main(
            [
                "--accept-noncommercial-license",
                "--approve-repin",
                "--expected-base-sha256",
                reviewed_base_hash,
                "--expected-manifest-sha256",
                reviewed_manifest_hash,
                "--cache-dir",
                str(cache),
                "--manifest",
                str(manifest_path),
            ]
        )
    assert current_base.read_bytes() != downloaded.read_bytes()
