from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path

import pytest

from nodetrace_ir.collectors.helpers import EvidenceFileChangedError, VerifiedEvidenceFile
from nodetrace_ir.preservation import PreservationError, preserve_file
import nodetrace_ir.preservation as preservation_module


def test_preserve_file_creates_verified_content_addressed_copy(tmp_path: Path) -> None:
    source = tmp_path / "suspect.bin"
    payload = (b"NodeTrace-IR\x00" * 8192) + b"tail"
    source.write_bytes(payload)
    before = source.stat()

    result = preserve_file(source, tmp_path / "evidence_store")

    expected = sha256(payload).hexdigest()
    assert result.sha256 == expected
    assert result.size_bytes == len(payload)
    assert result.copied is True
    assert result.stored_path == tmp_path / "evidence_store" / "sha256" / expected
    assert result.stored_path.read_bytes() == payload
    after = source.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns


def test_preserve_file_deduplicates_only_after_hash_verification(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    source.write_bytes(b"same bytes")
    store = tmp_path / "evidence_store"

    first = preserve_file(source, store)
    second = preserve_file(source, store)

    assert first.copied is True
    assert second.copied is False
    assert second.stored_path == first.stored_path
    assert list((store / "sha256").iterdir()) == [first.stored_path]


def test_preserve_file_rejects_corrupt_preexisting_digest_object(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"good")
    digest = sha256(b"good").hexdigest()
    digest_dir = tmp_path / "evidence_store" / "sha256"
    digest_dir.mkdir(parents=True)
    (digest_dir / digest).write_bytes(b"evil")

    with pytest.raises(PreservationError, match="SHA-256"):
        preserve_file(source, tmp_path / "evidence_store")


def test_preserve_file_detects_source_mutation_during_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "moving.bin"
    source.write_bytes(b"A" * 8192)
    original = preservation_module._copy_and_hash
    calls = 0

    def mutate_after_first_copy(input_stream, output_stream, chunk_size: int):
        nonlocal calls
        result = original(input_stream, output_stream, chunk_size)
        calls += 1
        if calls == 1:
            with source.open("ab") as changed:
                changed.write(b"changed")
                changed.flush()
                os.fsync(changed.fileno())
        return result

    monkeypatch.setattr(preservation_module, "_copy_and_hash", mutate_after_first_copy)
    with pytest.raises(EvidenceFileChangedError):
        preserve_file(source, tmp_path / "evidence_store")
    assert not any((tmp_path / "evidence_store" / "sha256").iterdir())


def test_late_source_mutation_removes_newly_created_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "late-change.bin"
    source.write_bytes(b"A" * 8192)
    original = VerifiedEvidenceFile.verify_unchanged
    calls = 0

    def mutate_before_context_exit(self: VerifiedEvidenceFile):
        nonlocal calls
        calls += 1
        if calls == 2:
            with source.open("ab") as changed:
                changed.write(b"late")
                changed.flush()
                os.fsync(changed.fileno())
        return original(self)

    monkeypatch.setattr(VerifiedEvidenceFile, "verify_unchanged", mutate_before_context_exit)
    with pytest.raises(EvidenceFileChangedError):
        preserve_file(source, tmp_path / "evidence_store")
    assert not any((tmp_path / "evidence_store" / "sha256").iterdir())


def test_preserve_file_rejects_linked_store_component(tmp_path: Path) -> None:
    target = tmp_path / "real-store"
    target.mkdir()
    linked = tmp_path / "linked-store"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable in this test environment")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")

    with pytest.raises(PreservationError, match="symlink or reparse"):
        preserve_file(source, linked)
