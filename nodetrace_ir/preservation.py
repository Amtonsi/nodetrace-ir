from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import stat
import tempfile

from .collectors.helpers import (
    EvidenceFileChangedError,
    UnsafeEvidencePathError,
    open_verified_evidence_file,
)
from .contracts import utc_now


class PreservationError(OSError):
    """Raised when a byte-for-byte, content-addressed copy cannot be proved."""


@dataclass(frozen=True, slots=True)
class PreservedEvidence:
    source_path: Path
    stored_path: Path
    sha256: str
    size_bytes: int
    copied: bool
    preserved_at: str
    source_modified_ns: int


def _is_reparse_or_link(path: Path) -> bool:
    item = path.lstat()
    attributes = int(getattr(item, "st_file_attributes", 0))
    return stat.S_ISLNK(item.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _prepare_store(root: Path) -> Path:
    if not root.is_absolute():
        raise PreservationError("evidence_store must be an absolute local path")

    # Refuse an already-present link/reparse component.  The application owns
    # newly created components, but must not follow a path redirected by the
    # investigated host.
    current = Path(root.anchor)
    for component in root.parts[1:]:
        current /= component
        if current.exists():
            if _is_reparse_or_link(current):
                raise PreservationError(
                    f"evidence_store contains a symlink or reparse point: {current}"
                )
            if not current.is_dir():
                raise PreservationError(
                    f"evidence_store component is not a directory: {current}"
                )
        else:
            try:
                current.mkdir()
            except FileExistsError:
                # A concurrent creator won the race; validate what appeared.
                if _is_reparse_or_link(current) or not current.is_dir():
                    raise PreservationError(
                        f"unsafe evidence_store component appeared: {current}"
                    )

    digest_directory = root / "sha256"
    if digest_directory.exists():
        if _is_reparse_or_link(digest_directory) or not digest_directory.is_dir():
            raise PreservationError(
                f"content-addressed store is not a regular directory: {digest_directory}"
            )
    else:
        try:
            digest_directory.mkdir()
        except FileExistsError:
            if _is_reparse_or_link(digest_directory) or not digest_directory.is_dir():
                raise PreservationError(
                    f"unsafe content-addressed store appeared: {digest_directory}"
                )
    return digest_directory


def _copy_and_hash(source, target, chunk_size: int) -> tuple[str, int]:
    digest = sha256()
    total = 0
    while True:
        block = source.read(chunk_size)
        if not block:
            break
        target.write(block)
        digest.update(block)
        total += len(block)
    return digest.hexdigest(), total


def _verify_stored_file(path: Path, expected_sha256: str, expected_size: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PreservationError(f"preserved object cannot be opened safely: {exc}") from exc

    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        opened = os.fstat(stream.fileno())
        attributes = int(getattr(opened, "st_file_attributes", 0))
        if not stat.S_ISREG(opened.st_mode) or attributes & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise PreservationError("preserved object is not a regular non-reparse file")
        if int(opened.st_size) != expected_size:
            raise PreservationError("existing preserved object has an unexpected size")
        actual = sha256()
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            actual.update(block)
        after = os.fstat(stream.fileno())
        if (
            int(after.st_size) != int(opened.st_size)
            or getattr(after, "st_mtime_ns", 0) != getattr(opened, "st_mtime_ns", 0)
            or getattr(after, "st_ctime_ns", 0) != getattr(opened, "st_ctime_ns", 0)
        ):
            raise PreservationError("preserved object changed while it was verified")
        if actual.hexdigest() != expected_sha256:
            raise PreservationError("existing preserved object failed SHA-256 verification")


def _remove_created_file(path: Path) -> None:
    try:
        path.chmod(stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def preserve_file(
    source: str | os.PathLike[str],
    evidence_store: str | os.PathLike[str],
    *,
    chunk_size: int = 1024 * 1024,
) -> PreservedEvidence:
    """Copy one suspect file into ``evidence_store/sha256/<digest>``.

    The source is opened once, read only, through the same local-file and
    reparse-point protections as the seed collector.  A source ``fstat`` check,
    an independently hashed staging copy, exclusive destination creation, and
    a final destination hash make a successful return a byte-for-byte claim.
    The function never executes, loads, repairs, quarantines, or deletes the
    source artifact.
    """

    if chunk_size < 4096:
        raise ValueError("chunk_size must be at least 4096 bytes")
    store = Path(evidence_store).expanduser()
    digest_directory = _prepare_store(store)
    staging_path: Path | None = None
    destination_created = False
    destination: Path | None = None

    try:
        with open_verified_evidence_file(source) as opened:
            opened.stream.seek(0)
            handle = tempfile.NamedTemporaryFile(
                mode="w+b",
                prefix=".acquire-",
                suffix=".tmp",
                dir=digest_directory,
                delete=False,
            )
            staging_path = Path(handle.name)
            try:
                source_digest, copied_size = _copy_and_hash(
                    opened.stream, handle, chunk_size
                )
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()

            final_source_state = opened.verify_unchanged()
            if copied_size != int(opened.initial_stat.st_size):
                raise EvidenceFileChangedError(
                    "Suspect file size changed while the preservation copy was read"
                )

            destination = digest_directory / source_digest
            copied = False
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
                descriptor = os.open(destination, flags, 0o400)
                destination_created = True
            except FileExistsError:
                _verify_stored_file(destination, source_digest, copied_size)
            else:
                final = os.fdopen(descriptor, "wb", closefd=True)
                try:
                    with staging_path.open("rb") as staged, final:
                        final_digest, final_size = _copy_and_hash(
                            staged, final, chunk_size
                        )
                        final.flush()
                        os.fsync(final.fileno())
                    if final_digest != source_digest or final_size != copied_size:
                        raise PreservationError(
                            "staged and final preservation hashes do not match"
                        )
                    try:
                        destination.chmod(stat.S_IREAD)
                    except OSError:
                        # Read-only mode is defence in depth; the hashes are the
                        # integrity assertion and are verified immediately below.
                        pass
                    _verify_stored_file(destination, source_digest, copied_size)
                    copied = True
                except Exception:
                    final.close()
                    _remove_created_file(destination)
                    destination_created = False
                    raise

            preserved = PreservedEvidence(
                source_path=opened.path,
                stored_path=destination,
                sha256=source_digest,
                size_bytes=copied_size,
                copied=copied,
                preserved_at=utc_now(),
                source_modified_ns=int(
                    getattr(
                        final_source_state,
                        "st_mtime_ns",
                        final_source_state.st_mtime * 1_000_000_000,
                    )
                ),
            )
        # Leaving the verified-source context performs one last fstat.  Only
        # after that succeeds is a newly created destination committed.
        destination_created = False
        return preserved
    except (UnsafeEvidencePathError, EvidenceFileChangedError):
        if destination_created and destination is not None:
            _remove_created_file(destination)
        raise
    except PreservationError:
        if destination_created and destination is not None:
            _remove_created_file(destination)
        raise
    except OSError as exc:
        if destination_created and destination is not None:
            _remove_created_file(destination)
        raise PreservationError(f"artifact preservation failed: {exc}") from exc
    finally:
        if staging_path is not None:
            try:
                staging_path.unlink(missing_ok=True)
            except OSError:
                pass
        # ``destination_created`` is deliberately not used for cleanup here:
        # once the final object passed verification it must remain preserved.


class EvidencePreserver:
    """Small injectable facade used by the detector-first pipeline."""

    def __init__(self, evidence_store: str | os.PathLike[str]) -> None:
        self.evidence_store = Path(evidence_store)

    def preserve(self, source: str | os.PathLike[str]) -> PreservedEvidence:
        return preserve_file(source, self.evidence_store)


__all__ = [
    "EvidencePreserver",
    "PreservationError",
    "PreservedEvidence",
    "preserve_file",
]
