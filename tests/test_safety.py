from __future__ import annotations

from fnmatch import fnmatchcase
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import subprocess
from typing import Iterable

import pytest

from nodetrace_ir.collectors import FileSeedCollector
from nodetrace_ir.collectors import file_seed, helpers
from nodetrace_ir.collectors.helpers import PowerShellResult
from nodetrace_ir.database import Database
from nodetrace_ir.engine import CollectionEngine


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows path namespace rules")
@pytest.mark.parametrize(
    "unsafe_path",
    [
        r"\\forensic-test.invalid\evidence\sample.exe",
        r"\\.\PhysicalDrive0",
        r"\\?\C:\Temp\sample.exe",
        r"C:\Temp\sample.exe:payload",
        r"C:\Temp\NUL.txt",
    ],
)
def test_verified_evidence_rejects_unc_device_and_ads_before_open(unsafe_path: str) -> None:
    with pytest.raises(helpers.UnsafeEvidencePathError):
        with helpers.open_verified_evidence_file(unsafe_path):
            pytest.fail("Unsafe path must be rejected before an evidence handle is opened")


def test_verified_evidence_rejects_reparse_point(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"preserved evidence")
    link = tmp_path / "linked-evidence.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        link.write_bytes(b"reparse test stand-in")
        real_lstat = Path.lstat

        def reparse_lstat(candidate: Path):
            current = real_lstat(candidate)
            if candidate == link:
                class ReparseStat:
                    st_mode = current.st_mode
                    st_file_attributes = 0x400

                return ReparseStat()
            return current

        monkeypatch.setattr(Path, "lstat", reparse_lstat)

    with pytest.raises(helpers.UnsafeEvidencePathError, match="Reparse"):
        with helpers.open_verified_evidence_file(link):
            pytest.fail("Reparse-point evidence must not be opened")


def test_verified_evidence_hashes_and_fstats_one_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = tmp_path / "single-handle.bin"
    payload = b"one stable evidence handle"
    sample.write_bytes(payload)
    real_fstat = helpers.os.fstat
    descriptors: list[int] = []

    def tracking_fstat(descriptor: int):
        descriptors.append(descriptor)
        return real_fstat(descriptor)

    monkeypatch.setattr(helpers.os, "fstat", tracking_fstat)
    with helpers.open_verified_evidence_file(sample) as opened:
        hashes = opened.hashes(chunk_size=4096)

    assert hashes["sha256"] == sha256(payload).hexdigest()
    assert len(descriptors) >= 3  # before hash, after hash, and before close
    assert len(set(descriptors)) == 1


def test_verified_evidence_fails_closed_when_fstat_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = tmp_path / "changing.bin"
    sample.write_bytes(b"initial evidence")
    real_fstat = helpers.os.fstat
    calls = 0

    def changing_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls == 1:
            return current
        fields = list(current)
        fields[6] = current.st_size + 1
        return os.stat_result(fields)

    monkeypatch.setattr(helpers.os, "fstat", changing_fstat)
    with pytest.raises(helpers.EvidenceFileChangedError, match="changed"):
        with helpers.open_verified_evidence_file(sample) as opened:
            opened.hashes(chunk_size=4096)


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC rejection")
def test_file_seed_rejects_unc_without_invoking_powershell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = r"\\forensic-test.invalid\evidence\sample.exe"

    def forbidden_metadata_query(*args, **kwargs):
        raise AssertionError("PowerShell must not run for a rejected suspect path")

    monkeypatch.setattr(file_seed.helpers, "run_powershell_json", forbidden_metadata_query)
    database = Database(tmp_path / "unsafe-path.sqlite3")
    case = database.create_case("Unsafe path", suspect_path=suspect)
    summary = CollectionEngine(database, [FileSeedCollector()], tmp_path / "artifacts").run(
        case.id, suspect, options={"read_only": True}
    )

    assert summary.status == "failed"
    assert database.list_evidence(case.id) == []
    gaps = database.list_gaps(case.id)
    assert len(gaps) == 1
    assert "Unsafe suspect path was rejected" in gaps[0].reason


def _gitignore_patterns(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _matches_directory_pattern(pattern: str, relative_path: str) -> bool:
    directory_pattern = pattern.rstrip("/").lstrip("/")
    path = PurePosixPath(relative_path)
    directory_parts = path.parts[:-1]
    if "/" not in directory_pattern:
        return any(fnmatchcase(part, directory_pattern) for part in directory_parts)

    parent_paths = ["/".join(directory_parts[: index + 1]) for index in range(len(directory_parts))]
    return any(
        fnmatchcase(parent, directory_pattern)
        or PurePosixPath(parent).match(directory_pattern)
        for parent in parent_paths
    )


def _matches_gitignore_pattern(pattern: str, relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/").lstrip("/")
    candidate = PurePosixPath(normalized)
    if pattern.endswith("/"):
        return _matches_directory_pattern(pattern, normalized)

    file_pattern = pattern.lstrip("/")
    if "/" not in file_pattern:
        return any(fnmatchcase(part, file_pattern) for part in candidate.parts)
    return fnmatchcase(normalized, file_pattern) or candidate.match(file_pattern)


def _is_ignored(relative_path: str, patterns: Iterable[str]) -> bool:
    ignored = False
    for raw_pattern in patterns:
        negated = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if negated else raw_pattern
        if _matches_gitignore_pattern(pattern, relative_path):
            ignored = not negated
    return ignored


def test_suspect_file_is_hashed_but_never_executed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "EXECUTED.txt"
    suspect = tmp_path / "sample';Set-Content PWNED;'.cmd"
    original = f'@echo off\r\n> "{marker}" echo EXECUTED\r\n'.encode("utf-8")
    suspect.write_bytes(original)
    expected_sha256 = sha256(original).hexdigest()
    metadata_calls: list[dict[str, str]] = []

    def fake_metadata_query(script: str, *, timeout: float, env: dict[str, str]) -> PowerShellResult:
        resolved = str(suspect.resolve(strict=False))
        assert resolved not in script
        assert env == {
            "NODETRACE_TARGET": resolved,
            "NODETRACE_EXPECTED_SHA256": expected_sha256,
        }
        assert "$env:NODETRACE_TARGET" in script
        metadata_calls.append(dict(env))
        return PowerShellResult(
            ok=True,
            data={
                "MetadataSha256": expected_sha256,
                "IdentityError": None,
                "ZoneIdentifier": {"Present": False, "Length": None, "Content": None, "Error": None},
                "Signature": {"Status": "NotSigned", "SignerThumbprint": None},
                "SignatureError": None,
            },
        )

    def forbidden_process_start(*args, **kwargs):
        raise AssertionError(f"The suspect file must never be executed: args={args!r}")

    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(file_seed.helpers, "run_powershell_json", fake_metadata_query)
    monkeypatch.setattr(subprocess, "Popen", forbidden_process_start)
    monkeypatch.setattr(subprocess, "run", forbidden_process_start)
    monkeypatch.setattr(subprocess, "call", forbidden_process_start)
    monkeypatch.setattr(subprocess, "check_call", forbidden_process_start)
    monkeypatch.setattr(subprocess, "check_output", forbidden_process_start)
    monkeypatch.setattr(os, "system", forbidden_process_start)
    monkeypatch.setattr(os, "popen", forbidden_process_start)
    monkeypatch.setattr(os, "startfile", forbidden_process_start, raising=False)

    database = Database(tmp_path / "state.sqlite3")
    case = database.create_case("Safety canary", suspect_path=str(suspect))
    summary = CollectionEngine(
        database,
        [FileSeedCollector()],
        tmp_path / "artifacts",
    ).run(case.id, str(suspect), options={"read_only": True})

    assert summary.status == "completed"
    assert len(metadata_calls) == 1
    assert not marker.exists()
    assert suspect.read_bytes() == original
    evidence = database.list_evidence(case.id)
    seed = next(item for item in evidence if item.entity_type == "file")
    assert seed.properties["sha256"] == expected_sha256
    assert seed.properties["path"] == str(suspect.resolve(strict=False))


def test_file_seed_discards_metadata_when_powershell_hash_differs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    suspect = tmp_path / "metadata-race.exe"
    suspect.write_bytes(b"stable original")

    monkeypatch.setattr(file_seed.helpers, "is_windows", lambda: True)
    monkeypatch.setattr(
        file_seed.helpers,
        "run_powershell_json",
        lambda *args, **kwargs: PowerShellResult(
            ok=True,
            data={
                "MetadataSha256": "0" * 64,
                "IdentityError": "The path resolved to content with a different SHA-256 hash",
                "ZoneIdentifier": {"Present": True, "Content": "ZoneId=3"},
                "Signature": {"Status": "Valid", "SignerThumbprint": "untrusted-race"},
                "SignatureError": None,
            },
        ),
    )
    database = Database(tmp_path / "metadata-race.sqlite3")
    case = database.create_case("Metadata race", suspect_path=str(suspect))
    summary = CollectionEngine(database, [FileSeedCollector()], tmp_path / "artifacts").run(
        case.id, str(suspect), options={"read_only": True}
    )

    assert summary.status == "partial"
    evidence = database.list_evidence(case.id)
    assert [item.entity_type for item in evidence] == ["file"]
    assert "zone_identifier_present" not in evidence[0].properties
    gaps = database.list_gaps(case.id)
    assert any("Path identity check failed" in gap.reason for gap in gaps)


def test_github_ignore_excludes_runtime_evidence_and_secrets() -> None:
    gitignore = PROJECT_ROOT / ".gitignore"
    assert gitignore.is_file(), "A public source tree needs an explicit .gitignore"
    patterns = _gitignore_patterns(gitignore)
    unsafe_examples = {
        "runtime/case.sqlite3": "live SQLite case database",
        "nodetrace_ir/__pycache__/module.cpython-313.pyc": "Python bytecode/cache",
        "artifacts/case-1/run-1/raw.json": "collected forensic artifact",
        "cases/incident-42.json": "case data",
        "reports/incident-42.html": "generated incident report",
        ".env": "local credentials/environment file",
        ".venv/pyvenv.cfg": "local Python environment",
        "tools/cache/avzbase.zip": "third-party AVZ database",
        "capture.pcapng": "network evidence",
        "release-signing.key": "private signing key",
        "docs/images/nodetrace-ir-ui.png": "host desktop screenshot pending sanitization",
    }

    missing = [
        f"{relative_path} ({description})"
        for relative_path, description in unsafe_examples.items()
        if not _is_ignored(relative_path, patterns)
    ]
    assert not missing, "Missing GitHub exclusions: " + ", ".join(missing)
