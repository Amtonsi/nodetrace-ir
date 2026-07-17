from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import zipfile

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGER = PROJECT_ROOT / "scripts" / "package_release.ps1"

FORBIDDEN_EXTENSIONS = {
    ".avz",
    ".cab",
    ".db",
    ".dll",
    ".dmp",
    ".esd",
    ".evtx",
    ".exe",
    ".iso",
    ".jks",
    ".kdbx",
    ".key",
    ".msi",
    ".msix",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".sys",
    ".vdi",
    ".vhd",
    ".vhdx",
    ".wim",
    ".zip",
}
FORBIDDEN_SEGMENTS = {
    ".pytest_cache",
    "__pycache__",
    "artifacts",
    "build",
    "cache",
    "case_artifacts",
    "cases",
    "dist",
    "history",
    "release",
    "reports",
}
HIGH_CONFIDENCE_SECRETS = (
    re.compile(rb"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(rb"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9])"),
)


def _powershell() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("powershell")


@pytest.mark.skipif(os.name != "nt", reason="release packager is Windows PowerShell")
def test_source_release_is_exact_allowlist_without_evidence_or_secrets(
    tmp_path: Path,
) -> None:
    powershell = _powershell()
    if powershell is None:
        pytest.skip("Windows PowerShell is unavailable")

    output = tmp_path / "release"
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PACKAGER),
            "-Version",
            "0.3.0-test",
            "-SourceOnly",
            "-OutputDirectory",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    archive_path = output / "NodeTraceIR-0.3.0-test-source.zip"
    checksum_path = output / "SHA256SUMS.txt"
    assert archive_path.is_file()
    assert checksum_path.is_file()
    expected_line = (
        f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  "
        f"{archive_path.name}"
    )
    assert checksum_path.read_text(encoding="utf-8").strip() == expected_line

    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(name.casefold() for name in names))
        assert names
        root = "NodeTraceIR-0.3.0-test"
        assert all(name.startswith(f"{root}/") for name in names)
        assert f"{root}/scripts/prepare_winpe_2004_x86_portable.ps1" in names
        assert f"{root}/tools/update_avz_base.py" in names
        assert f"{root}/tests/test_release_packaging.py" in names
        assert f"{root}/docs/images/nodetrace-ir-ui.png" not in names

        for name in names:
            path = PurePosixPath(name)
            assert path.suffix.casefold() not in FORBIDDEN_EXTENSIONS, name
            assert not (set(part.casefold() for part in path.parts) & FORBIDDEN_SEGMENTS)
            payload = archive.read(name)
            for pattern in HIGH_CONFIDENCE_SECRETS:
                assert pattern.search(payload) is None, name


def test_packager_has_no_extension_wildcard_for_public_source_folders() -> None:
    script = PACKAGER.read_text(encoding="utf-8")
    source_rule_block = script.split("$folderRules = @(", 1)[1].split(
        "foreach ($rule in $folderRules)", 1
    )[0]
    assert 'Extensions = @(".py")' not in source_rule_block
    assert 'Extensions = @(".ps1", ".py")' not in source_rule_block
    assert 'Extensions = @(".py", ".xml", ".txt")' not in source_rule_block
