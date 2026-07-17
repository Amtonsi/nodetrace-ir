from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = PROJECT_ROOT / "scripts" / "build_winpe_iso.ps1"
STARTNET = PROJECT_ROOT / "winpe" / "startnet.cmd"
LAUNCHER = PROJECT_ROOT / "winpe" / "launch_nodetrace.cmd"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_winpe_build_script_has_bootable_media_contract() -> None:
    script = _text(BUILD_SCRIPT)

    assert '[ValidateSet("x86", "amd64")]' in script
    assert '[string]$AdkRoot' in script
    assert '[string]$WinPERoot' in script
    assert "Resolve-AdkInstallationRoot" in script
    assert "Resolve-WinPEInstallationRoot" in script
    assert '"$Architecture\\Media"' in script
    assert "copype.cmd" in script
    assert "MakeWinPEMedia.cmd" in script
    assert "oscdimg.exe" in script
    assert '"/Mount-Image"' in script
    assert '"/Unmount-Image"' in script
    assert '"/Commit"' in script
    assert "boot.wim" in script
    assert 'SetEnvironmentVariable("WinPERoot"' in script
    assert 'SetEnvironmentVariable("OSCDImgRoot"' in script
    assert "startnet.cmd" in script
    assert "launch_nodetrace.cmd" in script


def test_winpe_build_script_enforces_architecture_and_verified_avz() -> None:
    script = _text(BUILD_SCRIPT)

    assert "Get-PeMachine" in script
    assert "0x014C" in script
    assert "0x8664" in script
    assert "amd64 WinPE has no WOW64" in script
    assert "$Architecture -eq \"x86\"" in script
    assert "-AcceptNonCommercialLicense" in script
    assert "-VerifyOnly" in script
    assert "fetch_avz.ps1" in script
    assert "Assert-SafeArchiveEntryPath" in script
    assert "Assert-ExtractedManifestEntry" in script
    assert "An extracted AVZ runtime file changed" in script
    assert "Get-FileHash" in script
    assert "payload-sha256.txt" in script
    assert '"$outputFull.sha256"' in script


def test_winpe_build_script_cleanup_is_scoped_and_mount_aware() -> None:
    script = _text(BUILD_SCRIPT)

    assert "Assert-ChildPath -Child $sessionRoot -Parent $buildRoot" in script
    assert '"nodetrace-winpe-{0}-{1}"' in script
    assert '"/Discard"' in script
    assert "$safeToRemoveSession" in script
    assert "$buildSucceeded" in script
    assert "Remove-Item -LiteralPath $incompleteOutput -Force" in script
    assert "Remove-Item -LiteralPath $sessionRoot -Recurse -Force" in script
    assert "Cleanup-Wim" not in script
    assert "Remove-Item -LiteralPath $buildRoot" not in script


def test_startnet_initializes_winpe_then_auto_launches() -> None:
    startnet = _text(STARTNET).casefold()

    assert "wpeinit" in startnet
    assert 'call "%systemroot%\\system32\\launch_nodetrace.cmd"' in startnet
    assert "pause" not in startnet
    assert "diskpart" not in startnet
    assert "format " not in startnet


def test_launcher_requires_offline_windows_and_external_writable_storage() -> None:
    launcher = _text(LAUNCHER)
    folded = launcher.casefold()

    assert "\\Windows\\System32\\Config\\SYSTEM" in launcher
    assert "\\Windows\\System32\\Config\\SOFTWARE" in launcher
    assert "NODETRACE_EVIDENCE_VOLUME" in launcher
    assert 'if /I "!CANDIDATE_DRIVE!"=="X:" exit /b 0' in launcher
    assert 'if /I "!CANDIDATE_DRIVE!"=="!OFFLINE_DRIVE!" exit /b 0' in launcher
    assert ".write-test-" in launcher
    assert "No separate writable evidence volume is available" in launcher
    assert "never stored only on volatile X:" in launcher
    assert "TEMP\\NodeTraceIR".casefold() not in folded
    assert "diskpart" not in folded
    assert "format " not in folded


def test_launcher_passes_explicit_winpe_offline_and_data_arguments() -> None:
    launcher = _text(LAUNCHER)

    assert '"%NODETRACE_EXE%" --winpe --offline-root "!OFFLINE_DRIVE!\\." --data-dir "!DATA_DIR!"' in launcher
    assert 'set "NODETRACE_IR_DATA_DIR=!DATA_DIR!"' in launcher
    assert 'set "NODETRACE_AVZ_EXE=%NODETRACE_HOME%\\AVZ\\avz.exe"' in launcher
    assert "AVZ requires x86 WinPE; amd64 WinPE has no WOW64." in launcher
    assert "winpe-session.txt" in launcher


@pytest.mark.skipif(os.name != "nt", reason="PowerShell syntax validation is Windows-only")
def test_winpe_build_script_parses_without_executing() -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")

    command = (
        "$ErrorActionPreference='Stop'; "
        "$text=[IO.File]::ReadAllText($env:NODETRACE_WINPE_SCRIPT); "
        "$null=[ScriptBlock]::Create($text)"
    )
    environment = os.environ.copy()
    environment["NODETRACE_WINPE_SCRIPT"] = str(BUILD_SCRIPT)
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
