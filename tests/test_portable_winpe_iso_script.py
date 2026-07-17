from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "build_winpe_iso_portable.ps1"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_portable_builder_uses_wimlib_without_mounting_or_elevation() -> None:
    script = _script()

    assert "[string]$WimlibImagex" in script
    assert "wimlib-imagex.exe" in script
    assert "$Commands | & $Wimlib update $Wim 1 --check --rebuild" in script
    assert '@("verify", $stagedWim)' in script
    assert '"extract",' in script
    assert '"--preserve-dir-structure"' in script
    assert "/Program Files/NodeTraceIR" in script
    assert "/Windows/System32/startnet.cmd" in script
    assert "/Windows/System32/launch_nodetrace.cmd" in script
    assert "Assert-Administrator" not in script
    assert '"/Mount-Image"' not in script
    assert '"/Unmount-Image"' not in script
    assert "dism.exe" not in script.casefold()


def test_portable_builder_requires_verified_x86_inputs_and_avz() -> None:
    script = _script()

    for parameter in (
        "WinPEMediaRoot",
        "WinPEWim",
        "BootSdi",
        "Bcd",
        "BootIa32Efi",
        "EfiBootImage",
        "BootManager",
        "WinPEExtractionManifest",
    ):
        assert f"[string]${parameter}" in script
    assert '"nodetrace-winpe-extraction/v1"' in script
    assert '"Microsoft Windows PE add-on 10.1.19041.5856"' in script
    assert '"nodetrace-microsoft-adk-2004-x86/v1"' in script
    assert 'CabSha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"' in script
    assert 'CabSha256 = "BFBEF5062372192C42D3833BE0AB99A9C197B4271D7B47D76F299C57DD6FA071"' in script
    assert "CabSha256 = $null" not in script
    assert "if ($null -ne $expected.CabSha256)" not in script
    assert "has no valid SHA-256 for the x86 boot WIM CAB" not in script
    assert "Assert-ExactManifestValue $payload.cab.sha256 $expected.CabSha256" in script
    assert "Assert-WinPEProvenance" in script
    assert "Assert-MsiFileHash" in script
    assert "fil642ac1bd3326d4b59398fe460db370b9" in script
    assert "fila6a550eed89046f3810ad344d06b2f13" in script
    assert "fil4db617e977c2929fa4a8a113dcc24567" in script
    assert "deployment_tools_bootstrap" in script
    assert 'OriginRole = "host-pcat-bcd"' in script
    assert 'OriginRole = "host-boot-sdi"' in script
    assert '"ia32-efi-el-torito-loader"' in script
    assert '[string]$manifest.architecture -ne "x86"' in script
    assert 'Assert-InputMatchesWinPEManifest $winPEWimFull "Media/sources/boot.wim"' in script
    assert 'Assert-InputMatchesWinPEManifest $bootIa32Full "Media/EFI/Boot/bootia32.efi"' in script
    assert 'Assert-InputMatchesWinPEManifest $efiBootImageFull "Media/fwfiles/efisys.bin"' in script
    assert "Get-PeMachine $nodeTraceFull" in script
    assert "Get-PeMachine $bootIa32Full" in script
    assert "0x014C" in script
    assert "Assert-MicrosoftAuthenticode $bootIa32Full" in script
    assert "Assert-MicrosoftAuthenticode $bootSdiFull" in script
    assert "Assert-MicrosoftAuthenticode $bcdFull" in script
    assert "if (-not $bootManagerPinnedByWinPEManifest)" in script
    assert 'Assert-MicrosoftAuthenticode $bootManagerFull "host fallback bootmgr"' in script
    assert "ADK x86 bootmgr is a flat boot binary" in script
    assert "Assert-MicrosoftAuthenticode $biosBootFull" in script
    assert 'Join-Path $env:SystemRoot "Boot\\PCAT\\bootmgr"' in script
    assert "-AcceptNonCommercialLicense" in script
    assert "-VerifyOnly" in script
    assert "fetch_avz.ps1" in script
    assert "Assert-ExtractedManifestEntry" in script
    assert "payload-sha256.txt" in script


def test_portable_builder_stages_required_bios_and_ia32_uefi_media() -> None:
    script = _script()

    assert 'Join-Path $stagingRoot "bootmgr"' in script
    assert 'Join-Path $stagingRoot "Boot\\BCD"' in script
    assert 'Join-Path $stagingRoot "Boot\\boot.sdi"' in script
    assert 'Join-Path $stagingRoot "EFI\\Boot\\bootia32.efi"' in script
    assert 'Join-Path $stagingRoot "EFI\\Microsoft\\Boot\\BCD"' in script
    assert 'Join-Path $stagingRoot "sources\\boot.wim"' in script
    assert "not interchangeable" in script
    assert "build_fat12_efi.py" in script
    assert '"--bcd"' in script
    assert "Creating and self-verifying the IA32 UEFI FAT boot image with BCD" in script
    assert 'Copy-Item -LiteralPath $efiBootImageFull -Destination $stagedEfiImage' in script
    assert 'efi_el_torito_source = $efiBootSource' in script
    assert "build_iso.py" in script
    assert "verify_bootable_iso.py" in script
    assert '"--bios-boot-image"' in script
    assert '"--efi-boot-image"' in script
    assert '"NodeTraceBoot/efisys.bin"' in script
    assert '"bootmgr",' in script
    assert '"Boot/BCD",' in script
    assert '"Boot/boot.sdi",' in script
    assert '"EFI/Boot/bootia32.efi",' in script
    assert '"EFI/Microsoft/Boot/BCD",' in script
    assert '"sources/boot.wim",' in script
    assert '$bootModes -notcontains "BIOS"' in script
    assert '$bootModes -notcontains "UEFI"' in script


def test_portable_builder_verifies_injected_hashes_and_records_build() -> None:
    script = _script()

    assert "Extracting the injected WIM paths for hash verification" in script
    assert "foreach ($sourceFile in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File)" in script
    assert "Assert-CopiedFileHash $sourceFile.FullName $extractedFile" in script
    assert '"$outputFull.sha256"' in script
    assert '"$outputFull.verification.json"' in script
    assert '"$outputFull.build.json"' in script
    assert 'schema = "nodetrace-winpe-build/v1"' in script
    assert "boot_wim_sha256" in script
    assert "iso_sha256" in script
    assert "avzbase_zip_sha256" in script
    assert "bootia32_efi_sha256" in script
    assert "bios_boot_image_sha256" in script
    assert "The ISO changed between structural verification and final hashing." in script


def test_portable_builder_cleanup_is_private_and_failure_aware() -> None:
    script = _script()

    assert '"build\\winpe-portable"' in script
    assert '"nodetrace-winpe-x86-" + [guid]::NewGuid().ToString("N")' in script
    assert "Assert-StrictChildPath -Child $sessionRoot -Parent $buildRoot" in script
    assert "if (-not $buildSucceeded)" in script
    assert "Remove-Item -LiteralPath $incompleteOutput -Force" in script
    assert "Remove-Item -LiteralPath $sessionRoot -Recurse -Force" in script
    assert "Remove-Item -LiteralPath $buildRoot" not in script


@pytest.mark.skipif(os.name != "nt", reason="PowerShell syntax validation is Windows-only")
def test_portable_builder_parses_without_needing_winpe_downloads() -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")

    environment = os.environ.copy()
    environment["NODETRACE_PORTABLE_WINPE_SCRIPT"] = str(SCRIPT)
    command = (
        "$ErrorActionPreference='Stop'; "
        "$text=[IO.File]::ReadAllText($env:NODETRACE_PORTABLE_WINPE_SCRIPT); "
        "$null=[ScriptBlock]::Create($text)"
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
