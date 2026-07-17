from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "smoke_test_winpe_vm.ps1"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_vm_smoke_script_is_x86_bios_dvd_and_isolated() -> None:
    script = _script()

    assert '"--ostype", "Windows10"' in script
    assert '"--firmware", "bios"' in script
    assert '"--boot1", "dvd"' in script
    assert '"--boot2", "none"' in script
    assert '"--nic1", "none"' in script
    assert '"--clipboard-mode", "disabled"' in script
    assert '"--drag-and-drop", "disabled"' in script
    assert '"--usb-ohci", "off"' in script
    assert '"--type", "headless"' in script
    assert "sharedfolder" not in script.casefold()


def test_functional_probe_is_default_on_and_uses_only_disposable_fat_images() -> None:
    script = _script()

    assert "[switch]$DisableFunctionalProbe" in script
    assert "$functionalProbeEnabled = -not $DisableFunctionalProbe.IsPresent" in script
    assert '"build_fat16_disk.py"' in script
    assert '"--label", "WIN_TARGET"' in script
    assert '"--label", "IR_EVIDENCE"' in script
    assert 'Windows/System32/Config/SYSTEM' in script
    assert 'Windows/System32/Config/SOFTWARE' in script
    assert 'NODETRACE_EVIDENCE_VOLUME' in script
    assert '"convertfromraw", $targetRawPath, $targetVdiPath, "--format=VDI"' in script
    assert '"convertfromraw", $evidenceRawPath, $evidenceVdiPath, "--format=VDI"' in script
    assert '"--name", "SATA"' in script
    assert '"--port", "0"' in script
    assert '"--port", "1"' in script
    assert "diskpart" not in script.casefold()
    assert "format.com" not in script.casefold()


def test_functional_probe_proves_launcher_and_application_wrote_evidence() -> None:
    script = _script()

    assert '"clonemedium", $evidenceVdiPath, $evidenceAfterRawPath' in script
    assert '$fatBuilderPath, "inspect"' in script
    assert "launcher_session_marker_detected" in script
    assert "application_database_detected" in script
    assert "winpe-session\\.txt" in script
    assert "nodetrace_ir\\.sqlite3" in script
    assert '"functional-probe-evidence.json"' in script
    assert "evidence_sha256_after_boot" in script
    assert "sha256_before_boot" in script
    assert "required_paths" in script
    assert "The disposable evidence disk contains no automatic NodeTrace IR launch artifacts" in script


def test_vm_smoke_script_has_bounded_observation_and_evidence() -> None:
    script = _script()

    assert "[ValidateRange(15, 900)]" in script
    assert "$BootTimeoutSeconds = 90" in script
    assert "$deadline = $startUtc.AddSeconds($BootTimeoutSeconds)" in script
    assert "$sleepSeconds = [Math]::Min([double]$PollIntervalSeconds, $remainingSeconds)" in script
    assert '"screenshotpng", $screenshotPath' in script
    assert '"winpe-final.png"' in script
    assert '"smoke-result.json"' in script
    assert '"SHA256SUMS.txt"' in script
    assert "Get-FileHash -LiteralPath $isoFull -Algorithm SHA256" in script
    assert 'Get-ChildItem -LiteralPath $sessionRoot -Recurse -File -Filter "VBox.log*"' in script


def test_process_output_is_drained_asynchronously_before_wait_for_exit() -> None:
    script = _script()

    for function_name, next_function_name in (
        ("Invoke-VBoxManage", "Invoke-Python"),
        ("Invoke-Python", "ConvertFrom-MachineReadableInfo"),
    ):
        body = script.split(f"function {function_name} {{", 1)[1].split(
            f"function {next_function_name} {{", 1
        )[0]
        wait = body.index("if (-not $process.WaitForExit(")
        stdout_start = body.index("$standardOutputTask = $process.StandardOutput.ReadToEndAsync()")
        stderr_start = body.index("$standardErrorTask = $process.StandardError.ReadToEndAsync()")
        stdout_finish = body.index("$standardOutputTask.GetAwaiter().GetResult()")
        stderr_finish = body.index("$standardErrorTask.GetAwaiter().GetResult()")

        assert stdout_start < wait < stdout_finish
        assert stderr_start < wait < stderr_finish
        assert "$process.StandardOutput.ReadToEnd()" not in body
        assert "$process.StandardError.ReadToEnd()" not in body

def test_vm_smoke_cleanup_is_scoped_and_identity_checked() -> None:
    script = _script()

    assert '"NodeTraceIR-WinPE-Smoke-$runId"' in script
    assert '"nodetrace-vm-smoke-$runId"' in script
    assert '".nodetrace-vm-smoke.json"' in script
    assert "Assert-CleanupMarker" in script
    assert "Assert-StrictChildPath -Child $cleanupConfiguration -Parent $sessionRoot" in script
    assert "The registered VM UUID changed" in script
    assert "$registrationProbe = Get-VmInfo -Identifier $vmName -AllowFailure" in script
    assert "Assert-StrictChildPath -Child $probedConfiguration -Parent $sessionRoot" in script
    assert '"unregistervm", [string]$cleanupInfo["UUID"], "--delete"' in script
    assert "Assert-NotReparsePoint -Path $SessionPath" in script
    assert "Assert-StrictChildPath -Child $evidenceAfterRawPath -Parent $sessionRoot" in script
    assert '"closemedium", "disk", $evidenceAfterRawPath' in script
    assert "Remove-Item -LiteralPath $sessionRoot -Recurse -Force" in script
    assert "Remove-Item -LiteralPath $buildRootFull" not in script
    assert "Remove-Item -LiteralPath $evidenceFull" not in script


def test_keep_retains_but_still_powers_off_vm() -> None:
    script = _script()

    assert "[switch]$Keep" in script
    assert '"controlvm", $(if ($null -ne $vmUuid) { $vmUuid } else { $vmName }), "poweroff"' in script
    assert "if (-not $Keep -and $vmRegistered)" in script
    assert "if ($Keep)" in script
    assert "The powered-off VM and private session were retained" in script


@pytest.mark.skipif(os.name != "nt", reason="PowerShell syntax validation is Windows-only")
def test_vm_smoke_script_parses_without_running_virtualbox() -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("Windows PowerShell is unavailable")

    environment = os.environ.copy()
    environment["NODETRACE_VM_SMOKE_SCRIPT"] = str(SCRIPT)
    command = (
        "$ErrorActionPreference='Stop'; "
        "$text=[IO.File]::ReadAllText($env:NODETRACE_VM_SMOKE_SCRIPT); "
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
