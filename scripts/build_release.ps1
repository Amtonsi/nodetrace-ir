[CmdletBinding()]
param(
    [string]$Python = "python",
    [ValidateSet("x86", "amd64")]
    [string]$Architecture = "amd64",
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "NodeTraceIR.exe must be built on Windows."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$entryPoint = Join-Path $projectRoot "run_nodetrace_ir.py"
$distDir = if ($Architecture -eq "x86") {
    Join-Path $projectRoot "dist\winpe-x86"
}
else {
    Join-Path $projectRoot "dist"
}
$workDir = Join-Path $projectRoot "build\pyinstaller-$Architecture"
$specDir = Join-Path $projectRoot "build\specs-$Architecture"
$outputExe = Join-Path $distDir "NodeTraceIR.exe"
$testScript = Join-Path $PSScriptRoot "run_tests.ps1"
$assetsDir = Join-Path $projectRoot "assets"
$iconPath = Join-Path $assetsDir "nodetrace-ir.ico"
$pngIconPath = Join-Path $assetsDir "nodetrace-icon.png"

if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    throw "NodeTrace IR entry point was not found: $entryPoint"
}
if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
    throw "NodeTrace IR icon was not found: $iconPath"
}
if (-not (Test-Path -LiteralPath $pngIconPath -PathType Leaf)) {
    throw "NodeTrace IR runtime icon was not found: $pngIconPath"
}

Push-Location -LiteralPath $projectRoot
try {
    Write-Host "==> Checking Python" -ForegroundColor Cyan
    & $Python --version
    if ($LASTEXITCODE -ne 0) {
        throw "Python could not be started: $Python"
    }
    $runtimeJson = & $Python -c "import json, struct, sys; print(json.dumps({'major': sys.version_info.major, 'minor': sys.version_info.minor, 'bits': struct.calcsize('P') * 8}))"
    if ($LASTEXITCODE -ne 0) {
        throw "Python runtime architecture could not be inspected: $Python"
    }
    $runtime = $runtimeJson | ConvertFrom-Json
    if ([int]$runtime.major -ne 3 -or [int]$runtime.minor -lt 11) {
        throw "NodeTrace IR requires Python 3.11 or newer; found $($runtime.major).$($runtime.minor)."
    }
    $expectedBits = if ($Architecture -eq "x86") { 32 } else { 64 }
    if ([int]$runtime.bits -ne $expectedBits) {
        throw "The $Architecture release must be built with $expectedBits-bit Python; found $($runtime.bits)-bit."
    }

    Write-Host "==> Checking PyInstaller" -ForegroundColor Cyan
    & $Python -c "import PyInstaller; print('PyInstaller ' + PyInstaller.__version__)"
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed. Run: $Python -m pip install pyinstaller"
    }

    if (-not $SkipTests) {
        & $testScript -Python $Python
        if (-not $?) {
            throw "Pre-build checks failed."
        }
    }
    else {
        Write-Warning "Tests were explicitly skipped. Do not publish this build without running scripts/run_tests.ps1."
    }

    New-Item -ItemType Directory -Force -Path $distDir, $workDir, $specDir | Out-Null

    Write-Host "`n==> Building one-file windowed $Architecture EXE" -ForegroundColor Cyan
    $pyInstallerArguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--uac-admin",
        "--name", "NodeTraceIR",
        "--icon", $iconPath,
        "--add-data", "$pngIconPath;assets",
        "--distpath", $distDir,
        "--workpath", $workDir,
        "--specpath", $specDir,
        "--paths", $projectRoot,
        $entryPoint
    )
    & $Python @pyInstallerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path -LiteralPath $outputExe -PathType Leaf)) {
        throw "PyInstaller completed without the expected output: $outputExe"
    }

    Write-Host "`n==> Running packaged smoke test" -ForegroundColor Cyan
    # The release requests elevation for AVZ and protected event logs.  The
    # self-contained smoke path never touches those sources, so RunAsInvoker
    # avoids an interactive UAC prompt while testing the packaged runtime.
    $previousCompatLayer = $env:__COMPAT_LAYER
    try {
        $env:__COMPAT_LAYER = "RunAsInvoker"
        $smoke = Start-Process -FilePath $outputExe -ArgumentList "--smoke-test" -PassThru -WindowStyle Hidden
        if (-not $smoke.WaitForExit(45000)) {
            Stop-Process -Id $smoke.Id -Force -ErrorAction SilentlyContinue
            throw "Packaged smoke test exceeded 45 seconds."
        }
        if ($smoke.ExitCode -ne 0) {
            throw "Packaged smoke test failed with exit code $($smoke.ExitCode)."
        }
    }
    finally {
        if ($null -eq $previousCompatLayer) {
            Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue
        }
        else {
            $env:__COMPAT_LAYER = $previousCompatLayer
        }
    }
    Write-Host "Packaged database/export smoke test passed." -ForegroundColor Green

    $file = Get-Item -LiteralPath $outputExe
    $digest = Get-FileHash -LiteralPath $outputExe -Algorithm SHA256
    Write-Host "`nBuild complete." -ForegroundColor Green
    Write-Host "Path:    $($file.FullName)"
    Write-Host "Size:    $($file.Length) bytes"
    Write-Host "SHA-256: $($digest.Hash)"
}
finally {
    Pop-Location
}
