[CmdletBinding()]
param(
    [string]$Python = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$entryPoint = Join-Path $projectRoot "run_nodetrace_ir.py"

if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    throw "NodeTrace IR entry point was not found: $entryPoint"
}

function Invoke-PythonStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host "`n==> $Label" -ForegroundColor Cyan
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

Push-Location -LiteralPath $projectRoot
try {
    Invoke-PythonStep -Label "Python runtime" -Arguments @("--version")
    Invoke-PythonStep -Label "Compile source" -Arguments @(
        "-m", "compileall", "-q", "nodetrace_ir", "run_nodetrace_ir.py"
    )

    & $Python -c "import pytest"
    if ($LASTEXITCODE -ne 0) {
        throw "pytest is not installed. Run: $Python -m pip install pytest"
    }

    Write-Host "`n==> Unit and integration tests" -ForegroundColor Cyan
    & $Python -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        throw "pytest failed with exit code $LASTEXITCODE."
    }

    Invoke-PythonStep -Label "Database and export smoke test" -Arguments @(
        "run_nodetrace_ir.py", "--smoke-test"
    )

    Write-Host "`nAll NodeTrace IR checks passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
