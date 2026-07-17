[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$NodeTraceExecutable,
    [string]$AvzDirectory,
    [string]$OutputPath,
    [int64]$SourceDateEpoch = 946684800,
    [switch]$AcceptNonCommercialLicense
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The NodeTrace IR live-media ISO must be assembled on Windows."
}
if (-not $AcceptNonCommercialLicense) {
    throw "Re-run with -AcceptNonCommercialLicense after reviewing AVZ terms and THIRD_PARTY_AVZ_NOTICE.txt."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($NodeTraceExecutable)) {
    $NodeTraceExecutable = Join-Path $projectRoot "dist\NodeTraceIR.exe"
}
if ([string]::IsNullOrWhiteSpace($AvzDirectory)) {
    $AvzDirectory = Join-Path $projectRoot "tools\cache"
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $projectRoot "dist\NodeTraceIR-IR-Live.iso"
}

$nodeTraceFull = [System.IO.Path]::GetFullPath($NodeTraceExecutable)
$avzRoot = [System.IO.Path]::GetFullPath($AvzDirectory)
$outputFull = [System.IO.Path]::GetFullPath($OutputPath)
$stagingRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "build\iso\staging"))
$safeStagingParent = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "build\iso"))
$builder = Join-Path $PSScriptRoot "build_iso.py"
$fetcher = Join-Path $projectRoot "tools\fetch_avz.ps1"
$manifest = Join-Path $projectRoot "tools\avz-manifest.json"
$launcher = Join-Path $projectRoot "iso\START_NODETRACE_IR.cmd"
$readme = Join-Path $projectRoot "iso\README_RU.txt"
$thirdPartyNotice = Join-Path $projectRoot "iso\THIRD_PARTY_AVZ_NOTICE.txt"

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $parentPrefix = $Parent.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Child.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing filesystem operation outside the intended build directory: $Child"
    }
}

foreach ($required in @($nodeTraceFull, $builder, $fetcher, $manifest, $launcher, $readme, $thirdPartyNotice)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required ISO input was not found: $required"
    }
}
if ([System.IO.Path]::GetExtension($outputFull) -ne ".iso") {
    throw "OutputPath must end in .iso: $outputFull"
}

Write-Host "==> Checking Python" -ForegroundColor Cyan
& $Python --version
if ($LASTEXITCODE -ne 0) {
    throw "Python could not be started: $Python"
}

Write-Host "==> Verifying pinned AVZ archives" -ForegroundColor Cyan
& $fetcher -AcceptNonCommercialLicense -VerifyOnly -Destination $avzRoot -ManifestPath $manifest
if ($LASTEXITCODE -ne 0) {
    throw "AVZ archive verification failed with exit code $LASTEXITCODE."
}

$avzArchive = Join-Path $avzRoot "avz4.zip"
$baseArchive = Join-Path $avzRoot "avzbase.zip"
Assert-ChildPath -Child $stagingRoot -Parent $safeStagingParent
if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}

try {
    $stagingAvz = Join-Path $stagingRoot "AVZ"
    New-Item -ItemType Directory -Force -Path $stagingAvz | Out-Null
    Copy-Item -LiteralPath $nodeTraceFull -Destination (Join-Path $stagingRoot "NodeTraceIR.exe")
    Copy-Item -LiteralPath $avzArchive -Destination (Join-Path $stagingAvz "avz4.zip")
    Copy-Item -LiteralPath $baseArchive -Destination (Join-Path $stagingAvz "avzbase.zip")
    Copy-Item -LiteralPath $launcher -Destination (Join-Path $stagingRoot "START_NODETRACE_IR.cmd")
    Copy-Item -LiteralPath $readme -Destination (Join-Path $stagingRoot "README_RU.txt")
    Copy-Item -LiteralPath $thirdPartyNotice -Destination (Join-Path $stagingRoot "THIRD_PARTY_AVZ_NOTICE.txt")
    Copy-Item -LiteralPath $manifest -Destination (Join-Path $stagingRoot "AVZ_MANIFEST.json")

    foreach ($pair in @(
        @($avzArchive, (Join-Path $stagingAvz "avz4.zip")),
        @($baseArchive, (Join-Path $stagingAvz "avzbase.zip"))
    )) {
        $sourceHash = (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash
        $copyHash = (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash
        if ($sourceHash -ne $copyHash) {
            throw "An AVZ archive changed while it was copied into ISO staging: $($pair[0])"
        }
    }

    $checksumLines = @(
        "$(Get-FileHash -LiteralPath (Join-Path $stagingRoot 'NodeTraceIR.exe') -Algorithm SHA256 | Select-Object -ExpandProperty Hash) *NodeTraceIR.exe",
        "$(Get-FileHash -LiteralPath (Join-Path $stagingAvz 'avz4.zip') -Algorithm SHA256 | Select-Object -ExpandProperty Hash) *AVZ/avz4.zip",
        "$(Get-FileHash -LiteralPath (Join-Path $stagingAvz 'avzbase.zip') -Algorithm SHA256 | Select-Object -ExpandProperty Hash) *AVZ/avzbase.zip"
    )
    [System.IO.File]::WriteAllText(
        (Join-Path $stagingRoot "MEDIA_SHA256SUMS.txt"),
        (($checksumLines -join "`n").ToLowerInvariant() + "`n"),
        (New-Object System.Text.UTF8Encoding($false))
    )

    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($outputFull)) | Out-Null
    Write-Host "==> Building deterministic ISO-9660/Joliet image" -ForegroundColor Cyan
    & $Python $builder --staging $stagingRoot --output $outputFull --volume-label "NODETRACE_IR" --source-date-epoch $SourceDateEpoch
    if ($LASTEXITCODE -ne 0) {
        throw "ISO builder failed with exit code $LASTEXITCODE."
    }

    $isoHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash.ToLowerInvariant()
    $sidecar = "$outputFull.sha256"
    [System.IO.File]::WriteAllText(
        $sidecar,
        "$isoHash *$([System.IO.Path]::GetFileName($outputFull))`n",
        (New-Object System.Text.UTF8Encoding($false))
    )
    $isoFile = Get-Item -LiteralPath $outputFull
    Write-Host "ISO build complete." -ForegroundColor Green
    Write-Host "Path:    $($isoFile.FullName)"
    Write-Host "Size:    $($isoFile.Length) bytes"
    Write-Host "SHA-256: $isoHash"
    Write-Host "Hash file: $sidecar"
}
finally {
    Assert-ChildPath -Child $stagingRoot -Parent $safeStagingParent
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}
