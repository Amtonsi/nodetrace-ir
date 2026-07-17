[CmdletBinding()]
param(
    [ValidateSet("x86", "amd64")]
    [string]$Architecture = "x86",
    [string]$NodeTraceExecutable,
    [string]$AdkRoot,
    [string]$WinPERoot,
    [string]$AvzDirectory,
    [string]$OutputPath,
    [switch]$AcceptNonCommercialLicense
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "A bootable NodeTrace IR WinPE ISO must be built on Windows."
}
if (-not $AcceptNonCommercialLicense) {
    throw "Re-run with -AcceptNonCommercialLicense after reviewing the AVZ distribution terms."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "build\winpe"))
$fetcher = Join-Path $projectRoot "tools\fetch_avz.ps1"
$manifestPath = Join-Path $projectRoot "tools\avz-manifest.json"
$startnetSource = Join-Path $projectRoot "winpe\startnet.cmd"
$launcherSource = Join-Path $projectRoot "winpe\launch_nodetrace.cmd"

if ([string]::IsNullOrWhiteSpace($NodeTraceExecutable)) {
    $NodeTraceExecutable = Join-Path $projectRoot "dist\NodeTraceIR.exe"
}
if ([string]::IsNullOrWhiteSpace($AvzDirectory)) {
    $AvzDirectory = Join-Path $projectRoot "tools\cache"
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $projectRoot "dist\NodeTraceIR-WinPE-$Architecture.iso"
}

$nodeTraceFull = [System.IO.Path]::GetFullPath($NodeTraceExecutable)
$avzRoot = [System.IO.Path]::GetFullPath($AvzDirectory)
$outputFull = [System.IO.Path]::GetFullPath($OutputPath)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "WinPE image servicing requires an elevated PowerShell session."
    }
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $childFull = [System.IO.Path]::GetFullPath($Child)
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd("\", "/")
    $prefix = $parentFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a build operation outside the private WinPE work root: $childFull"
    }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file was not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a reparse-point input file: $($item.FullName)"
    }
}

function Resolve-AdkInstallationRoot {
    param([string]$ExplicitRoot)

    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        $candidates.Add($ExplicitRoot)
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($env:WindowsSdkDir)) {
            $candidates.Add((Join-Path $env:WindowsSdkDir "Assessment and Deployment Kit"))
        }
        if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
            $candidates.Add((Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Assessment and Deployment Kit"))
        }
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
            $candidates.Add((Join-Path $env:ProgramFiles "Windows Kits\10\Assessment and Deployment Kit"))
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $full = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath (Join-Path $full "Deployment Tools") -PathType Container) {
            return $full
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        throw "The explicit ADK root does not contain 'Deployment Tools': $ExplicitRoot"
    }
    throw "Windows ADK Deployment Tools were not found. Install the ADK or pass -AdkRoot explicitly."
}

function Resolve-WinPEInstallationRoot {
    param(
        [string]$ExplicitRoot,
        [Parameter(Mandatory = $true)][string]$ResolvedAdkRoot
    )

    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        $candidates.Add($ExplicitRoot)
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($env:WinPERoot)) {
            $candidates.Add($env:WinPERoot)
        }
        $candidates.Add((Join-Path $ResolvedAdkRoot "Windows Preinstallation Environment"))
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $full = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath (Join-Path $full "copype.cmd") -PathType Leaf) {
            return $full
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExplicitRoot)) {
        throw "The explicit WinPE add-on root does not contain copype.cmd: $ExplicitRoot"
    }
    throw "The Windows PE add-on was not found. Install it or pass -WinPERoot explicitly."
}

function Find-FirstFile {
    param([Parameter(Mandatory = $true)][string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    return $null
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Write-Host "==> $Description" -ForegroundColor Cyan
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-RegularFile -Path $Path
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "The file is not a valid PE executable (missing MZ header): $Path"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            throw "The file has an invalid PE header offset: $Path"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "The file is not a valid PE executable (missing PE signature): $Path"
        }
        return [int]$reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Assert-SafeArchiveEntryPath {
    param([Parameter(Mandatory = $true)][string]$EntryPath)

    $normalized = $EntryPath.Replace("\", "/")
    $segments = @($normalized.Split([char]"/"))
    if (
        [string]::IsNullOrWhiteSpace($normalized) -or
        $normalized.StartsWith("/") -or
        $normalized -match "^[A-Za-z]:" -or
        $segments -contains "." -or
        $segments -contains ".."
    ) {
        throw "Unsafe path in the pinned AVZ manifest: $EntryPath"
    }
}

function Get-ManifestArchive {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = @($Manifest.archives) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if ($null -eq $result) {
        throw "Pinned AVZ manifest is missing archive metadata for $Name."
    }
    return $result
}

function Assert-ExtractedManifestEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object]$Entry
    )

    Assert-SafeArchiveEntryPath -EntryPath ([string]$Entry.path)
    if ([string]$Entry.path.EndsWith("/")) {
        return
    }
    $entryPath = Join-Path $Root ([string]$Entry.path).Replace("/", "\")
    if (-not (Test-Path -LiteralPath $entryPath -PathType Leaf)) {
        throw "A verified AVZ archive entry was not extracted: $($Entry.path)"
    }
    $hash = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash
    if ($hash -ne [string]$Entry.sha256) {
        throw "An extracted AVZ entry failed SHA-256 verification: $($Entry.path)"
    }
}

Assert-Administrator
foreach ($required in @($nodeTraceFull, $fetcher, $manifestPath, $startnetSource, $launcherSource)) {
    Assert-RegularFile -Path $required
}
if ([System.IO.Path]::GetExtension($outputFull) -ne ".iso") {
    throw "OutputPath must end in .iso: $outputFull"
}
if (Test-Path -LiteralPath $outputFull) {
    throw "Refusing to overwrite an existing ISO. Choose a new -OutputPath or remove it explicitly: $outputFull"
}
$sidecarPath = "$outputFull.sha256"
if (Test-Path -LiteralPath $sidecarPath) {
    throw "Refusing to overwrite an existing ISO checksum sidecar: $sidecarPath"
}

$expectedMachine = if ($Architecture -eq "x86") { 0x014C } else { 0x8664 }
$nodeTraceMachine = Get-PeMachine -Path $nodeTraceFull
if ($nodeTraceMachine -ne $expectedMachine) {
    throw ("NodeTraceIR.exe machine 0x{0:X4} does not match {1} WinPE (expected 0x{2:X4}). Build NodeTrace IR with a {3}-bit Python runtime." -f $nodeTraceMachine, $Architecture, $expectedMachine, $(if ($Architecture -eq "x86") { 32 } else { 64 }))
}

$resolvedAdkRoot = Resolve-AdkInstallationRoot -ExplicitRoot $AdkRoot
$resolvedWinPERoot = Resolve-WinPEInstallationRoot -ExplicitRoot $WinPERoot -ResolvedAdkRoot $resolvedAdkRoot
$copype = Join-Path $resolvedWinPERoot "copype.cmd"
$makeWinPEMedia = Join-Path $resolvedWinPERoot "MakeWinPEMedia.cmd"
$architectureMediaRoot = Join-Path $resolvedWinPERoot "$Architecture\Media"
if (-not (Test-Path -LiteralPath $architectureMediaRoot -PathType Container)) {
    $hint = if ($Architecture -eq "x86") {
        "Install a Windows 10 ADK/WinPE add-on release that still includes x86 WinPE; amd64-only WinPE cannot execute AVZ."
    }
    else {
        "Install the matching amd64 Windows PE add-on."
    }
    throw "The selected WinPE add-on has no $Architecture media template at $architectureMediaRoot. $hint"
}

$hostToolArchitecture = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
$toolArchitectures = if ([Environment]::Is64BitOperatingSystem) { @("amd64", "x86") } else { @("x86") }
$dismCandidates = [System.Collections.Generic.List[string]]::new()
$oscdimgCandidates = [System.Collections.Generic.List[string]]::new()
foreach ($toolArchitecture in $toolArchitectures) {
    $dismCandidates.Add((Join-Path $resolvedAdkRoot "Deployment Tools\$toolArchitecture\DISM\dism.exe"))
    $oscdimgCandidates.Add((Join-Path $resolvedAdkRoot "Deployment Tools\$toolArchitecture\Oscdimg\oscdimg.exe"))
}
$dismCandidates.Add((Join-Path $env:SystemRoot "System32\dism.exe"))
$dism = Find-FirstFile -Candidates $dismCandidates.ToArray()
$oscdimg = Find-FirstFile -Candidates $oscdimgCandidates.ToArray()
if ($null -eq $dism) {
    throw "DISM was not found in the ADK or Windows System32."
}
if (-not (Test-Path -LiteralPath $makeWinPEMedia -PathType Leaf) -and $null -eq $oscdimg) {
    throw "Neither MakeWinPEMedia.cmd nor oscdimg.exe was found in the selected ADK/WinPE installation."
}

Write-Host "==> Verifying pinned AVZ archives and every manifest entry" -ForegroundColor Cyan
& $fetcher -AcceptNonCommercialLicense -VerifyOnly -Destination $avzRoot -ManifestPath $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw "AVZ verification failed with exit code $LASTEXITCODE."
}

$avzArchive = Join-Path $avzRoot "avz4.zip"
$baseArchive = Join-Path $avzRoot "avzbase.zip"
Assert-RegularFile -Path $avzArchive
Assert-RegularFile -Path $baseArchive
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$avzMetadata = Get-ManifestArchive -Manifest $manifest -Name "avz4.zip"
$baseMetadata = Get-ManifestArchive -Manifest $manifest -Name "avzbase.zip"
foreach ($archiveMetadata in @($avzMetadata, $baseMetadata)) {
    foreach ($entry in @($archiveMetadata.zip.entries)) {
        Assert-SafeArchiveEntryPath -EntryPath ([string]$entry.path)
    }
}

New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
$sessionRoot = Join-Path $buildRoot ("nodetrace-winpe-{0}-{1}" -f $Architecture, [guid]::NewGuid().ToString("N"))
Assert-ChildPath -Child $sessionRoot -Parent $buildRoot
$workSet = Join-Path $sessionRoot "workset"
$mountRoot = Join-Path $sessionRoot "mount"
$payloadRoot = Join-Path $sessionRoot "payload"
$avzExtractRoot = Join-Path $sessionRoot "avz-extracted"
$mounted = $false
$safeToRemoveSession = $true
$buildSucceeded = $false
$adkEnvironmentNames = @(
    "DeploymentTools",
    "WinPERoot",
    "DISMRoot",
    "ImagingRoot",
    "BCDBootRoot",
    "OSCDImgRoot",
    "PATH"
)
$savedAdkEnvironment = @{}
foreach ($name in $adkEnvironmentNames) {
    $savedAdkEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$deploymentToolsRoot = Join-Path $resolvedAdkRoot "Deployment Tools"
$dismRoot = Join-Path $deploymentToolsRoot "$hostToolArchitecture\DISM"
$imagingRoot = Join-Path $deploymentToolsRoot "$hostToolArchitecture\Imaging"
$bcdBootRoot = Join-Path $deploymentToolsRoot "$hostToolArchitecture\BCDBoot"
$oscdimgRoot = Join-Path $deploymentToolsRoot "$hostToolArchitecture\Oscdimg"
$adkPathPrefix = @($dismRoot, $imagingRoot, $bcdBootRoot, $oscdimgRoot) -join ";"

try {
    [Environment]::SetEnvironmentVariable("DeploymentTools", $deploymentToolsRoot, "Process")
    [Environment]::SetEnvironmentVariable("WinPERoot", $resolvedWinPERoot, "Process")
    [Environment]::SetEnvironmentVariable("DISMRoot", $dismRoot, "Process")
    [Environment]::SetEnvironmentVariable("ImagingRoot", $imagingRoot, "Process")
    [Environment]::SetEnvironmentVariable("BCDBootRoot", $bcdBootRoot, "Process")
    [Environment]::SetEnvironmentVariable("OSCDImgRoot", $oscdimgRoot, "Process")
    [Environment]::SetEnvironmentVariable("PATH", "$adkPathPrefix;$env:PATH", "Process")

    New-Item -ItemType Directory -Path $sessionRoot, $mountRoot, $payloadRoot, $avzExtractRoot | Out-Null

    Write-Host "==> Preparing verified AVZ runtime" -ForegroundColor Cyan
    Expand-Archive -LiteralPath $avzArchive -DestinationPath $avzExtractRoot -Force
    $avzExeEntry = @($avzMetadata.zip.entries) |
        Where-Object { ([string]$_.path).Replace("\", "/") -match "(^|/)avz[.]exe$" } |
        Select-Object -First 1
    if ($null -eq $avzExeEntry) {
        throw "The pinned AVZ manifest does not contain avz.exe."
    }
    foreach ($entry in @($avzMetadata.zip.entries)) {
        Assert-ExtractedManifestEntry -Root $avzExtractRoot -Entry $entry
    }
    $sourceAvzExe = Join-Path $avzExtractRoot ([string]$avzExeEntry.path).Replace("/", "\")
    $sourceAvzHome = Split-Path -Parent $sourceAvzExe

    $firstBaseFile = @($baseMetadata.zip.entries) |
        Where-Object { -not ([string]$_.path).EndsWith("/") } |
        Select-Object -First 1
    if ($null -eq $firstBaseFile) {
        throw "The pinned AVZ base archive contains no files."
    }
    $baseSample = ([string]$firstBaseFile.path).Replace("\", "/")
    if ($baseSample.StartsWith("avz4/", [System.StringComparison]::OrdinalIgnoreCase)) {
        $baseDestination = $avzExtractRoot
        $baseVerificationRoot = $avzExtractRoot
    }
    elseif ($baseSample.StartsWith("Base/", [System.StringComparison]::OrdinalIgnoreCase)) {
        $baseDestination = $sourceAvzHome
        $baseVerificationRoot = $sourceAvzHome
    }
    else {
        $baseDestination = Join-Path $sourceAvzHome "Base"
        $baseVerificationRoot = $baseDestination
    }
    New-Item -ItemType Directory -Force -Path $baseDestination | Out-Null
    Expand-Archive -LiteralPath $baseArchive -DestinationPath $baseDestination -Force
    foreach ($entry in @($baseMetadata.zip.entries)) {
        Assert-ExtractedManifestEntry -Root $baseVerificationRoot -Entry $entry
    }

    $payloadAvz = Join-Path $payloadRoot "AVZ"
    New-Item -ItemType Directory -Path $payloadAvz | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $sourceAvzHome -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $payloadAvz -Recurse -Force
    }
    foreach ($sourceFile in Get-ChildItem -LiteralPath $sourceAvzHome -Recurse -File) {
        $relative = $sourceFile.FullName.Substring($sourceAvzHome.Length).TrimStart("\", "/")
        $copiedFile = Join-Path $payloadAvz $relative
        if (-not (Test-Path -LiteralPath $copiedFile -PathType Leaf) -or (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $copiedFile -Algorithm SHA256).Hash) {
            throw "An extracted AVZ runtime file changed while it was copied into the WinPE payload: $relative"
        }
    }
    $payloadAvzExe = Join-Path $payloadAvz "avz.exe"
    Assert-RegularFile -Path $payloadAvzExe
    $avzMachine = Get-PeMachine -Path $payloadAvzExe
    if ($avzMachine -ne 0x014C) {
        throw ("Pinned AVZ executable machine 0x{0:X4} is not x86 (0x014C)." -f $avzMachine)
    }

    $payloadArchives = Join-Path $payloadAvz "Archives"
    New-Item -ItemType Directory -Path $payloadArchives | Out-Null
    Copy-Item -LiteralPath $avzArchive -Destination (Join-Path $payloadArchives "avz4.zip")
    Copy-Item -LiteralPath $baseArchive -Destination (Join-Path $payloadArchives "avzbase.zip")
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $payloadAvz "AVZ_MANIFEST.json")
    foreach ($pair in @(
        @($avzArchive, (Join-Path $payloadArchives "avz4.zip")),
        @($baseArchive, (Join-Path $payloadArchives "avzbase.zip"))
    )) {
        if ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash) {
            throw "A verified AVZ archive changed while it was copied into the WinPE payload: $($pair[0])"
        }
    }

    Copy-Item -LiteralPath $nodeTraceFull -Destination (Join-Path $payloadRoot "NodeTraceIR.exe")
    Copy-Item -LiteralPath $launcherSource -Destination (Join-Path $payloadRoot "launch_nodetrace.cmd")
    [System.IO.File]::WriteAllText(
        (Join-Path $payloadRoot "winpe-architecture.txt"),
        "$Architecture`r`n",
        [System.Text.Encoding]::ASCII
    )
    $avzMode = if ($Architecture -eq "x86") { "enabled" } else { "disabled-no-wow64" }
    $buildInfo = @(
        "architecture=$Architecture",
        "nodetrace_sha256=$((Get-FileHash -LiteralPath $nodeTraceFull -Algorithm SHA256).Hash.ToLowerInvariant())",
        "avz_archive_sha256=$((Get-FileHash -LiteralPath $avzArchive -Algorithm SHA256).Hash.ToLowerInvariant())",
        "avz_base_sha256=$((Get-FileHash -LiteralPath $baseArchive -Algorithm SHA256).Hash.ToLowerInvariant())",
        "avz_execution=$avzMode",
        "avz_machine=0x$($avzMachine.ToString('X4'))"
    )
    [System.IO.File]::WriteAllLines(
        (Join-Path $payloadRoot "build-info.txt"),
        $buildInfo,
        [System.Text.UTF8Encoding]::new($false)
    )
    $payloadHashLines = foreach ($file in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Sort-Object FullName) {
        $relative = $file.FullName.Substring($payloadRoot.Length).TrimStart("\", "/").Replace("\", "/")
        "$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
    }
    [System.IO.File]::WriteAllLines(
        (Join-Path $payloadRoot "payload-sha256.txt"),
        $payloadHashLines,
        [System.Text.UTF8Encoding]::new($false)
    )

    if ($Architecture -eq "amd64") {
        Write-Warning "AVZ is a 32-bit executable. amd64 WinPE has no WOW64 and cannot run it; use -Architecture x86 with an x86 NodeTraceIR.exe for AVZ analysis. AVZ remains bundled for provenance only."
    }

    Invoke-Checked -FilePath $copype -Arguments @($Architecture, $workSet) -Description "Creating the $Architecture WinPE working set"
    $bootWim = Join-Path $workSet "media\sources\boot.wim"
    Assert-RegularFile -Path $bootWim

    Invoke-Checked -FilePath $dism -Arguments @(
        "/Mount-Image",
        "/ImageFile:$bootWim",
        "/Index:1",
        "/MountDir:$mountRoot",
        "/CheckIntegrity"
    ) -Description "Mounting boot.wim"
    $mounted = $true

    $mountedPayload = Join-Path $mountRoot "Program Files\NodeTraceIR"
    $mountedSystem32 = Join-Path $mountRoot "Windows\System32"
    New-Item -ItemType Directory -Force -Path $mountedPayload | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $payloadRoot -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $mountedPayload -Recurse -Force
    }
    Copy-Item -LiteralPath $startnetSource -Destination (Join-Path $mountedSystem32 "startnet.cmd") -Force
    Copy-Item -LiteralPath $launcherSource -Destination (Join-Path $mountedSystem32 "launch_nodetrace.cmd") -Force

    if ((Get-FileHash -LiteralPath (Join-Path $mountedPayload "NodeTraceIR.exe") -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $nodeTraceFull -Algorithm SHA256).Hash) {
        throw "NodeTraceIR.exe changed while it was injected into boot.wim."
    }
    if ((Get-FileHash -LiteralPath (Join-Path $mountedPayload "AVZ\avz.exe") -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $payloadAvzExe -Algorithm SHA256).Hash) {
        throw "avz.exe changed while it was injected into boot.wim."
    }

    Invoke-Checked -FilePath $dism -Arguments @(
        "/Unmount-Image",
        "/MountDir:$mountRoot",
        "/Commit",
        "/CheckIntegrity"
    ) -Description "Committing the NodeTrace IR payload into boot.wim"
    $mounted = $false

    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($outputFull)) | Out-Null
    if (Test-Path -LiteralPath $makeWinPEMedia -PathType Leaf) {
        Invoke-Checked -FilePath $makeWinPEMedia -Arguments @("/ISO", $workSet, $outputFull) -Description "Building a bootable WinPE ISO with MakeWinPEMedia"
    }
    else {
        $biosBoot = Find-FirstFile -Candidates @(
            (Join-Path $workSet "fwfiles\etfsboot.com"),
            (Join-Path $workSet "media\Boot\etfsboot.com")
        )
        $uefiBoot = Find-FirstFile -Candidates @(
            (Join-Path $workSet "fwfiles\efisys.bin"),
            (Join-Path $workSet "media\EFI\Microsoft\Boot\efisys.bin")
        )
        if ($null -eq $biosBoot) {
            throw "The WinPE working set does not contain etfsboot.com for oscdimg."
        }
        $bootArgument = if ($null -ne $uefiBoot) {
            "-bootdata:2#p0,e,b`"$biosBoot`"#pEF,e,b`"$uefiBoot`""
        }
        else {
            "-b$biosBoot"
        }
        Invoke-Checked -FilePath $oscdimg -Arguments @(
            "-m",
            "-o",
            "-h",
            "-u2",
            "-udfver102",
            "-lNODETRACE_IR",
            $bootArgument,
            (Join-Path $workSet "media"),
            $outputFull
        ) -Description "Building a bootable WinPE ISO with oscdimg"
    }

    if (-not (Test-Path -LiteralPath $outputFull -PathType Leaf) -or (Get-Item -LiteralPath $outputFull).Length -le 0) {
        throw "The WinPE media tool completed without creating a non-empty ISO: $outputFull"
    }
    $isoHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $sidecarPath,
        "$isoHash *$([System.IO.Path]::GetFileName($outputFull))`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "Bootable WinPE ISO build complete." -ForegroundColor Green
    Write-Host "Path:    $outputFull"
    Write-Host "SHA-256: $isoHash"
    Write-Host "Hash:    $sidecarPath"
    $buildSucceeded = $true
}
finally {
    try {
        if ($mounted) {
            Write-Warning "A failure occurred while boot.wim was mounted; discarding this private mount."
            & $dism "/Unmount-Image" "/MountDir:$mountRoot" "/Discard"
            if ($LASTEXITCODE -ne 0) {
                $safeToRemoveSession = $false
                Write-Warning "DISM could not discard the private mount. The work directory was preserved for manual recovery: $sessionRoot"
            }
        }
        Assert-ChildPath -Child $sessionRoot -Parent $buildRoot
        if ($safeToRemoveSession -and (Test-Path -LiteralPath $sessionRoot)) {
            Remove-Item -LiteralPath $sessionRoot -Recurse -Force
        }
        if (-not $buildSucceeded) {
            foreach ($incompleteOutput in @($outputFull, $sidecarPath)) {
                if (Test-Path -LiteralPath $incompleteOutput -PathType Leaf) {
                    Remove-Item -LiteralPath $incompleteOutput -Force
                }
            }
        }
    }
    finally {
        foreach ($name in $adkEnvironmentNames) {
            [Environment]::SetEnvironmentVariable($name, $savedAdkEnvironment[$name], "Process")
        }
    }
}
