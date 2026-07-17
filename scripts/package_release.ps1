[CmdletBinding()]
param(
    [string]$Version = "0.3.0",
    [string]$OutputDirectory = "",
    [string]$NodeTraceExecutable = "",
    [string]$BootableIso = "",
    [string]$Python = "python",
    [switch]$SourceOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Version -notmatch "^[0-9]+(?:\.[0-9]+){2}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$") {
    throw "Version must be a filesystem-safe SemVer value, for example 0.1.0 or 0.1.0-rc.1."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectRoot "release"
}
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $baseFullPath = [System.IO.Path]::GetFullPath($BasePath).TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
    $targetFullPath = [System.IO.Path]::GetFullPath($TargetPath)
    if (-not [string]::Equals(
        [System.IO.Path]::GetPathRoot($baseFullPath),
        [System.IO.Path]::GetPathRoot($targetFullPath),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Source file is outside the release root: $targetFullPath"
    }
    $baseUri = [System.Uri]::new($baseFullPath)
    $targetUri = [System.Uri]::new($targetFullPath)
    if (
        -not [string]::Equals($baseUri.Scheme, $targetUri.Scheme, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($baseUri.Host, $targetUri.Host, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Source file is outside the release root: $targetFullPath"
    }
    $relativeUri = $baseUri.MakeRelativeUri($targetUri)
    $relativePath = [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace(
        "/",
        [System.IO.Path]::DirectorySeparatorChar
    )
    if ($relativePath -eq ".." -or $relativePath.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)")) {
        throw "Source file is outside the release root: $targetFullPath"
    }
    return $relativePath
}

function New-ZipFromEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $validatedEntries = [System.Collections.Generic.List[object]]::new()
    $seenEntries = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($item in $Entries) {
        if (-not (Test-Path -LiteralPath $item.Source -PathType Leaf)) {
            throw "ZIP source file is missing: $($item.Source)"
        }
        $sourceItem = Get-Item -LiteralPath $item.Source -Force
        if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing reparse-point source file: $($sourceItem.FullName)"
        }

        $entryName = ([string]$item.Entry).Replace("\", "/")
        $segments = @($entryName.Split([char]"/"))
        if (
            [string]::IsNullOrWhiteSpace($entryName) -or
            $entryName.StartsWith("/") -or
            $entryName -match "^[A-Za-z]:" -or
            $segments -contains "" -or
            $segments -contains "." -or
            $segments -contains ".."
        ) {
            throw "Unsafe ZIP entry path: $entryName"
        }
        if (-not $seenEntries.Add($entryName)) {
            throw "Duplicate ZIP entry path: $entryName"
        }
        $validatedEntries.Add([pscustomobject]@{
            Source = $sourceItem.FullName
            Entry = $entryName
        })
    }

    $stream = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        try {
            foreach ($item in $validatedEntries) {
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $archive,
                    $item.Source,
                    $item.Entry,
                    [System.IO.Compression.CompressionLevel]::Optimal
                ) | Out-Null
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $reader = [System.IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "Release executable is not a valid PE file: $Path"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            throw "Release executable has an invalid PE header offset: $Path"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Release executable is missing the PE signature: $Path"
        }
        return [int]$reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Resolve-FirstReleaseInput {
    param(
        [string]$ExplicitPath,
        [Parameter(Mandatory = $true)][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $full = [System.IO.Path]::GetFullPath($ExplicitPath)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "$Description was not found: $full"
        }
        return $full
    }
    foreach ($candidate in $Candidates) {
        $full = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            return $full
        }
    }
    throw "$Description was not found. Pass its path explicitly. Checked: $($Candidates -join ', ')"
}

function Assert-SourceEntryPolicy {
    param([Parameter(Mandatory = $true)][object[]]$Entries)

    $forbiddenExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        ".avz", ".cab", ".db", ".dll", ".dmp", ".esd", ".evtx", ".exe",
        ".iso", ".jks", ".kdbx", ".key", ".msi", ".msix", ".p12", ".pem",
        ".pfx", ".sqlite", ".sqlite3", ".sys", ".vdi", ".vhd", ".vhdx",
        ".wim", ".zip"
    ) | ForEach-Object { $forbiddenExtensions.Add($_) | Out-Null }

    $forbiddenSegments = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        ".pytest_cache", "__pycache__", "artifacts", "build", "cache",
        "case_artifacts", "cases", "dist", "history", "release", "reports"
    ) | ForEach-Object { $forbiddenSegments.Add($_) | Out-Null }

    $forbiddenFileNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        ".env", ".npmrc", ".pypirc", "credentials.json", "id_ed25519",
        "id_rsa", "service-account.json"
    ) | ForEach-Object { $forbiddenFileNames.Add($_) | Out-Null }

    $textExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        "", ".cmd", ".gitignore", ".json", ".md", ".ps1", ".py", ".toml",
        ".txt", ".xml", ".yaml", ".yml"
    ) | ForEach-Object { $textExtensions.Add($_) | Out-Null }

    # These expressions intentionally target only high-confidence credential
    # formats.  Generic words such as "password" and synthetic test URLs must
    # not make a release impossible to build.
    $secretPatterns = @(
        [pscustomobject]@{
            Label = "private key"
            Pattern = "-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"
        },
        [pscustomobject]@{
            Label = "AWS access key"
            Pattern = "(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"
        },
        [pscustomobject]@{
            Label = "GitHub token"
            Pattern = "(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"
        },
        [pscustomobject]@{
            Label = "GitHub fine-grained token"
            Pattern = "(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9])"
        },
        [pscustomobject]@{
            Label = "OpenAI API key"
            Pattern = "(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])"
        },
        [pscustomobject]@{
            Label = "Slack token"
            Pattern = "(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9])"
        }
    )

    foreach ($item in $Entries) {
        $entryName = ([string]$item.Entry).Replace("\", "/")
        $segments = @($entryName.Split([char]"/"))
        foreach ($segment in $segments) {
            if ($forbiddenSegments.Contains($segment)) {
                throw "Forbidden generated/evidence directory in source archive: $entryName"
            }
        }
        $extension = [System.IO.Path]::GetExtension($entryName)
        if ($forbiddenExtensions.Contains($extension)) {
            throw "Forbidden binary/evidence file in source archive: $entryName"
        }
        $fileName = [System.IO.Path]::GetFileName($entryName)
        if (
            $forbiddenFileNames.Contains($fileName) -or
            $fileName.StartsWith(".env.", [System.StringComparison]::OrdinalIgnoreCase)
        ) {
            throw "Forbidden credential-bearing filename in source archive: $entryName"
        }
        if ($fileName -like "*.candidate.json") {
            throw "Forbidden update candidate in source archive: $entryName"
        }

        if ($textExtensions.Contains($extension)) {
            $content = [System.IO.File]::ReadAllText(
                [string]$item.Source,
                [System.Text.Encoding]::UTF8
            )
            foreach ($secretPattern in $secretPatterns) {
                if ([System.Text.RegularExpressions.Regex]::IsMatch(
                    $content,
                    [string]$secretPattern.Pattern,
                    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
                )) {
                    throw "Possible $($secretPattern.Label) in source archive entry: $entryName"
                }
            }
        }
    }
}

$releaseName = "NodeTraceIR-$Version"
$sourceZip = Join-Path $outputRoot "$releaseName-source.zip"
$sourceEntries = [System.Collections.Generic.List[object]]::new()

$rootFiles = @(
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
    "README.md",
    "requirements.txt",
    "run_nodetrace_ir.py",
    "SECURITY.md"
)
foreach ($relativePath in $rootFiles) {
    $sourcePath = Join-Path $projectRoot $relativePath
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Required source file is missing: $sourcePath"
    }
    $sourceEntries.Add([pscustomobject]@{
        Source = $sourcePath
        Entry = "$releaseName/$relativePath"
    })
}

$requiredScripts = @(
    "build_fat12_efi.py",
    "build_fat16_disk.py",
    "build_iso.ps1",
    "build_iso.py",
    "build_release.ps1",
    "build_winpe_iso.ps1",
    "build_winpe_iso_portable.ps1",
    "extract_fat12_file.py",
    "extract_mszip_ranges.py",
    "extract_winpe_2004_x86.ps1",
    "fetch_winpe_2004_x86.ps1",
    "fetch_winpe_2004_x86_selective.ps1",
    "inspect_cab.py",
    "package_release.ps1",
    "prepare_winpe_2004_x86_portable.ps1",
    "resume_http_ranges.py",
    "resume_range_parts.ps1",
    "run_tests.ps1",
    "smoke_test_winpe_vm.ps1",
    "verify_bootable_iso.py"
)
$requiredDocs = @(
    "ARCHITECTURE.md",
    "AVZ_DATABASE_UPDATES_RU.md",
    "COLLECTORS.md",
    "EVIDENCE_MODEL.md"
)
$requiredPackageFiles = @(
    "__init__.py",
    "admin.py",
    "app.py",
    "avz/__init__.py",
    "avz/importer.py",
    "avz/policy.py",
    "avz/runner.py",
    "collectors/__init__.py",
    "collectors/_common.py",
    "collectors/event_logs.py",
    "collectors/event_normalization.py",
    "collectors/evtx_native.py",
    "collectors/file_seed.py",
    "collectors/filesystem.py",
    "collectors/helpers.py",
    "collectors/network.py",
    "collectors/offline.py",
    "collectors/offline_sources.py",
    "collectors/persistence.py",
    "collectors/prefetch.py",
    "collectors/processes.py",
    "contracts.py",
    "database.py",
    "demo.py",
    "engine.py",
    "graph_view.py",
    "impact.py",
    "models.py",
    "pipeline.py",
    "presentation.py",
    "preservation.py",
    "report.py"
)
$requiredTests = @(
    "__init__.py",
    "fixtures/avz/avz5_sample.xml",
    "fixtures/avz/avz_scan_ru.txt",
    "test_app_lifecycle.py",
    "test_avz.py",
    "test_avz_update.py",
    "test_collectors.py",
    "test_database.py",
    "test_engine.py",
    "test_event_normalization.py",
    "test_evtx_native.py",
    "test_fat12_efi.py",
    "test_fat16_disk.py",
    "test_iso_builder.py",
    "test_observations.py",
    "test_offline_mode.py",
    "test_offline_sources.py",
    "test_pipeline.py",
    "test_portable_winpe_iso_script.py",
    "test_preservation.py",
    "test_release_packaging.py",
    "test_report.py",
    "test_safety.py",
    "test_verify_bootable_iso.py",
    "test_vm_smoke_script.py",
    "test_winpe_assets.py",
    "test_winpe_fetch.py"
)
$folderRules = @(
    [pscustomobject]@{ Folder = ".github"; Paths = @("workflows/tests.yml"); Extensions = @() },
    [pscustomobject]@{ Folder = "assets"; Paths = @("nodetrace-ir.ico", "nodetrace-icon.png"); Extensions = @() },
    [pscustomobject]@{ Folder = "docs"; Paths = $requiredDocs; Extensions = @() },
    [pscustomobject]@{ Folder = "iso"; Paths = @("README_RU.txt", "START_NODETRACE_IR.cmd", "THIRD_PARTY_AVZ_NOTICE.txt"); Extensions = @() },
    [pscustomobject]@{ Folder = "nodetrace_ir"; Paths = $requiredPackageFiles; Extensions = @() },
    [pscustomobject]@{ Folder = "scripts"; Paths = $requiredScripts; Extensions = @() },
    [pscustomobject]@{ Folder = "tools"; Paths = @("avz-manifest.json", "fetch_avz.ps1", "update_avz_base.py"); Extensions = @() },
    [pscustomobject]@{ Folder = "tests"; Paths = $requiredTests; Extensions = @() },
    [pscustomobject]@{ Folder = "winpe"; Paths = @("README_RU.txt", "launch_nodetrace.cmd", "startnet.cmd"); Extensions = @() }
)
foreach ($rule in $folderRules) {
    $folderPath = Join-Path $projectRoot $rule.Folder
    if (-not (Test-Path -LiteralPath $folderPath -PathType Container)) {
        throw "Required source folder is missing: $folderPath"
    }

    $folderItem = Get-Item -LiteralPath $folderPath -Force
    if (($folderItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse-point source folder: $folderPath"
    }
    $treeItems = @(Get-ChildItem -LiteralPath $folderPath -Recurse -Force)
    $reparseItem = $treeItems |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($null -ne $reparseItem) {
        throw "Refusing reparse point in source folder: $($reparseItem.FullName)"
    }

    $includedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $treeItems |
        Where-Object { -not $_.PSIsContainer } |
        Sort-Object FullName |
        ForEach-Object {
            $relativeInFolder = (Get-ReleaseRelativePath -BasePath $folderPath -TargetPath $_.FullName).Replace("\", "/")
            $include = (
                ($rule.Paths -contains $relativeInFolder) -or
                ($rule.Extensions -contains $_.Extension.ToLowerInvariant())
            )
            if ($include) {
                $includedPaths.Add($relativeInFolder) | Out-Null
                $relativePath = Get-ReleaseRelativePath -BasePath $projectRoot -TargetPath $_.FullName
                $sourceEntries.Add([pscustomobject]@{
                    Source = $_.FullName
                    Entry = "$releaseName/$relativePath"
                })
            }
        }

    foreach ($requiredPath in $rule.Paths) {
        if (-not $includedPaths.Contains($requiredPath)) {
            throw "Required allowlisted source file is missing: $($rule.Folder)/$requiredPath"
        }
    }
}

Assert-SourceEntryPolicy -Entries $sourceEntries.ToArray()
New-ZipFromEntries -Destination $sourceZip -Entries $sourceEntries.ToArray()
Write-Host "Source archive: $sourceZip" -ForegroundColor Green

$releaseFiles = [System.Collections.Generic.List[string]]::new()
$releaseFiles.Add($sourceZip)

if (-not $SourceOnly) {
    $builtExe = Resolve-FirstReleaseInput `
        -ExplicitPath $NodeTraceExecutable `
        -Candidates @(
            (Join-Path $projectRoot "dist\winpe-x86\NodeTraceIR.exe"),
            (Join-Path $projectRoot "dist\NodeTraceIR.exe")
        ) `
        -Description "Built x86 NodeTrace IR executable"
    $builtIso = Resolve-FirstReleaseInput `
        -ExplicitPath $BootableIso `
        -Candidates @(
            (Join-Path $projectRoot "dist\NodeTraceIR-AVZ-$Version-Bootable-x86.iso"),
            (Join-Path $projectRoot "dist\NodeTraceIR-WinPE-x86.iso")
        ) `
        -Description "Bootable x86 WinPE ISO"

    $machine = Get-PeMachine -Path $builtExe
    if ($machine -ne 0x014C) {
        throw ("WinPE AVZ release requires an x86 executable (PE machine 0x014C); found 0x{0:X4}: {1}" -f $machine, $builtExe)
    }

    $isoVerifier = Join-Path $projectRoot "scripts\verify_bootable_iso.py"
    $verificationOutput = & $Python $isoVerifier $builtIso --expect-path "SOURCES/BOOT.WIM" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Bootable ISO verification failed:`n$($verificationOutput -join [Environment]::NewLine)"
    }
    Write-Host "Bootable ISO structure verified." -ForegroundColor Green

    $releaseExe = Join-Path $outputRoot "$releaseName-winpe-x86.exe"
    if (-not [string]::Equals($builtExe, $releaseExe, [System.StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $builtExe -Destination $releaseExe -Force
    }

    $binaryZip = Join-Path $outputRoot "$releaseName-winpe-x86.zip"
    $binaryEntries = @(
        [pscustomobject]@{ Source = $releaseExe; Entry = "$releaseName/NodeTraceIR.exe" },
        [pscustomobject]@{ Source = (Join-Path $projectRoot "winpe\README_RU.txt"); Entry = "$releaseName/README_WINPE_RU.txt" },
        [pscustomobject]@{ Source = (Join-Path $projectRoot "README.md"); Entry = "$releaseName/README.md" },
        [pscustomobject]@{ Source = (Join-Path $projectRoot "LICENSE"); Entry = "$releaseName/LICENSE" },
        [pscustomobject]@{ Source = (Join-Path $projectRoot "NOTICE"); Entry = "$releaseName/NOTICE" },
        [pscustomobject]@{ Source = (Join-Path $projectRoot "SECURITY.md"); Entry = "$releaseName/SECURITY.md" }
    )
    New-ZipFromEntries -Destination $binaryZip -Entries $binaryEntries

    $releaseIso = Join-Path $outputRoot "NodeTraceIR-AVZ-$Version-Bootable-x86.iso"
    if (-not [string]::Equals($builtIso, $releaseIso, [System.StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $builtIso -Destination $releaseIso -Force
    }

    $releaseFiles.Add($releaseExe)
    $releaseFiles.Add($binaryZip)
    $releaseFiles.Add($releaseIso)
    Write-Host "WinPE x86 executable: $releaseExe" -ForegroundColor Green
    Write-Host "WinPE x86 archive:    $binaryZip" -ForegroundColor Green
    Write-Host "Bootable x86 ISO:     $releaseIso" -ForegroundColor Green
}

$hashFile = Join-Path $outputRoot "SHA256SUMS.txt"
$hashLines = foreach ($path in $releaseFiles | Sort-Object) {
    $digest = Get-FileHash -LiteralPath $path -Algorithm SHA256
    "$($digest.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($path))"
}
[System.IO.File]::WriteAllLines($hashFile, $hashLines, [System.Text.UTF8Encoding]::new($false))
Write-Host "Checksums: $hashFile" -ForegroundColor Green
