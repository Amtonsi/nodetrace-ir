[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LayoutDir,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [string]$SevenZipPath = "",

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# These values come from the external-payload entries in the Microsoft-signed
# ADK WinPE 10.1.19041.5856 Burn bundle.  Burn uses SHA-1 for this legacy
# bundle; the script additionally records SHA-256 for the extracted result.
$PinnedPayloads = @(
    [pscustomobject]@{
        Name = "Windows PE x86 x64-x86_en-us.msi"
        Size = 917504L
        Sha1 = "45E14889CB06CC68E87E519114A18F52827A9371"
    },
    [pscustomobject]@{
        Name = "a32918368eba6a062aaaaf73e3618131.cab"
        Size = 576974705L
        Sha1 = "1D21F3CB927959DAAD39A1956004C18D31E05EAE"
    },
    [pscustomobject]@{
        Name = "Windows PE x86 x64 wims-x86_en-us.msi"
        Size = 466944L
        Sha1 = "C3FBABFBD36BBE74BDCC814213A13F3601FD1ADA"
    },
    [pscustomobject]@{
        Name = "690b8ac88bc08254d351654d56805aea.cab"
        Size = 199404031L
        Sha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
    }
)

$PinnedX86RootDirectory = "dire6d156e2c918f2b127d9a1be8bfdab43"
$PinnedX86WimFile = "fil642ac1bd3326d4b59398fe460db370b9"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Get-LongMsiName {
    param([AllowEmptyString()][string]$Name)
    if ($Name -like "*|*") {
        return ($Name -split "\|", 2)[1]
    }
    return $Name
}

function Invoke-MsiQuery {
    param(
        [Parameter(Mandatory = $true)]$Database,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )

    $view = $Database.OpenView($Sql)
    [void]$view.Execute()
    try {
        while ($record = $view.Fetch()) {
            $row = [ordered]@{}
            for ($index = 0; $index -lt $Columns.Count; $index++) {
                $row[$Columns[$index]] = $record.StringData($index + 1)
            }
            [pscustomobject]$row
        }
    }
    finally {
        [void]$view.Close()
    }
}

function Read-MsiModel {
    param([Parameter(Mandatory = $true)][string]$MsiPath)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($MsiPath, 0)

    $directories = @{}
    foreach ($row in Invoke-MsiQuery $database 'SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`' @("Id", "Parent", "Default")) {
        $directories[$row.Id] = $row
    }

    $components = @{}
    foreach ($row in Invoke-MsiQuery $database 'SELECT `Component`,`Directory_` FROM `Component`' @("Id", "Directory")) {
        $components[$row.Id] = $row.Directory
    }

    $files = @(
        Invoke-MsiQuery $database 'SELECT `File`,`Component_`,`FileName`,`FileSize`,`Sequence` FROM `File`' @(
            "Id", "Component", "FileName", "Size", "Sequence"
        )
    )

    return [pscustomobject]@{
        Directories = $directories
        Components = $components
        Files = $files
    }
}

function Test-DirectoryUnder {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Directories,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Ancestor
    )

    $seen = @{}
    $current = $Directory
    while ($current -and -not $seen.ContainsKey($current)) {
        if ($current -eq $Ancestor) {
            return $true
        }
        $seen[$current] = $true
        if (-not $Directories.ContainsKey($current)) {
            break
        }
        $current = $Directories[$current].Parent
    }
    return $false
}

function Get-RelativeMsiDirectory {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Directories,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Ancestor
    )

    $parts = [Collections.Generic.List[string]]::new()
    $seen = @{}
    $current = $Directory
    while ($current -and $current -ne $Ancestor -and -not $seen.ContainsKey($current)) {
        $seen[$current] = $true
        if (-not $Directories.ContainsKey($current)) {
            throw "MSI directory graph is broken at '$current'."
        }
        $name = Get-LongMsiName $Directories[$current].Default
        if ($name -and $name -ne ".") {
            if ([IO.Path]::IsPathRooted($name) -or $name -in @("..", ".") -or $name.IndexOfAny([char[]]"/\") -ge 0) {
                throw "Unsafe MSI directory name '$name'."
            }
            [void]$parts.Insert(0, $name)
        }
        $current = $Directories[$current].Parent
    }
    if ($current -ne $Ancestor) {
        throw "Directory '$Directory' is not below '$Ancestor'."
    }
    return [string]::Join([IO.Path]::DirectorySeparatorChar, $parts)
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    $rootFull = (Get-NormalizedPath $Root) + [IO.Path]::DirectorySeparatorChar
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    if (-not $candidateFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a path outside the output root: '$candidateFull'."
    }
    return $candidateFull
}

function Resolve-CabExtractor {
    param([string]$Requested)
    $candidates = @()
    if ($Requested) {
        $candidates += $Requested
    }
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($command) {
        $candidates += $command.Source
    }
    $candidates += @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return [pscustomobject]@{
                Kind = "7zip"
                Path = (Get-NormalizedPath $candidate)
            }
        }
    }
    if ($Requested) {
        throw "The explicitly requested 7z.exe was not found: '$Requested'."
    }

    $expand = Join-Path $env:SystemRoot "System32\expand.exe"
    if (Test-Path -LiteralPath $expand -PathType Leaf) {
        return [pscustomobject]@{
            Kind = "expand"
            Path = (Get-NormalizedPath $expand)
        }
    }
    throw "Neither 7z.exe nor the Windows expand.exe utility was found."
}

function Expand-Cab {
    param(
        [Parameter(Mandatory = $true)]$Extractor,
        [Parameter(Mandatory = $true)][string]$Cab,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    if ($Extractor.Kind -eq "7zip") {
        & $Extractor.Path x -y "-o$Destination" $Cab | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "7-Zip failed to extract '$Cab' (exit $LASTEXITCODE)."
        }
        return
    }
    if ($Extractor.Kind -eq "expand") {
        $messages = @(& $Extractor.Path -F:* $Cab $Destination 2>&1)
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "expand.exe failed to extract '$Cab' (exit $exitCode): $($messages -join [Environment]::NewLine)"
        }
        Write-Verbose ($messages -join [Environment]::NewLine)
        return
    }
    throw "Unknown CAB extractor kind '$($Extractor.Kind)'."
}

$layoutRoot = Get-NormalizedPath $LayoutDir
if (Test-Path -LiteralPath (Join-Path $layoutRoot "Installers") -PathType Container) {
    $installerRoot = Join-Path $layoutRoot "Installers"
}
else {
    $installerRoot = $layoutRoot
}

$outputRoot = Get-NormalizedPath $OutputDir
if (Test-Path -LiteralPath $outputRoot) {
    $existing = @(Get-ChildItem -LiteralPath $outputRoot -Force -ErrorAction Stop)
    if ($existing.Count -gt 0 -and -not $Force) {
        throw "Output directory is not empty. Use a new directory or explicitly pass -Force."
    }
}
else {
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
}

$payloadPaths = @{}
foreach ($payload in $PinnedPayloads) {
    $path = Join-Path $installerRoot $payload.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required official payload is missing: '$path'."
    }
    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne $payload.Size) {
        throw "Size mismatch for '$($payload.Name)': $($item.Length), expected $($payload.Size)."
    }
    $sha1 = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash.ToUpperInvariant()
    if ($sha1 -ne $payload.Sha1) {
        throw "SHA-1 mismatch for '$($payload.Name)': $sha1, expected $($payload.Sha1)."
    }
    $payloadPaths[$payload.Name] = $path
}

$cabExtractor = Resolve-CabExtractor $SevenZipPath
$mediaMsi = $payloadPaths["Windows PE x86 x64-x86_en-us.msi"]
$mediaCab = $payloadPaths["a32918368eba6a062aaaaf73e3618131.cab"]
$wimMsi = $payloadPaths["Windows PE x86 x64 wims-x86_en-us.msi"]
$wimCab = $payloadPaths["690b8ac88bc08254d351654d56805aea.cab"]

$mediaModel = Read-MsiModel $mediaMsi
$wimModel = Read-MsiModel $wimMsi
if (-not $mediaModel.Directories.ContainsKey($PinnedX86RootDirectory) -or
    (Get-LongMsiName $mediaModel.Directories[$PinnedX86RootDirectory].Default) -ne "x86") {
    throw "The media MSI does not match the pinned x86 directory model."
}

$tempRoot = Assert-ChildPath $outputRoot (Join-Path $outputRoot (".extract-" + [guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    $mediaExtract = Join-Path $tempRoot "media-cab"
    $wimExtract = Join-Path $tempRoot "wim-cab"
    Expand-Cab $cabExtractor $mediaCab $mediaExtract
    Expand-Cab $cabExtractor $wimCab $wimExtract

    $copied = 0
    foreach ($file in $mediaModel.Files) {
        if (-not $mediaModel.Components.ContainsKey($file.Component)) {
            continue
        }
        $directory = $mediaModel.Components[$file.Component]
        if (-not (Test-DirectoryUnder $mediaModel.Directories $directory $PinnedX86RootDirectory)) {
            continue
        }
        $relativeDirectory = Get-RelativeMsiDirectory $mediaModel.Directories $directory $PinnedX86RootDirectory
        if ($relativeDirectory -ne "Media" -and -not $relativeDirectory.StartsWith("Media\", [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        if ($file.Id -notmatch '^[A-Za-z0-9._-]+$') {
            throw "Unsafe CAB member id '$($file.Id)'."
        }
        $name = Get-LongMsiName $file.FileName
        if (-not $name -or [IO.Path]::IsPathRooted($name) -or $name.IndexOfAny([char[]]"/\") -ge 0 -or $name -in @(".", "..")) {
            throw "Unsafe output file name '$name'."
        }

        $source = Join-Path $mediaExtract $file.Id
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "CAB member '$($file.Id)' is missing after extraction."
        }
        if ((Get-Item -LiteralPath $source).Length -ne [long]$file.Size) {
            throw "Extracted size mismatch for '$($file.Id)'."
        }

        $destinationDirectory = Assert-ChildPath $outputRoot (Join-Path $outputRoot $relativeDirectory)
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
        $destination = Assert-ChildPath $outputRoot (Join-Path $destinationDirectory $name)
        Copy-Item -LiteralPath $source -Destination $destination -Force
        $copied++
    }

    $wimRow = $wimModel.Files | Where-Object Id -eq $PinnedX86WimFile | Select-Object -First 1
    if (-not $wimRow) {
        throw "Pinned x86 winpe.wim member was not found in the WIM MSI."
    }
    $wimSource = Join-Path $wimExtract $PinnedX86WimFile
    if (-not (Test-Path -LiteralPath $wimSource -PathType Leaf) -or
        (Get-Item -LiteralPath $wimSource).Length -ne [long]$wimRow.Size) {
        throw "The extracted x86 winpe.wim is missing or has the wrong size."
    }
    $sourcesDirectory = Assert-ChildPath $outputRoot (Join-Path $outputRoot "Media\sources")
    New-Item -ItemType Directory -Path $sourcesDirectory -Force | Out-Null
    $bootWim = Assert-ChildPath $outputRoot (Join-Path $sourcesDirectory "boot.wim")
    Copy-Item -LiteralPath $wimSource -Destination $bootWim -Force

    $bootIa32 = Join-Path $outputRoot "Media\EFI\Boot\bootia32.efi"
    if (-not (Test-Path -LiteralPath $bootIa32 -PathType Leaf)) {
        throw "The extracted Media tree has no EFI\Boot\bootia32.efi."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $bootIa32
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "bootia32.efi does not have a valid Authenticode signature: $($signature.Status)."
    }

    $manifestRootPrefix = (Get-NormalizedPath $outputRoot) + [IO.Path]::DirectorySeparatorChar
    $manifestFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $outputRoot "Media") -File -Recurse |
            Sort-Object FullName |
            ForEach-Object {
                $fullName = [IO.Path]::GetFullPath($_.FullName)
                if (-not $fullName.StartsWith($manifestRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Refusing to record a file outside the output root: '$fullName'."
                }
                [pscustomobject]@{
                    path = $fullName.Substring($manifestRootPrefix.Length).Replace("\", "/")
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )
    $manifest = [ordered]@{
        schema = "nodetrace-winpe-extraction/v1"
        source = "Microsoft Windows PE add-on 10.1.19041.5856"
        architecture = "x86"
        extracted_utc = [DateTime]::UtcNow.ToString("o")
        media_files_copied = $copied
        files = $manifestFiles
    }
    $manifestPath = Join-Path $outputRoot "extraction-manifest.json"
    [IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "Portable x86 WinPE media extracted to: $outputRoot"
    Write-Host "Media files copied: $copied"
    Write-Host "boot.wim SHA-256: $((Get-FileHash -LiteralPath $bootWim -Algorithm SHA256).Hash)"
    Write-Host "Manifest: $manifestPath"
}
finally {
    $tempFull = Get-NormalizedPath $tempRoot
    $safePrefix = (Get-NormalizedPath $outputRoot) + [IO.Path]::DirectorySeparatorChar
    if ($tempFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $tempFull) -like ".extract-*") {
        Remove-Item -LiteralPath $tempFull -Recurse -Force -ErrorAction SilentlyContinue
    }
}
