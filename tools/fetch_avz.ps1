[CmdletBinding()]
param(
    [switch]$AcceptNonCommercialLicense,

    [string]$Destination,
    [string]$ManifestPath,
    [switch]$VerifyOnly,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Windows PowerShell 5.1 can evaluate parameter default expressions before
# $PSScriptRoot is populated for a script invoked with -File.  Resolve these
# defaults after parameter binding so the documented no-path command works on
# the same host used to build the WinPE image.
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $PSScriptRoot "cache"
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $PSScriptRoot "avz-manifest.json"
}

if (-not $AcceptNonCommercialLicense) {
    throw "AVZ may be fetched only after explicit acknowledgement. Re-run with -AcceptNonCommercialLicense for authorized non-commercial use."
}
if ($Force -and $VerifyOnly) {
    throw "-Force and -VerifyOnly cannot be used together."
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "AVZ manifest was not found: $ManifestPath"
}

$crcSource = @'
using System;
using System.IO;
using System.Security.Cryptography;

public static class NodeTraceCrc32
{
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint index = 0; index < table.Length; index++)
        {
            uint value = index;
            for (int bit = 0; bit < 8; bit++)
            {
                value = (value & 1) != 0
                    ? 0xEDB88320U ^ (value >> 1)
                    : value >> 1;
            }
            table[index] = value;
        }
        return table;
    }

    public static string[] Compute(Stream stream)
    {
        uint crc = 0xFFFFFFFFU;
        var buffer = new byte[65536];
        SHA256 sha256 = SHA256.Create();
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                sha256.TransformBlock(buffer, 0, read, null, 0);
                for (int index = 0; index < read; index++)
                {
                    crc = Table[(crc ^ buffer[index]) & 0xFF] ^ (crc >> 8);
                }
            }
            sha256.TransformFinalBlock(new byte[0], 0, 0);
            string shaHex = BitConverter.ToString(sha256.Hash).Replace("-", "");
            return new string[] { (crc ^ 0xFFFFFFFFU).ToString("X8"), shaHex };
        }
        finally
        {
            sha256.Dispose();
        }
    }
}
'@

if (-not ("NodeTraceCrc32" -as [type])) {
    Add-Type -TypeDefinition $crcSource -Language CSharp
}
Add-Type -AssemblyName System.IO.Compression

function Test-SafeZipPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains([char]0)) {
        return $false
    }
    $normalized = $Path.Replace("\", "/")
    if ($normalized.StartsWith("/") -or $normalized -match "^[A-Za-z]:" -or $normalized -match "(^|/)\.\.(/|$)") {
        return $false
    }
    return $true
}

function Assert-ArchiveMatchesManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Archive
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required AVZ archive was not found: $Path"
    }
    $file = Get-Item -LiteralPath $Path
    if ([int64]$file.Length -ne [int64]$Archive.size) {
        throw "$($Archive.name): size mismatch (expected $($Archive.size), got $($file.Length))."
    }

    $sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $md5 = (Get-FileHash -LiteralPath $Path -Algorithm MD5).Hash.ToLowerInvariant()
    if ($sha256 -ne ([string]$Archive.sha256).ToLowerInvariant()) {
        throw "$($Archive.name): SHA-256 mismatch. The mutable upstream file is not the pinned build input."
    }
    if ($md5 -ne ([string]$Archive.md5).ToLowerInvariant()) {
        throw "$($Archive.name): MD5 mismatch."
    }

    $expectedEntries = @{}
    foreach ($expected in @($Archive.zip.entries)) {
        $entryPath = [string]$expected.path
        if (-not (Test-SafeZipPath -Path $entryPath)) {
            throw "$($Archive.name): unsafe path in manifest: $entryPath"
        }
        if ($expectedEntries.ContainsKey($entryPath)) {
            throw "$($Archive.name): duplicate path in manifest: $entryPath"
        }
        $expectedEntries.Add($entryPath, $expected)
    }
    if ($expectedEntries.Count -ne [int]$Archive.zip.entry_count) {
        throw "$($Archive.name): manifest entry_count does not match its entries list."
    }

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            if ($zip.Entries.Count -ne [int]$Archive.zip.entry_count) {
                throw "$($Archive.name): ZIP entry count mismatch."
            }
            [int64]$totalUncompressed = 0
            $seen = @{}
            foreach ($entry in $zip.Entries) {
                $entryPath = [string]$entry.FullName
                if (-not (Test-SafeZipPath -Path $entryPath)) {
                    throw "$($Archive.name): unsafe ZIP path: $entryPath"
                }
                if ($seen.ContainsKey($entryPath)) {
                    throw "$($Archive.name): duplicate ZIP path: $entryPath"
                }
                $seen.Add($entryPath, $true)
                if (-not $expectedEntries.ContainsKey($entryPath)) {
                    throw "$($Archive.name): unexpected ZIP entry: $entryPath"
                }
                $expected = $expectedEntries[$entryPath]
                if ([int64]$entry.Length -ne [int64]$expected.size) {
                    throw "$($Archive.name): uncompressed size mismatch for $entryPath."
                }
                if ([int64]$entry.CompressedLength -ne [int64]$expected.compressed_size) {
                    throw "$($Archive.name): compressed size mismatch for $entryPath."
                }
                $totalUncompressed += [int64]$entry.Length
                $entryStream = $entry.Open()
                try {
                    $digests = [NodeTraceCrc32]::Compute($entryStream)
                }
                finally {
                    $entryStream.Dispose()
                }
                $crc32 = $digests[0]
                if ($crc32 -ne ([string]$expected.crc32).ToUpperInvariant()) {
                    throw "$($Archive.name): CRC-32 mismatch for $entryPath."
                }
                if ($digests[1] -ne ([string]$expected.sha256).ToUpperInvariant()) {
                    throw "$($Archive.name): entry SHA-256 mismatch for $entryPath."
                }
            }
            if ($totalUncompressed -ne [int64]$Archive.zip.uncompressed_size) {
                throw "$($Archive.name): total uncompressed size mismatch."
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    Write-Host "Verified $($Archive.name): size, outer hashes, and per-entry CRC-32/SHA-256." -ForegroundColor Green
}

$manifestText = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
$manifest = $manifestText | ConvertFrom-Json
if ([int]$manifest.schema_version -ne 1) {
    throw "Unsupported AVZ manifest schema: $($manifest.schema_version)"
}
if (@($manifest.archives).Count -ne 2) {
    throw "The AVZ manifest must pin exactly avz4.zip and avzbase.zip."
}
$archiveNames = @($manifest.archives | ForEach-Object { [string]$_.name })
if (($archiveNames | Sort-Object) -join "," -ne "avz4.zip,avzbase.zip") {
    throw "The AVZ manifest has an unexpected archive set: $($archiveNames -join ', ')"
}

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$destinationRoot = [System.IO.Path]::GetFullPath($Destination)

foreach ($archive in @($manifest.archives)) {
    $name = [string]$archive.name
    if ([System.IO.Path]::GetFileName($name) -ne $name) {
        throw "Unsafe archive filename in manifest: $name"
    }
    $target = Join-Path $destinationRoot $name

    if ($VerifyOnly) {
        Assert-ArchiveMatchesManifest -Path $target -Archive $archive
        continue
    }

    if ((Test-Path -LiteralPath $target -PathType Leaf) -and -not $Force) {
        Assert-ArchiveMatchesManifest -Path $target -Archive $archive
        continue
    }

    $uri = [Uri]([string]$archive.url)
    if ($uri.Scheme -ne "https" -or $uri.Host -notin @("z-oleg.com", "www.z-oleg.com")) {
        throw "Refusing non-official AVZ URL: $uri"
    }
    $temporary = "$target.download.$PID"
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    try {
        Write-Host "Downloading pinned $name from $uri" -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $uri -OutFile $temporary -UseBasicParsing
        Assert-ArchiveMatchesManifest -Path $temporary -Archive $archive
        Move-Item -LiteralPath $temporary -Destination $target -Force
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "AVZ archives are ready in: $destinationRoot" -ForegroundColor Green
