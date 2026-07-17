[CmdletBinding()]
param(
    [string]$WinPEMediaRoot = "",
    [string]$WinPEWim = "",
    [string]$BootSdi = "",
    [string]$Bcd = "",
    [string]$BootIa32Efi = "",
    [string]$EfiBootImage = "",
    [string]$BootManager = "",
    [string]$WinPEExtractionManifest = "",
    [string]$BiosBootImage = "",
    [string]$NodeTraceExecutable = "",
    [string]$AvzDirectory = "",
    [string]$AvzManifest = "",
    [string]$WimlibImagex = "",
    [string]$Python = "python",
    [string]$OutputPath = "",
    [ValidatePattern("^[A-Z0-9_]{1,16}$")]
    [string]$VolumeLabel = "NODETRACE_IR",
    [ValidateRange(946684800, 4102444799)]
    [long]$SourceDateEpoch = 946684800,
    [switch]$AcceptNonCommercialLicense,
    [switch]$KeepBuildDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "Portable WinPE assembly currently requires a Windows build host."
}
if (-not $AcceptNonCommercialLicense) {
    throw "Re-run with -AcceptNonCommercialLicense after reviewing the AVZ distribution terms."
}

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$buildRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "build\winpe-portable"))
$fetcher = Join-Path $projectRoot "tools\fetch_avz.ps1"
$startnetSource = Join-Path $projectRoot "winpe\startnet.cmd"
$launcherSource = Join-Path $projectRoot "winpe\launch_nodetrace.cmd"
$fatBuilder = Join-Path $projectRoot "scripts\build_fat12_efi.py"
$isoVerifier = Join-Path $projectRoot "scripts\verify_bootable_iso.py"

if ([string]::IsNullOrWhiteSpace($NodeTraceExecutable)) {
    $NodeTraceExecutable = Join-Path $projectRoot "dist\winpe-x86\NodeTraceIR.exe"
}
if ([string]::IsNullOrWhiteSpace($AvzDirectory)) {
    $AvzDirectory = Join-Path $projectRoot "tools\cache"
}
if ([string]::IsNullOrWhiteSpace($AvzManifest)) {
    $AvzManifest = Join-Path $projectRoot "tools\avz-manifest.json"
}
if ([string]::IsNullOrWhiteSpace($WimlibImagex)) {
    $wimlibCandidates = @(
        (Join-Path $projectRoot "tools\wimlib\wimlib-imagex.exe"),
        (Join-Path $projectRoot "..\tools\wimlib-1.14.5\wimlib-imagex.exe")
    )
    $WimlibImagex = $wimlibCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($WimlibImagex)) {
        $WimlibImagex = $wimlibCandidates[0]
    }
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $projectRoot "dist\NodeTraceIR-WinPE-x86.iso"
}
if ([string]::IsNullOrWhiteSpace($BiosBootImage)) {
    $BiosBootImage = Join-Path $env:SystemRoot "Boot\DVD\PCAT\etfsboot.com"
}

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path)
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file was not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a reparse-point input file: $($item.FullName)"
    }
}

function Assert-DirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Required directory was not found: $Path"
    }
    $rootItem = Get-Item -LiteralPath $Path -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a reparse-point input directory: $($rootItem.FullName)"
    }
    $reparse = Get-ChildItem -LiteralPath $Path -Force -Recurse |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($null -ne $reparse) {
        throw "Refusing a reparse point inside an input directory: $($reparse.FullName)"
    }
}

function Assert-StrictChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $childFull = Get-FullPath $Child
    $parentFull = (Get-FullPath $Parent).TrimEnd("\", "/")
    $prefix = $parentFull + [IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing an operation outside the private build root: $childFull"
    }
    return $childFull
}

function Assert-SafeRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path.Replace("\", "/")
    $pathForSegments = $normalized.TrimEnd([char]"/")
    $segments = @($pathForSegments.Split([char]"/"))
    if (
        [string]::IsNullOrWhiteSpace($normalized) -or
        [string]::IsNullOrWhiteSpace($pathForSegments) -or
        $normalized.Contains([char]0) -or
        $normalized.StartsWith("/") -or
        $normalized.Contains("//") -or
        $normalized -match "^[A-Za-z]:" -or
        $segments -contains "" -or
        $segments -contains "." -or
        $segments -contains ".."
    ) {
        throw "Unsafe relative path: $Path"
    }
    return $normalized
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-RegularFile $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "The file is not a valid PE/COFF image: $Path"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            throw "The PE header offset is invalid: $Path"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "The PE signature is missing: $Path"
        }
        return [int]$reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Write-Host "==> $Description" -ForegroundColor Cyan
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Quote-WimCommandPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path.IndexOfAny([char[]]"`r`n`"") -ge 0) {
        throw "A WIM update path contains an unsupported control or quote character."
    }
    return '"' + $Path + '"'
}

function Invoke-WimUpdate {
    param(
        [Parameter(Mandatory = $true)][string]$Wimlib,
        [Parameter(Mandatory = $true)][string]$Wim,
        [Parameter(Mandatory = $true)][string]$Commands
    )

    $savedOutputEncoding = $OutputEncoding
    try {
        $OutputEncoding = [Text.UTF8Encoding]::new($false)
        $Commands | & $Wimlib update $Wim 1 --check --rebuild
        if ($LASTEXITCODE -ne 0) {
            throw "wimlib-imagex update failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        $OutputEncoding = $savedOutputEncoding
    }
}

function Get-ManifestArchive {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = @($Manifest.archives) |
        Where-Object { [string]$_.name -eq $Name } |
        Select-Object -First 1
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

    $relative = Assert-SafeRelativePath ([string]$Entry.path)
    if ($relative.EndsWith("/")) {
        return
    }
    $entryPath = Join-Path $Root $relative.Replace("/", "\")
    Assert-RegularFile $entryPath
    $item = Get-Item -LiteralPath $entryPath
    if ($item.Length -ne [long]$Entry.size) {
        throw "An extracted AVZ entry has the wrong size: $relative"
    }
    $hash = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash
    if ($hash -ne [string]$Entry.sha256) {
        throw "An extracted AVZ entry failed SHA-256 verification: $relative"
    }
}

function Assert-ExactManifestValue {
    param(
        [AllowNull()][object]$Actual,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$IgnoreCase
    )

    $matches = if ($IgnoreCase) {
        [string]::Equals([string]$Actual, [string]$Expected, [StringComparison]::OrdinalIgnoreCase)
    }
    else {
        [string]::Equals([string]$Actual, [string]$Expected, [StringComparison]::Ordinal)
    }
    if (-not $matches) {
        throw "WinPE provenance mismatch for $Description."
    }
}

function Assert-WinPEProvenance {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)]$Records
    )

    $provenance = $Manifest.provenance
    Assert-ExactManifestValue $provenance.profile "nodetrace-microsoft-adk-2004-x86/v1" "profile"
    Assert-ExactManifestValue $provenance.adk_version "10.1.19041.5856" "ADK version"
    Assert-ExactManifestValue $provenance.winpe_bootstrap.name "adkwinpesetup.exe" "WinPE bootstrap name"
    Assert-ExactManifestValue $provenance.winpe_bootstrap.size "1434088" "WinPE bootstrap size"
    Assert-ExactManifestValue `
        $provenance.winpe_bootstrap.sha256 `
        "39BB281EA5D631C7E0F989C53DBCD317BD5A6C4EEFF82B41B40256744D2C5D5D" `
        "WinPE bootstrap SHA-256" `
        -IgnoreCase
    Assert-ExactManifestValue $provenance.winpe_bootstrap.authenticode "Valid" "WinPE bootstrap signature"
    Assert-ExactManifestValue `
        $provenance.winpe_bootstrap.signer_organization `
        "Microsoft Corporation" `
        "WinPE bootstrap signer"

    $expectedPayloads = @(
        [pscustomobject]@{
            Role = "x86-boot-wim"
            Path = "Media/sources/boot.wim"
            MsiName = "Windows PE x86 x64 wims-x86_en-us.msi"
            MsiSize = 466944L
            MsiSha256 = "B8813D971D400BF36EDA5E04FD1B73DC744695977E5F04C91F3D5CC70CFBCDB5"
            CabName = "690b8ac88bc08254d351654d56805aea.cab"
            CabSize = 199404031L
            CabSha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
            CabSha256 = "BFBEF5062372192C42D3833BE0AB99A9C197B4271D7B47D76F299C57DD6FA071"
            Member = "fil642ac1bd3326d4b59398fe460db370b9"
            MsiFileHash = @(-721854461, 650304993, 1499151182, 1220197130)
        }
    )
    if ($Records.ContainsKey("Media/bootmgr")) {
        $expectedPayloads += [pscustomobject]@{
            Role = "x86-bios-bootmgr"
            Path = "Media/bootmgr"
            MsiName = "Windows PE x86 x64-x86_en-us.msi"
            MsiSize = 917504L
            MsiSha256 = "1BEC0E930BC95BA9A34F1EC72B09B13D08B9907EA79BC1D92CD33A75CB55D1D2"
            CabName = "aa25d18a5fcce134b0b89fb003ec99ff.cab"
            CabSize = 1817033L
            CabSha1 = "A81232D9F59DA3B3DC1A67FA8550B72D63F2BCA4"
            CabSha256 = "4C0A16C542DC232D1476BB1778B6AB16BB9BBF42EEC87F6A7688132142D4FA6A"
            Member = "fila6a550eed89046f3810ad344d06b2f13"
            MsiFileHash = @(1073898854, 1102876665, 502589138, -1875494190)
        }
    }
    if ($Records.ContainsKey("Media/fwfiles/efisys.bin")) {
        Assert-ExactManifestValue `
            $provenance.deployment_tools_bootstrap.name `
            "adksetup.exe" `
            "Deployment Tools bootstrap name"
        Assert-ExactManifestValue `
            $provenance.deployment_tools_bootstrap.size `
            "1970056" `
            "Deployment Tools bootstrap size"
        Assert-ExactManifestValue `
            $provenance.deployment_tools_bootstrap.sha256 `
            "79FFC10E1A7E2E699083467DB601D9747F71A419981B458063DE1A86FD8C47DD" `
            "Deployment Tools bootstrap SHA-256" `
            -IgnoreCase
        Assert-ExactManifestValue `
            $provenance.deployment_tools_bootstrap.authenticode `
            "Valid" `
            "Deployment Tools bootstrap signature"
        Assert-ExactManifestValue `
            $provenance.deployment_tools_bootstrap.signer_organization `
            "Microsoft Corporation" `
            "Deployment Tools bootstrap signer"

        $expectedPayloads += [pscustomobject]@{
            Role = "ia32-efi-el-torito"
            Path = "Media/fwfiles/efisys.bin"
            MsiName = "Windows Deployment Tools-x86_en-us.msi"
            MsiSize = 626688L
            MsiSha256 = "5DA7A3F65E6364735FBCEB08357773387D2B035B0073BA0BBC19A76A548C95B2"
            CabName = "5d984200acbde182fd99cbfbe9bad133.cab"
            CabSize = 1281728L
            CabSha1 = "542F751C77ED5F21EE3FB317333CC509A2484228"
            CabSha256 = "D693C814E565012D34BB53A985E116D328E6E03674C29809D3875C50F758EBAC"
            Member = "fil4db617e977c2929fa4a8a113dcc24567"
            MsiFileHash = @(1498138875, 923298925, 130554703, -663301826)
        }
    }

    $payloads = @($provenance.payloads)
    foreach ($expected in $expectedPayloads) {
        $matches = @($payloads | Where-Object { [string]$_.role -eq $expected.Role })
        if ($matches.Count -ne 1) {
            throw "WinPE provenance must contain exactly one payload role '$($expected.Role)'."
        }
        $payload = $matches[0]
        Assert-ExactManifestValue $payload.msi.name $expected.MsiName "$($expected.Role) MSI name"
        Assert-ExactManifestValue $payload.msi.size $expected.MsiSize "$($expected.Role) MSI size"
        Assert-ExactManifestValue $payload.msi.sha256 $expected.MsiSha256 "$($expected.Role) MSI SHA-256" -IgnoreCase
        Assert-ExactManifestValue $payload.msi.authenticode "Valid" "$($expected.Role) MSI signature"
        Assert-ExactManifestValue `
            $payload.msi.signer_organization `
            "Microsoft Corporation" `
            "$($expected.Role) MSI signer"
        Assert-ExactManifestValue $payload.cab.name $expected.CabName "$($expected.Role) CAB name"
        Assert-ExactManifestValue $payload.cab.size $expected.CabSize "$($expected.Role) CAB size"
        Assert-ExactManifestValue $payload.cab.sha1 $expected.CabSha1 "$($expected.Role) CAB SHA-1" -IgnoreCase
        Assert-ExactManifestValue $payload.cab.sha256 $expected.CabSha256 "$($expected.Role) CAB SHA-256" -IgnoreCase
        Assert-ExactManifestValue $payload.member.cab_member $expected.Member "$($expected.Role) CAB member"
        Assert-ExactManifestValue $payload.member.path $expected.Path "$($expected.Role) output path"
        $actualMsiFileHash = @($payload.member.msi_file_hash | ForEach-Object { [int]$_ }) -join ","
        $expectedMsiFileHash = @($expected.MsiFileHash | ForEach-Object { [int]$_ }) -join ","
        Assert-ExactManifestValue $actualMsiFileHash $expectedMsiFileHash "$($expected.Role) MsiFileHash"

        if (-not $Records.ContainsKey($expected.Path)) {
            throw "WinPE files manifest is missing provenance-backed path '$($expected.Path)'."
        }
        Assert-ExactManifestValue `
            $Records[$expected.Path].origin_role `
            $expected.Role `
            "$($expected.Role) file origin"
    }

    $isoBuilderProvenance = $provenance.iso_builder
    Assert-ExactManifestValue $isoBuilderProvenance.role "iso-builder-oscdimg" "oscdimg role"
    Assert-ExactManifestValue $isoBuilderProvenance.msi.name "Windows Deployment Tools-x86_en-us.msi" "oscdimg MSI name"
    Assert-ExactManifestValue $isoBuilderProvenance.msi.size "626688" "oscdimg MSI size"
    Assert-ExactManifestValue $isoBuilderProvenance.msi.sha256 "5DA7A3F65E6364735FBCEB08357773387D2B035B0073BA0BBC19A76A548C95B2" "oscdimg MSI SHA-256" -IgnoreCase
    Assert-ExactManifestValue $isoBuilderProvenance.msi.authenticode "Valid" "oscdimg MSI signature"
    Assert-ExactManifestValue $isoBuilderProvenance.msi.signer_organization "Microsoft Corporation" "oscdimg MSI signer"
    Assert-ExactManifestValue $isoBuilderProvenance.cab.name "5d984200acbde182fd99cbfbe9bad133.cab" "oscdimg CAB name"
    Assert-ExactManifestValue $isoBuilderProvenance.cab.size "1281728" "oscdimg CAB size"
    Assert-ExactManifestValue $isoBuilderProvenance.cab.sha1 "542F751C77ED5F21EE3FB317333CC509A2484228" "oscdimg CAB SHA-1" -IgnoreCase
    Assert-ExactManifestValue $isoBuilderProvenance.cab.sha256 "D693C814E565012D34BB53A985E116D328E6E03674C29809D3875C50F758EBAC" "oscdimg CAB SHA-256" -IgnoreCase
    Assert-ExactManifestValue $isoBuilderProvenance.member.cab_member "fil720cc132fbb53f3bed2e525eb77bdbc1" "oscdimg CAB member"
    Assert-ExactManifestValue $isoBuilderProvenance.member.path "Tools/oscdimg.exe" "oscdimg output path"
    Assert-ExactManifestValue $isoBuilderProvenance.member.file_name "oscdimg.exe" "oscdimg MSI file name"
    Assert-ExactManifestValue $isoBuilderProvenance.member.file_size "117824" "oscdimg MSI file size"
    Assert-ExactManifestValue $isoBuilderProvenance.member.file_version "2.56.0.1010" "oscdimg MSI file version"
    Assert-ExactManifestValue $isoBuilderProvenance.member.sequence "215" "oscdimg MSI sequence"
    Assert-ExactManifestValue $isoBuilderProvenance.extracted_file.size "117824" "oscdimg extracted size"
    Assert-ExactManifestValue $isoBuilderProvenance.extracted_file.sha256 "59972E5867CFAD380D0FE376575221FB6ABB5F6B847A4D833916680E9ECCE8D9" "oscdimg extracted SHA-256" -IgnoreCase
    Assert-ExactManifestValue $isoBuilderProvenance.extracted_file.authenticode "Valid" "oscdimg signature"
    Assert-ExactManifestValue $isoBuilderProvenance.extracted_file.signer_organization "Microsoft Corporation" "oscdimg signer"
    Assert-ExactManifestValue $isoBuilderProvenance.pe_machine "0x014C" "oscdimg PE machine"
    Assert-ExactManifestValue $isoBuilderProvenance.file_version "2.56" "oscdimg file version"
    if (-not $Records.ContainsKey("Tools/oscdimg.exe")) {
        throw "WinPE files manifest is missing Tools/oscdimg.exe."
    }
    Assert-ExactManifestValue $Records["Tools/oscdimg.exe"].origin_role "iso-builder-oscdimg" "oscdimg file origin"
    Assert-ExactManifestValue $Records["Tools/oscdimg.exe"].size "117824" "oscdimg file size"
    Assert-ExactManifestValue $Records["Tools/oscdimg.exe"].sha256 "59972E5867CFAD380D0FE376575221FB6ABB5F6B847A4D833916680E9ECCE8D9" "oscdimg file SHA-256" -IgnoreCase

    $expectedHostAssets = @(
        [pscustomobject]@{
            Path = "Media/Boot/BCD"
            SourcePath = "C:\Windows\Boot\DVD\PCAT\BCD"
            OriginRole = "host-pcat-bcd"
        },
        [pscustomobject]@{
            Path = "Media/Boot/boot.sdi"
            SourcePath = "C:\Windows\Boot\DVD\PCAT\boot.sdi"
            OriginRole = "host-boot-sdi"
        }
    )
    $hostAssets = @($provenance.host_assets)
    foreach ($expectedHost in $expectedHostAssets) {
        $matches = @($hostAssets | Where-Object { [string]$_.path -eq $expectedHost.Path })
        if ($matches.Count -ne 1) {
            throw "WinPE provenance must contain exactly one host asset '$($expectedHost.Path)'."
        }
        $hostAsset = $matches[0]
        Assert-ExactManifestValue $hostAsset.source_type "host-windows-signed" "$($expectedHost.Path) source type"
        Assert-ExactManifestValue $hostAsset.source_path $expectedHost.SourcePath "$($expectedHost.Path) source path" -IgnoreCase
        Assert-ExactManifestValue $hostAsset.origin_role $expectedHost.OriginRole "$($expectedHost.Path) host origin role"
        Assert-ExactManifestValue $hostAsset.authenticode "Valid" "$($expectedHost.Path) host signature"
        Assert-ExactManifestValue `
            $hostAsset.signer_organization `
            "Microsoft Corporation" `
            "$($expectedHost.Path) host signer"
        if (-not $Records.ContainsKey($expectedHost.Path)) {
            throw "WinPE files manifest is missing host asset '$($expectedHost.Path)'."
        }
        $record = $Records[$expectedHost.Path]
        Assert-ExactManifestValue $record.origin_role $expectedHost.OriginRole "$($expectedHost.Path) file origin"
        Assert-ExactManifestValue $hostAsset.size $record.size "$($expectedHost.Path) host size"
        Assert-ExactManifestValue $hostAsset.sha256 $record.sha256 "$($expectedHost.Path) host SHA-256" -IgnoreCase
    }

    if ($Records.ContainsKey("Media/EFI/Boot/bootia32.efi")) {
        Assert-ExactManifestValue `
            $Records["Media/EFI/Boot/bootia32.efi"].origin_role `
            "ia32-efi-el-torito-loader" `
            "standalone bootia32.efi origin"
    }
}

function Assert-MsiFileHash {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-RegularFile $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        $digest = $md5.ComputeHash($stream)
    }
    finally {
        $md5.Dispose()
        $stream.Dispose()
    }
    $actual = for ($index = 0; $index -lt 4; $index++) {
        [BitConverter]::ToInt32($digest, $index * 4)
    }
    if (($actual -join ",") -ne ($Expected -join ",")) {
        throw "$Description does not match the pinned Microsoft MSI FileHash."
    }
}

function Read-And-VerifyWinPEManifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-RegularFile $Path
    $manifestFull = Get-FullPath $Path
    $manifestRoot = Split-Path -Parent $manifestFull
    $manifest = Get-Content -LiteralPath $manifestFull -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$manifest.schema -ne "nodetrace-winpe-extraction/v1") {
        throw "Unsupported WinPE extraction manifest schema: $($manifest.schema)"
    }
    if ([string]$manifest.source -ne "Microsoft Windows PE add-on 10.1.19041.5856") {
        throw "The WinPE extraction manifest has an unexpected source/version."
    }
    if ([string]$manifest.architecture -ne "x86") {
        throw "The WinPE extraction manifest is not for x86 media."
    }
    if (@($manifest.files).Count -eq 0) {
        throw "The WinPE extraction manifest contains no files."
    }

    $records = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($record in @($manifest.files)) {
        $relative = Assert-SafeRelativePath ([string]$record.path)
        $isMediaFile = $relative.StartsWith("Media/", [StringComparison]::OrdinalIgnoreCase)
        $isPinnedTool = [string]::Equals(
            $relative,
            "Tools/oscdimg.exe",
            [StringComparison]::OrdinalIgnoreCase
        )
        if (-not $isMediaFile -and -not $isPinnedTool) {
            throw "WinPE manifest entry is outside the allowed Media/Tools trees: $relative"
        }
        if ($records.ContainsKey($relative)) {
            throw "Duplicate WinPE extraction manifest path: $relative"
        }
        $candidate = Join-Path $manifestRoot $relative.Replace("/", "\")
        $candidateFull = Assert-StrictChildPath -Child $candidate -Parent $manifestRoot
        Assert-RegularFile $candidateFull
        $item = Get-Item -LiteralPath $candidateFull
        if ($item.Length -ne [long]$record.size) {
            throw "WinPE extraction size mismatch: $relative"
        }
        $hash = (Get-FileHash -LiteralPath $candidateFull -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne ([string]$record.sha256).ToLowerInvariant()) {
            throw "WinPE extraction SHA-256 mismatch: $relative"
        }
        $records.Add($relative, $record)
    }

    Assert-WinPEProvenance -Manifest $manifest -Records $records

    return [pscustomobject]@{
        Manifest = $manifest
        ManifestPath = $manifestFull
        ManifestRoot = $manifestRoot
        Records = $records
    }
}

function Assert-InputMatchesWinPEManifest {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$ExpectedRelativePath,
        [Parameter(Mandatory = $true)]$ManifestState
    )

    $relative = Assert-SafeRelativePath $ExpectedRelativePath
    if (-not $ManifestState.Records.ContainsKey($relative)) {
        throw "WinPE extraction manifest is missing required input: $relative"
    }
    Assert-RegularFile $InputPath
    $record = $ManifestState.Records[$relative]
    $item = Get-Item -LiteralPath $InputPath
    if ($item.Length -ne [long]$record.size) {
        throw "Explicit WinPE input does not match the extraction manifest size: $InputPath"
    }
    $hash = (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne ([string]$record.sha256).ToLowerInvariant()) {
        throw "Explicit WinPE input does not match the extraction manifest hash: $InputPath"
    }
}

function Assert-CopiedFileHash {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-RegularFile $Destination
    if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash) {
        throw "$Description changed while it was copied."
    }
}

function Assert-UnchangedFileHash {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-RegularFile $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "$Description changed during the build; discard all outputs and rebuild."
    }
}

function Assert-MicrosoftAuthenticode {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-RegularFile $Path
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "$Description does not have a valid Authenticode signature: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch "(^|, )O=Microsoft Corporation(,|$)") {
        throw "$Description is not signed by Microsoft Corporation."
    }
}

$nodeTraceFull = Get-FullPath $NodeTraceExecutable
$avzRoot = Get-FullPath $AvzDirectory
$avzManifestFull = Get-FullPath $AvzManifest
$wimlibFull = Get-FullPath $WimlibImagex
$biosBootFull = Get-FullPath $BiosBootImage
$outputFull = Get-FullPath $OutputPath
$sidecarPath = "$outputFull.sha256"
$verificationPath = "$outputFull.verification.json"
$buildManifestPath = "$outputFull.build.json"

foreach ($required in @(
    $nodeTraceFull,
    $avzManifestFull,
    $wimlibFull,
    $biosBootFull,
    $fetcher,
    $startnetSource,
    $launcherSource,
    $fatBuilder,
    $isoVerifier
)) {
    Assert-RegularFile $required
}
if ([IO.Path]::GetExtension($outputFull) -ne ".iso") {
    throw "OutputPath must end in .iso: $outputFull"
}
foreach ($protectedOutput in @($outputFull, $sidecarPath, $verificationPath, $buildManifestPath)) {
    if (Test-Path -LiteralPath $protectedOutput) {
        throw "Refusing to overwrite an existing output: $protectedOutput"
    }
}
if ((Get-PeMachine $nodeTraceFull) -ne 0x014C) {
    throw "NodeTraceIR.exe must be an x86 PE image for the AVZ-capable x86 WinPE build."
}
if ((Get-Item -LiteralPath $biosBootFull).Length -le 0 -or
    (Get-Item -LiteralPath $biosBootFull).Length % 512 -ne 0) {
    throw "The BIOS El Torito image must be non-empty and sector aligned: $biosBootFull"
}

if (-not [string]::IsNullOrWhiteSpace($WinPEMediaRoot)) {
    $mediaRootFull = Get-FullPath $WinPEMediaRoot
    Assert-DirectoryTree $mediaRootFull
    if ([string]::IsNullOrWhiteSpace($WinPEExtractionManifest)) {
        $WinPEExtractionManifest = Join-Path (Split-Path -Parent $mediaRootFull) "extraction-manifest.json"
    }
    if ([string]::IsNullOrWhiteSpace($WinPEWim)) {
        $WinPEWim = Join-Path $mediaRootFull "sources\boot.wim"
    }
    if ([string]::IsNullOrWhiteSpace($BootSdi)) {
        $BootSdi = Join-Path $mediaRootFull "Boot\boot.sdi"
    }
    if ([string]::IsNullOrWhiteSpace($Bcd)) {
        $Bcd = Join-Path $mediaRootFull "Boot\BCD"
    }
    if ([string]::IsNullOrWhiteSpace($BootIa32Efi)) {
        $BootIa32Efi = Join-Path $mediaRootFull "EFI\Boot\bootia32.efi"
    }
    if ([string]::IsNullOrWhiteSpace($EfiBootImage)) {
        $mediaEfiBootImage = Join-Path $mediaRootFull "fwfiles\efisys.bin"
        if (Test-Path -LiteralPath $mediaEfiBootImage -PathType Leaf) {
            $EfiBootImage = $mediaEfiBootImage
        }
    }
    if ([string]::IsNullOrWhiteSpace($BootManager)) {
        $mediaBootManager = Join-Path $mediaRootFull "bootmgr"
        if (Test-Path -LiteralPath $mediaBootManager -PathType Leaf) {
            $BootManager = $mediaBootManager
        }
        else {
            $BootManager = Join-Path $env:SystemRoot "Boot\PCAT\bootmgr"
        }
    }
}
else {
    $missingInputs = @()
    foreach ($pair in @(
        @("WinPEWim", $WinPEWim),
        @("BootSdi", $BootSdi),
        @("Bcd", $Bcd),
        @("BootIa32Efi", $BootIa32Efi)
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$pair[1])) {
            $missingInputs += [string]$pair[0]
        }
    }
    if ($missingInputs.Count -gt 0) {
        throw "Pass -WinPEMediaRoot or all explicit WinPE inputs. Missing: $($missingInputs -join ', ')"
    }
    if ([string]::IsNullOrWhiteSpace($BootManager)) {
        $derivedMediaRoot = Split-Path -Parent (Split-Path -Parent (Get-FullPath $BootSdi))
        $derivedBootManager = Join-Path $derivedMediaRoot "bootmgr"
        if (Test-Path -LiteralPath $derivedBootManager -PathType Leaf) {
            $BootManager = $derivedBootManager
        }
        else {
            $BootManager = Join-Path $env:SystemRoot "Boot\PCAT\bootmgr"
        }
    }
    if ([string]::IsNullOrWhiteSpace($WinPEExtractionManifest)) {
        $derivedMediaRoot = Split-Path -Parent (Split-Path -Parent (Get-FullPath $BootSdi))
        $WinPEExtractionManifest = Join-Path (Split-Path -Parent $derivedMediaRoot) "extraction-manifest.json"
    }
    $mediaRootFull = $null
}

$winPEWimFull = Get-FullPath $WinPEWim
$bootSdiFull = Get-FullPath $BootSdi
$bcdFull = Get-FullPath $Bcd
$bootIa32Full = Get-FullPath $BootIa32Efi
$bootManagerFull = Get-FullPath $BootManager
$winPEManifestFull = Get-FullPath $WinPEExtractionManifest
$oscdimgFull = Get-FullPath (Join-Path (Split-Path -Parent $winPEManifestFull) "Tools\oscdimg.exe")
foreach ($required in @($winPEWimFull, $bootSdiFull, $bcdFull, $bootIa32Full, $bootManagerFull, $winPEManifestFull, $oscdimgFull)) {
    Assert-RegularFile $required
}
$efiBootImageFull = $null
if (-not [string]::IsNullOrWhiteSpace($EfiBootImage)) {
    $efiBootImageFull = Get-FullPath $EfiBootImage
    Assert-RegularFile $efiBootImageFull
    if ((Get-Item -LiteralPath $efiBootImageFull).Length -le 0 -or
        (Get-Item -LiteralPath $efiBootImageFull).Length % 512 -ne 0) {
        throw "The official IA32 EFI El Torito image must be non-empty and sector aligned."
    }
}

$winPEManifestState = Read-And-VerifyWinPEManifest $winPEManifestFull
Assert-InputMatchesWinPEManifest $oscdimgFull "Tools/oscdimg.exe" $winPEManifestState
$oscdimgHash = (Get-FileHash -LiteralPath $oscdimgFull -Algorithm SHA256).Hash.ToLowerInvariant()
if ($oscdimgHash -ne "59972e5867cfad380d0fe376575221fb6abb5f6b847a4d833916680e9ecce8d9") {
    throw "oscdimg.exe failed its pinned SHA-256 identity."
}
if ((Get-Item -LiteralPath $oscdimgFull).Length -ne 117824) {
    throw "oscdimg.exe failed its pinned size identity."
}
if ((Get-PeMachine $oscdimgFull) -ne 0x014C) {
    throw "The pinned oscdimg.exe is not x86."
}
Assert-MicrosoftAuthenticode $oscdimgFull "oscdimg.exe"
$oscdimgVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($oscdimgFull).FileVersion
if ($oscdimgVersion -ne "2.56") {
    throw "Unexpected oscdimg.exe file version: '$oscdimgVersion'."
}

Assert-InputMatchesWinPEManifest $winPEWimFull "Media/sources/boot.wim" $winPEManifestState
Assert-MsiFileHash `
    $winPEWimFull `
    @(-721854461, 650304993, 1499151182, 1220197130) `
    "source WinPE WIM"
Assert-InputMatchesWinPEManifest $bootSdiFull "Media/Boot/boot.sdi" $winPEManifestState
Assert-InputMatchesWinPEManifest $bcdFull "Media/Boot/BCD" $winPEManifestState
Assert-InputMatchesWinPEManifest $bootIa32Full "Media/EFI/Boot/bootia32.efi" $winPEManifestState
if ($null -ne $efiBootImageFull) {
    Assert-InputMatchesWinPEManifest $efiBootImageFull "Media/fwfiles/efisys.bin" $winPEManifestState
    Assert-MsiFileHash `
        $efiBootImageFull `
        @(1498138875, 923298925, 130554703, -663301826) `
        "official IA32 EFI El Torito image"
}
$bootManagerPinnedByWinPEManifest = $winPEManifestState.Records.ContainsKey("Media/bootmgr")
if ($bootManagerPinnedByWinPEManifest) {
    Assert-InputMatchesWinPEManifest $bootManagerFull "Media/bootmgr" $winPEManifestState
    Assert-MsiFileHash `
        $bootManagerFull `
        @(1073898854, 1102876665, 502589138, -1875494190) `
        "official x86 bootmgr"
}
if ((Get-PeMachine $bootIa32Full) -ne 0x014C) {
    throw "EFI/Boot/bootia32.efi is not an IA32 PE/COFF boot application."
}
Assert-MicrosoftAuthenticode $bootIa32Full "bootia32.efi"
Assert-MicrosoftAuthenticode $bootSdiFull "boot.sdi"
Assert-MicrosoftAuthenticode $bcdFull "BCD"
if (-not $bootManagerPinnedByWinPEManifest) {
    # The ADK x86 bootmgr is a flat boot binary rather than a normal PE, so
    # Get-AuthenticodeSignature may report UnknownError.  Its exact size/hash
    # is trusted through the extraction manifest backed by the pinned MSI/CAB.
    # Only the host fallback must carry a directly verifiable Microsoft signature.
    Assert-MicrosoftAuthenticode $bootManagerFull "host fallback bootmgr"
}
Assert-MicrosoftAuthenticode $biosBootFull "etfsboot.com"

Write-Host "==> Verifying the pinned AVZ runtime and database archives" -ForegroundColor Cyan
& $fetcher `
    -AcceptNonCommercialLicense `
    -VerifyOnly `
    -Destination $avzRoot `
    -ManifestPath $avzManifestFull

$avzArchive = Join-Path $avzRoot "avz4.zip"
$baseArchive = Join-Path $avzRoot "avzbase.zip"
Assert-RegularFile $avzArchive
Assert-RegularFile $baseArchive
$avzManifestHash = (Get-FileHash -LiteralPath $avzManifestFull -Algorithm SHA256).Hash.ToLowerInvariant()
$avzManifestObject = Get-Content -LiteralPath $avzManifestFull -Raw -Encoding UTF8 | ConvertFrom-Json
$avzMetadata = Get-ManifestArchive $avzManifestObject "avz4.zip"
$baseMetadata = Get-ManifestArchive $avzManifestObject "avzbase.zip"
$nodeTraceHash = (Get-FileHash -LiteralPath $nodeTraceFull -Algorithm SHA256).Hash.ToLowerInvariant()
$avzArchiveHash = (Get-FileHash -LiteralPath $avzArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$baseArchiveHash = (Get-FileHash -LiteralPath $baseArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$winPEWimHash = (Get-FileHash -LiteralPath $winPEWimFull -Algorithm SHA256).Hash.ToLowerInvariant()
$winPEManifestHash = (Get-FileHash -LiteralPath $winPEManifestFull -Algorithm SHA256).Hash.ToLowerInvariant()
$bootSdiHash = (Get-FileHash -LiteralPath $bootSdiFull -Algorithm SHA256).Hash.ToLowerInvariant()
$bcdHash = (Get-FileHash -LiteralPath $bcdFull -Algorithm SHA256).Hash.ToLowerInvariant()
$bootIa32Hash = (Get-FileHash -LiteralPath $bootIa32Full -Algorithm SHA256).Hash.ToLowerInvariant()
$bootManagerHash = (Get-FileHash -LiteralPath $bootManagerFull -Algorithm SHA256).Hash.ToLowerInvariant()
$biosBootHash = (Get-FileHash -LiteralPath $biosBootFull -Algorithm SHA256).Hash.ToLowerInvariant()
$wimlibHash = (Get-FileHash -LiteralPath $wimlibFull -Algorithm SHA256).Hash.ToLowerInvariant()
$officialEfiBootHash = if ($null -ne $efiBootImageFull) {
    (Get-FileHash -LiteralPath $efiBootImageFull -Algorithm SHA256).Hash.ToLowerInvariant()
}
else {
    $null
}

New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
$sessionRoot = Join-Path $buildRoot ("nodetrace-winpe-x86-" + [guid]::NewGuid().ToString("N"))
$sessionRoot = Assert-StrictChildPath -Child $sessionRoot -Parent $buildRoot
$stagingRoot = Join-Path $sessionRoot "media"
$payloadRoot = Join-Path $sessionRoot "payload"
$avzExtractRoot = Join-Path $sessionRoot "avz-extracted"
$wimVerifyRoot = Join-Path $sessionRoot "wim-verify"
$buildSucceeded = $false

try {
    New-Item -ItemType Directory -Path $sessionRoot, $stagingRoot, $payloadRoot, $avzExtractRoot, $wimVerifyRoot | Out-Null

    if ($null -ne $mediaRootFull) {
        Write-Host "==> Staging the verified official x86 WinPE Media tree" -ForegroundColor Cyan
        foreach ($item in Get-ChildItem -LiteralPath $mediaRootFull -Force) {
            Copy-Item -LiteralPath $item.FullName -Destination $stagingRoot -Recurse -Force
        }
    }
    else {
        Write-Host "==> Staging the verified minimal x86 WinPE boot tree" -ForegroundColor Cyan
        foreach ($directory in @(
            (Join-Path $stagingRoot "sources"),
            (Join-Path $stagingRoot "Boot"),
            (Join-Path $stagingRoot "EFI\Boot"),
            (Join-Path $stagingRoot "EFI\Microsoft\Boot")
        )) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }

    # Overlay the exact verified components even when a selective Media tree
    # was extracted.  BIOS requires root bootmgr; it is not interchangeable
    # with the 4 KiB etfsboot.com El Torito boot sector image.
    foreach ($directory in @(
        (Join-Path $stagingRoot "sources"),
        (Join-Path $stagingRoot "Boot"),
        (Join-Path $stagingRoot "EFI\Boot"),
        (Join-Path $stagingRoot "EFI\Microsoft\Boot")
    )) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Copy-Item -LiteralPath $winPEWimFull -Destination (Join-Path $stagingRoot "sources\boot.wim") -Force
    Copy-Item -LiteralPath $bootSdiFull -Destination (Join-Path $stagingRoot "Boot\boot.sdi") -Force
    Copy-Item -LiteralPath $bcdFull -Destination (Join-Path $stagingRoot "Boot\BCD") -Force
    Copy-Item -LiteralPath $bcdFull -Destination (Join-Path $stagingRoot "EFI\Microsoft\Boot\BCD") -Force
    Copy-Item -LiteralPath $bootIa32Full -Destination (Join-Path $stagingRoot "EFI\Boot\bootia32.efi") -Force
    Copy-Item -LiteralPath $bootManagerFull -Destination (Join-Path $stagingRoot "bootmgr") -Force

    $stagedWim = Join-Path $stagingRoot "sources\boot.wim"
    $stagedBootSdi = Join-Path $stagingRoot "Boot\boot.sdi"
    $stagedBcd = Join-Path $stagingRoot "Boot\BCD"
    $stagedBootIa32 = Join-Path $stagingRoot "EFI\Boot\bootia32.efi"
    $stagedBootManager = Join-Path $stagingRoot "bootmgr"
    foreach ($required in @($stagedWim, $stagedBootSdi, $stagedBcd, $stagedBootIa32, $stagedBootManager)) {
        Assert-RegularFile $required
    }
    Assert-CopiedFileHash $winPEWimFull $stagedWim "boot.wim"
    Assert-CopiedFileHash $bootSdiFull $stagedBootSdi "boot.sdi"
    Assert-CopiedFileHash $bcdFull $stagedBcd "BCD"
    Assert-CopiedFileHash $bootIa32Full $stagedBootIa32 "bootia32.efi"
    Assert-CopiedFileHash $bootManagerFull $stagedBootManager "bootmgr"
    $stagedWimItem = Get-Item -LiteralPath $stagedWim -Force
    if (($stagedWimItem.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
        $stagedWimItem.Attributes = $stagedWimItem.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
    }

    Invoke-Checked $wimlibFull @("verify", $stagedWim) "Verifying the source WinPE WIM"

    Write-Host "==> Preparing the verified AVZ payload" -ForegroundColor Cyan
    Expand-Archive -LiteralPath $avzArchive -DestinationPath $avzExtractRoot -Force
    $avzExeEntry = @($avzMetadata.zip.entries) |
        Where-Object { ([string]$_.path).Replace("\", "/") -match "(^|/)avz[.]exe$" } |
        Select-Object -First 1
    if ($null -eq $avzExeEntry) {
        throw "The pinned AVZ manifest does not contain avz.exe."
    }
    foreach ($entry in @($avzMetadata.zip.entries)) {
        Assert-ExtractedManifestEntry $avzExtractRoot $entry
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
    if ($baseSample.StartsWith("avz4/", [StringComparison]::OrdinalIgnoreCase)) {
        $baseDestination = $avzExtractRoot
        $baseVerificationRoot = $avzExtractRoot
    }
    elseif ($baseSample.StartsWith("Base/", [StringComparison]::OrdinalIgnoreCase)) {
        $baseDestination = $sourceAvzHome
        $baseVerificationRoot = $sourceAvzHome
    }
    else {
        $baseDestination = Join-Path $sourceAvzHome "Base"
        $baseVerificationRoot = $baseDestination
    }
    New-Item -ItemType Directory -Path $baseDestination -Force | Out-Null
    Expand-Archive -LiteralPath $baseArchive -DestinationPath $baseDestination -Force
    foreach ($entry in @($baseMetadata.zip.entries)) {
        Assert-ExtractedManifestEntry $baseVerificationRoot $entry
    }

    $payloadAvz = Join-Path $payloadRoot "AVZ"
    New-Item -ItemType Directory -Path $payloadAvz | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $sourceAvzHome -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $payloadAvz -Recurse -Force
    }
    $payloadAvzExe = Join-Path $payloadAvz "avz.exe"
    Assert-RegularFile $payloadAvzExe
    if ((Get-PeMachine $payloadAvzExe) -ne 0x014C) {
        throw "The pinned AVZ executable is not x86."
    }

    $payloadArchives = Join-Path $payloadAvz "Archives"
    New-Item -ItemType Directory -Path $payloadArchives | Out-Null
    Copy-Item -LiteralPath $avzArchive -Destination (Join-Path $payloadArchives "avz4.zip")
    Copy-Item -LiteralPath $baseArchive -Destination (Join-Path $payloadArchives "avzbase.zip")
    Copy-Item -LiteralPath $avzManifestFull -Destination (Join-Path $payloadAvz "AVZ_MANIFEST.json")
    Assert-CopiedFileHash $avzArchive (Join-Path $payloadArchives "avz4.zip") "avz4.zip"
    Assert-CopiedFileHash $baseArchive (Join-Path $payloadArchives "avzbase.zip") "avzbase.zip"
    Assert-CopiedFileHash $avzManifestFull (Join-Path $payloadAvz "AVZ_MANIFEST.json") "AVZ manifest"

    Copy-Item -LiteralPath $nodeTraceFull -Destination (Join-Path $payloadRoot "NodeTraceIR.exe")
    Copy-Item -LiteralPath $launcherSource -Destination (Join-Path $payloadRoot "launch_nodetrace.cmd")
    Copy-Item -LiteralPath $winPEManifestFull -Destination (Join-Path $payloadRoot "WINPE_EXTRACTION_MANIFEST.json")
    [IO.File]::WriteAllText(
        (Join-Path $payloadRoot "winpe-architecture.txt"),
        "x86`r`n",
        [Text.Encoding]::ASCII
    )

    $wimlibVersion = (& $wimlibFull --version | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query the selected wimlib-imagex executable."
    }
    $buildInfo = @(
        "architecture=x86",
        "nodetrace_sha256=$nodeTraceHash",
        "avz_archive_sha256=$avzArchiveHash",
        "avz_base_sha256=$baseArchiveHash",
        "avz_manifest_sha256=$avzManifestHash",
        "winpe_source_wim_sha256=$winPEWimHash",
        "winpe_extraction_manifest_sha256=$winPEManifestHash",
        "bootmgr_pinned_by_winpe_manifest=$($bootManagerPinnedByWinPEManifest.ToString().ToLowerInvariant())",
        "efi_el_torito_source=$(if ($null -ne $efiBootImageFull) { 'official-winpe-extraction' } else { 'deterministic-fat12-fallback' })",
        "wimlib_sha256=$wimlibHash",
        "wimlib_version=$wimlibVersion",
        "oscdimg_sha256=$oscdimgHash",
        "oscdimg_version=$oscdimgVersion",
        "iso_filesystem=udf-1.02-with-iso9660-bridge",
        "avz_execution=enabled"
    )
    [IO.File]::WriteAllLines(
        (Join-Path $payloadRoot "build-info.txt"),
        $buildInfo,
        [Text.UTF8Encoding]::new($false)
    )
    $payloadHashLines = foreach ($file in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Sort-Object FullName) {
        $relative = $file.FullName.Substring($payloadRoot.Length).TrimStart("\", "/").Replace("\", "/")
        "$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
    }
    [IO.File]::WriteAllLines(
        (Join-Path $payloadRoot "payload-sha256.txt"),
        $payloadHashLines,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "==> Injecting NodeTrace IR and AVZ with wimlib (no mount, DISM or elevation)" -ForegroundColor Cyan
    $updateCommands = @(
        "add --no-acls $(Quote-WimCommandPath $payloadRoot) `"/Program Files/NodeTraceIR`"",
        "add --no-acls $(Quote-WimCommandPath $startnetSource) `"/Windows/System32/startnet.cmd`"",
        "add --no-acls $(Quote-WimCommandPath $launcherSource) `"/Windows/System32/launch_nodetrace.cmd`""
    ) -join "`n"
    Invoke-WimUpdate -Wimlib $wimlibFull -Wim $stagedWim -Commands $updateCommands
    Invoke-Checked $wimlibFull @("verify", $stagedWim) "Verifying the updated WinPE WIM"

    Invoke-Checked $wimlibFull @(
        "extract",
        $stagedWim,
        "1",
        "/Program Files/NodeTraceIR",
        "/Windows/System32/startnet.cmd",
        "/Windows/System32/launch_nodetrace.cmd",
        "--dest-dir=$wimVerifyRoot",
        "--preserve-dir-structure",
        "--no-globs",
        "--no-acls",
        "--no-attributes"
    ) "Extracting the injected WIM paths for hash verification"

    $extractedPayload = Join-Path $wimVerifyRoot "Program Files\NodeTraceIR"
    foreach ($sourceFile in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File) {
        $relative = $sourceFile.FullName.Substring($payloadRoot.Length).TrimStart("\", "/")
        $extractedFile = Join-Path $extractedPayload $relative
        Assert-CopiedFileHash $sourceFile.FullName $extractedFile "Injected WIM payload file '$relative'"
    }
    Assert-CopiedFileHash $startnetSource (Join-Path $wimVerifyRoot "Windows\System32\startnet.cmd") "Injected startnet.cmd"
    Assert-CopiedFileHash $launcherSource (Join-Path $wimVerifyRoot "Windows\System32\launch_nodetrace.cmd") "Injected launcher"

    $bootImageRoot = Join-Path $stagingRoot "NodeTraceBoot"
    New-Item -ItemType Directory -Path $bootImageRoot | Out-Null
    $stagedBiosBoot = Join-Path $bootImageRoot "etfsboot.com"
    $stagedEfiImage = Join-Path $bootImageRoot "efisys.bin"
    Copy-Item -LiteralPath $biosBootFull -Destination $stagedBiosBoot
    Assert-CopiedFileHash $biosBootFull $stagedBiosBoot "BIOS El Torito image"
    if ($null -ne $efiBootImageFull) {
        Copy-Item -LiteralPath $efiBootImageFull -Destination $stagedEfiImage
        Assert-CopiedFileHash $efiBootImageFull $stagedEfiImage "Official IA32 EFI El Torito image"
        $efiBootSource = "official-winpe-extraction"
    }
    else {
        Invoke-Checked $Python @(
            $fatBuilder,
            $stagedBootIa32,
            $stagedEfiImage,
            "--destination",
            "EFI/BOOT/BOOTIA32.EFI",
            "--bcd",
            $stagedBcd,
            "--volume-label",
            "NODETRACE"
        ) "Creating and self-verifying the IA32 UEFI FAT boot image with BCD"
        $efiBootSource = "deterministic-fat12-fallback"
    }

    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($outputFull)) -Force | Out-Null
    $oscdimgTimestamp = ([DateTimeOffset]::FromUnixTimeSeconds($SourceDateEpoch)).UtcDateTime.ToString(
        "MM/dd/yyyy,HH:mm:ss",
        [Globalization.CultureInfo]::InvariantCulture
    )
    Invoke-Checked $oscdimgFull @(
        "-m",
        "-o",
        "-u1",
        "-udfver102",
        "-l$VolumeLabel",
        "-t$oscdimgTimestamp",
        "-bootdata:2#p0,e,b$stagedBiosBoot#pEF,e,b$stagedEfiImage",
        $stagingRoot,
        $outputFull
    ) "Building the UDF 1.02 BIOS/IA32-UEFI ISO with Microsoft oscdimg"

    $expectedIsoPaths = @(
        "BOOTMGR",
        "BOOT/BCD",
        "BOOT/BOOT.SDI",
        "EFI/BOOT/BOOTIA32.EFI",
        "EFI/MICROSOF/BOOT/BCD",
        "SOURCES/BOOT.WIM",
        "NODETRAC/ETFSBOOT.COM",
        "NODETRAC/EFISYS.BIN"
    )
    $verifyArguments = [Collections.Generic.List[string]]::new()
    $verifyArguments.Add($isoVerifier)
    $verifyArguments.Add($outputFull)
    $verifyArguments.Add("--require-udf-nsr02")
    foreach ($expectedPath in $expectedIsoPaths) {
        $verifyArguments.Add("--expect-path")
        $verifyArguments.Add($expectedPath)
    }
    $verificationJson = @(& $Python @($verifyArguments.ToArray()))
    $verificationExitCode = $LASTEXITCODE
    [IO.File]::WriteAllText(
        $verificationPath,
        (($verificationJson -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    if ($verificationExitCode -ne 0) {
        throw "ISO structural verification failed. Review: $verificationPath"
    }
    $verification = ($verificationJson -join "`n") | ConvertFrom-Json
    $bootModes = @($verification.boot_modes | ForEach-Object { [string]$_ })
    if ($bootModes -notcontains "BIOS" -or $bootModes -notcontains "UEFI") {
        throw "The ISO verifier did not confirm both BIOS and IA32 UEFI boot entries."
    }

    foreach ($inputState in @(
        [pscustomobject]@{ Path = $nodeTraceFull; Hash = $nodeTraceHash; Description = "NodeTraceIR.exe" },
        [pscustomobject]@{ Path = $avzArchive; Hash = $avzArchiveHash; Description = "avz4.zip" },
        [pscustomobject]@{ Path = $baseArchive; Hash = $baseArchiveHash; Description = "avzbase.zip" },
        [pscustomobject]@{ Path = $avzManifestFull; Hash = $avzManifestHash; Description = "AVZ manifest" },
        [pscustomobject]@{ Path = $winPEWimFull; Hash = $winPEWimHash; Description = "source WinPE WIM" },
        [pscustomobject]@{ Path = $winPEManifestFull; Hash = $winPEManifestHash; Description = "WinPE extraction manifest" },
        [pscustomobject]@{ Path = $bootSdiFull; Hash = $bootSdiHash; Description = "boot.sdi" },
        [pscustomobject]@{ Path = $bcdFull; Hash = $bcdHash; Description = "BCD" },
        [pscustomobject]@{ Path = $bootIa32Full; Hash = $bootIa32Hash; Description = "bootia32.efi" },
        [pscustomobject]@{ Path = $bootManagerFull; Hash = $bootManagerHash; Description = "bootmgr" },
        [pscustomobject]@{ Path = $biosBootFull; Hash = $biosBootHash; Description = "etfsboot.com" },
        [pscustomobject]@{ Path = $wimlibFull; Hash = $wimlibHash; Description = "wimlib-imagex.exe" },
        [pscustomobject]@{ Path = $oscdimgFull; Hash = $oscdimgHash; Description = "oscdimg.exe" }
    )) {
        Assert-UnchangedFileHash $inputState.Path $inputState.Hash $inputState.Description
    }
    if ($null -ne $efiBootImageFull) {
        Assert-UnchangedFileHash $efiBootImageFull $officialEfiBootHash "official efisys.bin"
    }
    $isoHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::Equals(
        [string]$verification.image.sha256,
        $isoHash,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The ISO changed between structural verification and final hashing."
    }
    [IO.File]::WriteAllText(
        $sidecarPath,
        "$isoHash *$([IO.Path]::GetFileName($outputFull))`n",
        [Text.UTF8Encoding]::new($false)
    )
    $externalBuildManifest = [ordered]@{
        schema = "nodetrace-winpe-build/v1"
        architecture = "x86"
        boot_modes = @("BIOS", "UEFI-IA32")
        bootmgr_pinned_by_winpe_manifest = $bootManagerPinnedByWinPEManifest
        efi_el_torito_source = $efiBootSource
        built_utc = [DateTime]::UtcNow.ToString("o")
        source_date_epoch = $SourceDateEpoch
        iso_filesystem = "UDF 1.02 with ISO9660 8.3 bridge"
        expected_iso_paths = $expectedIsoPaths
        expected_iso9660_bridge_paths = $expectedIsoPaths
        staged_udf_paths = @(
            "bootmgr",
            "Boot/BCD",
            "Boot/boot.sdi",
            "EFI/Boot/bootia32.efi",
            "EFI/Microsoft/Boot/BCD",
            "sources/boot.wim",
            "NodeTraceBoot/etfsboot.com",
            "NodeTraceBoot/efisys.bin"
        )
        hashes = [ordered]@{
            iso_sha256 = $isoHash
            boot_wim_sha256 = (Get-FileHash -LiteralPath $stagedWim -Algorithm SHA256).Hash.ToLowerInvariant()
            source_winpe_wim_sha256 = $winPEWimHash
            winpe_extraction_manifest_sha256 = $winPEManifestHash
            nodetrace_exe_sha256 = $nodeTraceHash
            avz4_zip_sha256 = $avzArchiveHash
            avzbase_zip_sha256 = $baseArchiveHash
            avz_manifest_sha256 = $avzManifestHash
            boot_sdi_sha256 = $bootSdiHash
            bcd_sha256 = $bcdHash
            bootia32_efi_sha256 = $bootIa32Hash
            bootmgr_sha256 = $bootManagerHash
            bios_boot_image_sha256 = $biosBootHash
            efi_fat_image_sha256 = (Get-FileHash -LiteralPath $stagedEfiImage -Algorithm SHA256).Hash.ToLowerInvariant()
            wimlib_imagex_sha256 = $wimlibHash
            oscdimg_sha256 = $oscdimgHash
        }
        tools = [ordered]@{
            wimlib = $wimlibVersion
            iso_builder = [ordered]@{
                name = "oscdimg.exe"
                version = $oscdimgVersion
                sha256 = $oscdimgHash
                provenance = "Tools/oscdimg.exe in the verified WinPE extraction manifest"
                udf_version = "1.02"
                iso9660_bridge = "8.3"
            }
            iso_verifier = "scripts/verify_bootable_iso.py"
            efi_image_builder = "scripts/build_fat12_efi.py"
        }
    }
    [IO.File]::WriteAllText(
        $buildManifestPath,
        ($externalBuildManifest | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "Portable bootable WinPE ISO build complete." -ForegroundColor Green
    Write-Host "ISO:          $outputFull"
    Write-Host "SHA-256:      $isoHash"
    Write-Host "Verification: $verificationPath"
    Write-Host "Build record: $buildManifestPath"
    $buildSucceeded = $true
}
finally {
    $sessionRoot = Assert-StrictChildPath -Child $sessionRoot -Parent $buildRoot
    if (-not $buildSucceeded) {
        foreach ($incompleteOutput in @($outputFull, $sidecarPath, $verificationPath, $buildManifestPath)) {
            if (Test-Path -LiteralPath $incompleteOutput -PathType Leaf) {
                Remove-Item -LiteralPath $incompleteOutput -Force
            }
        }
    }
    if ($KeepBuildDirectory) {
        Write-Host "Private build directory retained: $sessionRoot" -ForegroundColor Yellow
    }
    elseif (Test-Path -LiteralPath $sessionRoot -PathType Container) {
        Remove-Item -LiteralPath $sessionRoot -Recurse -Force
    }
}
