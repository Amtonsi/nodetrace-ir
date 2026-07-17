[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CacheDir,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [string]$PythonPath = "python",

    [switch]$AcceptMicrosoftLicense
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $AcceptMicrosoftLicense) {
    throw "Pass -AcceptMicrosoftLicense after reviewing and accepting the Microsoft ADK license."
}

$CacheRoot = [IO.Path]::GetFullPath($CacheDir).TrimEnd("\", "/")
$OutputRoot = [IO.Path]::GetFullPath($OutputDir).TrimEnd("\", "/")
$MszipExtractor = Join-Path $PSScriptRoot "extract_mszip_ranges.py"
$FatExtractor = Join-Path $PSScriptRoot "extract_fat12_file.py"
$WinPEBaseUrl = "https://download.microsoft.com/download/058b9477-7235-48ec-a700-73c5ccf9c286/adkwinpeaddons/Installers/"
$AdkBaseUrl = "https://download.microsoft.com/download/3b40cb81-ff9c-4322-aacd-c78d01b2c2ed/adk/Installers/"

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Assert-StrictChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $parentFull = (Get-FullPath $Parent) + [IO.Path]::DirectorySeparatorChar
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its intended root: '$childFull'."
    }
    return $childFull
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required regular file is missing: '$Path'."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse-point inputs are not accepted: '$Path'."
    }
}

function Assert-FileIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][ValidateSet("SHA1", "SHA256")][string]$Algorithm,
        [Parameter(Mandatory = $true)][string]$Hash
    )
    $expectedHashLength = if ($Algorithm -eq "SHA1") { 40 } else { 64 }
    if ($Hash -notmatch "^[0-9A-Fa-f]{$expectedHashLength}$") {
        throw "Pinned $Algorithm value must contain exactly $expectedHashLength hexadecimal characters."
    }
    Assert-RegularFile $Path
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -ne $Size) {
        throw "Pinned payload size mismatch for '$Path': $($item.Length), expected $Size."
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash
    if (-not [string]::Equals($actual, $Hash, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Pinned payload $Algorithm mismatch for '$Path': $actual, expected $Hash."
    }
}

function Assert-MicrosoftSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-RegularFile $Path
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "Microsoft signature is not valid for '$Path': $($signature.Status)."
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Unexpected signer for '$Path': '$subject'."
    }
    return $signature
}

function Resolve-PinnedPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][ValidateSet("SHA1", "SHA256")][string]$Algorithm,
        [Parameter(Mandatory = $true)][string]$Hash
    )
    $candidates = @(
        (Join-Path $CacheRoot $Name),
        (Join-Path $CacheRoot (Join-Path "winpe-layout\Installers" $Name)),
        (Join-Path $CacheRoot (Join-Path "Installers" $Name))
    )
    foreach ($candidate in $candidates) {
        Assert-StrictChildPath -Child $candidate -Parent $CacheRoot | Out-Null
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Assert-FileIdentity $candidate $Size $Algorithm $Hash
            return (Get-FullPath $candidate)
        }
    }
    throw "Pinned payload '$Name' was not found below '$CacheRoot'."
}

function Assert-MsiMemberHash {
    param(
        [Parameter(Mandatory = $true)][string]$Msi,
        [Parameter(Mandatory = $true)][string]$Member,
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][int[]]$ExpectedParts
    )
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Msi, 0)
    $escaped = $Member.Replace("'", "''")
    $view = $database.OpenView(
        "SELECT ``HashPart1``,``HashPart2``,``HashPart3``,``HashPart4`` " +
        "FROM ``MsiFileHash`` WHERE ``File_``='$escaped'"
    )
    [void]$view.Execute()
    try {
        $record = $view.Fetch()
        if ($null -eq $record) {
            throw "Signed MSI has no MsiFileHash for '$Member'."
        }
        $actual = $installer.FileHash($File, 0)
        for ($index = 1; $index -le 4; $index++) {
            $signedValue = $record.IntegerData($index)
            if ($signedValue -ne $ExpectedParts[$index - 1]) {
                throw "Pinned MsiFileHash constant disagrees with signed MSI for '$Member'."
            }
            if ($actual.IntegerData($index) -ne $signedValue) {
                throw "Extracted '$File' failed signed MsiFileHash for '$Member'."
            }
        }
    }
    finally {
        [void]$view.Close()
    }
}

function Invoke-PythonChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    Write-Host "==> $Label" -ForegroundColor Cyan
    & $PythonPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path -LiteralPath $CacheRoot -PathType Container)) {
    throw "CacheDir does not exist: '$CacheRoot'."
}
foreach ($script in @($MszipExtractor, $FatExtractor)) {
    Assert-RegularFile $script
}
if (Test-Path -LiteralPath $OutputRoot) {
    if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
        throw "OutputDir is not a directory: '$OutputRoot'."
    }
    if (@(Get-ChildItem -LiteralPath $OutputRoot -Force).Count -ne 0) {
        throw "OutputDir must be empty; existing data is never removed: '$OutputRoot'."
    }
}
else {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}

$winpeBootstrap = Resolve-PinnedPayload `
    "adkwinpesetup.exe" 1434088 "SHA256" `
    "39BB281EA5D631C7E0F989C53DBCD317BD5A6C4EEFF82B41B40256744D2C5D5D"
$adkBootstrap = Resolve-PinnedPayload `
    "adksetup.exe" 1970056 "SHA256" `
    "79FFC10E1A7E2E699083467DB601D9747F71A419981B458063DE1A86FD8C47DD"
$wimMsi = Resolve-PinnedPayload `
    "Windows PE x86 x64 wims-x86_en-us.msi" 466944 "SHA256" `
    "B8813D971D400BF36EDA5E04FD1B73DC744695977E5F04C91F3D5CC70CFBCDB5"
$mediaMsi = Resolve-PinnedPayload `
    "Windows PE x86 x64-x86_en-us.msi" 917504 "SHA256" `
    "1BEC0E930BC95BA9A34F1EC72B09B13D08B9907EA79BC1D92CD33A75CB55D1D2"
$deploymentMsi = Resolve-PinnedPayload `
    "Windows Deployment Tools-x86_en-us.msi" 626688 "SHA256" `
    "5DA7A3F65E6364735FBCEB08357773387D2B035B0073BA0BBC19A76A548C95B2"
$wimCab = Resolve-PinnedPayload `
    "690b8ac88bc08254d351654d56805aea.cab" 199404031 "SHA1" `
    "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
$bootCab = Resolve-PinnedPayload `
    "aa25d18a5fcce134b0b89fb003ec99ff.cab" 1817033 "SHA256" `
    "4C0A16C542DC232D1476BB1778B6AB16BB9BBF42EEC87F6A7688132142D4FA6A"
$efiCab = Resolve-PinnedPayload `
    "5d984200acbde182fd99cbfbe9bad133.cab" 1281728 "SHA256" `
    "D693C814E565012D34BB53A985E116D328E6E03674C29809D3875C50F758EBAC"

foreach ($signedPayload in @(
    $winpeBootstrap, $adkBootstrap, $wimMsi, $mediaMsi, $deploymentMsi
)) {
    Assert-MicrosoftSignature $signedPayload | Out-Null
}

$provenanceDir = Assert-StrictChildPath `
    -Child (Join-Path $OutputRoot ".provenance") `
    -Parent $OutputRoot
New-Item -ItemType Directory -Path $provenanceDir | Out-Null

$bootWim = Assert-StrictChildPath (Join-Path $OutputRoot "Media\sources\boot.wim") $OutputRoot
$bootManager = Assert-StrictChildPath (Join-Path $OutputRoot "Media\bootmgr") $OutputRoot
$efiImage = Assert-StrictChildPath (Join-Path $OutputRoot "Media\fwfiles\efisys.bin") $OutputRoot
$bootIa32 = Assert-StrictChildPath (Join-Path $OutputRoot "Media\EFI\Boot\bootia32.efi") $OutputRoot
$bootBcd = Assert-StrictChildPath (Join-Path $OutputRoot "Media\Boot\BCD") $OutputRoot
$bootSdi = Assert-StrictChildPath (Join-Path $OutputRoot "Media\Boot\boot.sdi") $OutputRoot

Invoke-PythonChecked "Extracting the pinned x86 boot WIM" @(
    $MszipExtractor, $wimCab,
    "--full-cab", $wimCab,
    "--output-dir", $OutputRoot,
    "--map", "fil642ac1bd3326d4b59398fe460db370b9=Media/sources/boot.wim",
    "--manifest", (Join-Path $provenanceDir "wim-extraction.json")
)
Invoke-PythonChecked "Extracting the pinned Microsoft BIOS boot manager" @(
    $MszipExtractor, $bootCab,
    "--full-cab", $bootCab,
    "--output-dir", $OutputRoot,
    "--map", "fila6a550eed89046f3810ad344d06b2f13=Media/bootmgr",
    "--manifest", (Join-Path $provenanceDir "bootmgr-extraction.json")
)
Invoke-PythonChecked "Extracting the official IA32 EFI El Torito image" @(
    $MszipExtractor, $efiCab,
    "--full-cab", $efiCab,
    "--output-dir", $OutputRoot,
    "--map", "fil4db617e977c2929fa4a8a113dcc24567=Media/fwfiles/efisys.bin",
    "--manifest", (Join-Path $provenanceDir "efisys-extraction.json")
)
Invoke-PythonChecked "Recovering signed BOOTIA32.EFI from the official FAT12 image" @(
    $FatExtractor, $efiImage, "EFI/BOOT/BOOTIA32.EFI", $bootIa32
)

Assert-FileIdentity $bootWim 200131143 "SHA256" `
    ((Get-FileHash -LiteralPath $bootWim -Algorithm SHA256).Hash)
Assert-FileIdentity $bootManager 420266 "SHA256" `
    "5B61EE9E0770753F2743D01DA6D64C73DFAFDE930052395CB43FB0ACD6EDCE34"
Assert-FileIdentity $efiImage 1474560 "SHA256" `
    "51831A5EF7480BCFC39D306DDF4E12C89093CE35519862B99A07354E352C4E89"
Assert-FileIdentity $bootIa32 1010080 "SHA256" `
    "BB5B85E5CF1F582CC2A9F269E48EB6BA1B6AC0445006DA911DA981AB87D14F97"
Assert-MsiMemberHash $wimMsi "fil642ac1bd3326d4b59398fe460db370b9" $bootWim `
    @(-721854461, 650304993, 1499151182, 1220197130)
Assert-MsiMemberHash $mediaMsi "fila6a550eed89046f3810ad344d06b2f13" $bootManager `
    @(1073898854, 1102876665, 502589138, -1875494190)
Assert-MsiMemberHash $deploymentMsi "fil4db617e977c2929fa4a8a113dcc24567" $efiImage `
    @(1498138875, 923298925, 130554703, -663301826)
Assert-MicrosoftSignature $bootIa32 | Out-Null

$windowsRoot = Get-FullPath $env:SystemRoot
if (-not [string]::Equals($windowsRoot, "C:\Windows", [StringComparison]::OrdinalIgnoreCase)) {
    throw "The strict portable manifest profile requires the canonical C:\Windows host asset paths."
}
$hostBcd = "C:\Windows\Boot\DVD\PCAT\BCD"
$hostSdi = "C:\Windows\Boot\DVD\PCAT\boot.sdi"
foreach ($hostAsset in @($hostBcd, $hostSdi)) {
    Assert-MicrosoftSignature $hostAsset | Out-Null
}
foreach ($destination in @($bootBcd, $bootSdi)) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
}
Copy-Item -LiteralPath $hostBcd -Destination $bootBcd
Copy-Item -LiteralPath $hostSdi -Destination $bootSdi
Assert-MicrosoftSignature $bootBcd | Out-Null
Assert-MicrosoftSignature $bootSdi | Out-Null

$originRoles = [ordered]@{
    "Media/sources/boot.wim" = "x86-boot-wim"
    "Media/bootmgr" = "x86-bios-bootmgr"
    "Media/fwfiles/efisys.bin" = "ia32-efi-el-torito"
    "Media/EFI/Boot/bootia32.efi" = "ia32-efi-el-torito-loader"
    "Media/Boot/BCD" = "host-pcat-bcd"
    "Media/Boot/boot.sdi" = "host-boot-sdi"
}
$manifestFiles = @(
    foreach ($relative in $originRoles.Keys) {
        $full = Assert-StrictChildPath `
            -Child (Join-Path $OutputRoot $relative.Replace("/", "\")) `
            -Parent $OutputRoot
        Assert-RegularFile $full
        $item = Get-Item -LiteralPath $full -Force
        [pscustomobject]@{
            path = $relative
            size = $item.Length
            sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
            origin_role = $originRoles[$relative]
        }
    }
)

function New-SignedFileProvenance {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    [ordered]@{
        name = $item.Name
        size = $item.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        authenticode = "Valid"
        signer_organization = "Microsoft Corporation"
    }
}

$wimCabSha256 = (Get-FileHash -LiteralPath $wimCab -Algorithm SHA256).Hash
$manifest = [ordered]@{
    schema = "nodetrace-winpe-extraction/v1"
    source = "Microsoft Windows PE add-on 10.1.19041.5856"
    architecture = "x86"
    extracted_utc = [DateTime]::UtcNow.ToString("o")
    provenance = [ordered]@{
        profile = "nodetrace-microsoft-adk-2004-x86/v1"
        adk_version = "10.1.19041.5856"
        winpe_bootstrap = New-SignedFileProvenance $winpeBootstrap
        deployment_tools_bootstrap = New-SignedFileProvenance $adkBootstrap
        payloads = @(
            [ordered]@{
                role = "x86-boot-wim"
                base_url = $WinPEBaseUrl
                msi = New-SignedFileProvenance $wimMsi
                cab = [ordered]@{
                    name = "690b8ac88bc08254d351654d56805aea.cab"
                    size = 199404031L
                    sha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
                    sha256 = $wimCabSha256
                }
                member = [ordered]@{
                    cab_member = "fil642ac1bd3326d4b59398fe460db370b9"
                    path = "Media/sources/boot.wim"
                    msi_file_hash = @(-721854461, 650304993, 1499151182, 1220197130)
                }
            },
            [ordered]@{
                role = "x86-bios-bootmgr"
                base_url = $WinPEBaseUrl
                msi = New-SignedFileProvenance $mediaMsi
                cab = [ordered]@{
                    name = "aa25d18a5fcce134b0b89fb003ec99ff.cab"
                    size = 1817033L
                    sha1 = "A81232D9F59DA3B3DC1A67FA8550B72D63F2BCA4"
                    sha256 = "4C0A16C542DC232D1476BB1778B6AB16BB9BBF42EEC87F6A7688132142D4FA6A"
                }
                member = [ordered]@{
                    cab_member = "fila6a550eed89046f3810ad344d06b2f13"
                    path = "Media/bootmgr"
                    msi_file_hash = @(1073898854, 1102876665, 502589138, -1875494190)
                    equivalent_x86_member = "fil2c982ca7ca0ed4898e594265a6b3f029"
                }
            },
            [ordered]@{
                role = "ia32-efi-el-torito"
                base_url = $AdkBaseUrl
                msi = New-SignedFileProvenance $deploymentMsi
                cab = [ordered]@{
                    name = "5d984200acbde182fd99cbfbe9bad133.cab"
                    size = 1281728L
                    sha1 = "542F751C77ED5F21EE3FB317333CC509A2484228"
                    sha256 = "D693C814E565012D34BB53A985E116D328E6E03674C29809D3875C50F758EBAC"
                }
                member = [ordered]@{
                    cab_member = "fil4db617e977c2929fa4a8a113dcc24567"
                    path = "Media/fwfiles/efisys.bin"
                    msi_file_hash = @(1498138875, 923298925, 130554703, -663301826)
                    embedded_loader = [ordered]@{
                        source_image_path = "Media/fwfiles/efisys.bin"
                        source_member_path = "EFI/BOOT/BOOTIA32.EFI"
                        path = "Media/EFI/Boot/bootia32.efi"
                        origin_role = "ia32-efi-el-torito-loader"
                        size = 1010080L
                        sha256 = "BB5B85E5CF1F582CC2A9F269E48EB6BA1B6AC0445006DA911DA981AB87D14F97"
                        authenticode = "Valid"
                        signer_organization = "Microsoft Corporation"
                    }
                }
            }
        )
        host_assets = @(
            [ordered]@{
                source_type = "host-windows-signed"
                source_path = $hostBcd
                path = "Media/Boot/BCD"
                origin_role = "host-pcat-bcd"
                size = (Get-Item -LiteralPath $bootBcd).Length
                sha256 = (Get-FileHash -LiteralPath $bootBcd -Algorithm SHA256).Hash.ToLowerInvariant()
                authenticode = "Valid"
                signer_organization = "Microsoft Corporation"
            },
            [ordered]@{
                source_type = "host-windows-signed"
                source_path = $hostSdi
                path = "Media/Boot/boot.sdi"
                origin_role = "host-boot-sdi"
                size = (Get-Item -LiteralPath $bootSdi).Length
                sha256 = (Get-FileHash -LiteralPath $bootSdi -Algorithm SHA256).Hash.ToLowerInvariant()
                authenticode = "Valid"
                signer_organization = "Microsoft Corporation"
            }
        )
    }
    files = $manifestFiles
}

$manifestPath = Join-Path $OutputRoot "extraction-manifest.json"
[IO.File]::WriteAllText(
    $manifestPath,
    ($manifest | ConvertTo-Json -Depth 12),
    [Text.UTF8Encoding]::new($false)
)
Write-Host "Prepared verified portable x86 WinPE inputs: $OutputRoot" -ForegroundColor Green
Write-Host "Manifest: $manifestPath"
Write-Host "WIM CAB SHA-256: $wimCabSha256"
