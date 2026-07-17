[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CacheDir,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [string]$PythonPath = "python",

    [switch]$MediaOnly,

    [switch]$AcceptMicrosoftLicense
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $AcceptMicrosoftLicense) {
    throw "Pass -AcceptMicrosoftLicense after reviewing and accepting the Microsoft ADK license."
}

$DownloadRoot = "https://download.microsoft.com/download/058b9477-7235-48ec-a700-73c5ccf9c286/adkwinpeaddons/Installers"
$Extractor = Join-Path $PSScriptRoot "extract_mszip_ranges.py"
$CacheRoot = [IO.Path]::GetFullPath($CacheDir).TrimEnd("\", "/")
$OutputRoot = [IO.Path]::GetFullPath($OutputDir).TrimEnd("\", "/")

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd("\", "/")
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    if (-not $candidateFull.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its intended root: '$candidateFull'."
    }
    return $candidateFull
}

function Assert-MicrosoftSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "Microsoft payload has an invalid Authenticode signature ($($signature.Status)): '$Path'."
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Payload signer is not Microsoft Corporation: '$subject'."
    }
}

function Assert-FileIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][string]$Sha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    if ((Get-Item -LiteralPath $Path).Length -ne $Size) {
        return $false
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256
}

function Receive-VerifiedRange {
    param(
        [Parameter(Mandatory = $true)][uri]$Url,
        [Parameter(Mandatory = $true)][long]$Start,
        [Parameter(Mandatory = $true)][long]$End,
        [Parameter(Mandatory = $true)][string]$Destination,
        [ValidateRange(1, 100)][int]$Retries = 30
    )

    if ($Url.Scheme -ne "https" -or $Url.Host -ne "download.microsoft.com") {
        throw "Refusing a non-official download URL: '$Url'."
    }
    if ($End -lt $Start) {
        throw "Invalid byte range $Start-$End."
    }
    $expected = $End - $Start + 1
    if ((Test-Path -LiteralPath $Destination -PathType Leaf) -and (Get-Item -LiteralPath $Destination).Length -eq $expected) {
        Write-Host "Verified existing range: $(Split-Path -Leaf $Destination) ($expected bytes)"
        return
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "An invalid existing range must be removed manually: '$Destination'."
    }

    $partial = "$Destination.partial"
    Assert-ChildPath -Root $CacheRoot -Candidate $partial | Out-Null
    if ((Test-Path -LiteralPath $partial -PathType Leaf) -and (Get-Item -LiteralPath $partial).Length -gt $expected) {
        throw "Partial range is larger than expected and must be removed manually: '$partial'."
    }

    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    try {
        for ($attempt = 1; $attempt -le $Retries; $attempt++) {
            $downloaded = if (Test-Path -LiteralPath $partial -PathType Leaf) { (Get-Item -LiteralPath $partial).Length } else { 0L }
            if ($downloaded -eq $expected) {
                Move-Item -LiteralPath $partial -Destination $Destination
                Write-Host "Completed range: $(Split-Path -Leaf $Destination) ($expected bytes)"
                return
            }
            $requestStart = $Start + $downloaded
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Url)
            $request.Headers.Range = [Net.Http.Headers.RangeHeaderValue]::new($requestStart, $End)
            $response = $null
            try {
                Write-Host "Downloading bytes $requestStart-$End (attempt $attempt/$Retries)..."
                $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                if ($response.StatusCode -ne [Net.HttpStatusCode]::PartialContent) {
                    throw "Server returned HTTP $([int]$response.StatusCode), expected 206."
                }
                $contentRange = $response.Content.Headers.ContentRange
                if ($null -eq $contentRange -or $contentRange.From -ne $requestStart -or $contentRange.To -ne $End) {
                    throw "Server returned an unexpected Content-Range: '$contentRange'."
                }

                $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $output = [IO.File]::Open($partial, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
                try {
                    $buffer = New-Object byte[] (1024 * 1024)
                    while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $output.Write($buffer, 0, $read)
                        if ($output.Length -gt $expected) {
                            throw "Range response exceeded the expected size."
                        }
                    }
                    $output.Flush($true)
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
            catch {
                if ($attempt -eq $Retries) {
                    throw
                }
                Write-Warning "Range transfer interrupted; resuming the retained partial file: $($_.Exception.Message)"
                Start-Sleep -Seconds ([Math]::Min(10, $attempt))
            }
            finally {
                if ($null -ne $response) {
                    $response.Dispose()
                }
                $request.Dispose()
            }
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
    throw "Range transfer did not complete: '$Destination'."
}

function Assert-MsiMemberHash {
    param(
        [Parameter(Mandatory = $true)][string]$Msi,
        [Parameter(Mandatory = $true)][string]$Member,
        [Parameter(Mandatory = $true)][string]$File
    )
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Msi, 0)
    $sql = "SELECT ``HashPart1``,``HashPart2``,``HashPart3``,``HashPart4`` FROM ``MsiFileHash`` WHERE ``File_``='$Member'"
    $view = $database.OpenView($sql)
    [void]$view.Execute()
    try {
        $expected = $view.Fetch()
        if ($null -eq $expected) {
            throw "Signed MSI has no MsiFileHash for '$Member'."
        }
        $actual = $installer.FileHash($File, 0)
        for ($index = 1; $index -le 4; $index++) {
            if ($actual.IntegerData($index) -ne $expected.IntegerData($index)) {
                throw "MsiFileHash mismatch for '$Member' part $index."
            }
        }
    }
    finally {
        [void]$view.Close()
    }
}

New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
if (Test-Path -LiteralPath $OutputRoot) {
    if (@(Get-ChildItem -LiteralPath $OutputRoot -Force).Count -gt 0) {
        throw "OutputDir must be empty; choose a new directory: '$OutputRoot'."
    }
}
else {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $Extractor -PathType Leaf)) {
    throw "MSZIP range extractor is missing: '$Extractor'."
}

$mediaMsi = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "Windows PE x86 x64-x86_en-us.msi")
$wimMsi = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "Windows PE x86 x64 wims-x86_en-us.msi")
$mediaHeader = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "a329-header.bin")
$mediaFolder13 = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "a329-folder13.range")
$mediaFolder20 = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "a329-folder20.range")
$wimHeader = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "690b-header.bin")
$wimFolder0 = Assert-ChildPath $CacheRoot (Join-Path $CacheRoot "690b-folder0.range")

if (-not (Assert-FileIdentity $mediaMsi 917504 "1BEC0E930BC95BA9A34F1EC72B09B13D08B9907EA79BC1D92CD33A75CB55D1D2")) {
    if (Test-Path -LiteralPath $mediaMsi) { throw "Invalid existing media MSI: '$mediaMsi'." }
    Receive-VerifiedRange "$DownloadRoot/Windows%20PE%20x86%20x64-x86_en-us.msi" 0 917503 $mediaMsi
}
if (-not (Assert-FileIdentity $mediaMsi 917504 "1BEC0E930BC95BA9A34F1EC72B09B13D08B9907EA79BC1D92CD33A75CB55D1D2")) {
    throw "Downloaded media MSI failed pinned SHA-256 verification."
}
Assert-MicrosoftSignature $mediaMsi

Receive-VerifiedRange "$DownloadRoot/a32918368eba6a062aaaaf73e3618131.cab" 0 1048575 $mediaHeader
Receive-VerifiedRange "$DownloadRoot/a32918368eba6a062aaaaf73e3618131.cab" 337744046 360218263 $mediaFolder13
Receive-VerifiedRange "$DownloadRoot/a32918368eba6a062aaaaf73e3618131.cab" 495034156 535501512 $mediaFolder20

$mediaManifest = Join-Path $OutputRoot "media-extraction-manifest.json"
& $PythonPath $Extractor $mediaHeader `
    --folder-range "13=$mediaFolder13" `
    --folder-range "20=$mediaFolder20" `
    --output-dir $OutputRoot `
    --map "fil9723970721c88cd8051382c9e1b62aae=Media/Boot/boot.sdi" `
    --map "fild9193215ee5ca6461e2f3125cc89b346=Media/EFI/Boot/bootia32.efi" `
    --map "file5d936f06cd0619d5a6e62c4f0dce751=Media/Boot/BCD" `
    --manifest $mediaManifest
if ($LASTEXITCODE -ne 0) {
    throw "Selective media extraction failed (exit $LASTEXITCODE)."
}

$bootSdi = Join-Path $OutputRoot "Media\Boot\boot.sdi"
$bootIa32 = Join-Path $OutputRoot "Media\EFI\Boot\bootia32.efi"
$bootBcd = Join-Path $OutputRoot "Media\Boot\BCD"
Assert-MsiMemberHash $mediaMsi "fil9723970721c88cd8051382c9e1b62aae" $bootSdi
Assert-MsiMemberHash $mediaMsi "file5d936f06cd0619d5a6e62c4f0dce751" $bootBcd
Assert-MicrosoftSignature $bootIa32

if (-not $MediaOnly) {
    if (-not (Assert-FileIdentity $wimMsi 466944 "B8813D971D400BF36EDA5E04FD1B73DC744695977E5F04C91F3D5CC70CFBCDB5")) {
        if (Test-Path -LiteralPath $wimMsi) { throw "Invalid existing WIM MSI: '$wimMsi'." }
        Receive-VerifiedRange "$DownloadRoot/Windows%20PE%20x86%20x64%20wims-x86_en-us.msi" 0 466943 $wimMsi
    }
    if (-not (Assert-FileIdentity $wimMsi 466944 "B8813D971D400BF36EDA5E04FD1B73DC744695977E5F04C91F3D5CC70CFBCDB5")) {
        throw "Downloaded WIM MSI failed pinned SHA-256 verification."
    }
    Assert-MicrosoftSignature $wimMsi

    Receive-VerifiedRange "$DownloadRoot/690b8ac88bc08254d351654d56805aea.cab" 0 1048575 $wimHeader
    Receive-VerifiedRange "$DownloadRoot/690b8ac88bc08254d351654d56805aea.cab" 172 199394198 $wimFolder0
    $wimManifest = Join-Path $OutputRoot "wim-extraction-manifest.json"
    & $PythonPath $Extractor $wimHeader `
        --folder-range "0=$wimFolder0" `
        --output-dir $OutputRoot `
        --map "fil642ac1bd3326d4b59398fe460db370b9=Media/sources/boot.wim" `
        --manifest $wimManifest
    if ($LASTEXITCODE -ne 0) {
        throw "Selective WIM extraction failed (exit $LASTEXITCODE)."
    }
    Assert-MsiMemberHash $wimMsi "fil642ac1bd3326d4b59398fe460db370b9" (Join-Path $OutputRoot "Media\sources\boot.wim")
}

$files = @(
    Get-ChildItem -LiteralPath $OutputRoot -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($OutputRoot.Length).TrimStart("\", "/").Replace("\", "/")
                size = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
)
$manifest = [ordered]@{
    schema = "nodetrace-winpe-selective-fetch/v1"
    product = "Microsoft Windows PE 10.1.19041.5856"
    architecture = "x86"
    media_only = [bool]$MediaOnly
    verified_utc = [DateTime]::UtcNow.ToString("o")
    files = $files
}
$manifestPath = Join-Path $OutputRoot "selective-fetch-manifest.json"
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 7), [Text.UTF8Encoding]::new($false))
Write-Host "Verified selective x86 WinPE staging tree: $OutputRoot"
Write-Host "Manifest: $manifestPath"
