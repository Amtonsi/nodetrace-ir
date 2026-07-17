[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LayoutDir,

    [ValidateRange(1, 32)]
    [int]$Parallel = 12,

    [switch]$AcceptMicrosoftLicense
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $AcceptMicrosoftLicense) {
    throw "Pass -AcceptMicrosoftLicense after reviewing and accepting the Microsoft ADK license."
}

$DownloadRoot = "https://download.microsoft.com/download/058b9477-7235-48ec-a700-73c5ccf9c286/adkwinpeaddons/Installers"
$Payloads = @(
    [pscustomobject]@{
        Name = "Windows PE x86 x64-x86_en-us.msi"
        UrlName = "Windows%20PE%20x86%20x64-x86_en-us.msi"
        Size = 917504L
        Sha1 = "45E14889CB06CC68E87E519114A18F52827A9371"
        Parallel = $false
    },
    [pscustomobject]@{
        Name = "a32918368eba6a062aaaaf73e3618131.cab"
        UrlName = "a32918368eba6a062aaaaf73e3618131.cab"
        Size = 576974705L
        Sha1 = "1D21F3CB927959DAAD39A1956004C18D31E05EAE"
        Parallel = $true
    },
    [pscustomobject]@{
        Name = "Windows PE x86 x64 wims-x86_en-us.msi"
        UrlName = "Windows%20PE%20x86%20x64%20wims-x86_en-us.msi"
        Size = 466944L
        Sha1 = "C3FBABFBD36BBE74BDCC814213A13F3601FD1ADA"
        Parallel = $false
    },
    [pscustomobject]@{
        Name = "690b8ac88bc08254d351654d56805aea.cab"
        UrlName = "690b8ac88bc08254d351654d56805aea.cab"
        Size = 199404031L
        Sha1 = "10FA653EF230E3CEA8E9C8E8A9DF9CCD412AB7ED"
        Parallel = $true
    }
)

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Assert-Payload {
    param(
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Payload.Size) {
        return $false
    }
    $sha1 = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToUpperInvariant()
    return $sha1 -eq $Payload.Sha1
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains('"')) {
        throw "A process argument contains an unsupported quote character."
    }
    return '"' + $Value + '"'
}

function Invoke-CurlDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    & curl.exe -fL --silent --show-error --retry 5 --retry-delay 2 --connect-timeout 30 --output $Destination $Url
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed to download '$Url' (exit $LASTEXITCODE)."
    }
}

function Invoke-ParallelRangeDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][long]$Size,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][int]$PartCount,
        [Parameter(Mandatory = $true)][string]$WorkingRoot
    )

    $destinationName = [IO.Path]::GetFileName($Destination)
    $partRoot = Join-Path $WorkingRoot ($destinationName + ".parts")
    New-Item -ItemType Directory -Path $partRoot -Force | Out-Null
    $partRootFull = Get-NormalizedPath $partRoot
    $safePrefix = (Get-NormalizedPath $WorkingRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not $partRootFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe range-download working directory."
    }

    $chunk = [long][Math]::Ceiling($Size / [double]$PartCount)
    $parts = @()
    $processes = @()
    for ($index = 0; $index -lt $PartCount; $index++) {
        $start = [long]$index * $chunk
        if ($start -ge $Size) {
            break
        }
        $end = [Math]::Min($Size - 1, $start + $chunk - 1)
        $expected = $end - $start + 1
        $part = Join-Path $partRoot ("part-{0:D2}" -f $index)
        $parts += [pscustomobject]@{
            Index = $index
            Start = $start
            End = $end
            Expected = $expected
            Path = $part
        }

        if ((Test-Path -LiteralPath $part -PathType Leaf) -and (Get-Item -LiteralPath $part).Length -eq $expected) {
            continue
        }

        $errorLog = $part + ".err"
        $argumentLine = @(
            "-fL",
            "--silent",
            "--show-error",
            "--retry 5",
            "--retry-delay 2",
            "--connect-timeout 30",
            "--range $start-$end",
            "--output $(Quote-ProcessArgument $part)",
            (Quote-ProcessArgument $Url)
        ) -join " "
        $process = Start-Process -FilePath "curl.exe" -ArgumentList $argumentLine -WindowStyle Hidden -RedirectStandardError $errorLog -PassThru
        $processes += [pscustomobject]@{
            Process = $process
            Part = $part
            ErrorLog = $errorLog
        }
    }

    foreach ($entry in $processes) {
        $entry.Process.WaitForExit()
        if ($entry.Process.ExitCode -ne 0) {
            $message = if (Test-Path -LiteralPath $entry.ErrorLog) {
                Get-Content -LiteralPath $entry.ErrorLog -Raw -ErrorAction SilentlyContinue
            }
            else {
                ""
            }
            throw "Range download failed for '$($entry.Part)' (exit $($entry.Process.ExitCode)): $message"
        }
    }

    foreach ($part in $parts) {
        if (-not (Test-Path -LiteralPath $part.Path -PathType Leaf)) {
            throw "Range part is missing: '$($part.Path)'."
        }
        $actual = (Get-Item -LiteralPath $part.Path).Length
        if ($actual -ne $part.Expected) {
            throw "Range server returned $actual bytes for part $($part.Index), expected $($part.Expected)."
        }
    }

    $partial = $Destination + ".partial"
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    $partialFull = [IO.Path]::GetFullPath($partial)
    if (-not $destinationFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not $partialFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe output path for range merge."
    }
    if (Test-Path -LiteralPath $partial) {
        Remove-Item -LiteralPath $partial -Force
    }

    $output = [IO.File]::Open($partial, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        foreach ($part in $parts | Sort-Object Index) {
            $input = [IO.File]::OpenRead($part.Path)
            try {
                $input.CopyTo($output)
            }
            finally {
                $input.Dispose()
            }
        }
    }
    finally {
        $output.Dispose()
    }
    if ((Get-Item -LiteralPath $partial).Length -ne $Size) {
        throw "Merged payload has the wrong size."
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force

    # Delete only the exact per-payload working directory created above.
    if ($partRootFull.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $partRootFull) -eq ($destinationName + ".parts")) {
        Remove-Item -LiteralPath $partRootFull -Recurse -Force
    }
}

$layoutRoot = Get-NormalizedPath $LayoutDir
$installerRoot = Join-Path $layoutRoot "Installers"
New-Item -ItemType Directory -Path $installerRoot -Force | Out-Null
$installerRoot = Get-NormalizedPath $installerRoot

foreach ($payload in $Payloads) {
    $destination = Join-Path $installerRoot $payload.Name
    if (Assert-Payload $payload $destination) {
        Write-Host "Verified existing payload: $($payload.Name)"
        continue
    }
    if (Test-Path -LiteralPath $destination) {
        throw "An invalid existing payload must be removed or quarantined manually: '$destination'."
    }

    $url = "$DownloadRoot/$($payload.UrlName)"
    Write-Host "Downloading official Microsoft payload: $($payload.Name)"
    if ($payload.Parallel -and $Parallel -gt 1) {
        Invoke-ParallelRangeDownload $url $payload.Size $destination $Parallel $installerRoot
    }
    else {
        Invoke-CurlDownload $url $destination
    }
    if (-not (Assert-Payload $payload $destination)) {
        throw "Downloaded payload failed pinned size/SHA-1 verification: '$destination'."
    }
    Write-Host "Verified: $($payload.Name)"
}

$records = @(
    foreach ($payload in $Payloads) {
        $path = Join-Path $installerRoot $payload.Name
        [pscustomobject]@{
            name = $payload.Name
            size = (Get-Item -LiteralPath $path).Length
            sha1 = (Get-FileHash -LiteralPath $path -Algorithm SHA1).Hash.ToLowerInvariant()
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            url = "$DownloadRoot/$($payload.UrlName)"
        }
    }
)
$manifest = [ordered]@{
    schema = "nodetrace-winpe-payloads/v1"
    product = "Microsoft Windows PE add-on 10.1.19041.5856"
    architecture = "x86"
    verified_utc = [DateTime]::UtcNow.ToString("o")
    payloads = $records
}
$manifestPath = Join-Path $layoutRoot "winpe-2004-x86-payloads.json"
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Write-Host "All pinned payloads verified. Manifest: $manifestPath"
