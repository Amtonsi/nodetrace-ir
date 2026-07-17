[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [uri]$Url,

    [Parameter(Mandatory = $true)]
    [long]$TotalSize,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 128)]
    [int]$PartCount,

    [Parameter(Mandatory = $true)]
    [string]$PartsDir,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedSha1,

    [ValidateRange(1, 100)]
    [int]$RetriesPerPart = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Url.Scheme -ne "https" -or $Url.Host -ne "download.microsoft.com") {
    throw "Only the pinned Microsoft HTTPS host is accepted: '$Url'."
}
if ($TotalSize -le 0) {
    throw "TotalSize must be positive."
}

$partsRoot = [IO.Path]::GetFullPath($PartsDir).TrimEnd("\", "/")
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$partialOutput = "$outputFull.partial"
if (-not (Test-Path -LiteralPath $partsRoot -PathType Container)) {
    throw "PartsDir does not exist: '$partsRoot'."
}
if ($outputFull.StartsWith($partsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath must be outside PartsDir so assembly cannot overwrite a part."
}
if (Test-Path -LiteralPath $outputFull) {
    throw "Refusing to overwrite an existing output: '$outputFull'."
}
if (Test-Path -LiteralPath $partialOutput) {
    throw "Refusing to overwrite an existing assembly partial: '$partialOutput'."
}

Add-Type -AssemblyName System.Net.Http
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $true
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromMinutes(10)

function Resume-Part {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$RemoteStart,
        [Parameter(Mandatory = $true)][long]$RemoteEnd,
        [Parameter(Mandatory = $true)][int]$Retries
    )

    $expected = $RemoteEnd - $RemoteStart + 1
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stream.Dispose()
    }
    $actual = (Get-Item -LiteralPath $Path).Length
    if ($actual -gt $expected) {
        throw "Part '$Path' is larger than expected ($actual > $expected)."
    }

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $actual = (Get-Item -LiteralPath $Path).Length
        if ($actual -eq $expected) {
            return
        }

        $requestStart = $RemoteStart + $actual
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Url)
        $request.Headers.Range = [Net.Http.Headers.RangeHeaderValue]::new($requestStart, $RemoteEnd)
        $response = $null
        try {
            Write-Host "Resuming $(Split-Path -Leaf $Path): bytes $requestStart-$RemoteEnd (attempt $attempt/$Retries)"
            $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            if ($response.StatusCode -ne [Net.HttpStatusCode]::PartialContent) {
                throw "HTTP $([int]$response.StatusCode), expected 206."
            }
            $range = $response.Content.Headers.ContentRange
            if ($null -eq $range -or $range.From -ne $requestStart -or $range.To -ne $RemoteEnd) {
                throw "Unexpected Content-Range: '$range'."
            }

            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = [IO.File]::Open($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try {
                $buffer = New-Object byte[] (1024 * 1024)
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $output.Write($buffer, 0, $read)
                    if ($output.Length -gt $expected) {
                        throw "Server sent more bytes than the part boundary permits."
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
            Write-Warning "Transfer interrupted; keeping '$Path' for the next sequential resume: $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Min(10, $attempt))
        }
        finally {
            if ($null -ne $response) {
                $response.Dispose()
            }
            $request.Dispose()
        }
    }
    throw "Part did not complete: '$Path'."
}

try {
    $chunk = [long][Math]::Ceiling($TotalSize / [double]$PartCount)
    $parts = @()
    for ($index = 0; $index -lt $PartCount; $index++) {
        $start = [long]$index * $chunk
        if ($start -ge $TotalSize) {
            break
        }
        $end = [Math]::Min($TotalSize - 1, $start + $chunk - 1)
        $part = Join-Path $partsRoot ("part-{0:D2}" -f $index)
        $partFull = [IO.Path]::GetFullPath($part)
        if (-not $partFull.StartsWith($partsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe part path: '$partFull'."
        }
        Resume-Part -Path $partFull -RemoteStart $start -RemoteEnd $end -Retries $RetriesPerPart
        $parts += [pscustomobject]@{
            Index = $index
            Path = $partFull
            Expected = $end - $start + 1
        }
    }

    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($outputFull)) -Force | Out-Null
    $assembled = [IO.File]::Open($partialOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        foreach ($part in $parts | Sort-Object Index) {
            if ((Get-Item -LiteralPath $part.Path).Length -ne $part.Expected) {
                throw "Part changed before assembly: '$($part.Path)'."
            }
            $input = [IO.File]::OpenRead($part.Path)
            try {
                $input.CopyTo($assembled)
            }
            finally {
                $input.Dispose()
            }
        }
        $assembled.Flush($true)
    }
    finally {
        $assembled.Dispose()
    }

    if ((Get-Item -LiteralPath $partialOutput).Length -ne $TotalSize) {
        throw "Assembled payload has the wrong size."
    }
    $sha1 = (Get-FileHash -LiteralPath $partialOutput -Algorithm SHA1).Hash
    if ($sha1 -ne $ExpectedSha1.ToUpperInvariant()) {
        throw "Assembled payload SHA-1 mismatch: $sha1. Parts were preserved."
    }
    Move-Item -LiteralPath $partialOutput -Destination $outputFull
    Write-Host "Verified assembly complete: $outputFull"
    Write-Host "SHA-1: $sha1"
}
finally {
    $client.Dispose()
    $handler.Dispose()
    # On failure, preserve every downloaded part and the assembly partial for audit/recovery.
}
