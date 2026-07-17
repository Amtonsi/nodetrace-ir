#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$IsoPath,

    [string]$BuildRoot,
    [string]$EvidenceDirectory,
    [string]$VBoxManagePath,
    [string]$PythonPath,

    [ValidateRange(15, 900)]
    [int]$BootTimeoutSeconds = 90,

    [ValidateRange(1, 30)]
    [int]$PollIntervalSeconds = 2,

    [ValidateRange(5, 120)]
    [int]$CommandTimeoutSeconds = 30,

    [switch]$DisableFunctionalProbe,
    [switch]$Keep
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The VirtualBox WinPE smoke test must run on Windows."
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path $projectRoot "build\vm-smoke"
}

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "A required path is empty."
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-StrictChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $childFull = Get-FullPath -Path $Child
    $parentFull = (Get-FullPath -Path $Parent).TrimEnd("\", "/")
    $prefix = $parentFull + [System.IO.Path]::DirectorySeparatorChar
    if (
        $childFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Refusing an operation outside the private VM smoke-test root: $childFull"
    }
    return $childFull
}

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a reparse-point path: $($item.FullName)"
    }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file was not found: $Path"
    }
    Assert-NotReparsePoint -Path $Path
    if ((Get-Item -LiteralPath $Path -Force).Length -le 0) {
        throw "Required file is empty: $Path"
    }
}

function Resolve-VBoxManage {
    param([string]$ExplicitPath)

    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $candidates.Add($ExplicitPath)
    }
    else {
        $command = Get-Command "VBoxManage.exe" -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $candidates.Add($command.Source)
        }
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
            $candidates.Add((Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"))
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $full = Get-FullPath -Path $candidate
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            Assert-RegularFile -Path $full
            return $full
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        throw "VBoxManage was not found at the explicit path: $ExplicitPath"
    }
    throw "VBoxManage.exe was not found. Install Oracle VirtualBox or pass -VBoxManagePath."
}

function Resolve-Python {
    param([string]$ExplicitPath)

    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        $candidates.Add($ExplicitPath)
    }
    else {
        foreach ($commandName in @("python.exe", "python")) {
            $command = Get-Command $commandName -ErrorAction SilentlyContinue
            if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace($command.Source)) {
                $candidates.Add($command.Source)
            }
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $full = Get-FullPath -Path $candidate
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            Assert-RegularFile -Path $full
            return $full
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        throw "Python was not found at the explicit path: $ExplicitPath"
    }
    throw "python.exe was not found. Install Python 3 or pass -PythonPath, or use -DisableFunctionalProbe."
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    # Apply the CommandLineToArgvW quoting rules used by native Windows tools.
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Write-CommandLog {
    param([Parameter(Mandatory = $true)][string]$Text)

    [System.IO.File]::AppendAllText(
        $script:commandLogPath,
        $Text + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Invoke-VBoxManage {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $renderedArguments = @($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join " "
    Write-CommandLog -Text ("[{0}] VBoxManage {1}" -f [DateTime]::UtcNow.ToString("o"), $renderedArguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:vboxManageFull
    $startInfo.Arguments = $renderedArguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "VBoxManage could not be started."
    }
    $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
    $standardErrorTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
        try {
            $process.Kill()
        }
        catch {
            Write-CommandLog -Text ("Could not terminate timed-out VBoxManage process: {0}" -f $_.Exception.Message)
        }
        throw "VBoxManage exceeded the per-command timeout of $CommandTimeoutSeconds seconds."
    }

    $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
    $standardError = $standardErrorTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()

    if (-not [string]::IsNullOrWhiteSpace($standardOutput)) {
        Write-CommandLog -Text $standardOutput.TrimEnd()
    }
    if (-not [string]::IsNullOrWhiteSpace($standardError)) {
        Write-CommandLog -Text $standardError.TrimEnd()
    }
    Write-CommandLog -Text ("Exit code: {0}" -f $exitCode)

    $result = [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $standardOutput
        StdErr = $standardError
    }
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        $message = if ([string]::IsNullOrWhiteSpace($standardError)) { $standardOutput.Trim() } else { $standardError.Trim() }
        throw "VBoxManage failed with exit code $exitCode. $message"
    }
    return $result
}

function Invoke-Python {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $renderedArguments = @($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join " "
    Write-CommandLog -Text ("[{0}] Python {1}" -f [DateTime]::UtcNow.ToString("o"), $renderedArguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:pythonFull
    $startInfo.Arguments = $renderedArguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Python could not be started."
    }
    $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
    $standardErrorTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
        try {
            $process.Kill()
        }
        catch {
            Write-CommandLog -Text ("Could not terminate timed-out Python process: {0}" -f $_.Exception.Message)
        }
        throw "Python exceeded the per-command timeout of $CommandTimeoutSeconds seconds."
    }

    $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
    $standardError = $standardErrorTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()
    if (-not [string]::IsNullOrWhiteSpace($standardOutput)) {
        Write-CommandLog -Text $standardOutput.TrimEnd()
    }
    if (-not [string]::IsNullOrWhiteSpace($standardError)) {
        Write-CommandLog -Text $standardError.TrimEnd()
    }
    Write-CommandLog -Text ("Exit code: {0}" -f $exitCode)
    if ($exitCode -ne 0) {
        $message = if ([string]::IsNullOrWhiteSpace($standardError)) { $standardOutput.Trim() } else { $standardError.Trim() }
        throw "Python helper failed with exit code $exitCode. $message"
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $standardOutput
        StdErr = $standardError
    }
}

function ConvertFrom-MachineReadableInfo {
    param([Parameter(Mandatory = $true)][string]$Text)

    $fields = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^([^=]+)="(.*)"$') {
            $fields[$matches[1]] = $matches[2].Replace('\"', '"')
        }
        elseif ($line -match '^([^=]+)=(.*)$') {
            $fields[$matches[1]] = $matches[2]
        }
    }
    return $fields
}

function Get-VmInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Identifier,
        [switch]$AllowFailure
    )

    $result = Invoke-VBoxManage -Arguments @("showvminfo", $Identifier, "--machinereadable") -AllowFailure:$AllowFailure
    if ($result.ExitCode -ne 0) {
        return $null
    }
    return ConvertFrom-MachineReadableInfo -Text $result.StdOut
}

function Assert-CleanupMarker {
    param(
        [Parameter(Mandatory = $true)][string]$SessionPath,
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedToken,
        [Parameter(Mandatory = $true)][string]$ExpectedVmName
    )

    Assert-StrictChildPath -Child $SessionPath -Parent $script:buildRootFull | Out-Null
    if (-not ([System.IO.Path]::GetFileName($SessionPath)).StartsWith("nodetrace-vm-smoke-", [System.StringComparison]::Ordinal)) {
        throw "The private session directory has an unexpected name: $SessionPath"
    }
    Assert-NotReparsePoint -Path $SessionPath
    Assert-StrictChildPath -Child $MarkerPath -Parent $SessionPath | Out-Null
    Assert-RegularFile -Path $MarkerPath

    $marker = Get-Content -LiteralPath $MarkerPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$marker.token -ne $ExpectedToken -or
        [string]$marker.vm_name -ne $ExpectedVmName -or
        -not ([string]$marker.session_root).Equals($SessionPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$marker.build_root).Equals($script:buildRootFull, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "The private session cleanup marker did not match this smoke-test run."
    }
}

$isoFull = Get-FullPath -Path $IsoPath
Assert-RegularFile -Path $isoFull
if (-not ([System.IO.Path]::GetExtension($isoFull)).Equals(".iso", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "IsoPath must refer to an .iso file: $isoFull"
}

$buildRootFull = Get-FullPath -Path $BuildRoot
$buildRootTrimmed = $buildRootFull.TrimEnd("\", "/")
$volumeRootTrimmed = ([System.IO.Path]::GetPathRoot($buildRootFull)).TrimEnd("\", "/")
if ($buildRootTrimmed.Equals($volumeRootTrimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "BuildRoot cannot be a filesystem volume root: $buildRootFull"
}
New-Item -ItemType Directory -Force -Path $buildRootFull | Out-Null
Assert-NotReparsePoint -Path $buildRootFull

$runId = [guid]::NewGuid().ToString("N")
$vmName = "NodeTraceIR-WinPE-Smoke-$runId"
$sessionRoot = Assert-StrictChildPath -Child (Join-Path $buildRootFull "nodetrace-vm-smoke-$runId") -Parent $buildRootFull

if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $safeIsoName = [System.IO.Path]::GetFileNameWithoutExtension($isoFull) -replace '[^A-Za-z0-9._-]', '_'
    $evidenceLeaf = "{0}-{1}-{2}" -f $safeIsoName, [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ"), $runId.Substring(0, 8)
    $EvidenceDirectory = Join-Path (Join-Path $buildRootFull "smoke-results") $evidenceLeaf
}
$evidenceFull = Assert-StrictChildPath -Child $EvidenceDirectory -Parent $buildRootFull
if (Test-Path -LiteralPath $evidenceFull) {
    throw "Refusing to overwrite an existing evidence directory: $evidenceFull"
}
if (
    $evidenceFull.StartsWith($sessionRoot.TrimEnd("\", "/") + "\", [System.StringComparison]::OrdinalIgnoreCase) -or
    $sessionRoot.StartsWith($evidenceFull.TrimEnd("\", "/") + "\", [System.StringComparison]::OrdinalIgnoreCase)
) {
    throw "The evidence directory and disposable VM session directory must be separate."
}

New-Item -ItemType Directory -Path $evidenceFull -Force | Out-Null
Assert-NotReparsePoint -Path $evidenceFull
$commandLogPath = Join-Path $evidenceFull "vbox-commands.log"
[System.IO.File]::WriteAllText($commandLogPath, "", [System.Text.UTF8Encoding]::new($false))

$vboxManageFull = Resolve-VBoxManage -ExplicitPath $VBoxManagePath
$versionResult = Invoke-VBoxManage -Arguments @("--version")
$vboxVersion = $versionResult.StdOut.Trim()

New-Item -ItemType Directory -Path $sessionRoot | Out-Null
Assert-NotReparsePoint -Path $sessionRoot
$cleanupToken = [guid]::NewGuid().ToString("N")
$markerPath = Join-Path $sessionRoot ".nodetrace-vm-smoke.json"
$markerData = [ordered]@{
    schema_version = 1
    token = $cleanupToken
    vm_name = $vmName
    session_root = $sessionRoot
    build_root = $buildRootFull
    created_utc = [DateTime]::UtcNow.ToString("o")
}
[System.IO.File]::WriteAllText(
    $markerPath,
    ($markerData | ConvertTo-Json -Depth 4),
    [System.Text.UTF8Encoding]::new($false)
)

$isoItem = Get-Item -LiteralPath $isoFull
$isoSha256 = (Get-FileHash -LiteralPath $isoFull -Algorithm SHA256).Hash.ToLowerInvariant()
$screenshotPath = Join-Path $evidenceFull "winpe-final.png"
$showInfoPath = Join-Path $evidenceFull "showvminfo.txt"
$probeInspectionPath = Join-Path $evidenceFull "functional-probe-evidence.json"
$functionalProbeEnabled = -not $DisableFunctionalProbe.IsPresent
$fatBuilderPath = Get-FullPath -Path (Join-Path $PSScriptRoot "build_fat16_disk.py")
$probeContentRoot = Assert-StrictChildPath -Child (Join-Path $sessionRoot "probe-content") -Parent $sessionRoot
$targetRawPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "offline-target.raw") -Parent $sessionRoot
$targetVdiPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "offline-target.vdi") -Parent $sessionRoot
$evidenceRawPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "evidence-volume.raw") -Parent $sessionRoot
$evidenceVdiPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "evidence-volume.vdi") -Parent $sessionRoot
$evidenceAfterRawPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "evidence-volume-after.raw") -Parent $sessionRoot
$targetBuildManifestPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "offline-target-build.json") -Parent $sessionRoot
$evidenceBuildManifestPath = Assert-StrictChildPath -Child (Join-Path $sessionRoot "evidence-volume-build.json") -Parent $sessionRoot
$pythonFull = $null
$pythonVersion = $null
$probeDiskRecords = [System.Collections.Generic.List[object]]::new()
$targetDiskRecord = $null
$evidenceDiskRecord = $null
$functionalProbeError = $null
$launcherMarkerDetected = $false
$applicationDatabaseDetected = $false
$detectedProbePaths = @()
$evidenceAfterSha256 = $null
$evidenceChanged = $null
$postBootCloneNeedsClose = $false
$vmRegistered = $false
$vmUuid = $null
$vmStarted = $false
$startUtc = $null
$finishUtc = $null
$runError = $null
$cleanupErrors = [System.Collections.Generic.List[string]]::new()
$stateTransitions = [System.Collections.Generic.List[object]]::new()
$lastState = $null
$copiedLogPaths = [System.Collections.Generic.List[string]]::new()

try {
    if ($functionalProbeEnabled) {
        Write-Host "==> Building disposable FAT16 target and evidence disks" -ForegroundColor Cyan
        Assert-RegularFile -Path $fatBuilderPath
        $pythonFull = Resolve-Python -ExplicitPath $PythonPath
        $pythonVersionResult = Invoke-Python -Arguments @("--version")
        $pythonVersion = if ([string]::IsNullOrWhiteSpace($pythonVersionResult.StdOut)) {
            $pythonVersionResult.StdErr.Trim()
        }
        else {
            $pythonVersionResult.StdOut.Trim()
        }

        New-Item -ItemType Directory -Path $probeContentRoot | Out-Null
        Assert-NotReparsePoint -Path $probeContentRoot
        $systemHiveSource = Assert-StrictChildPath -Child (Join-Path $probeContentRoot "SYSTEM") -Parent $probeContentRoot
        $softwareHiveSource = Assert-StrictChildPath -Child (Join-Path $probeContentRoot "SOFTWARE") -Parent $probeContentRoot
        $evidenceMarkerSource = Assert-StrictChildPath -Child (Join-Path $probeContentRoot "NODETRACE_EVIDENCE_VOLUME") -Parent $probeContentRoot
        [System.IO.File]::WriteAllText(
            $systemHiveSource,
            "NodeTrace IR synthetic SYSTEM hive placeholder. This is intentionally not a live registry hive.`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::WriteAllText(
            $softwareHiveSource,
            "NodeTrace IR synthetic SOFTWARE hive placeholder. This is intentionally not a live registry hive.`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::WriteAllText(
            $evidenceMarkerSource,
            "NodeTrace IR disposable VM evidence volume.`r`n",
            [System.Text.UTF8Encoding]::new($false)
        )

        Invoke-Python -Arguments @(
            $fatBuilderPath, "build",
            "--output", $targetRawPath,
            "--label", "WIN_TARGET",
            "--size-mib", "16",
            "--file", ("{0}=Windows/System32/Config/SYSTEM" -f $systemHiveSource),
            "--file", ("{0}=Windows/System32/Config/SOFTWARE" -f $softwareHiveSource),
            "--json-output", $targetBuildManifestPath
        ) | Out-Null
        Invoke-Python -Arguments @(
            $fatBuilderPath, "build",
            "--output", $evidenceRawPath,
            "--label", "IR_EVIDENCE",
            "--size-mib", "64",
            "--file", ("{0}=NODETRACE_EVIDENCE_VOLUME" -f $evidenceMarkerSource),
            "--json-output", $evidenceBuildManifestPath
        ) | Out-Null
        foreach ($probeFile in @($targetRawPath, $evidenceRawPath, $targetBuildManifestPath, $evidenceBuildManifestPath)) {
            Assert-RegularFile -Path $probeFile
            Assert-StrictChildPath -Child $probeFile -Parent $sessionRoot | Out-Null
        }

        Invoke-VBoxManage -Arguments @("convertfromraw", $targetRawPath, $targetVdiPath, "--format=VDI") | Out-Null
        Invoke-VBoxManage -Arguments @("convertfromraw", $evidenceRawPath, $evidenceVdiPath, "--format=VDI") | Out-Null
        Assert-RegularFile -Path $targetVdiPath
        Assert-RegularFile -Path $evidenceVdiPath
        Assert-StrictChildPath -Child $targetVdiPath -Parent $sessionRoot | Out-Null
        Assert-StrictChildPath -Child $evidenceVdiPath -Parent $sessionRoot | Out-Null

        $targetBuild = Get-Content -LiteralPath $targetBuildManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $evidenceBuild = Get-Content -LiteralPath $evidenceBuildManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $targetDiskRecord = [ordered]@{
            role = "offline_windows_target"
            controller = "SATA"
            port = 0
            volume_label = [string]$targetBuild.volume_label
            size_mib = 16
            required_paths = @("Windows/System32/Config/SYSTEM", "Windows/System32/Config/SOFTWARE")
            raw = [ordered]@{
                name = [System.IO.Path]::GetFileName($targetRawPath)
                size = (Get-Item -LiteralPath $targetRawPath).Length
                sha256 = [string]$targetBuild.sha256
            }
            vdi = [ordered]@{
                name = [System.IO.Path]::GetFileName($targetVdiPath)
                size = (Get-Item -LiteralPath $targetVdiPath).Length
                sha256_before_boot = (Get-FileHash -LiteralPath $targetVdiPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        $evidenceDiskRecord = [ordered]@{
            role = "writable_evidence_volume"
            controller = "SATA"
            port = 1
            volume_label = [string]$evidenceBuild.volume_label
            size_mib = 64
            required_paths = @("NODETRACE_EVIDENCE_VOLUME")
            raw = [ordered]@{
                name = [System.IO.Path]::GetFileName($evidenceRawPath)
                size = (Get-Item -LiteralPath $evidenceRawPath).Length
                sha256 = [string]$evidenceBuild.sha256
            }
            vdi = [ordered]@{
                name = [System.IO.Path]::GetFileName($evidenceVdiPath)
                size = (Get-Item -LiteralPath $evidenceVdiPath).Length
                sha256_before_boot = (Get-FileHash -LiteralPath $evidenceVdiPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        $probeDiskRecords.Add($targetDiskRecord)
        $probeDiskRecords.Add($evidenceDiskRecord)
    }

    Write-Host "==> Creating isolated x86 BIOS VM: $vmName" -ForegroundColor Cyan
    Invoke-VBoxManage -Arguments @(
        "createvm", "--name", $vmName,
        "--ostype", "Windows10",
        "--basefolder", $sessionRoot,
        "--register"
    ) | Out-Null
    $vmRegistered = $true

    $createdInfo = Get-VmInfo -Identifier $vmName
    if (-not $createdInfo.ContainsKey("UUID") -or -not $createdInfo.ContainsKey("CfgFile")) {
        throw "VirtualBox did not report the UUID and configuration path of the created VM."
    }
    $vmUuid = [string]$createdInfo["UUID"]
    $configurationPath = Get-FullPath -Path ([string]$createdInfo["CfgFile"])
    Assert-StrictChildPath -Child $configurationPath -Parent $sessionRoot | Out-Null

    Invoke-VBoxManage -Arguments @(
        "modifyvm", $vmUuid,
        "--memory", "1536",
        "--vram", "32",
        "--cpus", "1",
        "--firmware", "bios",
        "--boot1", "dvd",
        "--boot2", "none",
        "--boot3", "none",
        "--boot4", "none",
        "--graphicscontroller", "vboxsvga",
        "--nic1", "none",
        "--audio-enabled", "off",
        "--clipboard-mode", "disabled",
        "--drag-and-drop", "disabled",
        "--usb-ohci", "off",
        "--usb-ehci", "off",
        "--usb-xhci", "off"
    ) | Out-Null
    Invoke-VBoxManage -Arguments @(
        "storagectl", $vmUuid,
        "--name", "IDE",
        "--add", "ide",
        "--controller", "PIIX4"
    ) | Out-Null
    Invoke-VBoxManage -Arguments @(
        "storageattach", $vmUuid,
        "--storagectl", "IDE",
        "--port", "0",
        "--device", "0",
        "--type", "dvddrive",
        "--medium", $isoFull
    ) | Out-Null
    if ($functionalProbeEnabled) {
        Invoke-VBoxManage -Arguments @(
            "storagectl", $vmUuid,
            "--name", "SATA",
            "--add", "sata",
            "--controller", "IntelAhci",
            "--portcount", "2",
            "--bootable", "on"
        ) | Out-Null
        Invoke-VBoxManage -Arguments @(
            "storageattach", $vmUuid,
            "--storagectl", "SATA",
            "--port", "0",
            "--device", "0",
            "--type", "hdd",
            "--medium", $targetVdiPath
        ) | Out-Null
        Invoke-VBoxManage -Arguments @(
            "storageattach", $vmUuid,
            "--storagectl", "SATA",
            "--port", "1",
            "--device", "0",
            "--type", "hdd",
            "--medium", $evidenceVdiPath
        ) | Out-Null
    }

    $configuredInfo = Invoke-VBoxManage -Arguments @("showvminfo", $vmUuid, "--details")
    [System.IO.File]::WriteAllText(
        $showInfoPath,
        $configuredInfo.StdOut,
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "==> Booting headless for at most $BootTimeoutSeconds seconds" -ForegroundColor Cyan
    Invoke-VBoxManage -Arguments @("startvm", $vmUuid, "--type", "headless") | Out-Null
    $vmStarted = $true
    $startUtc = [DateTime]::UtcNow
    $deadline = $startUtc.AddSeconds($BootTimeoutSeconds)

    while ([DateTime]::UtcNow -lt $deadline) {
        $runningInfo = Get-VmInfo -Identifier $vmUuid
        $state = if ($runningInfo.ContainsKey("VMState")) { [string]$runningInfo["VMState"] } else { "unknown" }
        if ($state -ne $lastState) {
            $stateTransitions.Add([ordered]@{
                utc = [DateTime]::UtcNow.ToString("o")
                state = $state
            })
            $lastState = $state
        }
        if ($state -ne "running") {
            throw "The VM stopped before the boot observation timeout (state: $state)."
        }
        $remainingSeconds = [Math]::Max(0.0, ($deadline - [DateTime]::UtcNow).TotalSeconds)
        $sleepSeconds = [Math]::Min([double]$PollIntervalSeconds, $remainingSeconds)
        if ($sleepSeconds -gt 0) {
            Start-Sleep -Milliseconds ([Math]::Max(1, [int][Math]::Ceiling($sleepSeconds * 1000.0)))
        }
    }

    Invoke-VBoxManage -Arguments @("controlvm", $vmUuid, "screenshotpng", $screenshotPath) | Out-Null
    Assert-RegularFile -Path $screenshotPath
    Write-Host "==> Boot screenshot captured: $screenshotPath" -ForegroundColor Green
}
catch {
    $runError = $_
}
finally {
    $finishUtc = [DateTime]::UtcNow

    # A timed-out createvm process can register a VM before the host process is
    # terminated. Detect that narrow case and only adopt it for cleanup when
    # VirtualBox confirms that its configuration lives below this run's root.
    if (-not $vmRegistered) {
        try {
            $registrationProbe = Get-VmInfo -Identifier $vmName -AllowFailure
            if ($null -ne $registrationProbe -and $registrationProbe.ContainsKey("UUID") -and $registrationProbe.ContainsKey("CfgFile")) {
                $probedConfiguration = Get-FullPath -Path ([string]$registrationProbe["CfgFile"])
                Assert-StrictChildPath -Child $probedConfiguration -Parent $sessionRoot | Out-Null
                $vmUuid = [string]$registrationProbe["UUID"]
                $vmRegistered = $true
            }
        }
        catch {
            $cleanupErrors.Add("Registration recovery check failed: $($_.Exception.Message)")
        }
    }

    if ($vmRegistered) {
        try {
            $finalInfoResult = Invoke-VBoxManage -Arguments @("showvminfo", $(if ($null -ne $vmUuid) { $vmUuid } else { $vmName }), "--machinereadable") -AllowFailure
            if ($finalInfoResult.ExitCode -eq 0) {
                [System.IO.File]::WriteAllText(
                    (Join-Path $evidenceFull "showvminfo-final.txt"),
                    $finalInfoResult.StdOut,
                    [System.Text.UTF8Encoding]::new($false)
                )
                $finalInfo = ConvertFrom-MachineReadableInfo -Text $finalInfoResult.StdOut
                $finalState = if ($finalInfo.ContainsKey("VMState")) { [string]$finalInfo["VMState"] } else { "unknown" }
                if ($finalState -notin @("poweroff", "aborted", "saved")) {
                    $powerResult = Invoke-VBoxManage -Arguments @("controlvm", $(if ($null -ne $vmUuid) { $vmUuid } else { $vmName }), "poweroff") -AllowFailure
                    if ($powerResult.ExitCode -ne 0) {
                        $cleanupErrors.Add("VirtualBox could not power off the VM.")
                    }
                }
            }
            else {
                $cleanupErrors.Add("VirtualBox could not query the VM during cleanup.")
            }
        }
        catch {
            $cleanupErrors.Add("VM shutdown check failed: $($_.Exception.Message)")
        }
    }

    if ($functionalProbeEnabled -and $vmStarted) {
        try {
            Assert-RegularFile -Path $evidenceVdiPath
            Assert-StrictChildPath -Child $evidenceAfterRawPath -Parent $sessionRoot | Out-Null
            if (Test-Path -LiteralPath $evidenceAfterRawPath) {
                throw "Refusing to overwrite the post-boot evidence image: $evidenceAfterRawPath"
            }
            Invoke-VBoxManage -Arguments @(
                "clonemedium", $evidenceVdiPath, $evidenceAfterRawPath,
                "disk", "--format=RAW"
            ) | Out-Null
            $postBootCloneNeedsClose = $true
            Assert-RegularFile -Path $evidenceAfterRawPath
            $evidenceAfterSha256 = (Get-FileHash -LiteralPath $evidenceAfterRawPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $evidenceChanged = -not $evidenceAfterSha256.Equals(
                [string]$evidenceDiskRecord["raw"]["sha256"],
                [System.StringComparison]::OrdinalIgnoreCase
            )

            Invoke-Python -Arguments @(
                $fatBuilderPath, "inspect",
                "--image", $evidenceAfterRawPath,
                "--json-output", $probeInspectionPath
            ) | Out-Null
            Assert-RegularFile -Path $probeInspectionPath
            $inspection = Get-Content -LiteralPath $probeInspectionPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $allProbePaths = @($inspection.entries | ForEach-Object { [string]$_.path })
            $detectedProbePaths = @(
                $allProbePaths | Where-Object {
                    $_ -match '^NodeTraceIR-Evidence/' -or $_ -eq 'NODETRACE_EVIDENCE_VOLUME'
                }
            )
            $launcherMarkerDetected = @(
                $allProbePaths | Where-Object {
                    $_ -match '^NodeTraceIR-Evidence/session-[^/]+/winpe-session\.txt$'
                }
            ).Count -gt 0
            $applicationDatabaseDetected = @(
                $allProbePaths | Where-Object {
                    $_ -match '^NodeTraceIR-Evidence/session-[^/]+/nodetrace_ir\.sqlite3$'
                }
            ).Count -gt 0
            if (-not $applicationDatabaseDetected) {
                $functionalProbeError = if ($launcherMarkerDetected) {
                    "The automatic WinPE launcher wrote its session marker, but the NodeTrace IR application database was not created."
                }
                else {
                    "The disposable evidence disk contains no automatic NodeTrace IR launch artifacts."
                }
            }

        }
        catch {
            $functionalProbeError = "Functional probe inspection failed: $($_.Exception.Message)"
        }
        finally {
            if ($postBootCloneNeedsClose) {
                try {
                    # clonemedium registers its destination. Unregister only
                    # this exact guarded path, then scoped cleanup removes it.
                    Assert-StrictChildPath -Child $evidenceAfterRawPath -Parent $sessionRoot | Out-Null
                    $closeCloneResult = Invoke-VBoxManage -Arguments @(
                        "closemedium", "disk", $evidenceAfterRawPath
                    ) -AllowFailure
                    if ($closeCloneResult.ExitCode -ne 0) {
                        $cleanupErrors.Add("VirtualBox could not unregister the private post-boot RAW clone.")
                    }
                    else {
                        $postBootCloneNeedsClose = $false
                    }
                }
                catch {
                    $cleanupErrors.Add("Post-boot RAW clone cleanup failed: $($_.Exception.Message)")
                }
            }
        }
    }
    elseif ($functionalProbeEnabled -and $null -eq $runError) {
        $functionalProbeError = "The functional probe was enabled, but the VM never started."
    }

    try {
        if (Test-Path -LiteralPath $sessionRoot -PathType Container) {
            $logIndex = 0
            foreach ($logFile in Get-ChildItem -LiteralPath $sessionRoot -Recurse -File -Filter "VBox.log*") {
                Assert-StrictChildPath -Child $logFile.FullName -Parent $sessionRoot | Out-Null
                Assert-NotReparsePoint -Path $logFile.FullName
                $logIndex++
                $destination = Join-Path $evidenceFull ("vbox-{0:D2}-{1}" -f $logIndex, $logFile.Name)
                Copy-Item -LiteralPath $logFile.FullName -Destination $destination
                $copiedLogPaths.Add($destination)
            }
        }
    }
    catch {
        $cleanupErrors.Add("VirtualBox log collection failed: $($_.Exception.Message)")
    }

    if (-not $Keep -and $vmRegistered) {
        try {
            Assert-CleanupMarker -SessionPath $sessionRoot -MarkerPath $markerPath -ExpectedToken $cleanupToken -ExpectedVmName $vmName
            $identity = if ($null -ne $vmUuid) { $vmUuid } else { $vmName }
            $cleanupInfo = Get-VmInfo -Identifier $identity -AllowFailure
            if ($null -eq $cleanupInfo -or -not $cleanupInfo.ContainsKey("UUID") -or -not $cleanupInfo.ContainsKey("CfgFile")) {
                throw "VirtualBox did not return cleanup identity fields."
            }
            if ($null -ne $vmUuid -and -not ([string]$cleanupInfo["UUID"]).Equals($vmUuid, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The registered VM UUID changed; refusing to unregister it."
            }
            $cleanupConfiguration = Get-FullPath -Path ([string]$cleanupInfo["CfgFile"])
            Assert-StrictChildPath -Child $cleanupConfiguration -Parent $sessionRoot | Out-Null

            $unregisterResult = Invoke-VBoxManage -Arguments @("unregistervm", [string]$cleanupInfo["UUID"], "--delete") -AllowFailure
            if ($unregisterResult.ExitCode -ne 0) {
                throw "VirtualBox could not unregister and delete the private VM."
            }
            $vmRegistered = $false
        }
        catch {
            $cleanupErrors.Add("Private VM cleanup failed: $($_.Exception.Message)")
        }
    }

    if (-not $Keep -and -not $vmRegistered -and (Test-Path -LiteralPath $sessionRoot)) {
        try {
            Assert-CleanupMarker -SessionPath $sessionRoot -MarkerPath $markerPath -ExpectedToken $cleanupToken -ExpectedVmName $vmName
            Remove-Item -LiteralPath $sessionRoot -Recurse -Force
        }
        catch {
            $cleanupErrors.Add("Private session directory cleanup failed: $($_.Exception.Message)")
        }
    }
}

$artifacts = [System.Collections.Generic.List[object]]::new()
foreach ($artifactPath in @($screenshotPath, $showInfoPath, $probeInspectionPath, $commandLogPath) + $copiedLogPaths.ToArray()) {
    if (Test-Path -LiteralPath $artifactPath -PathType Leaf) {
        $artifact = Get-Item -LiteralPath $artifactPath
        $artifacts.Add([ordered]@{
            name = $artifact.Name
            size = $artifact.Length
            sha256 = (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
}

$status = if ($null -ne $runError -or $null -ne $functionalProbeError -or $cleanupErrors.Count -gt 0) { "failed" } else { "evidence-captured" }
$resultPath = Join-Path $evidenceFull "smoke-result.json"
$resultData = [ordered]@{
    schema_version = 2
    status = $status
    test_id = $runId
    started_utc = if ($null -eq $startUtc) { $null } else { $startUtc.ToString("o") }
    finished_utc = $finishUtc.ToString("o")
    boot_timeout_seconds = $BootTimeoutSeconds
    firmware = "bios"
    guest_os_type = "Windows10 (32-bit/x86)"
    network = "disabled"
    vm_name = $vmName
    vm_uuid = $vmUuid
    vm_started = $vmStarted
    vm_retained = [bool]$Keep -or $vmRegistered
    session_root = if ([bool]$Keep -or $vmRegistered) { $sessionRoot } else { $null }
    evidence_directory = $evidenceFull
    virtualbox = [ordered]@{
        executable = $vboxManageFull
        version = $vboxVersion
    }
    iso = [ordered]@{
        path = $isoFull
        size = $isoItem.Length
        sha256 = $isoSha256
    }
    functional_probe = [ordered]@{
        enabled = $functionalProbeEnabled
        default_on = $true
        disable_switch = "-DisableFunctionalProbe"
        python = if ($functionalProbeEnabled) {
            [ordered]@{
                executable = $pythonFull
                version = $pythonVersion
            }
        }
        else {
            $null
        }
        builder = if ($functionalProbeEnabled) { $fatBuilderPath } else { $null }
        disks = $probeDiskRecords.ToArray()
        expected_flow = "offline Windows hives -> automatic launcher -> separate marked evidence volume -> NodeTrace IR database"
        evidence_sha256_after_boot = $evidenceAfterSha256
        evidence_changed = $evidenceChanged
        launcher_session_marker_detected = $launcherMarkerDetected
        application_database_detected = $applicationDatabaseDetected
        observed_nodetrace_paths = $detectedProbePaths
        inspection_artifact = if (Test-Path -LiteralPath $probeInspectionPath -PathType Leaf) {
            [System.IO.Path]::GetFileName($probeInspectionPath)
        }
        else {
            $null
        }
        error = $functionalProbeError
    }
    state_transitions = $stateTransitions.ToArray()
    artifacts = $artifacts.ToArray()
    run_error = if ($null -eq $runError) { $null } else { $runError.Exception.Message }
    cleanup_errors = $cleanupErrors.ToArray()
}
[System.IO.File]::WriteAllText(
    $resultPath,
    ($resultData | ConvertTo-Json -Depth 12),
    [System.Text.UTF8Encoding]::new($false)
)

$hashLines = foreach ($file in Get-ChildItem -LiteralPath $evidenceFull -File | Sort-Object Name) {
    if ($file.Name -eq "SHA256SUMS.txt") {
        continue
    }
    "{0}  {1}" -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $file.Name
}
[System.IO.File]::WriteAllLines(
    (Join-Path $evidenceFull "SHA256SUMS.txt"),
    $hashLines,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Evidence directory: $evidenceFull"
Write-Host "Result manifest:    $resultPath"
if ($Keep) {
    Write-Host "The powered-off VM and private session were retained because -Keep was supplied: $sessionRoot" -ForegroundColor Yellow
}
if ($null -ne $runError) {
    throw "WinPE VM smoke test failed: $($runError.Exception.Message). Evidence: $evidenceFull"
}
if ($null -ne $functionalProbeError) {
    throw "WinPE VM functional probe failed: $functionalProbeError Evidence: $evidenceFull"
}
if ($cleanupErrors.Count -gt 0) {
    throw "WinPE VM smoke test completed with cleanup errors: $($cleanupErrors -join ' ') Evidence: $evidenceFull"
}

Write-Host "VirtualBox WinPE smoke evidence captured successfully." -ForegroundColor Green
