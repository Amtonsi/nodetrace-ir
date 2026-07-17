@echo off
setlocal

set "NODETRACE_AVZ_ARCHIVE=%~dp0AVZ\avz4.zip"
set "NODETRACE_AVZ_BASE_ARCHIVE=%~dp0AVZ\avzbase.zip"
set "NODETRACE_AVZ_MANIFEST=%~dp0AVZ_MANIFEST.json"
set "NODETRACE_AVZ_DISTRIBUTION=noncommercial-consent"
set "NODETRACE_AVZ_EXE="
set "NODETRACE_AVZ_CACHE="

if not exist "%~dp0NodeTraceIR.exe" (
  echo ERROR: NodeTraceIR.exe is missing from this media.
  exit /b 2
)
if not exist "%NODETRACE_AVZ_ARCHIVE%" (
  echo ERROR: AVZ\avz4.zip is missing from this media.
  exit /b 3
)
if not exist "%NODETRACE_AVZ_BASE_ARCHIVE%" (
  echo ERROR: AVZ\avzbase.zip is missing from this media.
  exit /b 4
)
if not exist "%NODETRACE_AVZ_MANIFEST%" (
  echo ERROR: AVZ_MANIFEST.json is missing from this media.
  exit /b 5
)
if not defined LOCALAPPDATA (
  echo ERROR: LOCALAPPDATA is not available; a writable per-user cache cannot be created.
  exit /b 6
)

set "NODETRACE_IR_DATA_DIR=%LOCALAPPDATA%\NodeTraceIR\cases"
if not exist "%NODETRACE_IR_DATA_DIR%" mkdir "%NODETRACE_IR_DATA_DIR%" >nul 2>&1
if not exist "%NODETRACE_IR_DATA_DIR%" (
  echo ERROR: Cannot create case storage: %NODETRACE_IR_DATA_DIR%
  exit /b 7
)

echo Verifying and preparing the pinned AVZ diagnostic toolkit...
for /f "tokens=1,* delims=|" %%I in ('powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $m=Get-Content -LiteralPath $env:NODETRACE_AVZ_MANIFEST -Raw -Encoding UTF8 | ConvertFrom-Json; $app=$null; $base=$null; foreach($a in @($m.archives)){if($a.name -eq 'avz4.zip'){$app=$a}; if($a.name -eq 'avzbase.zip'){$base=$a}}; if($null -eq $app -or $null -eq $base){throw 'AVZ manifest archive set is incomplete.'}; foreach($pair in @(@($env:NODETRACE_AVZ_ARCHIVE,$app),@($env:NODETRACE_AVZ_BASE_ARCHIVE,$base))){$f=Get-Item -LiteralPath $pair[0]; if($f.Length -ne [int64]$pair[1].size){throw ('AVZ archive size mismatch: '+$f.Name)}; if((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash -ne $pair[1].sha256){throw ('AVZ archive SHA-256 mismatch: '+$f.Name)}}; $exeEntry=$null; foreach($e in @($app.zip.entries)){if($e.path -match '(^|/)avz[.]exe$'){$exeEntry=$e}}; if($null -eq $exeEntry){throw 'avz.exe is not pinned in the manifest.'}; $id=$app.sha256.Substring(0,12)+'-'+$base.sha256.Substring(0,12); $root=Join-Path $env:LOCALAPPDATA 'NodeTraceIR\tool-cache'; $null=New-Item -ItemType Directory -Force -Path $root; $target=Join-Path $root ('avz-'+$id); $marker=Join-Path $target '.nodetrace-manifest.sha256'; $manifestHash=(Get-FileHash -LiteralPath $env:NODETRACE_AVZ_MANIFEST -Algorithm SHA256).Hash; $relativeExe=$exeEntry.path.Replace('/','\'); $exe=Join-Path $target $relativeExe; $sample=$null; foreach($e in @($base.zip.entries)){if(-not $e.path.EndsWith('/')){$sample=$e.path; break}}; if($null -eq $sample){throw 'AVZ base archive is empty.'}; $targetAvzHome=Split-Path -Parent $exe; if($sample.StartsWith('avz4/')){$cachedBaseRoot=$target; $cachedBaseMode='root'} elseif($sample.StartsWith('Base/')){$cachedBaseRoot=$targetAvzHome; $cachedBaseMode='home'} else {$cachedBaseRoot=Join-Path $targetAvzHome 'Base'; $cachedBaseMode='base'}; $valid=(Test-Path -LiteralPath $exe -PathType Leaf) -and (Test-Path -LiteralPath $marker -PathType Leaf); if($valid){$valid=((Get-Content -LiteralPath $marker -Raw).Trim() -eq $manifestHash) -and ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -eq $exeEntry.sha256)}; if($valid){foreach($e in @($base.zip.entries)){if($e.path.EndsWith('/')){continue}; if($cachedBaseMode -eq 'root'){$p=Join-Path $target $e.path.Replace('/','\\')} elseif($cachedBaseMode -eq 'home'){$p=Join-Path $targetAvzHome $e.path.Replace('/','\\')} else {$p=Join-Path $cachedBaseRoot $e.path.Replace('/','\\')}; if(-not (Test-Path -LiteralPath $p -PathType Leaf) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $e.sha256){$valid=$false; break}}}; if(-not $valid){if(Test-Path -LiteralPath $target){throw ('Versioned AVZ cache failed integrity checks: '+$target)}; $temp=Join-Path $root ('.tmp-'+[guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $temp; try{Expand-Archive -LiteralPath $env:NODETRACE_AVZ_ARCHIVE -DestinationPath $temp -Force; $tempExe=Join-Path $temp $relativeExe; if(-not (Test-Path -LiteralPath $tempExe -PathType Leaf)){throw 'avz.exe was not extracted.'}; if((Get-FileHash -LiteralPath $tempExe -Algorithm SHA256).Hash -ne $exeEntry.sha256){throw 'Extracted avz.exe failed SHA-256 verification.'}; $sample=$null; foreach($e in @($base.zip.entries)){if(-not $e.path.EndsWith('/')){$sample=$e.path; break}}; if($null -eq $sample){throw 'AVZ base archive is empty.'}; $avzHome=Split-Path -Parent $tempExe; if($sample.StartsWith('avz4/')){$baseDestination=$temp; $baseMode='root'} elseif($sample.StartsWith('Base/')){$baseDestination=$avzHome; $baseMode='home'} else {$baseDestination=Join-Path $avzHome 'Base'; $baseMode='base'}; $null=New-Item -ItemType Directory -Force -Path $baseDestination; Expand-Archive -LiteralPath $env:NODETRACE_AVZ_BASE_ARCHIVE -DestinationPath $baseDestination -Force; foreach($e in @($base.zip.entries)){if($e.path.EndsWith('/')){continue}; if($baseMode -eq 'root'){$p=Join-Path $temp $e.path.Replace('/','\')} elseif($baseMode -eq 'home'){$p=Join-Path $avzHome $e.path.Replace('/','\')} else {$p=Join-Path $baseDestination $e.path.Replace('/','\')}; if(-not (Test-Path -LiteralPath $p -PathType Leaf) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $e.sha256){throw ('Extracted AVZ base entry failed SHA-256 verification: '+$e.path)}}; [IO.File]::WriteAllText((Join-Path $temp '.nodetrace-manifest.sha256'),$manifestHash,[Text.UTF8Encoding]::new($false)); Move-Item -LiteralPath $temp -Destination $target; $exe=Join-Path $target $relativeExe} finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}}}; Write-Output ($exe+'|'+$target)"') do (
  set "NODETRACE_AVZ_EXE=%%I"
  set "NODETRACE_AVZ_CACHE=%%J"
)

if not defined NODETRACE_AVZ_EXE (
  echo ERROR: AVZ preparation failed. NodeTrace IR was not started.
  exit /b 8
)
if not exist "%NODETRACE_AVZ_EXE%" (
  echo ERROR: Verified avz.exe is unavailable: %NODETRACE_AVZ_EXE%
  exit /b 9
)

"%~dp0NodeTraceIR.exe"
set "NODETRACE_EXIT=%ERRORLEVEL%"
exit /b %NODETRACE_EXIT%
