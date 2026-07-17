@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "NODETRACE_HOME=%ProgramFiles%\NodeTraceIR"
set "NODETRACE_EXE=%NODETRACE_HOME%\NodeTraceIR.exe"
set "OFFLINE_DRIVE="
set "OFFLINE_ROOT="
set "EVIDENCE_ROOT="

if not exist "%NODETRACE_EXE%" (
  echo [NodeTrace IR] ERROR: WinPE payload is missing: %NODETRACE_EXE%
  exit /b 10
)

rem An explicit root is optional; normal boot is fully automatic.
if defined NODETRACE_OFFLINE_ROOT (
  for %%R in ("!NODETRACE_OFFLINE_ROOT!") do set "OFFLINE_DRIVE=%%~dR"
  if defined OFFLINE_DRIVE if exist "!OFFLINE_DRIVE!\Windows\System32\Config\SYSTEM" if exist "!OFFLINE_DRIVE!\Windows\System32\Config\SOFTWARE" (
    set "OFFLINE_ROOT=!OFFLINE_DRIVE!\"
  )
)

rem Locate the first mounted Windows installation by its registry hives.
if not defined OFFLINE_ROOT for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined OFFLINE_ROOT if exist "%%D:\Windows\System32\Config\SYSTEM" if exist "%%D:\Windows\System32\Config\SOFTWARE" (
    set "OFFLINE_DRIVE=%%D:"
    set "OFFLINE_ROOT=%%D:\"
  )
)

if not defined OFFLINE_ROOT (
  echo [NodeTrace IR] ERROR: No offline Windows installation was detected.
  echo [NodeTrace IR] Unlock BitLocker volumes if required, then run launch_nodetrace.cmd again.
  exit /b 20
)
echo [NodeTrace IR] Offline Windows: !OFFLINE_ROOT!

rem A caller may nominate a drive, but it still has to pass all safety checks.
if defined NODETRACE_EVIDENCE_DRIVE call :TryEvidenceDrive "!NODETRACE_EVIDENCE_DRIVE!"

rem Prefer a removable/data volume explicitly marked by the analyst.
if not defined EVIDENCE_ROOT for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined EVIDENCE_ROOT if exist "%%D:\NODETRACE_EVIDENCE_VOLUME" call :TryEvidenceDrive "%%D:"
)

rem Otherwise use the first writable volume that is neither X: nor any Windows installation.
if not defined EVIDENCE_ROOT for %%D in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if not defined EVIDENCE_ROOT call :TryEvidenceDrive "%%D:"
)

if not defined EVIDENCE_ROOT (
  echo [NodeTrace IR] ERROR: No separate writable evidence volume is available.
  echo [NodeTrace IR] Attach a writable USB/data volume. Optionally create NODETRACE_EVIDENCE_VOLUME in its root.
  echo [NodeTrace IR] Evidence is never stored only on volatile X: or on the investigated Windows volume.
  exit /b 21
)

set "SESSION_ID=session-!RANDOM!-!RANDOM!"
set "DATA_DIR=!EVIDENCE_ROOT!\!SESSION_ID!"
2>nul md "!DATA_DIR!"
if not exist "!DATA_DIR!" (
  echo [NodeTrace IR] ERROR: Cannot create evidence session directory: !DATA_DIR!
  exit /b 22
)

set "NODETRACE_IR_DATA_DIR=!DATA_DIR!"
set "NODETRACE_AVZ_DISTRIBUTION=noncommercial-consent"
set "NODETRACE_AVZ_MANIFEST=%NODETRACE_HOME%\AVZ\AVZ_MANIFEST.json"
set "NODETRACE_AVZ_ARCHIVE=%NODETRACE_HOME%\AVZ\Archives\avz4.zip"
set "NODETRACE_AVZ_BASE_ARCHIVE=%NODETRACE_HOME%\AVZ\Archives\avzbase.zip"
set "WINPE_ARCHITECTURE=unknown"
if exist "%NODETRACE_HOME%\winpe-architecture.txt" set /p WINPE_ARCHITECTURE=<"%NODETRACE_HOME%\winpe-architecture.txt"

if /I "!WINPE_ARCHITECTURE!"=="x86" (
  if exist "%NODETRACE_HOME%\AVZ\avz.exe" (
    set "NODETRACE_AVZ_EXE=%NODETRACE_HOME%\AVZ\avz.exe"
    set "AVZ_STATUS=enabled"
  ) else (
    set "NODETRACE_AVZ_EXE="
    set "AVZ_STATUS=missing"
  )
) else (
  rem AVZ is x86. amd64 WinPE does not provide WOW64 for 32-bit applications.
  set "NODETRACE_AVZ_EXE="
  set "NODETRACE_AVZ_UNAVAILABLE_REASON=AVZ requires x86 WinPE; amd64 WinPE has no WOW64."
  set "AVZ_STATUS=disabled-no-wow64"
  echo [NodeTrace IR] WARNING: AVZ cannot execute in !WINPE_ARCHITECTURE! WinPE. Use the x86 ISO for AVZ analysis.
)

> "!DATA_DIR!\winpe-session.txt" (
  echo offline_root=!OFFLINE_ROOT!
  echo evidence_root=!EVIDENCE_ROOT!
  echo data_dir=!DATA_DIR!
  echo winpe_architecture=!WINPE_ARCHITECTURE!
  echo avz_status=!AVZ_STATUS!
)

echo [NodeTrace IR] Evidence destination: !DATA_DIR!
echo [NodeTrace IR] Starting automatic offline investigation...
"%NODETRACE_EXE%" --winpe --offline-root "!OFFLINE_DRIVE!\." --data-dir "!DATA_DIR!"
set "APP_EXIT=!ERRORLEVEL!"
echo [NodeTrace IR] NodeTrace IR exited with code !APP_EXIT!.
endlocal & exit /b %APP_EXIT%

:TryEvidenceDrive
if defined EVIDENCE_ROOT exit /b 0
set "CANDIDATE_DRIVE=%~d1"
if not defined CANDIDATE_DRIVE exit /b 0
if /I "!CANDIDATE_DRIVE!"=="X:" exit /b 0
if /I "!CANDIDATE_DRIVE!"=="!OFFLINE_DRIVE!" exit /b 0
if not exist "!CANDIDATE_DRIVE!\" exit /b 0
rem Never use a second Windows installation as evidence storage either.
if exist "!CANDIDATE_DRIVE!\Windows\System32\Config\SYSTEM" exit /b 0

set "CANDIDATE_ROOT=!CANDIDATE_DRIVE!\NodeTraceIR-Evidence"
2>nul md "!CANDIDATE_ROOT!"
if not exist "!CANDIDATE_ROOT!" exit /b 0
set "WRITE_TEST=!CANDIDATE_ROOT!\.write-test-!RANDOM!-!RANDOM!.tmp"
> "!WRITE_TEST!" echo NodeTrace IR WinPE write test
if not exist "!WRITE_TEST!" exit /b 0
del /f /q "!WRITE_TEST!" >nul 2>&1
if exist "!WRITE_TEST!" exit /b 0
set "EVIDENCE_ROOT=!CANDIDATE_ROOT!"
exit /b 0
