@echo off
setlocal EnableExtensions

echo [NodeTrace IR] Initializing Windows PE devices and storage...
wpeinit
if errorlevel 1 (
  echo [NodeTrace IR] WARNING: wpeinit returned error %ERRORLEVEL%.
)

call "%SystemRoot%\System32\launch_nodetrace.cmd"
set "NODETRACE_EXIT=%ERRORLEVEL%"
if not "%NODETRACE_EXIT%"=="0" (
  echo [NodeTrace IR] Investigation did not start or ended with error %NODETRACE_EXIT%.
  echo [NodeTrace IR] Review the messages above. The WinPE command prompt remains available.
)

endlocal & exit /b %NODETRACE_EXIT%
