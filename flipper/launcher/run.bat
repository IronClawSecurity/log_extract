@echo off
REM log_extract Windows launcher — invoked by the BadUSB payload from the
REM Flipper SD root. %~d0 is the drive letter the script is running from,
REM so output lands back on the Flipper SD next to the binary.
setlocal
set DRV=%~d0
echo [log_extract] running from %DRV%
"%DRV%\log_extract.exe" -a -o "%DRV%\output"
set RC=%ERRORLEVEL%
echo [log_extract] exit=%RC% archive in %DRV%\output
REM Pause briefly so the elevated console doesn't disappear before the
REM operator can read the result.
timeout /t 8 >nul
endlocal
exit /b %RC%
