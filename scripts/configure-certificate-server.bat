@echo off
:: Batch wrapper for configure-certificate-server.ps1
:: This script automatically requests administrator privileges and runs the PowerShell script

setlocal
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    goto :run_script
)

:: Request elevation
echo Requesting administrator privileges...
powershell.exe -Command "Start-Process '%~f0' -Verb RunAs"
exit /b

:run_script
:: Run the PowerShell script with bypass execution policy
set "PS_SCRIPT=%SCRIPT_DIR%configure-certificate-server.ps1"

echo.
echo ========================================
echo  Gate Proxy - Certificate Server Setup
echo ========================================
echo.
echo This script will configure your certificate server for Gate Proxy WebAuthn certificates.
echo.
echo You will need:
echo   - External hostname (e.g., sora2jailbreak.com)
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

if %errorLevel% neq 0 (
    echo.
    echo ERROR: Script execution failed with error code %errorLevel%
    pause
    exit /b %errorLevel%
)

echo.
echo Script completed successfully.
pause
