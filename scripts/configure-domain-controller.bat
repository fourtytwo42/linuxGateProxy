@echo off
:: configure-domain-controller.bat
:: Wrapper script that calls the PowerShell schema update script
:: This batch file automatically requests administrator privileges
::
:: IMPORTANT: The logged-in user must be a member of the Schema Admins group.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ================================================================
echo Linux Gate Proxy - Active Directory Schema Configuration
echo ================================================================
echo.
echo IMPORTANT: This script requires:
echo   1. Administrator privileges (this script will request them)
echo   2. Schema Admin group membership for the logged-in user
echo   3. Must be run on the Schema Master Domain Controller
echo.
echo The script will use the credentials of the currently logged-in user.
echo No passwords or additional configuration are required.
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

powershell -ExecutionPolicy Bypass -File "%~dp0configure-domain-controller.ps1"

if %errorLevel% neq 0 (
    echo.
    echo Error: Schema update failed.
    echo.
    echo Please verify:
    echo   - You are logged in as a Schema Admin
    echo   - You are running this on the Schema Master DC
    echo   - You logged off and on after being added to Schema Admins
    echo.
    pause
    exit /b %errorLevel%
)

echo.
echo Configuration complete!
pause
