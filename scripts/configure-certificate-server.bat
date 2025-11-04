@echo off
:: configure-certificate-server.bat
:: Wrapper script that calls the PowerShell certificate server setup script
:: This batch file automatically requests administrator privileges
::
:: This script sets up Active Directory Certificate Services (AD CS) for domain certificate authority

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ================================================================
echo Linux Gate Proxy - Certificate Server Setup
echo ================================================================
echo.
echo This script will set up Active Directory Certificate Services (AD CS)
echo on this server. This allows issuing trusted certificates to all
echo domain-joined machines automatically.
echo.
echo IMPORTANT: This script requires:
echo   1. Administrator privileges (this script will request them)
echo   2. Must be run on a domain controller or member server
echo.
echo The script will:
echo   - Install AD CS role and required features
echo   - Install RSAT tools if needed
echo   - Configure certificate authority
echo   - Set up firewall rules
echo.
echo No additional parameters are required.
echo The script will guide you through any necessary configuration.
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

powershell -ExecutionPolicy Bypass -File "%~dp0configure-certificate-server.ps1"

if %errorLevel% neq 0 (
    echo.
    echo Error: Certificate server setup failed.
    echo.
    pause
    exit /b %errorLevel%
)

echo.
echo Certificate server setup complete!
pause
