@echo off
REM configure-gateproxy-dc.bat
REM Auto-elevating wrapper for configure-gateproxy-dc.ps1
REM This script configures LDAPS and updates the AD schema for GateProxy

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    goto :run
)

:: Request elevation
echo Requesting administrator privileges...
powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
:: Change to script directory
cd /d "%~dp0"

:: Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0configure-gateproxy-dc.ps1" %*

if %errorLevel% == 0 (
    echo.
    echo Configuration completed successfully!
    pause
) else (
    echo.
    echo Configuration failed with error code: %errorLevel%
    pause
    exit /b %errorLevel%
)

