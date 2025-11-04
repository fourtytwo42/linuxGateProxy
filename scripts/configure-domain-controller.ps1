# configure-domain-controller.ps1
# Wrapper script that calls the schema update script to extend Active Directory schema
# Run with Schema Admin privileges on the Schema Master Domain Controller.
#
# IMPORTANT: This script must be run by a user who is a member of the Schema Admins group.
# The script will use the credentials of the currently logged-in user.

param(
    [string]$Action = 'Initialize'
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Linux Gate Proxy - Active Directory Schema Configuration" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if user is Schema Admin
Write-Host "Checking for Schema Admin privileges..." -ForegroundColor Yellow

try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
        Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
    
    # Check for Schema Admins group membership
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
    
    $schemaAdminsSid = (New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::AccountSchemaAdminsSid, $null)).Value
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUserGroups = $currentUser.Groups | Where-Object { $_.Value -eq $schemaAdminsSid }
    
    if ($currentUserGroups.Count -eq 0) {
        Write-Host ""
        Write-Host "WARNING: The current user may not be a member of Schema Admins group." -ForegroundColor Red
        Write-Host ""
        Write-Host "This script REQUIRES Schema Admin privileges to modify the Active Directory schema." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To add yourself to Schema Admins:" -ForegroundColor Cyan
        Write-Host "  1. Open Active Directory Users and Computers" -ForegroundColor White
        Write-Host "  2. Navigate to the 'Builtin' container" -ForegroundColor White
        Write-Host "  3. Find 'Schema Admins' group" -ForegroundColor White
        Write-Host "  4. Add your user account to this group" -ForegroundColor White
        Write-Host "  5. Log off and log back on" -ForegroundColor White
        Write-Host "  6. Run this script again" -ForegroundColor White
        Write-Host ""
        Write-Host "Are you sure you want to continue? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-Host "Aborted." -ForegroundColor Gray
            exit 0
        }
    } else {
        Write-Host "Schema Admin privileges confirmed." -ForegroundColor Green
    }
} catch {
    Write-Host ""
    Write-Host "WARNING: Could not verify Schema Admin membership. Continuing anyway..." -ForegroundColor Yellow
    Write-Host "If schema update fails, ensure you are a Schema Admin and have logged off/on after adding yourself to the group." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "IMPORTANT: This script must be run on the Schema Master Domain Controller." -ForegroundColor Cyan
Write-Host "The script will use the credentials of the currently logged-in user." -ForegroundColor Cyan
Write-Host "No additional passwords or configuration are required." -ForegroundColor Cyan
Write-Host ""

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$schemaScript = Join-Path $scriptPath "update-schema-gateproxy.ps1"

if (-not (Test-Path $schemaScript)) {
    Write-Error "Schema update script not found: $schemaScript"
    Write-Host "Please ensure update-schema-gateproxy.ps1 is in the same directory as this script." -ForegroundColor Red
    exit 1
}

Write-Host "Running schema update script..." -ForegroundColor Cyan
Write-Host ""

& $schemaScript -Action $Action

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Schema update script exited with error code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Schema configuration complete!" -ForegroundColor Green

