# configure-domain-controller.ps1
# Wrapper script that calls the schema update script to extend Active Directory schema
# Run with Schema Admin privileges on the Schema Master Domain Controller.

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$schemaScript = Join-Path $scriptPath "update-schema-gateproxy.ps1"

if (-not (Test-Path $schemaScript)) {
    Write-Error "Schema update script not found: $schemaScript"
    exit 1
}

Write-Host "Configuring Active Directory schema for Linux Gate Proxy integration" -ForegroundColor Cyan
Write-Host ""
Write-Host "Running schema update script..." -ForegroundColor Cyan
Write-Host ""

& $schemaScript -Action Initialize
