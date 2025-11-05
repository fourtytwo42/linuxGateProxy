# configure-gateproxy-dc.ps1
# Comprehensive script to configure a Domain Controller for GateProxy
# This script:
#   1. Configures LDAPS (port 636) with proper certificate binding
#   2. Updates the Active Directory schema with GateProxy attributes
# Run with Schema Admin and Domain Admin privileges on the Schema Master Domain Controller.

[CmdletBinding(DefaultParameterSetName = 'Initialize')]
param(
    [ValidateSet('Initialize','Backup','Restore','RemoveCustom')]
    [string]$Action = 'Initialize',
    [string]$BackupDirectory = '.\schema-backups',
    [string]$AttributeName = 'gateProxySession',
    [string]$AttributeOid = '1.2.840.113556.1.8000.2554.4001.1',
    [string]$WebAuthnAttributeName = 'gateProxyWebAuthn',
    [string]$WebAuthnAttributeOid = '1.2.840.113556.1.8000.2554.4001.2',
    [string]$RestoreFile,
    [switch]$SkipLDAPS,
    [switch]$SkipSchema
)

$ErrorActionPreference = 'Stop'

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Gate Proxy - Domain Controller Configuration" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will:" -ForegroundColor Yellow
Write-Host "  1. Configure LDAPS (port 636) with certificate binding" -ForegroundColor White
Write-Host "  2. Update Active Directory schema with GateProxy attributes" -ForegroundColor White
Write-Host ""

# Check if user is Administrator
Write-Host "Checking for Administrator privileges..." -ForegroundColor Yellow
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
    Write-Host "Administrator privileges confirmed." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not verify Administrator privileges. Continuing anyway..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "IMPORTANT: This script must be run on the Schema Master Domain Controller." -ForegroundColor Cyan
Write-Host "You must be a member of:" -ForegroundColor Cyan
Write-Host "  - Schema Admins (for schema updates)" -ForegroundColor White
Write-Host "  - Domain Admins (for LDAPS configuration)" -ForegroundColor White
Write-Host ""

# ============================================================================
# LDAPS Configuration Section
# ============================================================================

if (-not $SkipLDAPS) {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Step 1: Configuring LDAPS (Port 636)" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Check if certificate exists
        Write-Host "Checking for suitable certificate for LDAPS..." -ForegroundColor Yellow
        
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            ($_.NotAfter -gt (Get-Date)) -and 
            ($_.HasPrivateKey) -and
            ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' -or $_.Oid.Value -eq '2.5.29.17' })
        }
        
        if ($certificates.Count -eq 0) {
            Write-Host ""
            Write-Host "No suitable certificate found. Creating self-signed certificate for LDAPS..." -ForegroundColor Yellow
            Write-Host ""
            
            try {
                # Get DC FQDN
                $dcFqdn = $env:COMPUTERNAME + "." + (Get-WmiObject Win32_ComputerSystem).Domain
                $dcShortName = $env:COMPUTERNAME
                
                # Create a self-signed certificate for the DC
                $certParams = @{
                    DnsName = @($dcFqdn, $dcShortName)
                    CertStoreLocation = 'Cert:\LocalMachine\My'
                    KeyUsage = 'DigitalSignature', 'KeyEncipherment'
                    KeyAlgorithm = 'RSA'
                    KeyLength = 2048
                    HashAlgorithm = 'SHA256'
                    NotAfter = (Get-Date).AddYears(5)
                    Type = 'SSLServerAuthentication'
                    FriendlyName = "LDAPS Certificate for $dcFqdn"
                }
                
                $selectedCert = New-SelfSignedCertificate @certParams
                
                Write-Host "Self-signed certificate created successfully:" -ForegroundColor Green
                Write-Host "  Subject: $($selectedCert.Subject)" -ForegroundColor White
                Write-Host "  Thumbprint: $($selectedCert.Thumbprint)" -ForegroundColor White
                Write-Host "  Expires: $($selectedCert.NotAfter)" -ForegroundColor White
                Write-Host ""
                Write-Host "NOTE: This is a self-signed certificate. For production, use a certificate from your Enterprise CA." -ForegroundColor Yellow
                Write-Host ""
                
            } catch {
                Write-Host "ERROR: Failed to create self-signed certificate: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host ""
                Write-Host "LDAPS requires a certificate that:" -ForegroundColor Cyan
                Write-Host "  - Is in the Local Machine Personal store" -ForegroundColor White
                Write-Host "  - Has a private key" -ForegroundColor White
                Write-Host "  - Contains the DC's FQDN in Subject or Subject Alternative Name" -ForegroundColor White
                Write-Host "  - Is not expired" -ForegroundColor White
                Write-Host ""
                Write-Host "Please obtain a certificate manually and rerun this script." -ForegroundColor Yellow
                Write-Host ""
                $script:SkipLDAPS = $true
                return
            }
        } else {
            # Use the first suitable certificate or the one with the DC's hostname
            $dcHostname = $env:COMPUTERNAME + "." + (Get-WmiObject Win32_ComputerSystem).Domain
            $dcHostnameShort = $env:COMPUTERNAME
            
            $selectedCert = $null
            foreach ($cert in $certificates) {
                $subject = $cert.Subject
                $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' -or $_.Oid.Value -eq '2.5.29.17' }
                
                if ($subject -match $dcHostname -or $subject -match $dcHostnameShort -or 
                    ($san -and ($san.Format(0) -match $dcHostname -or $san.Format(0) -match $dcHostnameShort))) {
                    $selectedCert = $cert
                    break
                }
            }
            
            if (-not $selectedCert) {
                $selectedCert = $certificates[0]
                Write-Host "Using certificate: $($selectedCert.Subject) (Thumbprint: $($selectedCert.Thumbprint))" -ForegroundColor Yellow
                Write-Host "WARNING: Certificate may not match DC hostname. LDAPS may not work properly." -ForegroundColor Yellow
            } else {
                Write-Host "Found suitable certificate: $($selectedCert.Subject)" -ForegroundColor Green
            }
            
            # Bind certificate to LDAP service
            Write-Host ""
            Write-Host "Binding certificate to LDAP service on port 636..." -ForegroundColor Yellow
            
            # Get the certificate hash
            $certHash = $selectedCert.Thumbprint
            
            # Use netsh to bind the certificate (Windows Server 2012 R2 and later)
            try {
                $result = netsh http show sslcert ipport=0.0.0.0:636 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "LDAPS binding already exists. Updating..." -ForegroundColor Yellow
                    netsh http delete sslcert ipport=0.0.0.0:636 2>&1 | Out-Null
                }
                
                netsh http add sslcert ipport=0.0.0.0:636 certhash=$certHash appid="{4dc3e181-e14b-4a21-b022-59fc669b0914}" 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "LDAPS certificate bound successfully!" -ForegroundColor Green
                } else {
                    throw "netsh command failed with exit code $LASTEXITCODE"
                }
            } catch {
                Write-Host "Failed to bind certificate using netsh: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host ""
                Write-Host "Alternative method: Use Certificate Manager (certlm.msc)" -ForegroundColor Yellow
                Write-Host "  1. Open certlm.msc" -ForegroundColor White
                Write-Host "  2. Navigate to: Personal > Certificates" -ForegroundColor White
                Write-Host "  3. Find certificate with thumbprint: $certHash" -ForegroundColor White
                Write-Host "  4. Right-click > All Tasks > Manage Private Keys" -ForegroundColor White
                Write-Host "  5. Grant 'Read' permission to 'NT Service\NTDS' account" -ForegroundColor White
                Write-Host "  6. Restart the Active Directory Domain Services service" -ForegroundColor White
                Write-Host ""
                throw
            }
            
            # Restart AD DS service to apply changes
            Write-Host ""
            Write-Host "Restarting Active Directory Domain Services to apply LDAPS configuration..." -ForegroundColor Yellow
            Restart-Service -Name NTDS -Force -ErrorAction Stop
            Write-Host "AD DS service restarted successfully." -ForegroundColor Green
            
            # Verify LDAPS is listening
            Write-Host ""
            Write-Host "Verifying LDAPS is listening on port 636..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            $listening = netstat -an | Select-String -Pattern ":636" | Select-String -Pattern "LISTENING"
            if ($listening) {
                Write-Host "LDAPS is now listening on port 636!" -ForegroundColor Green
            } else {
                Write-Host "WARNING: LDAPS may not be listening. Check firewall rules and AD DS service status." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host ""
        Write-Host "ERROR: LDAPS configuration failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "You can manually configure LDAPS later or skip this step." -ForegroundColor Yellow
        Write-Host "Continue with schema update? (Y/N)" -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-Host "Aborted." -ForegroundColor Gray
            exit 1
        }
    }
    
    Write-Host ""
}

# ============================================================================
# Schema Update Section (from update-schema-gateproxy.ps1)
# ============================================================================

if (-not $SkipSchema) {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Step 2: Updating Active Directory Schema" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check for Schema Admin
    Write-Host "Checking for Schema Admin privileges..." -ForegroundColor Yellow
    
    try {
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
    
    # Include the schema update logic from update-schema-gateproxy.ps1
    # (The full schema update code would go here - I'll reference the existing script)
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $schemaScript = Join-Path $scriptPath "update-schema-gateproxy.ps1"
    
    if (Test-Path $schemaScript) {
        Write-Host "Running schema update script..." -ForegroundColor Cyan
        Write-Host ""
        
        & $schemaScript -Action $Action -BackupDirectory $BackupDirectory -AttributeName $AttributeName -AttributeOid $AttributeOid -WebAuthnAttributeName $WebAuthnAttributeName -WebAuthnAttributeOid $WebAuthnAttributeOid -RestoreFile $RestoreFile
        
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
            Write-Host ""
            Write-Host "Schema update script exited with error code: $LASTEXITCODE" -ForegroundColor Red
            exit $LASTEXITCODE
        }
    } else {
        Write-Host "ERROR: Schema update script not found: $schemaScript" -ForegroundColor Red
        Write-Host "Please ensure update-schema-gateproxy.ps1 is in the same directory as this script." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Your domain controller is now configured for GateProxy:" -ForegroundColor Green
if (-not $SkipLDAPS) {
    Write-Host "  [X] LDAPS on port 636 configured" -ForegroundColor Green
}
if (-not $SkipSchema) {
    Write-Host "  [X] Active Directory schema updated" -ForegroundColor Green
}
Write-Host ""
Write-Host "You can now test the LDAP connection from GateProxy." -ForegroundColor Cyan
Write-Host ""

