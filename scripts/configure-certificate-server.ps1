# Setup Active Directory Certificate Services (AD CS) for Domain Certificate Authority
# This script helps set up AD CS on a domain controller or member server
# Run as Domain Administrator

param(
    [string]$CACommonName = "",
    [string]$CAValidityPeriod = "Years",
    [int]$CAValidityPeriodUnits = 10,
    [switch]$InstallOnDC = $false,
    [string]$ServerName = $env:COMPUTERNAME
)

# Function to configure Windows Firewall for Certificate Authority
function Configure-CAFirewall {
    Write-Host "Configuring Windows Firewall rules for Certificate Authority..." -ForegroundColor Cyan
    
    try {
        $firewallProfile = "Domain"
        
        # RPC Endpoint Mapper (port 135) - required for CA enrollment
        Write-Host "  Adding RPC Endpoint Mapper rule (TCP 135)..." -ForegroundColor Gray
        try {
            $existing = Get-NetFirewallRule -DisplayName "CA - RPC Endpoint Mapper" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "    Rule already exists, updating..." -ForegroundColor DarkGray
                Enable-NetFirewallRule -DisplayName "CA - RPC Endpoint Mapper" -ErrorAction SilentlyContinue
            } else {
                New-NetFirewallRule -DisplayName "CA - RPC Endpoint Mapper" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 135 `
                    -Action Allow `
                    -Profile $firewallProfile `
                    -Description "Allows RPC Endpoint Mapper for Certificate Authority enrollment" `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Rule added successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "    Failed to add RPC Endpoint Mapper rule: $($_.Exception.Message)"
        }
        
        # RPC Dynamic Ports (49152-65535) - required for RPC communication
        Write-Host "  Adding RPC Dynamic Ports rule (TCP 49152-65535)..." -ForegroundColor Gray
        try {
            $existing = Get-NetFirewallRule -DisplayName "CA - RPC Dynamic Ports" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "    Rule already exists, updating..." -ForegroundColor DarkGray
                Enable-NetFirewallRule -DisplayName "CA - RPC Dynamic Ports" -ErrorAction SilentlyContinue
            } else {
                New-NetFirewallRule -DisplayName "CA - RPC Dynamic Ports" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 49152-65535 `
                    -Action Allow `
                    -Profile $firewallProfile `
                    -Description "Allows RPC dynamic ports for Certificate Authority enrollment" `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Rule added successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "    Failed to add RPC Dynamic Ports rule: $($_.Exception.Message)"
        }
        
        # Certificate Services (port 445 - SMB, if using file-based CA)
        # Note: This is optional but helpful for certificate enrollment
        Write-Host "  Adding Certificate Services SMB rule (TCP 445)..." -ForegroundColor Gray
        try {
            $existing = Get-NetFirewallRule -DisplayName "CA - SMB" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "    Rule already exists, updating..." -ForegroundColor DarkGray
                Enable-NetFirewallRule -DisplayName "CA - SMB" -ErrorAction SilentlyContinue
            } else {
                New-NetFirewallRule -DisplayName "CA - SMB" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 445 `
                    -Action Allow `
                    -Profile $firewallProfile `
                    -Description "Allows SMB for Certificate Authority (if needed)" `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Rule added successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "    Failed to add SMB rule: $($_.Exception.Message)"
        }
        
        # LDAP (port 389) - for AD integration
        Write-Host "  Adding LDAP rule (TCP 389)..." -ForegroundColor Gray
        try {
            $existing = Get-NetFirewallRule -DisplayName "CA - LDAP" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "    Rule already exists, updating..." -ForegroundColor DarkGray
                Enable-NetFirewallRule -DisplayName "CA - LDAP" -ErrorAction SilentlyContinue
            } else {
                New-NetFirewallRule -DisplayName "CA - LDAP" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 389 `
                    -Action Allow `
                    -Profile $firewallProfile `
                    -Description "Allows LDAP for Certificate Authority AD integration" `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Rule added successfully" -ForegroundColor Green
            }
        } catch {
            Write-Warning "    Failed to add LDAP rule: $($_.Exception.Message)"
        }
        
        Write-Host "Firewall configuration complete." -ForegroundColor Green
        
    } catch {
        Write-Warning "Firewall configuration encountered errors: $($_.Exception.Message)"
        Write-Host "You may need to manually configure firewall rules for:" -ForegroundColor Yellow
        Write-Host "  - RPC Endpoint Mapper (TCP 135)" -ForegroundColor White
        Write-Host "  - RPC Dynamic Ports (TCP 49152-65535)" -ForegroundColor White
        Write-Host "  - LDAP (TCP 389)" -ForegroundColor White
    }
}

Write-Host "=== Active Directory Certificate Services Setup ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will guide you through installing AD CS (Certificate Authority)" -ForegroundColor Yellow
Write-Host "on your domain. This will allow you to issue trusted certificates to all" -ForegroundColor Yellow
Write-Host "domain-joined machines automatically." -ForegroundColor Yellow
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Check if AD CS is already installed
$caService = Get-WindowsFeature -Name AD-Certificate | Where-Object { $_.InstallState -eq 'Installed' }
$caConfigured = $false

if ($caService) {
    # Check if CA is actually configured (not just installed)
    try {
        $caRegistry = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction SilentlyContinue
        if ($caRegistry) {
            $caConfigured = $true
        }
    } catch {
        $caConfigured = $false
    }
    
    if ($caConfigured) {
        Write-Host "AD CS is already installed and configured on this server." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "This script will:" -ForegroundColor Cyan
        Write-Host "  1. Verify CA is operational" -ForegroundColor White
        Write-Host "  2. Configure firewall rules for remote CA access" -ForegroundColor White
        Write-Host "  3. Ensure CA service is running" -ForegroundColor White
        Write-Host ""
        $continue = Read-Host "Continue with verification and configuration? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            exit 0
        }
        
        # Run verification and configuration
        Write-Host ""
        Write-Host "Step 1: Verifying CA Status..." -ForegroundColor Cyan
        
        try {
            $caServiceStatus = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
            if ($caServiceStatus) {
                if ($caServiceStatus.Status -eq 'Running') {
                    Write-Host "Certificate Authority service is running." -ForegroundColor Green
                } else {
                    Write-Host "Starting Certificate Authority service..." -ForegroundColor Yellow
                    Start-Service -Name CertSvc -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                    if ((Get-Service -Name CertSvc).Status -eq 'Running') {
                        Write-Host "CA service started successfully." -ForegroundColor Green
                    } else {
                        Write-Warning "CA service failed to start. Check event logs."
                    }
                }
            } else {
                Write-Warning "Certificate Authority service not found."
            }
        } catch {
            Write-Warning "Could not verify CA service: $($_.Exception.Message)"
        }
        
        Write-Host ""
        Write-Host "Step 2: Configuring Firewall for CA Access..." -ForegroundColor Cyan
        
        Configure-CAFirewall
        
        Write-Host ""
        Write-Host "=== CA Verification and Configuration Complete ===" -ForegroundColor Green
        Write-Host ""
        Write-Host "The CA server is ready to accept certificate requests." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "1. Verify firewall rules are active: Get-NetFirewallRule -DisplayName 'CA - *'" -ForegroundColor White
        Write-Host "2. Test from a remote server: certutil -ping $env:COMPUTERNAME" -ForegroundColor White
        Write-Host "3. Request certificates using request_gateway_cert.bat on gateway servers" -ForegroundColor White
        Write-Host ""
        
        # Still show certificate request instructions
        $showInstructions = $true
    } else {
        $showInstructions = $false
        Write-Host "AD CS features are installed but CA is not configured yet." -ForegroundColor Yellow
        Write-Host "This may happen if a previous installation attempt was interrupted." -ForegroundColor Gray
        Write-Host ""
        $continue = Read-Host "Do you want to configure the CA now? (Y/N)"
        if ($continue -eq 'Y' -or $continue -eq 'y') {
            # Set flag to continue with configuration
            $caConfigured = $false
        } else {
            Write-Host "Skipping CA configuration. You can run this script again later to complete setup." -ForegroundColor Yellow
            exit 0
        }
    }
}

# If CA is not configured, proceed with installation/configuration
if (-not $caConfigured) {
    # Check if Web Enrollment was installed (for later configuration step)
    $webEnrollmentInstalled = (Get-WindowsFeature -Name ADCS-Web-Enrollment | Where-Object { $_.InstallState -eq 'Installed' })
    
    # If features are already installed, skip installation step
    $featuresInstalled = $caService -ne $null
    
    if (-not $featuresInstalled) {
        Write-Host "Step 1: Installing Active Directory Certificate Services..." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Components that will be installed:" -ForegroundColor Gray
        Write-Host "  - Certification Authority (CA)" -ForegroundColor White
        Write-Host "  - Certification Authority Web Enrollment (optional, for web enrollment)" -ForegroundColor White
        Write-Host "  - Network Device Enrollment Service (optional, for network devices)" -ForegroundColor White
        Write-Host ""
        
        $installWeb = Read-Host "Install Web Enrollment? This allows requesting certs via web browser (Y/N)"
        $installWebEnrollment = $installWeb -eq 'Y' -or $installWeb -eq 'y'
        
        Write-Host ""
        Write-Host "Installing Windows Features..." -ForegroundColor Cyan
        
        try {
            # Install AD CS feature
            $featuresToInstall = @('ADCS-Cert-Authority')
            
            if ($installWebEnrollment) {
                $featuresToInstall += 'ADCS-Web-Enrollment'
                $featuresToInstall += 'RSAT-ADCS'
            }
            
            Install-WindowsFeature -Name $featuresToInstall -IncludeManagementTools
            
            Write-Host "Features installed successfully." -ForegroundColor Green
            Write-Host ""
            $webEnrollmentInstalled = $installWebEnrollment
        } catch {
            Write-Error "Failed to install Windows features: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Host "Step 1: AD CS features are already installed." -ForegroundColor Green
        if ($webEnrollmentInstalled) {
            Write-Host "Web Enrollment is also installed." -ForegroundColor Green
        }
        Write-Host ""
    }
    
    try {
        # Prompt for CA Common Name if not provided
        if ([string]::IsNullOrWhiteSpace($CACommonName)) {
            $domainInfo = Get-WmiObject Win32_ComputerSystem
            if ($domainInfo.PartOfDomain) {
                $domainNetbios = ($domainInfo.Domain -split '\.')[0]
                $defaultCAName = "$domainNetbios-CA"
            } else {
                $defaultCAName = "Enterprise-CA"
            }
            Write-Host "Step 2: Configuring Certification Authority..." -ForegroundColor Cyan
            Write-Host ""
            $CACommonName = Read-Host "Enter CA Common Name (or press Enter for '$defaultCAName')"
            if ([string]::IsNullOrWhiteSpace($CACommonName)) {
                $CACommonName = $defaultCAName
            }
        } else {
            Write-Host "Step 2: Configuring Certification Authority..." -ForegroundColor Cyan
            Write-Host ""
        }
        
        Write-Host "CA Configuration:" -ForegroundColor Yellow
        Write-Host "  Common Name: $CACommonName" -ForegroundColor White
        Write-Host "  Validity Period: $CAValidityPeriodUnits $CAValidityPeriod" -ForegroundColor White
        Write-Host ""
        
        $confirm = Read-Host "Proceed with CA configuration? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "CA configuration cancelled." -ForegroundColor Yellow
            exit 0
        }
        
        # Configure CA
        Write-Host "Configuring CA..." -ForegroundColor Cyan
        
        # Determine CA Type
        $caType = "EnterpriseRootCA"  # Enterprise CA for domain integration
        
        $configParams = @{
            CACommonName = $CACommonName
            CAType = $caType
            ValidityPeriod = $CAValidityPeriod
            ValidityPeriodUnits = $CAValidityPeriodUnits
            CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
            HashAlgorithmName = "SHA256"
            KeyLength = 2048
            Force = $true
        }
        
        try {
            Install-AdcsCertificationAuthority @configParams -WarningAction SilentlyContinue
            $caConfigured = $true
        } catch {
            # Check if CA is already configured (common error if partially configured)
            if ($_.Exception.Message -like "*already configured*" -or $_.Exception.Message -like "*already exists*") {
                Write-Host "CA appears to already be configured (or partially configured)." -ForegroundColor Yellow
                Write-Host "Attempting to verify configuration..." -ForegroundColor Gray
                
                # Try to verify CA is actually working
                try {
                    $testCa = Get-CertificationAuthority -ErrorAction SilentlyContinue
                    if ($testCa) {
                        Write-Host "CA is configured and operational." -ForegroundColor Green
                        $caConfigured = $true
                    } else {
                        throw "CA registry found but CA object not accessible"
                    }
                } catch {
                    Write-Warning "CA configuration status is unclear. You may need to check certsrv.msc manually."
                    $caConfigured = $false
                }
            } else {
                throw
            }
        }
        
        # If Web Enrollment was installed, configure it separately
        if ($webEnrollmentInstalled -and $caConfigured) {
            Write-Host ""
            Write-Host "Configuring Web Enrollment..." -ForegroundColor Cyan
            try {
                Install-AdcsWebEnrollment -Force -WarningAction SilentlyContinue
                Write-Host "Web Enrollment configured successfully." -ForegroundColor Green
            } catch {
                if ($_.Exception.Message -like "*already configured*") {
                    Write-Host "Web Enrollment is already configured." -ForegroundColor Green
                } else {
                    Write-Warning "Web Enrollment configuration had issues: $($_.Exception.Message)"
                    Write-Host "You can configure Web Enrollment later via Server Manager or certsrv.msc" -ForegroundColor Yellow
                }
            }
        }
        
        if ($caConfigured) {
            Write-Host "CA configured successfully!" -ForegroundColor Green
            Write-Host ""
            
            Write-Host "Step 3: Verifying CA Status..." -ForegroundColor Cyan
            
            # Verify CA is running
            try {
                $caServiceStatus = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
                if ($caServiceStatus -and $caServiceStatus.Status -eq 'Running') {
                    Write-Host "Certificate Authority service is running." -ForegroundColor Green
                } else {
                    Write-Host "Starting Certificate Authority service..." -ForegroundColor Yellow
                    Start-Service -Name CertSvc -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                }
            } catch {
                Write-Warning "Could not verify CA service status"
            }
            
            Write-Host ""
            Write-Host "Step 4: Configuring Firewall for CA Access..." -ForegroundColor Cyan
            
            # Configure Windows Firewall for CA
            Configure-CAFirewall
            
            Write-Host ""
            Write-Host "=== CA Installation and Configuration Complete ===" -ForegroundColor Green
            Write-Host ""
            Write-Host "Next steps:" -ForegroundColor Cyan
            Write-Host "1. Open Certificate Authority console (certsrv.msc) to verify CA is operational" -ForegroundColor White
            Write-Host "2. Check that the CA can issue certificates (test with a simple certificate request)" -ForegroundColor White
            Write-Host "3. Configure certificate templates if needed (certtmpl.msc)" -ForegroundColor White
            Write-Host "4. Request certificate for your gateway server using request_gateway_cert.bat" -ForegroundColor White
            Write-Host ""
        }
    } catch {
        Write-Error "Failed to install/configure AD CS: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "If the error indicates the CA is already configured, you can:" -ForegroundColor Yellow
        Write-Host "  - Continue with certificate request using request_gateway_cert.bat" -ForegroundColor Gray
        Write-Host "  - Or open certsrv.msc to verify the CA status" -ForegroundColor Gray
        exit 1
    }
}

# Only show certificate request instructions if CA is configured
if ($caConfigured -or $showInstructions) {

    # Instructions for requesting certificate
    Write-Host "=== Certificate Request for Gateway Server ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "CA is configured and ready. To request a certificate for your gateway server:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Quick method (automated):" -ForegroundColor White
    Write-Host "  Run: request_gateway_cert.bat" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Manual methods:" -ForegroundColor White
    Write-Host "  Option 1: Using certreq.exe" -ForegroundColor Gray
    Write-Host "    1. Create a certificate request file (INF)" -ForegroundColor DarkGray
    Write-Host "    2. Run: certreq -new request.inf request.req" -ForegroundColor DarkGray
    Write-Host "    3. Submit request to CA: certreq -submit request.req cert.cer" -ForegroundColor DarkGray
    Write-Host "    4. Install certificate: certreq -accept cert.cer" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Option 2: Using MMC Certificate snap-in" -ForegroundColor Gray
    Write-Host "    1. Open certmgr.msc" -ForegroundColor DarkGray
    Write-Host "    2. Right-click Personal -> All Tasks -> Request New Certificate" -ForegroundColor DarkGray
    Write-Host "    3. Select 'Web Server' template" -ForegroundColor DarkGray
    Write-Host "    4. Add DNS names for your gateway server" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Option 3: Using Web Enrollment (if installed)" -ForegroundColor Gray
    Write-Host "    Visit: http://$ServerName/certsrv" -ForegroundColor DarkGray
    Write-Host ""
}

# Save CA info
try {
    $caInfo = @{
        CACommonName = $CACommonName
        ServerName = $ServerName
        InstallDate = Get-Date
        Configured = $caConfigured
    }
    
    $caInfoFile = Join-Path $PSScriptRoot "ca_info.json"
    $caInfo | ConvertTo-Json | Out-File -FilePath $caInfoFile -Encoding UTF8
    Write-Host "CA information saved to: $caInfoFile" -ForegroundColor Green
} catch {
    Write-Warning "Could not save CA info file"
}

