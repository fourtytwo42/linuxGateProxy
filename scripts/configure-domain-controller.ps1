Param(
    [Parameter(Mandatory = $false)]
    [string]$TunnelHostname,

    [Parameter(Mandatory = $false)]
    [string]$GateProxyHost
)

Write-Host "Configuring domain controller for Linux Gate Proxy integration" -ForegroundColor Cyan
Write-Host ""

# Prompt for parameters if not provided
if (-not $TunnelHostname) {
    $TunnelHostname = Read-Host "Enter the tunnel hostname (e.g., tunnel.yourdomain.com)"
}
if (-not $GateProxyHost) {
    $GateProxyHost = Read-Host "Enter the Gate Proxy host IP address (e.g., 192.168.1.100)"
}

Write-Host ""
Import-Module ActiveDirectory

$serviceAccount = "Svc_GateProxy"
$ouPath = "OU=Service Accounts,DC=$(($env:USERDNSDOMAIN -replace '\.', ',DC='))"

if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'" -ErrorAction SilentlyContinue)) {
    Write-Host "Creating service account OU: $ouPath"
    New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=$(($env:USERDNSDOMAIN -replace '\.', ',DC='))" | Out-Null
}

if (-not (Get-ADUser -Identity $serviceAccount -ErrorAction SilentlyContinue)) {
    $password = Read-Host "Enter a strong password for $serviceAccount" -AsSecureString
    New-ADUser -Name $serviceAccount -SamAccountName $serviceAccount -UserPrincipalName "$serviceAccount@$env:USERDNSDOMAIN" -AccountPassword $password -Enabled $true -Path $ouPath -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    Write-Host "Service account $serviceAccount created." -ForegroundColor Green
} else {
    Write-Host "Service account $serviceAccount already exists." -ForegroundColor Yellow
}

Write-Host "Updating firewall rules for gate proxy host $GateProxyHost"
New-NetFirewallRule -DisplayName "Allow GateProxy LDAPS" -Direction Inbound -Protocol TCP -LocalPort 636 -RemoteAddress $GateProxyHost -Action Allow -Profile Domain -ErrorAction SilentlyContinue | Out-Null

Write-Host "Creating Cloudflare tunnel CNAME $TunnelHostname"
Add-DnsServerResourceRecordCName -Name ($TunnelHostname -split '\.')[0] -HostNameAlias "$TunnelHostname" -ZoneName $env:USERDNSDOMAIN -ErrorAction SilentlyContinue | Out-Null

Write-Host "Domain controller configuration complete." -ForegroundColor Green

