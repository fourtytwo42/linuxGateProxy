# update_schema_gateproxy.ps1
# Extends Active Directory schema with a custom attribute used by GateProxy for centralized session token storage.
# Run with Schema Admin privileges on a domain controller.

[CmdletBinding(DefaultParameterSetName = 'Initialize')]
param(
    [ValidateSet('Initialize','Backup','Restore','RemoveCustom')]
    [string]$Action = 'Initialize',
    [string]$BackupDirectory = '.\schema-backups',
    [string]$AttributeName = 'gateProxySession',
    [string]$AttributeOid = '1.2.840.113556.1.8000.2554.4001.1',
    [string]$WebAuthnAttributeName = 'gateProxyWebAuthn',
    [string]$WebAuthnAttributeOid = '1.2.840.113556.1.8000.2554.4001.2',
    [string]$RestoreFile
)

function Ensure-Module {
    param([string]$Name)

    try {
        Import-Module $Name -ErrorAction Stop | Out-Null
        return
    } catch {
        Write-Warning "PowerShell module '$Name' not found. Attempting to install required RSAT components..."
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $isServer = $os.ProductType -ne 1

        if ($isServer) {
            try {
                Import-Module ServerManager -ErrorAction Stop | Out-Null
                $feature = Get-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop
                if ($feature.Installed -eq $false) {
                    Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop | Out-Null
                }
            } catch {
                throw "Failed to install RSAT-AD-PowerShell: $($_.Exception.Message)"
            }
        } else {
            try {
                $capability = Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop
                if ($capability.State -ne 'Installed') {
                    Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop | Out-Null
                }
            } catch {
                throw "Failed to install RSAT DS-LDS tools: $($_.Exception.Message)"
            }
        }

        Import-Module $Name -ErrorAction Stop | Out-Null
    } catch {
        throw "Module '$Name' is required and automatic installation failed: $($_.Exception.Message)"
    }
}

function Get-LdifdePath {
    $candidates = @(
        (Join-Path $env:SystemRoot 'System32\ldifde.exe'),
        (Join-Path $env:SystemRoot 'SysWOW64\ldifde.exe'),
        'ldifde.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
        try {
            $cmd = Get-Command $candidate -ErrorAction Stop
            if ($cmd) { return $cmd.Source }
        } catch { }
    }
    return $null
}

function Resolve-LdifdePath {
    $path = Get-LdifdePath
    if ($path) { return $path }

    Write-Warning "ldifde.exe not found. Installing AD DS command-line tools..."
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $isServer = $os.ProductType -ne 1

    if ($isServer) {
        try {
            Import-Module ServerManager -ErrorAction Stop | Out-Null
            $feature = Get-WindowsFeature -Name RSAT-ADDS-Tools -ErrorAction Stop
            if ($feature.Installed -eq $false) {
                Install-WindowsFeature -Name RSAT-ADDS-Tools -IncludeManagementTools -ErrorAction Stop | Out-Null
            }
        } catch {
            throw "Failed to install RSAT-ADDS-Tools: $($_.Exception.Message)"
        }
    } else {
        try {
            $capability = Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop
            if ($capability.State -ne 'Installed') {
                Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop | Out-Null
            }
        } catch {
            throw "Failed to install ldifde capability: $($_.Exception.Message)"
        }
    }

    $path = Get-LdifdePath
    if ($path) { return $path }
    throw 'Unable to locate ldifde.exe after attempting installation. Install Active Directory Domain Services tools manually.'
}

function Invoke-Ldifde {
    param(
        [string[]]$Arguments
    )

    $exe = Resolve-LdifdePath
    $mergedArgs = @()
    if ($script:SchemaMasterServer -and -not ($Arguments -contains '-s')) {
        $mergedArgs += @('-s', $script:SchemaMasterServer)
    }
    $mergedArgs += $Arguments

    $process = Start-Process -FilePath $exe -ArgumentList $mergedArgs -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        if ($process.ExitCode -eq 5) {
            $guidance = @"
ldifde reported 'Access is denied' (exit code 5).

Schema changes can only be applied when:
  • You are signed in with an account that is a member of Schema Admins (log off/on after adding yourself).
  • You run the script on the domain controller that holds the Schema Master FSMO role (`Get-ADForest | Select-Object SchemaMaster`).
  • Schema updates are enabled on that DC: `reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "Schema Update Allowed" /t REG_DWORD /d 1 /f` (set back to 0 afterwards).

After completing the steps above, rerun `update_schema_gateproxy.ps1 -Action Initialize`.
"@
            throw $guidance
        }
        
        # Exit code 8202 is "No Such Attribute" - often means schema hasn't replicated yet
        if ($process.ExitCode -eq 8202) {
            Write-Warning "LDIF import returned 'No Such Attribute' (exit code 8202). This may indicate schema replication is needed."
            Write-Warning "The attribute may need time to replicate before it can be added to the user class."
            Write-Warning "You may need to wait a few minutes and retry, or the attribute may already be correctly configured."
        }
        
        throw "ldifde exited with code $($process.ExitCode). Arguments: $($mergedArgs -join ' ')"
    }
}

function Ensure-Directory {
    param([string]$Path)
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Export-GateProxySchema {
    param(
        [string]$OutputPath,
        [string]$SchemaNc,
        [string[]]$AttributeNames
    )

    $filterParts = @("(cn=User)")
    foreach ($name in $AttributeNames) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $filterParts += "(lDAPDisplayName=$name)"
        }
    }
    $filter = "(|$($filterParts -join ''))"
    # Quote the output path to handle spaces and special characters like (1)
    $quotedPath = "`"$OutputPath`""
    Invoke-Ldifde -Arguments @('-f', $quotedPath, '-d', $SchemaNc, '-p', 'subtree', '-r', $filter, '-l', '*', '-o', 'whenChanged,whenCreated')
}

function Test-AttributeExists {
    param(
        [string]$SchemaNc,
        [string]$AttributeName
    )

    try {
        $obj = Get-ADObject -SearchBase $SchemaNc -LDAPFilter "(lDAPDisplayName=$AttributeName)" -ErrorAction Stop
        return $null -ne $obj
    } catch {
        return $false
    }
}

function New-TempLdif {
    param([string]$Content)
    $temp = New-TemporaryFile
    Set-Content -Path $temp -Value $Content -Encoding Unicode
    # Return quoted path to handle spaces and special characters
    return "`"$($temp.FullName)`""
}

function Get-UserClassObject {
    param(
        [string]$UserClassDn
    )

    try {
        return Get-ADObject -Identity $UserClassDn -Properties mayContain,systemMayContain -ErrorAction Stop
    } catch {
        throw "Unable to load user class schema object at ${UserClassDn}: $($_.Exception.Message)"
    }
}

function Ensure-UserClassMayContain {
    param(
        [string]$UserClassDn,
        [string]$AttributeName
    )

    $userClass = Get-UserClassObject -UserClassDn $UserClassDn
    $current = @()
    if ($userClass.mayContain) { $current += $userClass.mayContain }
    if ($userClass.systemMayContain) { $current += $userClass.systemMayContain }

    if ($current -contains $AttributeName) {
        Write-Host "User class already allows $AttributeName." -ForegroundColor DarkGray
        return
    }

    # Wait a moment for schema replication if attribute was just created
    Write-Host "Waiting for schema replication..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 3

    try {
        Set-ADObject -Identity $UserClassDn -Add @{ mayContain = $AttributeName } -ErrorAction Stop
        Write-Host "Linked $AttributeName to user class." -ForegroundColor Green
    } catch {
        if ($_.Exception -and $_.Exception.Message -match 'attributeOrValueExists') {
            Write-Host "User class already contains $AttributeName." -ForegroundColor DarkGray
            return
        }

        Write-Warning "Direct update of user class failed ($($_.Exception.Message)). Waiting longer and retrying..."
        
        # Wait longer for schema replication
        Start-Sleep -Seconds 5
        
        try {
            Set-ADObject -Identity $UserClassDn -Add @{ mayContain = $AttributeName } -ErrorAction Stop
            Write-Host "Linked $AttributeName to user class on retry." -ForegroundColor Green
            return
        } catch {
            Write-Warning "Second attempt also failed. Trying LDIF import..."
        }

        $ldif = @"
dn: $UserClassDn
changetype: modify
add: mayContain
mayContain: $AttributeName
-
"@

        $tempLdif = New-TempLdif -Content $ldif
        try {
            # Wait a bit more before LDIF import
            Start-Sleep -Seconds 2
            Invoke-Ldifde -Arguments @('-i','-k','-f', $tempLdif)
            Write-Host "Linked $AttributeName to user class via ldifde." -ForegroundColor Green
        } catch {
            Write-Warning "LDIF import failed. This may be normal if the attribute was already added. Error: $($_.Exception.Message)"
            # Check if it's actually there now
            $userClassCheck = Get-UserClassObject -UserClassDn $UserClassDn
            $currentCheck = @()
            if ($userClassCheck.mayContain) { $currentCheck += $userClassCheck.mayContain }
            if ($userClassCheck.systemMayContain) { $currentCheck += $userClassCheck.systemMayContain }
            
            if ($currentCheck -contains $AttributeName) {
                Write-Host "Attribute $AttributeName is already in user class (may have been replicated)." -ForegroundColor Green
                return
            }
            
            throw "Failed to add $AttributeName to user class: $($_.Exception.Message)"
        } finally {
            Remove-Item $tempLdif -Force -ErrorAction SilentlyContinue
        }
    }
}

function Ensure-UserClassDoesNotContain {
    param(
        [string]$UserClassDn,
        [string]$AttributeName
    )

    $userClass = Get-UserClassObject -UserClassDn $UserClassDn
    $current = @()
    if ($userClass.mayContain) { $current += $userClass.mayContain }
    if ($userClass.systemMayContain) { $current += $userClass.systemMayContain }

    if ($current -notcontains $AttributeName) {
        return
    }

    try {
        Set-ADObject -Identity $UserClassDn -Delete @{ mayContain = $AttributeName } -ErrorAction Stop
        Write-Host "Removed $AttributeName from user class." -ForegroundColor Green
    } catch {
        if ($_.Exception -and $_.Exception.Message -match 'No Such Attribute') {
            Write-Host "$AttributeName already absent from user class." -ForegroundColor DarkGray
        } else {
            Write-Warning "Failed to remove $AttributeName from user class: $($_.Exception.Message)"
        }
    }
}

Ensure-Module -Name ActiveDirectory

try {
    $root = Get-ADRootDSE -ErrorAction Stop
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $script:SchemaMasterServer = $forest.SchemaMaster
    } catch {
        $script:SchemaMasterServer = $null
    }
} catch {
    throw 'Unable to query AD RootDSE. Run this on a domain-joined machine with Domain/Schema Admin rights.'
}

$schemaNc = $root.schemaNamingContext
$userClassDn = "CN=User,$schemaNc"

$attributes = @(
    @{
        Name = $AttributeName
        Oid = $AttributeOid
        Description = 'GateProxy session secret (base64) and expiry timestamp'
        IsSingleValued = $true
        AttributeSyntax = '2.5.5.12'
        OmSyntax = 64
    },
    @{
        Name = $WebAuthnAttributeName
        Oid = $WebAuthnAttributeOid
        Description = 'GateProxy WebAuthn credentials (JSON payloads)'
        IsSingleValued = $false
        AttributeSyntax = '2.5.5.12'
        OmSyntax = 64
    }
)

$resolvedBackupDir = Resolve-Path -Path $BackupDirectory -ErrorAction SilentlyContinue
if ($resolvedBackupDir) {
    $resolvedBackupDir = $resolvedBackupDir.Path
}
if (-not $resolvedBackupDir) {
    Ensure-Directory -Path $BackupDirectory
    $resolvedBackupDir = (Resolve-Path -Path $BackupDirectory).Path
}

switch ($Action) {
    'Backup' {
        $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $backupFile = Join-Path $resolvedBackupDir "gateproxy-schema-$timestamp.ldf"
        Write-Host "Backing up schema elements to $backupFile" -ForegroundColor Cyan
        Export-GateProxySchema -OutputPath $backupFile -SchemaNc $schemaNc -AttributeNames ($attributes | ForEach-Object { $_.Name })
        Write-Host 'Backup complete.' -ForegroundColor Green
    }
    'Restore' {
        if ([string]::IsNullOrWhiteSpace($RestoreFile)) {
            throw 'Specify -RestoreFile when using Action Restore.'
        }
        $fullPath = Resolve-Path $RestoreFile -ErrorAction Stop
        Write-Host "Restoring schema content from $fullPath" -ForegroundColor Yellow
        $quotedPath = "`"$fullPath`""
        Invoke-Ldifde -Arguments @('-i', '-k', '-f', $quotedPath)
        Write-Host 'Restore completed.' -ForegroundColor Green
    }
    'RemoveCustom' {
        $toRemove = $attributes | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
        foreach ($attr in $toRemove) {
            if (Test-AttributeExists -SchemaNc $schemaNc -AttributeName $attr.Name) {
                Ensure-UserClassDoesNotContain -UserClassDn $userClassDn -AttributeName $attr.Name

                $attrDn = "CN=$($attr.Name),$schemaNc"
                $ldif = @"
dn: $attrDn
changetype: delete
"@
                $tempLdif = New-TempLdif -Content $ldif
                try {
                    Invoke-Ldifde -Arguments @('-i', '-k', '-f', $tempLdif)
                    Write-Host "Removed schema attribute $($attr.Name)." -ForegroundColor Green
                } finally {
                    Remove-Item $tempLdif -Force -ErrorAction SilentlyContinue
                }
            } else {
                Write-Host "Attribute $($attr.Name) not present. Skipping." -ForegroundColor DarkGray
            }
        }
    }
    Default {
        $backupFile = Join-Path $resolvedBackupDir "gateproxy-schema-preinit-$(Get-Date -Format 'yyyyMMdd-HHmmss').ldf"
        Write-Host "Creating pre-change backup at $backupFile" -ForegroundColor Cyan
        Export-GateProxySchema -OutputPath $backupFile -SchemaNc $schemaNc -AttributeNames ($attributes | ForEach-Object { $_.Name })

        foreach ($attr in $attributes) {
            if ([string]::IsNullOrWhiteSpace($attr.Name)) { continue }

            $attrDn = "CN=$($attr.Name),$schemaNc"

            if (Test-AttributeExists -SchemaNc $schemaNc -AttributeName $attr.Name) {
                Write-Host "Attribute $($attr.Name) already exists." -ForegroundColor Yellow
            } else {
                $schemaGuid = [Guid]::NewGuid()
                $schemaGuidB64 = [Convert]::ToBase64String($schemaGuid.ToByteArray())
                $isSingleValued = if ($attr.IsSingleValued) { 'TRUE' } else { 'FALSE' }
                $ldif = @"
dn: $attrDn
changetype: add
objectClass: attributeSchema
cn: $($attr.Name)
attributeID: $($attr.Oid)
attributeSyntax: $($attr.AttributeSyntax)
oMSyntax: $($attr.OmSyntax)
isSingleValued: $isSingleValued
adminDisplayName: $($attr.Name)
adminDescription: $($attr.Description)
lDAPDisplayName: $($attr.Name)
schemaIDGUID:: $schemaGuidB64
searchFlags: 0
systemOnly: FALSE

"@
                $tempLdif = New-TempLdif -Content $ldif
                try {
                    Invoke-Ldifde -Arguments @('-i', '-k', '-f', $tempLdif)
                    Write-Host "Schema attribute $($attr.Name) created." -ForegroundColor Green
                } finally {
                    Remove-Item $tempLdif -Force -ErrorAction SilentlyContinue
                }
            }

            # Wait for schema replication before adding to user class
            # Schema changes need time to replicate before they can be referenced
            Write-Host "Waiting for schema replication before linking $($attr.Name) to user class..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 5
            
            # Verify the attribute exists before trying to add it to the class
            $maxRetries = 3
            $retryCount = 0
            $attributeVerified = $false
            
            while ($retryCount -lt $maxRetries -and -not $attributeVerified) {
                if (Test-AttributeExists -SchemaNc $schemaNc -AttributeName $attr.Name) {
                    $attributeVerified = $true
                    Write-Host "Attribute $($attr.Name) verified in schema." -ForegroundColor DarkGray
                } else {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "Attribute $($attr.Name) not yet replicated, waiting 5 more seconds (attempt $retryCount/$maxRetries)..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 5
                    }
                }
            }
            
            if (-not $attributeVerified) {
                Write-Warning "Could not verify attribute $($attr.Name) exists after waiting. Continuing anyway - it may have replicated."
            }
            
            Ensure-UserClassMayContain -UserClassDn $userClassDn -AttributeName $attr.Name
        }
    }
}
