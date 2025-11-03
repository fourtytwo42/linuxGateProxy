Param(
    [Parameter(Mandatory = $true)]
    [string]$ExternalHostname
)

Write-Host "Preparing certificate templates for Gate Proxy" -ForegroundColor Cyan

Import-Module ADCSAdministration

$templateName = "GateProxyWebAuthn"

if (-not (Get-CATemplate -Name $templateName -ErrorAction SilentlyContinue)) {
    $template = Get-CATemplate -Name "WebServer"
    $newTemplate = Duplicate-CATemplate -InputObject $template -NewName $templateName
    $newTemplate.PublishTemplate()
    Write-Host "Template $templateName created." -ForegroundColor Green
} else {
    Write-Host "Template $templateName already exists." -ForegroundColor Yellow
}

Write-Host "Requesting certificate for $ExternalHostname"
$certReq = @"
<Request>
  <PKCS10>
    <Subject>CN=$ExternalHostname</Subject>
    <Attributes>
      <Attribute Type="CertTemplateName">$templateName</Attribute>
    </Attributes>
  </PKCS10>
</Request>
"@

$tmpFile = [System.IO.Path]::GetTempFileName()
$certReq | Out-File -FilePath $tmpFile
certreq -submit $tmpFile
Remove-Item $tmpFile

Write-Host "Certificate request submitted." -ForegroundColor Green

