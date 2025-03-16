# Save this as Test-MSALUpdates.ps1

# Load the core DLLs directly
$dllPath = if ($PSVersionTable.PSEdition -eq "Core") {
    ".\build\packages\Microsoft.Identity.Client.4.59.0\lib\netstandard2.0"
} else {
    ".\build\packages\Microsoft.Identity.Client.4.59.0\lib\net462"
}

$msalDll = Join-Path $dllPath "Microsoft.Identity.Client.dll"

Write-Host "Loading $msalDll" -ForegroundColor Cyan
Add-Type -Path $msalDll -ErrorAction Stop

# Check MSAL version
try {
    $msalVersion = [Microsoft.Identity.Client.PublicClientApplication].Assembly.GetName().Version
    Write-Host "Successfully loaded Microsoft.Identity.Client version $msalVersion" -ForegroundColor Green
}
catch {
    Write-Warning "Could not determine MSAL.NET version: $($_.Exception.Message)"
}

# Load your modified PowerShell scripts
$scripts = @(
    # Internal helpers
    ".\src\internal\ConvertFrom-SecureStringAsPlainText.ps1",
    ".\src\internal\ConvertTo-Dictionary.ps1",
    ".\src\internal\Select-PsBoundParameters.ps1",

    # Your modified files
    ".\src\New-MsalClientApplication.ps1",
    ".\src\Get-MsalToken.ps1"
)

foreach ($script in $scripts) {
    Write-Host "Loading $script" -ForegroundColor Cyan
    . $script
}

# Create module variables
$script:PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
$script:ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'

# Define feature support
$script:ModuleFeatureSupport = [ordered]@{
    WebView1Support        = $PSVersionTable.PSEdition -eq 'Desktop'
    WebView2Support        = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and [System.Environment]::Is64BitProcess
    DeviceCodeSupport      = $true
    TokenCacheSupport      = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'6.0'
    AuthBrokerSupport      = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'7.0'
    WAMSupport             = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and [System.Environment]::OSVersion.Version -ge [version]'10.0.17763'
    CAESupport             = $true
}

# Create module config
$script:ModuleConfigDefault = [PSCustomObject]@{
    'dll.lenientLoading' = $false
    'dll.lenientLoadingPrompt' = $true
}
$script:ModuleConfig = $script:ModuleConfigDefault.psobject.Copy()

Write-Host "`nAvailable commands:" -ForegroundColor Cyan
$commands = @(
    "New-MsalClientApplication",
    "Get-MsalToken"
)

foreach ($command in $commands) {
    if (Get-Command $command -ErrorAction SilentlyContinue) {
        Write-Host "$command is available" -ForegroundColor Green

        # List parameters to verify our new parameters are there
        $params = (Get-Command $command).Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters }
        Write-Host "  Parameters: $($params -join ', ')" -ForegroundColor DarkGray
    }
    else {
        Write-Host "$command is not available" -ForegroundColor Red
    }
}

Write-Host "`nTEST EXAMPLE:" -ForegroundColor Yellow
Write-Host "New-MsalClientApplication -ClientId '00000000-0000-0000-0000-000000000000' -WAMAccountId 'user@contoso.com'" -ForegroundColor Yellow
Write-Host "Get-MsalToken -ClientId '00000000-0000-0000-0000-000000000000' -EnableCAE" -ForegroundColor Yellow
