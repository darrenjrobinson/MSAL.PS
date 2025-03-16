# First, load the DLLs
$dllPath = Join-Path $PSScriptRoot "lib"
$dllFiles = Get-ChildItem -Path $dllPath -Filter "*.dll" -File
foreach ($dll in $dllFiles) {
    try {
        Add-Type -Path $dll.FullName -ErrorAction Stop
        Write-Verbose "Loaded $($dll.Name)"
    }
    catch {
        Write-Warning "Error loading $($dll.Name): $($_.Exception.Message)"
    }
}

# Now, check MSAL version
try {
    $msalVersion = [Microsoft.Identity.Client.PublicClientApplication].Assembly.GetName().Version
    Write-Verbose "Microsoft.Identity.Client version: $msalVersion"
}
catch {
    Write-Warning "Could not determine MSAL.NET version: $($_.Exception.Message)"
}

# AFTER the DLLs are loaded, initialize module variables that need the MSAL types
$script:PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
$script:ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'

# Define feature support
$script:ModuleFeatureSupport = [ordered]@{
    WebView1Support        = $PSVersionTable.PSEdition -eq 'Desktop'
    WebView2Support        = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and [System.Environment]::Is64BitProcess -and (Get-ChildItem -Path "$PSScriptRoot\lib" -Filter "Microsoft.Web.WebView2.Core.dll" -ErrorAction SilentlyContinue)
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

# Load module scripts
$psFiles = @(
        'Add-MsalClientApplication.ps1',
    'Clear-MsalTokenCache.ps1',
    'Enable-MsalTokenCacheOnDisk.ps1',
    'Get-MsalAccount.ps1',
    'Get-MsalClientApplication.ps1',
    'Get-MsalFeatureSupport.ps1',
    'Get-MsalToken.ps1',
    'internal\Assert-DirectoryExists.ps1',
    'internal\ConvertFrom-SecureStringAsPlainText.ps1',
    'internal\ConvertTo-Dictionary.ps1',
    'internal\Export-Config.ps1',
    'internal\Get-DeviceRegistrationStatus.ps1',
    'internal\Get-ObjectPropertyValue.ps1',
    'internal\Import-Config.ps1',
    'internal\Select-PsBoundParameters.ps1',
    'internal\Set-Config.ps1',
    'internal\Write-HostPrompt.ps1',
    'New-MsalClientApplication.ps1',
    'Remove-MsalClientApplication.ps1',
    'Select-MsalClientApplication.ps1',
    'Set-MsalAccountBinding.ps1'
)

foreach ($file in $psFiles) {
    . (Join-Path $PSScriptRoot $file)
}

Write-Verbose "MSAL.PS Module v$ModuleVersion loaded successfully"
