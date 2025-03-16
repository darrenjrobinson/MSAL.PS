# Save as Build-SimpleModule.ps1

param (
    [Parameter(Mandatory = $false)]
    [string] $OutputPath = ".\build\simple-release\MSAL.PS\4.69.1",

    [Parameter(Mandatory = $false)]
    [version] $ModuleVersion = "4.69.1"
)

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "Building module to: $OutputPath" -ForegroundColor Cyan

# Copy PS1 files
Write-Host "Copying PowerShell files..." -ForegroundColor Cyan
Copy-Item -Path ".\src\*.ps1" -Destination $OutputPath -Force
Copy-Item -Path ".\src\*.psd1" -Destination $OutputPath -Force
Copy-Item -Path ".\src\*.psm1" -Destination $OutputPath -Force

# Create internal directory
$internalDir = Join-Path $OutputPath "internal"
if (-not (Test-Path $internalDir)) {
    New-Item -Path $internalDir -ItemType Directory -Force | Out-Null
}
Copy-Item -Path ".\src\internal\*.ps1" -Destination $internalDir -Force
Copy-Item -Path ".\src\internal\*.cs" -Destination $internalDir -Force

# Create lib directory with DLLs
$libDir = Join-Path $OutputPath "lib"
New-Item -Path $libDir -ItemType Directory -Force | Out-Null

# Copy DLLs
Write-Host "Copying DLLs..." -ForegroundColor Cyan
$dllSources = @{
    "Microsoft.Identity.Client" = ".\build\packages\Microsoft.Identity.Client.4.69.1\lib\net462\Microsoft.Identity.Client.dll"
    "Microsoft.Identity.Client.Desktop" = ".\build\packages\Microsoft.Identity.Client.Desktop.4.69.1\lib\net462\Microsoft.Identity.Client.Desktop.dll"
    "Microsoft.Web.WebView2.Core" = ".\build\packages\Microsoft.Web.WebView2.1.0.3124.44\lib\net45\Microsoft.Web.WebView2.Core.dll"
}

foreach ($dll in $dllSources.Keys) {
    $source = $dllSources[$dll]
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $libDir -Force
        Write-Host "  Copied $dll" -ForegroundColor Green
    }
    else {
        Write-Host "  Could not find $source" -ForegroundColor Yellow
    }
}

# Create simplified module loader - FIXED ORDER OF OPERATIONS
$moduleLoader = @'
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

# Load module scripts
$psFiles = @(
    "internal\Assert-DirectoryExists.ps1",
    "internal\ConvertFrom-SecureStringAsPlainText.ps1",
    "internal\ConvertTo-Dictionary.ps1",
    "internal\Export-Config.ps1",
    "internal\Get-DeviceRegistrationStatus.ps1",
    "internal\Get-ObjectPropertyValue.ps1",
    "internal\Import-Config.ps1",
    "internal\Select-PsBoundParameters.ps1",
    "internal\Set-Config.ps1",
    "internal\Write-HostPrompt.ps1",
    "Add-MsalClientApplication.ps1",
    "Clear-MsalTokenCache.ps1",
    "Enable-MsalTokenCacheOnDisk.ps1",
    "Get-MsalAccount.ps1",
    "Get-MsalClientApplication.ps1",
    "Get-MsalFeatureSupport.ps1",
    "Get-MsalToken.ps1",
    "New-MsalClientApplication.ps1",
    "Remove-MsalClientApplication.ps1",
    "Select-MsalClientApplication.ps1",
    "Set-MsalAccountBinding.ps1"
)

foreach ($file in $psFiles) {
    . (Join-Path $PSScriptRoot $file)
}

Write-Verbose "MSAL.PS Module v$ModuleVersion loaded successfully"
'@

Set-Content -Path (Join-Path $OutputPath "MSAL.PS.psm1") -Value $moduleLoader

# Update module manifest
$manifestPath = Join-Path $OutputPath "MSAL.PS.psd1"
$manifestContent = Get-Content $manifestPath -Raw

# Update version
$manifestContent = $manifestContent -replace "ModuleVersion = '.*'", "ModuleVersion = '$ModuleVersion'"

# Simplify RequiredAssemblies
$requiredAssembliesString = "RequiredAssemblies = @(`r`n    'lib\Microsoft.Identity.Client.dll',`r`n    'lib\Microsoft.Identity.Client.Desktop.dll',`r`n    'lib\Microsoft.Web.WebView2.Core.dll'`r`n)"
$manifestContent = $manifestContent -replace "RequiredAssemblies = @\(.*?\)", $requiredAssembliesString

# Simplify FileList
$fileListString = "FileList = @()"
$manifestContent = $manifestContent -replace "FileList = @\(.*?\)", $fileListString

# Remove ScriptsToProcess to use our custom loader
$manifestContent = $manifestContent -replace "ScriptsToProcess = .*", "# ScriptsToProcess = @()"

# Empty NestedModules since we're handling this in the module loader
$manifestContent = $manifestContent -replace "NestedModules = @\(.*?\)", "NestedModules = @()"

# Save updated manifest
$manifestContent | Set-Content $manifestPath

Write-Host "Module built successfully!" -ForegroundColor Green
Write-Host "Location: $OutputPath" -ForegroundColor Cyan
Write-Host "Import with: Import-Module $OutputPath\MSAL.PS.psd1 -Force -Verbose" -ForegroundColor Cyan
