# Save as Build-CompleteModule.ps1

param (
    [Parameter(Mandatory = $false)]
    [string] $OutputPath = ".\build\complete-module\MSAL.PS\4.69.1",

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

# Get the actual WebView2 package path - search for any version
$webViewPackagePath = Get-ChildItem -Path ".\build\packages" -Filter "Microsoft.Web.WebView2.*" -Directory |
    Sort-Object -Property Name -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if ($webViewPackagePath) {
    Write-Host "Found WebView2 package: $webViewPackagePath" -ForegroundColor Green

    # Look for the net462 directory first, then try other common paths
    $webViewDllPaths = @(
        "$webViewPackagePath\lib\net462\Microsoft.Web.WebView2.Core.dll",
        "$webViewPackagePath\lib\netstandard2.0\Microsoft.Web.WebView2.Core.dll",
        "$webViewPackagePath\lib\netcoreapp3.0\Microsoft.Web.WebView2.Core.dll"
    )

    $webViewDll = $null
    foreach ($path in $webViewDllPaths) {
        if (Test-Path $path) {
            $webViewDll = $path
            Write-Host "Found WebView2 DLL at: $webViewDll" -ForegroundColor Green
            break
        }
    }

    if (-not $webViewDll) {
        # If we still don't have a match, try to find any matching DLL
        $webViewDll = Get-ChildItem -Path $webViewPackagePath -Filter "Microsoft.Web.WebView2.Core.dll" -Recurse |
            Select-Object -First 1 -ExpandProperty FullName

        if ($webViewDll) {
            Write-Host "Found WebView2 DLL at: $webViewDll" -ForegroundColor Green
        }
    }
} else {
    Write-Host "WebView2 package not found. WebView2 support will be disabled." -ForegroundColor Yellow
    $webViewDll = $null
}

$dllSources = @{
    "Microsoft.Identity.Client" = ".\build\packages\Microsoft.Identity.Client.4.69.1\lib\net462\Microsoft.Identity.Client.dll"
    "Microsoft.Identity.Client.Desktop" = ".\build\packages\Microsoft.Identity.Client.Desktop.4.69.1\lib\net462\Microsoft.Identity.Client.Desktop.dll"
    "Microsoft.IdentityModel.Abstractions" = ".\build\packages\Microsoft.IdentityModel.Abstractions.8.6.1\lib\net462\Microsoft.IdentityModel.Abstractions.dll"
    "Microsoft.Identity.Client.Broker" = ".\build\packages\Microsoft.Identity.Client.Broker.4.69.1\lib\net462\Microsoft.Identity.Client.Broker.dll"
    "Microsoft.Identity.Client.NativeInterop" = ".\build\packages\Microsoft.Identity.Client.NativeInterop.0.18.1\lib\net461\Microsoft.Identity.Client.NativeInterop.dll"
}

# Add WebView2 if found
if ($webViewDll) {
    $dllSources["Microsoft.Web.WebView2.Core"] = $webViewDll
}

# Track successfully copied DLLs for the manifest
$requiredAssemblies = @()

foreach ($dll in $dllSources.Keys) {
    $source = $dllSources[$dll]
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $libDir -Force
        $requiredAssemblies += "lib\" + (Split-Path $source -Leaf)
        Write-Host "  Copied $dll" -ForegroundColor Green
    }
    else {
        Write-Host "  Could not find $source" -ForegroundColor Yellow
    }
}

# Get all PS1 files in the module directory
$allPs1Files = @()
$allPs1Files += Get-ChildItem -Path $internalDir -Filter "*.ps1" | ForEach-Object { "internal\" + $_.Name }
$allPs1Files += Get-ChildItem -Path $OutputPath -Filter "*.ps1" | ForEach-Object { $_.Name }
$allPs1Files = $allPs1Files | Where-Object { $_ -ne "MSAL.PS.ps1" } | Sort-Object

# Create module loader with dynamic file list
$moduleLoaderTemplate = @'
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
    __PS_FILES_PLACEHOLDER__
)

foreach ($file in $psFiles) {
    . (Join-Path $PSScriptRoot $file)
}

Write-Verbose "MSAL.PS Module v$ModuleVersion loaded successfully"
'@

# Insert the actual list of PS1 files
$psFilesString = "    '" + ($allPs1Files -join "',`r`n    '") + "'"
$moduleLoader = $moduleLoaderTemplate -replace "__PS_FILES_PLACEHOLDER__", $psFilesString

Set-Content -Path (Join-Path $OutputPath "MSAL.PS.psm1") -Value $moduleLoader

# Get list of functions to export
$functionFiles = Get-ChildItem -Path $OutputPath -Filter "*.ps1" |
    Where-Object { $_.Name -ne "MSAL.PS.ps1" } |
    ForEach-Object {
        $content = Get-Content $_.FullName -Raw
        if ($content -match "function\s+([A-Za-z0-9-]+)") {
            $matches[1]
        }
    }

# Update module manifest
$manifestPath = Join-Path $OutputPath "MSAL.PS.psd1"
$manifestContent = Get-Content $manifestPath -Raw

# Update version
$manifestContent = $manifestContent -replace "ModuleVersion = '.*'", "ModuleVersion = '$ModuleVersion'"

# Update RequiredAssemblies with the ones that were actually copied
$requiredAssembliesString = "RequiredAssemblies = @(`r`n    '" + ($requiredAssemblies -join "',`r`n    '") + "'`r`n)"
$manifestContent = $manifestContent -replace "RequiredAssemblies = @\(.*?\)", $requiredAssembliesString

# Update FileList - leave empty as we're handling this differently now
$fileListString = "FileList = @()"
$manifestContent = $manifestContent -replace "FileList = @\(.*?\)", $fileListString

# Remove ScriptsToProcess
$manifestContent = $manifestContent -replace "ScriptsToProcess = .*", "# ScriptsToProcess = @()"

# Empty NestedModules since we're handling this in our custom loader
$manifestContent = $manifestContent -replace "NestedModules = @\(.*?\)", "NestedModules = @()"

# Update FunctionsToExport with dynamically discovered functions
$functionsToExportString = "FunctionsToExport = @(`r`n    '" + ($functionFiles -join "',`r`n    '") + "'`r`n)"
$manifestContent = $manifestContent -replace "FunctionsToExport = @\(.*?\)", $functionsToExportString

# Save updated manifest
$manifestContent | Set-Content $manifestPath

Write-Host "Module built successfully!" -ForegroundColor Green
Write-Host "Location: $OutputPath" -ForegroundColor Cyan
Write-Host "Import with: Import-Module $OutputPath\MSAL.PS.psd1 -Force -Verbose" -ForegroundColor Cyan
Write-Host "Functions exported: $($functionFiles.Count)" -ForegroundColor Cyan
