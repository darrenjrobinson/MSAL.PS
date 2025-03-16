# Create a simplified test script (Test-Changes.ps1)

# Define the correct DLL paths based on PowerShell edition
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $msalPath = ".\build\packages\Microsoft.Identity.Client.4.59.0\lib\net462\Microsoft.Identity.Client.dll"
    $msalDesktopPath = ".\build\packages\Microsoft.Identity.Client.Desktop.4.59.0\lib\net462\Microsoft.Identity.Client.Desktop.dll"
    $webView2Path = ".\build\packages\Microsoft.Web.WebView2.1.0.2210.55\lib\net45\Microsoft.Web.WebView2.Core.dll"
}
else {
    # PowerShell Core - preferring netcoreapp paths where available
    $msalPath = ".\build\packages\Microsoft.Identity.Client.4.59.0\lib\net462\Microsoft.Identity.Client.dll"
    $msalDesktopPath = ".\build\packages\Microsoft.Identity.Client.Desktop.4.59.0\lib\netcoreapp3.1\Microsoft.Identity.Client.Desktop.dll"
    $webView2Path = ".\build\packages\Microsoft.Web.WebView2.1.0.2210.55\lib\netcoreapp3.0\Microsoft.Web.WebView2.Core.dll"
}

# Check if Microsoft.Identity.Client is already loaded
$msalLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GetName().Name -eq "Microsoft.Identity.Client" }

# If not loaded, try to load it
if (-not $msalLoaded) {
    if (Test-Path $msalPath) {
        try {
            Add-Type -Path $msalPath -ErrorAction Stop
            Write-Host "Successfully loaded Microsoft.Identity.Client" -ForegroundColor Green
        }
        catch {
            Write-Host ("Error loading Microsoft.Identity.Client: " + $_.Exception.Message) -ForegroundColor Red
        }
    }
    else {
        Write-Host "Could not find Microsoft.Identity.Client.dll at $msalPath" -ForegroundColor Red
    }
}
else {
    Write-Host "Microsoft.Identity.Client is already loaded (Version: $($msalLoaded.GetName().Version))" -ForegroundColor Green
}

# Try to load Microsoft.Identity.Client.Desktop
if (Test-Path $msalDesktopPath) {
    try {
        Add-Type -Path $msalDesktopPath -ErrorAction Stop
        Write-Host "Successfully loaded Microsoft.Identity.Client.Desktop" -ForegroundColor Green
    }
    catch {
        Write-Host ("Error loading Microsoft.Identity.Client.Desktop: " + $_.Exception.Message) -ForegroundColor Red
    }
}
else {
    Write-Host "Could not find Microsoft.Identity.Client.Desktop.dll at $msalDesktopPath" -ForegroundColor Yellow
}

# Try to load WebView2
if (Test-Path $webView2Path) {
    try {
        Add-Type -Path $webView2Path -ErrorAction Stop
        Write-Host "Successfully loaded WebView2" -ForegroundColor Green
    }
    catch {
        Write-Host ("Error loading WebView2: " + $_.Exception.Message) -ForegroundColor Red
    }
}
else {
    Write-Host "Could not find WebView2 at $webView2Path" -ForegroundColor Yellow
}

# Initialize module variables that might be needed
try {
    # Create the needed collections for client applications
    $script:PublicClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IPublicClientApplication]'
    $script:ConfidentialClientApplications = New-Object 'System.Collections.Generic.List[Microsoft.Identity.Client.IConfidentialClientApplication]'

    # Define feature support hashtable
    $script:ModuleFeatureSupport = [ordered]@{
        WebView1Support        = $PSVersionTable.PSEdition -eq 'Desktop'
        WebView2Support        = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and [System.Environment]::Is64BitProcess
        DeviceCodeSupport      = $true
        TokenCacheSupport      = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'6.0'
        AuthBrokerSupport      = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'7.0'
        WAMSupport             = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -and [System.Environment]::OSVersion.Version -ge [version]'10.0.17763'
        CAESupport             = $true
    }

    # Create default module config
    $script:ModuleConfigDefault = [PSCustomObject]@{
        'dll.lenientLoading' = $false
        'dll.lenientLoadingPrompt' = $true
    }
    $script:ModuleConfig = $script:ModuleConfigDefault.psobject.Copy()

    Write-Host "Successfully initialized module variables" -ForegroundColor Green
}
catch {
    Write-Host ("Error initializing module variables: " + $_.Exception.Message) -ForegroundColor Red
}

# Import helper functions first
$helperScripts = @(
    ".\src\internal\Assert-DirectoryExists.ps1",
    ".\src\internal\ConvertFrom-SecureStringAsPlainText.ps1",
    ".\src\internal\ConvertTo-Dictionary.ps1",
    ".\src\internal\Export-Config.ps1",
    ".\src\internal\Get-DeviceRegistrationStatus.ps1",
    ".\src\internal\Get-ObjectPropertyValue.ps1",
    ".\src\internal\Import-Config.ps1",
    ".\src\internal\Select-PsBoundParameters.ps1",
    ".\src\internal\Set-Config.ps1",
    ".\src\internal\Write-HostPrompt.ps1"
)

foreach ($script in $helperScripts) {
    if (Test-Path $script) {
        try {
            . $script
            Write-Host "Loaded $script" -ForegroundColor Green
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "Error loading $script`: $errorMsg" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Could not find $script" -ForegroundColor Yellow
    }
}

# Import main cmdlets
$mainScripts = @(
    ".\src\Add-MsalClientApplication.ps1",
    ".\src\Clear-MsalTokenCache.ps1",
    ".\src\Enable-MsalTokenCacheOnDisk.ps1",
    ".\src\Get-MsalAccount.ps1",
    ".\src\Get-MsalClientApplication.ps1",
    ".\src\Get-MsalFeatureSupport.ps1",
    ".\src\Get-MsalToken.ps1", # Your modified file
    ".\src\New-MsalClientApplication.ps1", # Your modified file
    ".\src\Remove-MsalClientApplication.ps1",
    ".\src\Select-MsalClientApplication.ps1"
)

foreach ($script in $mainScripts) {
    if (Test-Path $script) {
        try {
            . $script
            Write-Host "Loaded $script" -ForegroundColor Green
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "Error loading $script`: $errorMsg" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Could not find $script" -ForegroundColor Yellow
    }
}

Write-Host "`nTesting loaded commands:" -ForegroundColor Cyan

# Check if our modified functions are available
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

Write-Host "`nYou can now test your modified commands directly" -ForegroundColor Cyan
