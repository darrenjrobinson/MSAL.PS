# Simple-Test-MsalPS.ps1
# A simplified script to test the MSAL.PS module with basic functionality

[CmdletBinding()]
param(
    # Your tenant ID
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    # Your client ID (a public client app you've already registered)
    [Parameter(Mandatory = $true)]
    [string] $ClientId
)

# Initialize ModuleState if it doesn't exist
if (-not (Get-Variable -Name ModuleState -Scope Script -ErrorAction SilentlyContinue)) {
    $script:ModuleState = @{
        DeviceRegistrationStatus = @{}
        UseWebView2 = $false
    }
}

# Test basic functionality
Write-Host "Testing basic MSAL.PS functionality..." -ForegroundColor Cyan
try {
    # Create a simple public client application
    $app = New-MsalClientApplication -ClientId $ClientId -TenantId $TenantId
    Write-Host "Successfully created MSAL client application" -ForegroundColor Green

    # Try to get a token interactively
    Write-Host "Attempting to get a token interactively..." -ForegroundColor Cyan
    $token = $app | Get-MsalToken -Interactive -Scopes "User.Read"

    if ($token -and $token.AccessToken) {
        Write-Host "Successfully acquired token!" -ForegroundColor Green
        Write-Host "Account: $($token.Account.Username)" -ForegroundColor Green
        Write-Host "Token Expires: $($token.ExpiresOn)" -ForegroundColor Green
        Write-Host "Scopes: $($token.Scopes -join ', ')" -ForegroundColor Green
    }
    else {
        Write-Host "Failed to acquire token." -ForegroundColor Red
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red

    # Provide a potential fix for the DeviceRegistrationStatus issue
    Write-Host "`nPossible fix for the DeviceRegistrationStatus error:" -ForegroundColor Yellow
    Write-Host "Add the following code to your MSAL.PS.psm1 file, near the beginning after module imports:" -ForegroundColor Yellow
    Write-Host @'
# Initialize module state
if (-not (Get-Variable -Name ModuleState -Scope Script -ErrorAction SilentlyContinue)) {
    $script:ModuleState = @{
        DeviceRegistrationStatus = @{}
        UseWebView2 = $false
    }
}
'@ -ForegroundColor Cyan
}
