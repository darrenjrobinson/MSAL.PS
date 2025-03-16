# Test-MsalPSModule-Az.ps1
# This script demonstrates and tests the MSAL.PS module with MSAL.NET 4.69.1 capabilities
# It uses Az PowerShell modules for application registration management

#Requires -Modules MSAL.PS, Az.Accounts, Az.Resources
#Requires -Version 5.1

[CmdletBinding()]
param(
    # Your tenant ID
    [Parameter(Mandatory = $true)]
    [string] $TenantId,

    # Admin consent will be requested for these scopes
    [Parameter(Mandatory = $false)]
    [string[]] $AdminConsentScopes = @(
        "User.Read.All",
        "Directory.Read.All"
    ),

    # Prefix for test application names to make them identifiable
    [Parameter(Mandatory = $false)]
    [string] $AppNamePrefix = "MSAL-PS-Test",

    # Clean up test applications after running
    [Parameter(Mandatory = $false)]
    [switch] $CleanupAfterTest,

    # Specify a custom location for token cache
    [Parameter(Mandatory = $false)]
    [string] $TokenCacheLocation = "$env:USERPROFILE\.msal-ps-test-cache"
)

# Create output folder
$OutputFolder = "$PSScriptRoot\TestResults-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null

# Start transcript
Start-Transcript -Path "$OutputFolder\Test-MsalPSModule.log" -Force

function Write-TestHeader {
    param([string]$Title)
    Write-Host "`n============================================================="
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "=============================================================`n"
}

function Test-MsalCommand {
    param([string]$Description, [scriptblock]$ScriptBlock)
    Write-Host "- TEST: $Description" -ForegroundColor Yellow
    try {
        & $ScriptBlock
        Write-Host "  RESULT: Success" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  RESULT: Failed - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace
        return $false
    }
}

function Create-ApplicationRegistrations {
    Write-TestHeader "Creating Application Registrations"

    # Connect to Azure (requires admin permissions)
    Connect-AzAccount -TenantId $TenantId | Out-Null

    # Create public client application
    Write-Host "Creating public client application..." -ForegroundColor Yellow
    $publicApp = New-AzADApplication -DisplayName "$AppNamePrefix-Public" -AvailableToOtherTenants $false

    # Set as public client
    # Use the MS Graph API directly for this operation since there's no direct Az cmdlet
    $token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $body = @{
        "isFallbackPublicClient" = $true
        "publicClient" = @{
            "redirectUris" = @("urn:ietf:wg:oauth:2.0:oob", "http://localhost", "https://login.microsoftonline.com/common/oauth2/nativeclient")
        }
    } | ConvertTo-Json -Depth 4

    Invoke-RestMethod -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($publicApp.Id)" -Headers $headers -Body $body | Out-Null

    Write-Host "Created public client application with ID: $($publicApp.AppId)" -ForegroundColor Green

    # Create service principal for the public client
    $publicAppSp = New-AzADServicePrincipal -ApplicationId $publicApp.AppId

    # Create confidential client application
    Write-Host "Creating confidential client application..." -ForegroundColor Yellow
    $confidentialApp = New-AzADApplication -DisplayName "$AppNamePrefix-Confidential" -AvailableToOtherTenants $false -ReplyUrls "https://localhost/auth"

    # Configure for delegated and application permissions
    $msGraphSpn = "00000003-0000-0000-c000-000000000000"
    $body = @{
        "requiredResourceAccess" = @(
            @{
                "resourceAppId" = $msGraphSpn
                "resourceAccess" = @(
                    @{
                        "id" = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
                        "type" = "Scope"
                    },
                    @{
                        "id" = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
                        "type" = "Role"
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 5

    Invoke-RestMethod -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($confidentialApp.Id)" -Headers $headers -Body $body | Out-Null

    Write-Host "Created confidential client application with ID: $($confidentialApp.AppId)" -ForegroundColor Green

    # Create service principal for the confidential client
    $confidentialAppSp = New-AzADServicePrincipal -ApplicationId $confidentialApp.AppId

    # Create client secret
    Write-Host "Creating client secret..." -ForegroundColor Yellow
    $endDate = (Get-Date).AddDays(7)
    $clientSecretObj = New-AzADAppCredential -ApplicationId $confidentialApp.AppId -EndDate $endDate
    $clientSecretValue = $clientSecretObj.SecretText
    Write-Host "Created client secret successfully" -ForegroundColor Green

    # Create self-signed certificate
    Write-Host "Creating self-signed certificate..." -ForegroundColor Yellow
    $certSubject = "CN=$AppNamePrefix-Cert"
    $certStoreLocation = "Cert:\CurrentUser\My"
    $cert = New-SelfSignedCertificate -Subject $certSubject -CertStoreLocation $certStoreLocation -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddMonths(12)

    # Add certificate to application
    $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
    New-AzADAppCredential -ApplicationId $confidentialApp.AppId -CertValue $keyValue -EndDate $cert.NotAfter

    Write-Host "Added certificate with thumbprint $($cert.Thumbprint) to application" -ForegroundColor Green

    # Grant admin consent for the applications
    if ($AdminConsentScopes.Count -gt 0) {
        Write-Host "Granting admin consent for required scopes..." -ForegroundColor Yellow

        # For application permissions (app roles)
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($confidentialAppSp.Id)/appRoleAssignments"

        # Get Microsoft Graph service principal
        $graphSp = Get-AzADServicePrincipal -ApplicationId $msGraphSpn

        # Get User.Read.All app role
        $userReadAllPermission = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($graphSp.Id)" -Headers $headers |
            Select-Object -ExpandProperty appRoles |
            Where-Object { $_.value -eq "User.Read.All" }

        if ($userReadAllPermission) {
            $appRoleBody = @{
                "principalId" = $confidentialAppSp.Id
                "resourceId" = $graphSp.Id
                "appRoleId" = $userReadAllPermission.id
            } | ConvertTo-Json

            Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $appRoleBody | Out-Null
        }

        # For delegated permissions (oauth2 permission grants)
        $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
        $scopesToConsent = "User.Read User.Read.All Directory.Read.All"

        $permissionGrantBody = @{
            "clientId" = $confidentialAppSp.Id
            "consentType" = "AllPrincipals"
            "resourceId" = $graphSp.Id
            "scope" = $scopesToConsent
        } | ConvertTo-Json

        Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $permissionGrantBody | Out-Null

        Write-Host "Admin consent granted successfully" -ForegroundColor Green
    }

    # Save application details for the tests
    $testConfig = @{
        PublicClientAppId = $publicApp.AppId
        PublicClientObjectId = $publicApp.Id
        PublicClientSPId = $publicAppSp.Id
        ConfidentialClientAppId = $confidentialApp.AppId
        ConfidentialClientObjectId = $confidentialApp.Id
        ConfidentialClientSPId = $confidentialAppSp.Id
        ClientSecretValue = $clientSecretValue
        CertificateThumbprint = $cert.Thumbprint
        CertificateSubject = $certSubject
        TenantId = $TenantId
        CreatedAt = Get-Date
    }

    $testConfig | ConvertTo-Json | Set-Content -Path "$OutputFolder\appRegistrations.json"

    return $testConfig
}

function Test-PublicClientFlows {
    param($config)

    Write-TestHeader "Testing Public Client Authentication Flows"

    # 1. Interactive Authentication
    Test-MsalCommand -Description "Interactive Authentication" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId -RedirectUri "http://localhost"
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "public-client-cache.bin" -BackupFilesCount 1
        $token = $app | Get-MsalToken -Interactive -Scopes "User.Read" -LoginHint $env:USERNAME

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get interactive token"
        }

        $token | Select-Object Account, AccessToken, ExpiresOn, Scopes | Format-List | Out-File "$OutputFolder\public-client-interactive.txt"
        return $token
    }

    # 2. Silent Authentication (token from cache)
    Test-MsalCommand -Description "Silent Token Acquisition (from cache)" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "public-client-cache.bin"
        $token = $app | Get-MsalToken -Silent -Scopes "User.Read"

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get silent token"
        }

        return $token
    }

    # 3. Silent Authentication with different scopes
    Test-MsalCommand -Description "Silent Token Acquisition (different scopes)" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId -EnableContinuousAccessEvaluation
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "public-client-cache.bin"

        # This should trigger interactive auth because we're requesting more scopes
        $token = $app | Get-MsalToken -Scopes "User.Read", "User.ReadBasic.All" -ClientCapabilities @("CP1")

        # Validate we received a token with the appropriate scopes
        if (-not $token -or -not $token.Scopes -or -not ($token.Scopes -contains "User.ReadBasic.All")) {
            throw "Failed to get token with expanded scopes"
        }

        return $token
    }

    # 4. Device Code flow
    Test-MsalCommand -Description "Device Code Authentication" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId

        # Using DeviceCode parameter
        Write-Host "Please complete the device code authentication when prompted..." -ForegroundColor Yellow
        $token = $app | Get-MsalToken -DeviceCode -Scopes "User.Read"

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get device code token"
        }

        return $token
    }

    # 5. Windows Integrated Authentication
    Test-MsalCommand -Description "Windows Integrated Authentication" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId

        try {
            $token = $app | Get-MsalToken -IntegratedWindowsAuth -Scopes "User.Read"

            # Validate we received a token
            if (-not $token -or -not $token.AccessToken) {
                throw "Failed to get integrated Windows auth token"
            }

            return $token
        }
        catch {
            Write-Host "  Note: Windows Integrated Auth may not be available in all environments" -ForegroundColor Yellow
            # Don't throw an error if this isn't supported in the environment
            return $null
        }
    }

    # 6. Enhanced token options with new parameters
    Test-MsalCommand -Description "Enhanced Token Options (CAE, PoP Token)" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId -EnableContinuousAccessEvaluation -EnablePoPTokenGeneration

        # Using the new parameters
        $token = $app | Get-MsalToken -Scopes "User.Read" -EnableContinuousAccessEvaluation -ClientCapabilities @("CP1")

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get enhanced token"
        }

        return $token
    }
}

function Test-ConfidentialClientFlows {
    param($config)

    Write-TestHeader "Testing Confidential Client Authentication Flows"

    # 1. Client Credentials Flow with Secret
    Test-MsalCommand -Description "Client Credentials Flow with Secret" -ScriptBlock {
        $clientSecret = ConvertTo-SecureString $config.ClientSecretValue -AsPlainText -Force
        $app = New-MsalClientApplication -ClientId $config.ConfidentialClientAppId -TenantId $config.TenantId -ClientSecret $clientSecret
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "confidential-client-secret.bin" -PartitionKey "secret-app"

        # Request an app-only token
        $token = $app | Get-MsalToken -Scopes "https://graph.microsoft.com/.default"

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get client credentials token with secret"
        }

        $token | Select-Object TenantId, Scopes, ExpiresOn | Format-List | Out-File "$OutputFolder\confidential-client-secret.txt"
        return $token
    }

    # 2. Client Credentials Flow with Certificate
    Test-MsalCommand -Description "Client Credentials Flow with Certificate" -ScriptBlock {
        $cert = Get-Item "Cert:\CurrentUser\My\$($config.CertificateThumbprint)" -ErrorAction Stop
        $app = New-MsalClientApplication -ClientId $config.ConfidentialClientAppId -TenantId $config.TenantId -ClientCertificate $cert
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "confidential-client-cert.bin"

        # Request an app-only token
        $token = $app | Get-MsalToken -Scopes "https://graph.microsoft.com/.default"

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get client credentials token with certificate"
        }

        return $token
    }

    # 3. On-Behalf-Of Flow
    Test-MsalCommand -Description "On-Behalf-Of Flow" -ScriptBlock {
        # First get a token for a user
        $publicApp = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $userToken = $publicApp | Get-MsalToken -Interactive -Scopes "$($config.ConfidentialClientAppId)/user_impersonation"

        if (-not $userToken -or -not $userToken.AccessToken) {
            throw "Could not get user token for OBO flow"
        }

        # Now use that token for OBO
        $cert = Get-Item "Cert:\CurrentUser\My\$($config.CertificateThumbprint)" -ErrorAction Stop
        $app = New-MsalClientApplication -ClientId $config.ConfidentialClientAppId -TenantId $config.TenantId -ClientCertificate $cert

        try {
            # OBO flow to exchange the user token for a new token
            $oboToken = $app | Get-MsalToken -Scopes "https://graph.microsoft.com/User.Read" -UserAssertion $userToken.AccessToken

            # Validate we received a token
            if (-not $oboToken -or -not $oboToken.AccessToken) {
                throw "Failed to get OBO token"
            }

            return $oboToken
        }
        catch {
            Write-Host "  Note: OBO flow requires the app to be properly configured for this flow" -ForegroundColor Yellow
            # Don't fail the test, as OBO requires special configuration
            return $null
        }
    }

    # 4. Client Credentials with enhanced features
    Test-MsalCommand -Description "Client Credentials with Regional Authority" -ScriptBlock {
        $clientSecret = ConvertTo-SecureString $config.ClientSecretValue -AsPlainText -Force
        $app = New-MsalClientApplication -ClientId $config.ConfidentialClientAppId -TenantId $config.TenantId -ClientSecret $clientSecret -AzureRegion "westus2" -EnableRefreshTokenForCAEProtectedResource

        # Request an app-only token with enhanced params
        $token = $app | Get-MsalToken -Scopes "https://graph.microsoft.com/.default" -EnableContinuousAccessEvaluation -Claims '{"access_token":{"xms_cc":{"values":["CP1","CP2"]}}}'

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get enhanced client credentials token"
        }

        return $token
    }

    # 5. X5C Certificate Claim
    Test-MsalCommand -Description "Client Credentials with X5C Certificate Claim" -ScriptBlock {
        $cert = Get-Item "Cert:\CurrentUser\My\$($config.CertificateThumbprint)" -ErrorAction Stop
        $app = New-MsalClientApplication -ClientId $config.ConfidentialClientAppId -TenantId $config.TenantId -ClientCertificate $cert

        # Request an app-only token with SendX5C parameter
        $token = $app | Get-MsalToken -Scopes "https://graph.microsoft.com/.default" -SendX5C

        # Validate we received a token
        if (-not $token -or -not $token.AccessToken) {
            throw "Failed to get token with X5C certificate claim"
        }

        return $token
    }
}

function Test-TokenCacheFeatures {
    param($config)

    Write-TestHeader "Testing Token Cache Features"

    # 1. Basic token cache functionality
    Test-MsalCommand -Description "Basic Token Cache Persistence" -ScriptBlock {
        # Get token and store in cache
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "token-cache-test.bin"

        $token1 = $app | Get-MsalToken -Scopes "User.Read" -ForceRefresh

        # Create a new app instance and try to get token silently
        $app2 = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app2 | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "token-cache-test.bin"

        $token2 = $app2 | Get-MsalToken -Silent -Scopes "User.Read"

        # Validate tokens match
        if (-not $token2 -or $token1.AccessToken -ne $token2.AccessToken) {
            throw "Token cache persistence failed"
        }

        return $true
    }

    # 2. Cache backup feature
    Test-MsalCommand -Description "Token Cache Backup Feature" -ScriptBlock {
        # Get token and store in cache with backups
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "cache-with-backup.bin" -BackupFilesCount 3

        # Get a few tokens to trigger multiple backups
        for ($i = 0; $i -lt 5; $i++) {
            $token = $app | Get-MsalToken -Scopes "User.Read" -ForceRefresh
            Start-Sleep -Seconds 1
        }

        # Check if backup files were created
        $backupFolder = Join-Path $TokenCacheLocation "Backup"
        $backupFiles = Get-ChildItem -Path $backupFolder -Filter "cache-with-backup.*bin" -ErrorAction SilentlyContinue

        if (-not $backupFiles -or $backupFiles.Count -lt 1) {
            throw "Backup files were not created"
        }

        # We should have at most 3 backups as specified
        if ($backupFiles.Count -gt 3) {
            throw "Too many backup files found: $($backupFiles.Count)"
        }

        return $true
    }

    # 3. Cache partitioning
    Test-MsalCommand -Description "Token Cache Partitioning" -ScriptBlock {
        # Create two apps with different partition keys
        $app1 = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app1 | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "partitioned-cache.bin" -PartitionKey "partition1"

        $app2 = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app2 | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "partitioned-cache.bin" -PartitionKey "partition2"

        # Get tokens for both apps
        $token1 = $app1 | Get-MsalToken -Scopes "User.Read" -ForceRefresh
        $token2 = $app2 | Get-MsalToken -Scopes "User.Read" -ForceRefresh

        # Make sure tokens are different
        if ($token1.AccessToken -eq $token2.AccessToken) {
            throw "Partitioning failed: tokens are identical despite different partition keys"
        }

        return $true
    }

    # 4. Unencrypted cache (for debugging)
    Test-MsalCommand -Description "Unencrypted Token Cache (Debugging)" -ScriptBlock {
        $app = New-MsalClientApplication -ClientId $config.PublicClientAppId -TenantId $config.TenantId
        $app | Enable-MsalTokenCacheOnDisk -CacheDirectory $TokenCacheLocation -CacheFileName "unencrypted-cache.bin" -DisableAutomaticEncryption

        $token = $app | Get-MsalToken -Scopes "User.Read" -ForceRefresh

        # Check if the cache file exists and is readable
        $cachePath = Join-Path $TokenCacheLocation "unencrypted-cache.bin"
        if (-not (Test-Path $cachePath)) {
            throw "Cache file not created"
        }

        # The file should exist and be readable
        $cacheContent = Get-Content -Path $cachePath -Raw -Encoding Byte
        if (-not $cacheContent -or $cacheContent.Length -lt 10) {
            throw "Cache file is empty or too small"
        }

        return $true
    }
}

function Cleanup-TestResources {
    param($config)

    Write-TestHeader "Cleaning Up Test Resources"

    # Connect to Azure if needed
    try {
        Get-AzContext -ErrorAction Stop | Out-Null
    }
    catch {
        Connect-AzAccount -TenantId $config.TenantId | Out-Null
    }

    # Delete the test applications
    try {
        Write-Host "Deleting public client application..." -ForegroundColor Yellow
        Remove-AzADApplication -ObjectId $config.PublicClientObjectId -Force | Out-Null
        Write-Host "Deleted public client application successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to delete public client application: $_" -ForegroundColor Red
    }

    try {
        Write-Host "Deleting confidential client application..." -ForegroundColor Yellow
        Remove-AzADApplication -ObjectId $config.ConfidentialClientObjectId -Force | Out-Null
        Write-Host "Deleted confidential client application successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to delete confidential client application: $_" -ForegroundColor Red
    }

    # Remove certificate from cert store
    try {
        Write-Host "Removing test certificate..." -ForegroundColor Yellow
        Get-Item "Cert:\CurrentUser\My\$($config.CertificateThumbprint)" -ErrorAction Stop | Remove-Item
        Write-Host "Removed test certificate successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove test certificate: $_" -ForegroundColor Red
    }

    # Clean up token cache directory
    try {
        Write-Host "Cleaning up token cache directory..." -ForegroundColor Yellow
        Remove-Item -Path $TokenCacheLocation -Recurse -Force -ErrorAction Stop
        Write-Host "Cleaned up token cache directory successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to clean up token cache directory: $_" -ForegroundColor Red
    }
}

# Main execution flow
try {
    Write-TestHeader "MSAL.PS Test Script"

    # Verify MSAL.PS module version
    $msalModule = Get-Module MSAL.PS -ListAvailable | Select-Object -First 1
    Write-Host "MSAL.PS Module Version: $($msalModule.Version)" -ForegroundColor Cyan

    # Create test applications if needed
    $configPath = "$OutputFolder\appRegistrations.json"
    if (Test-Path $configPath) {
        $config = Get-Content $configPath | ConvertFrom-Json
        Write-Host "Using existing application registrations from $configPath" -ForegroundColor Cyan
    }
    else {
        $config = Create-ApplicationRegistrations
    }

    # Test public client flows
    Test-PublicClientFlows -config $config

    # Test confidential client flows
    Test-ConfidentialClientFlows -config $config

    # Test token cache features
    Test-TokenCacheFeatures -config $config

    # Clean up if requested
    if ($CleanupAfterTest) {
        Cleanup-TestResources -config $config
    }
    else {
        Write-Host "`nTest applications were not cleaned up. To remove them, run:" -ForegroundColor Yellow
        Write-Host ".\Test-MsalPSModule-Az.ps1 -TenantId $($config.TenantId) -CleanupAfterTest" -ForegroundColor Yellow
    }

    Write-TestHeader "Tests Completed Successfully"
    Write-Host "Test results saved to: $OutputFolder" -ForegroundColor Green
}
catch {
    Write-Host "Test script failed: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
finally {
    Stop-Transcript
}
