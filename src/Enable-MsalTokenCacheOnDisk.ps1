<#
.SYNOPSIS
    Enable client application to use persistent token cache on disk.
.DESCRIPTION
    This cmdlet will enable a client application object to use persistent token cache on disk.
    The token cache can be customized with options for directory location, file naming, and encryption settings.
.EXAMPLE
    PS C:\>Enable-MsalTokenCacheOnDisk $ClientApplication
    Enable client application to use persistent token cache on disk.
.EXAMPLE
    PS C:\>Enable-MsalTokenCacheOnDisk $ClientApplication -PassThru
    Enable client application to use persistent token cache on disk and return the object.
.EXAMPLE
    PS C:\>Enable-MsalTokenCacheOnDisk $ClientApplication -CacheDirectory "C:\TokenCache" -CacheFileName "CustomCache.bin"
    Enable client application to use persistent token cache on disk with a custom directory and file name.
.EXAMPLE
    PS C:\>Enable-MsalTokenCacheOnDisk $ClientApplication -DisableAutomaticEncryption
    Enable client application to use persistent token cache on disk without automatic encryption.
    This is not recommended for production environments.
.EXAMPLE
    PS C:\>$ClientApplication = New-MsalClientApplication -ClientId "00000000-0000-0000-0000-000000000000"
    PS C:\>$ClientApplication | Enable-MsalTokenCacheOnDisk -CacheDirectory "$env:USERPROFILE\.tokens" -BackupFilesCount 5
    Create a client application and enable token caching with a custom directory and keep 5 backup files.
.EXAMPLE
    PS C:\>Enable-MsalTokenCacheOnDisk $ClientApplication -PartitionKey "MyAppKey" -EnableMacPartitioning
    Enable partitioned token cache with a custom partition key and Mac-style partitioning for improved isolation.
#>
function Enable-MsalTokenCacheOnDisk {
    [CmdletBinding(DefaultParameterSetName = 'PublicClient')]
    [OutputType([Microsoft.Identity.Client.PublicClientApplication], [Microsoft.Identity.Client.ConfidentialClientApplication])]
    param
    (
        # Public client application
        [Parameter(Mandatory = $true, ParameterSetName = 'PublicClient', Position = 0, ValueFromPipeline = $true)]
        [Microsoft.Identity.Client.IPublicClientApplication] $PublicClientApplication,

        # Confidential client application
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfidentialClient', Position = 0, ValueFromPipeline = $true)]
        [Microsoft.Identity.Client.IConfidentialClientApplication] $ConfidentialClientApplication,

        # Custom directory path to store the token cache file
        [Parameter(Mandatory = $false)]
        [string] $CacheDirectory,

        # Custom file name for the token cache
        [Parameter(Mandatory = $false)]
        [string] $CacheFileName,

        # Disable automatic encryption of the token cache
        [Parameter(Mandatory = $false)]
        [switch] $DisableAutomaticEncryption,

        # Number of backup files to maintain
        [Parameter(Mandatory = $false)]
        [int] $BackupFilesCount,

        # Use a custom partition key for the token cache
        [Parameter(Mandatory = $false)]
        [string] $PartitionKey,

        # Enable Mac-style cache partitioning
        [Parameter(Mandatory = $false)]
        [switch] $EnableMacPartitioning,

        # Returns client application
        [Parameter(Mandatory = $false)]
        [switch] $PassThru
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublicClient" {
            $ClientApplication = $PublicClientApplication
            break
        }
        "ConfidentialClient" {
            $ClientApplication = $ConfidentialClientApplication
            break
        }
    }

    if ([System.Environment]::OSVersion.Platform -eq 'Win32NT' -and $PSVersionTable.PSVersion -lt [version]'6.0') {
        # Configure TokenCacheHelper settings if provided
        if ($PSBoundParameters.ContainsKey('CacheDirectory')) {
            [TokenCacheHelper]::SetCacheDirectory($CacheDirectory)
        }

        if ($PSBoundParameters.ContainsKey('CacheFileName')) {
            [TokenCacheHelper]::SetCacheFileName($CacheFileName)
        }

        if ($DisableAutomaticEncryption) {
            [TokenCacheHelper]::DisableEncryption()
        }

        if ($PSBoundParameters.ContainsKey('BackupFilesCount')) {
            [TokenCacheHelper]::SetBackupCount($BackupFilesCount)
        }

        if ($PSBoundParameters.ContainsKey('PartitionKey')) {
            [TokenCacheHelper]::SetPartitionKey($PartitionKey)
        }

        if ($EnableMacPartitioning) {
            [TokenCacheHelper]::EnableMacKeychain()
        }

        # Enable cache serialization for the appropriate cache types
        if ($ClientApplication -is [Microsoft.Identity.Client.IConfidentialClientApplication]) {
            [TokenCacheHelper]::EnableSerialization($ClientApplication.AppTokenCache)
        }
        [TokenCacheHelper]::EnableSerialization($ClientApplication.UserTokenCache)
    }
    else {
        Write-Warning 'Using TokenCache On Disk only works on Windows platform using Windows PowerShell. The token cache will stored in memory and not persisted on disk.'
    }

    if ($PassThru) {
        Write-Output $ClientApplication
    }
}
