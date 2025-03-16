<#
.SYNOPSIS
    Binds a user account to an application or tenant.
.DESCRIPTION
    This cmdlet enables you to bind a user account to a specific application or tenant
    for improved token acquisition performance.
#>
function Set-MsalAccountBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Identity.Client.IClientApplicationBase] $ClientApplication,

        [Parameter(Mandatory = $true)]
        [Microsoft.Identity.Client.IAccount] $Account,

        [Parameter(Mandatory = $false)]
        [string] $TenantId
    )

    process {
        # Handle account binding
        try {
            if ($TenantId) {
                $ClientApplication.BindToAccountAsync($Account, $TenantId).GetAwaiter().GetResult()
            }
            else {
                $ClientApplication.BindToAccountAsync($Account).GetAwaiter().GetResult()
            }
            Write-Verbose "Account successfully bound to application"
        }
        catch {
            Write-Error -Exception $_.Exception -Category ([System.Management.Automation.ErrorCategory]::OperationStopped) -CategoryActivity $MyInvocation.MyCommand
        }
    }
}
