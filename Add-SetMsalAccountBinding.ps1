# Save this script as Add-SetMsalAccountBinding.ps1

# First let's add the function directly to the module
$functionPath = ".\build\complete-module\MSAL.PS\4.69.1\Set-MsalAccountBinding.ps1"
$functionContent = Get-Content $functionPath -Raw

# Make sure the PSD1 file includes it
$psdPath = ".\build\complete-module\MSAL.PS\4.69.1\MSAL.PS.psd1"
$psd = Import-PowerShellDataFile $psdPath

# Add the function to FunctionsToExport
$functions = $psd.FunctionsToExport
if ($functions -notcontains 'Set-MsalAccountBinding') {
    $functions += 'Set-MsalAccountBinding'

    # Build the new functions to export string
    $functionsStr = "FunctionsToExport = @(`r`n    '" + ($functions -join "',`r`n    '") + "'`r`n)"

    # Update the manifest
    $content = Get-Content $psdPath -Raw
    $content = $content -replace "FunctionsToExport = @\(.*?\)", $functionsStr
    $content | Set-Content $psdPath

    Write-Host "Added Set-MsalAccountBinding to FunctionsToExport in module manifest" -ForegroundColor Green
}

# Check the psm1 to make sure the file is included
$psmPath = ".\build\complete-module\MSAL.PS\4.69.1\MSAL.PS.psm1"
$psm = Get-Content $psmPath -Raw

# Check if the file is in the $psFiles array
if ($psm -notmatch "'Set-MsalAccountBinding.ps1'") {
    $psm = $psm -replace "(\`$psFiles = @\([^)]*)", "`$1`r`n    'Set-MsalAccountBinding.ps1',"
    $psm | Set-Content $psmPath

    Write-Host "Added Set-MsalAccountBinding.ps1 to psFiles array in module script" -ForegroundColor Green
}

Write-Host "Module updated. Please reimport with:" -ForegroundColor Cyan
Write-Host "Import-Module .\build\complete-module\MSAL.PS\4.69.1\MSAL.PS.psd1 -Force -Verbose" -ForegroundColor Cyan
