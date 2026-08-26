# Preflight for azd up, native PowerShell.
#
# This exists as a .ps1 as well as a .sh because azd's "shell: sh" resolves to
# whichever sh it finds on Windows, which is often WSL bash expecting
# /mnt/c/... paths rather than Git Bash. Splitting the hook into posix and
# windows sub-keys in azure.yaml avoids that guess entirely.
#
# See the repository README if PowerShell refuses to run this because it is
# not digitally signed.

$ErrorActionPreference = 'Stop'

$missing = $false
$guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Test-Required {
    param([string]$Name)

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Host "  missing: $Name"
        return $false
    }
    if ($value -notmatch $guid) {
        Write-Host "  not a GUID: $Name=$value"
        return $false
    }
    return $true
}

Write-Host 'Checking the app registrations this deployment depends on.'

if (-not (Test-Required -Name 'API_CLIENT_ID')) { $missing = $true }
if (-not (Test-Required -Name 'SPA_CLIENT_ID')) { $missing = $true }

if ($missing) {
    Write-Host ''
    Write-Host 'This sample needs two app registrations before it can deploy anything useful.'
    Write-Host 'They are a separate step because creating them needs an administrator, and azd'
    Write-Host 'does not have that scope.'
    Write-Host ''
    Write-Host '  ./scripts/register-apps.ps1'
    Write-Host '  azd env set API_CLIENT_ID <api-app-client-id>'
    Write-Host '  azd env set SPA_CLIENT_ID <spa-app-client-id>'
    Write-Host '  azd up'
    Write-Host ''
    Write-Host 'AZURE_TENANT_ID is optional. Left unset, the template uses the tenant azd is'
    Write-Host 'signed in to.'
    exit 1
}

Write-Host '  API_CLIENT_ID and SPA_CLIENT_ID look like GUIDs. Continuing.'
