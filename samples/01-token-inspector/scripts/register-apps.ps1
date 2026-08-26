<#
.SYNOPSIS
  Creates the two app registrations this sample needs.

.DESCRIPTION
  A prerequisite, not an azd hook. It writes to the directory, so it needs a
  directory role (Application Administrator, Cloud Application Administrator or
  Global Administrator). azd up will not do it for you and should not:
  application objects outlive the resource group.

  Idempotent: re-running finds the existing apps by display name and patches
  them rather than creating duplicates.

  Requires the az CLI, logged in with: az login --allow-no-subscriptions

.EXAMPLE
  ./register-apps.ps1 -RedirectUris @('http://localhost:3000/', 'https://app-abc.azurewebsites.net/')
#>

[CmdletBinding()]
param(
  [string]$ApiAppName = 'token-inspector-api',
  [string]$SpaAppName = 'token-inspector-spa',
  [string]$ScopeName = 'Inspect.Read',
  [string[]]$RedirectUris = @('http://localhost:3000/')
)

# Deliberately NOT 'Stop'.
#
# az is a native command. Windows PowerShell 5.1 turns everything it writes to
# stderr into an ErrorRecord, and under ErrorActionPreference = 'Stop' that
# terminates the script. az writes to stderr routinely: deprecation notices,
# survey prompts, and the perfectly ordinary "this resource does not exist"
# answer to an existence check. A script that dies on those is a script that
# dies three times in a row for three unrelated reasons.
#
# So: run every az call through Invoke-Az, which reads the exit code, and mark
# the calls that genuinely must succeed with -Required.
$ErrorActionPreference = 'Continue'
$graph = 'https://graph.microsoft.com/v1.0'

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
  throw 'az CLI not found. Install it and run: az login --allow-no-subscriptions'
}

<#
  Runs az and reports what happened instead of throwing at the shell's whim.
  Returns Ok (exit code was zero), Text (stdout), Error (stderr) and Code.
  With -Required, a non-zero exit throws with a message worth reading.
#>
function Invoke-Az {
  param(
    [Parameter(Mandatory)][string[]]$Arguments,
    [switch]$Required,
    [string]$What = 'az command'
  )

  $captured = & az @Arguments 2>&1
  $code = $LASTEXITCODE

  $isError = { $_ -is [System.Management.Automation.ErrorRecord] }
  $text = ($captured | Where-Object { -not (& $isError) } | Out-String).Trim()
  $errText = ($captured | Where-Object $isError | Out-String).Trim()

  if ($Required -and $code -ne 0) {
    throw "Failed while $What (az exit code $code).`n$errText"
  }

  return [pscustomobject]@{
    Ok    = ($code -eq 0)
    Text  = $text
    Error = $errText
    Code  = $code
  }
}

function Invoke-GraphPatch {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][hashtable]$Body,
    [switch]$Required,
    [string]$What = 'patching an application object'
  )

  $json = $Body | ConvertTo-Json -Depth 12 -Compress
  $file = [System.IO.Path]::GetTempFileName()
  try {
    # UTF8 with no byte order mark. Windows PowerShell 5.1's Set-Content
    # -Encoding utf8 emits a BOM, which az rest passes straight through and
    # Graph rejects as malformed JSON.
    [System.IO.File]::WriteAllText($file, $json, (New-Object System.Text.UTF8Encoding($false)))

    # Pass the body as a file. Quoting a JSON blob on a command line is the
    # single most reliable way to lose a day to shell escaping.
    $arguments = @(
      'rest', '--method', 'PATCH', '--uri', $Uri,
      '--headers', 'Content-Type=application/json',
      '--body', "@$file"
    )
    return Invoke-Az -Arguments $arguments -Required:$Required -What $What
  }
  finally {
    Remove-Item $file -Force -ErrorAction SilentlyContinue
  }
}

function Get-OrCreateApp {
  param([string]$DisplayName)

  $lookup = Invoke-Az -Arguments @(
    'ad', 'app', 'list', '--display-name', $DisplayName,
    '--query', '[0].{appId:appId,objectId:id}', '-o', 'json'
  )

  if ($lookup.Ok -and $lookup.Text -and $lookup.Text -ne 'null') {
    $existing = $lookup.Text | ConvertFrom-Json
    if ($existing -and $existing.appId) {
      return $existing
    }
  }

  $created = Invoke-Az -Required -What "creating the app registration $DisplayName" -Arguments @(
    'ad', 'app', 'create', '--display-name', $DisplayName,
    '--sign-in-audience', 'AzureADMyOrg',
    '--query', '{appId:appId,objectId:id}', '-o', 'json'
  )
  return $created.Text | ConvertFrom-Json
}

$tenantId = (Invoke-Az -Required -What 'reading the signed in tenant' -Arguments @(
  'account', 'show', '--query', 'tenantId', '-o', 'tsv'
)).Text
Write-Host "Tenant: $tenantId"

# The API app is the RESOURCE. Optional claims are registered here and nowhere
# else, because access tokens are always generated from the resource manifest.
$api = Get-OrCreateApp -DisplayName $ApiAppName
Write-Host "API app:  $ApiAppName  appId=$($api.appId) objectId=$($api.objectId)"

# The SPA app is the CLIENT. A redirect URI of type spa enables auth code with
# PKCE and the CORS token endpoint, and caps its refresh token at 24 hours.
$spa = Get-OrCreateApp -DisplayName $SpaAppName
Write-Host "SPA app:  $SpaAppName  appId=$($spa.appId) objectId=$($spa.objectId)"

# Reuse an existing scope ID so re-running does not invalidate consent that has
# already been granted.
$scopeLookup = Invoke-Az -Arguments @(
  'ad', 'app', 'show', '--id', $api.appId,
  '--query', "api.oauth2PermissionScopes[?value=='$ScopeName'].id | [0]", '-o', 'tsv'
)
$scopeId = $scopeLookup.Text
if ([string]::IsNullOrWhiteSpace($scopeId) -or $scopeId -eq 'None') {
  $scopeId = [guid]::NewGuid().ToString()
}
Write-Host "Scope:    $ScopeName  id=$scopeId"

# This has to be TWO patches, not one, and the reason is worth knowing.
#
# Entra validates api.preAuthorizedApplications.delegatedPermissionIds against
# the scopes that already exist on the application, not against the scopes
# being created in the same request. Send both together on a new app and it
# fails with:
#
#   Property api.preAuthorizedApplications.delegatedPermissionIds has a
#   Permission Id that cannot be found in the AppPermissions sets.
#
# It is a race, not a schema error, which is why it sometimes succeeds on a
# second attempt and why the app looks fine afterwards.
#
# Patch 1 creates the scope and everything that does not depend on it:
#
#   requestedAccessTokenVersion 2  ask for v2.0 access tokens, where aud is the
#                                  client ID GUID rather than the App ID URI
#   api.oauth2PermissionScopes     expose Inspect.Read as a delegated scope
#   optionalClaims.accessToken     xms_cc and idtyp, on the RESOURCE, which is
#                                  the only place they can be registered
#
# xms_cc still only appears if the client also declares the cp1 capability.
# The SPA in src/public/app.js does that with clientCapabilities: ['cp1'].
$scopeDefinition = @{
  id                      = $scopeId
  value                   = $ScopeName
  type                    = 'User'
  isEnabled               = $true
  adminConsentDisplayName = 'Inspect your own token'
  adminConsentDescription = 'Allows the app to call the token inspector API on behalf of the signed-in user.'
  userConsentDisplayName  = 'Inspect your own token'
  userConsentDescription  = 'Allows the app to show you what is inside the token issued for you.'
}

$apiBody = @{
  identifierUris = @("api://$($api.appId)")
  api            = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes      = @($scopeDefinition)
  }
  optionalClaims = @{
    idToken     = @()
    saml2Token  = @()
    accessToken = @(
      @{ name = 'xms_cc'; source = $null; essential = $false; additionalProperties = @() },
      @{ name = 'idtyp'; source = $null; essential = $false; additionalProperties = @() }
    )
  }
}

Invoke-GraphPatch -Required -What 'registering the scope on the API app' `
  -Uri "$graph/applications/$($api.objectId)" -Body $apiBody | Out-Null
Write-Host 'Patched API app (1 of 2): scope, v2 access tokens, optional claims xms_cc and idtyp.'

# Wait for the scope to actually be readable before anything references it.
$visible = $false
for ($i = 1; $i -le 10; $i++) {
  $found = Invoke-Az -Arguments @(
    'ad', 'app', 'show', '--id', $api.appId,
    '--query', "api.oauth2PermissionScopes[?id=='$scopeId'].id | [0]", '-o', 'tsv'
  )
  if ($found.Ok -and -not [string]::IsNullOrWhiteSpace($found.Text) -and $found.Text -ne 'None') {
    $visible = $true
    break
  }
  Start-Sleep -Seconds 2
}

if (-not $visible) {
  Write-Host "  Scope $scopeId is not readable yet after 20 seconds. Trying the pre-authorization anyway."
}

# Patch 2 adds the pre-authorization. The full api object is sent, including
# the scope, because PATCH replaces a complex property rather than merging
# into it, and a body carrying only preAuthorizedApplications would drop the
# scope that was just created.
$preAuthBody = @{
  api = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes      = @($scopeDefinition)
    preAuthorizedApplications   = @(
      @{
        appId                  = $spa.appId
        delegatedPermissionIds = @($scopeId)
      }
    )
  }
}

$preAuthDone = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
  $result = Invoke-GraphPatch -Uri "$graph/applications/$($api.objectId)" -Body $preAuthBody
  if ($result.Ok) {
    $preAuthDone = $true
    break
  }
  Write-Host "  Pre-authorization attempt $attempt did not take. Waiting for directory replication."
  Start-Sleep -Seconds ($attempt * 3)
}

if ($preAuthDone) {
  Write-Host 'Patched API app (2 of 2): the SPA is pre-authorized for the scope.'
}
else {
  Write-Host ''
  Write-Host 'Pre-authorization did not take after five attempts. This is NOT fatal.'
  Write-Host 'Everything else is registered and the sample works. The only difference is'
  Write-Host 'that the first sign-in shows a consent prompt for the Inspect.Read scope'
  Write-Host 'instead of skipping it. Re-run this script in a few minutes to clear it.'
  Write-Host ''
}

$spaBody = @{
  spa                    = @{ redirectUris = $RedirectUris }
  web                    = @{ redirectUris = @() }
  requiredResourceAccess = @(
    @{
      resourceAppId  = $api.appId
      resourceAccess = @(@{ id = $scopeId; type = 'Scope' })
    }
  )
}

Invoke-GraphPatch -Required -What 'setting the SPA redirect URIs and required resource access' `
  -Uri "$graph/applications/$($spa.objectId)" -Body $spaBody | Out-Null
Write-Host 'Patched SPA app: spa redirect URIs and the required resource access.'

# Service principals, so the apps appear in the tenant enterprise apps list.
#
# "az ad sp show" on a service principal that does not exist is an error rather
# than an empty result, and an existence check that errors is a bad existence
# check. Ask a question with an empty answer instead.
#
# None of this is required. Entra creates the service principal on first
# sign-in anyway. It is done here so the apps show up in Enterprise
# applications before anyone has used them.
foreach ($entry in @(
    @{ Name = $ApiAppName; AppId = $api.appId },
    @{ Name = $SpaAppName; AppId = $spa.appId }
  )) {

  $existing = Invoke-Az -Arguments @(
    'ad', 'sp', 'list', '--filter', "appId eq '$($entry.AppId)'", '--query', '[0].id', '-o', 'tsv'
  )

  if ($existing.Ok -and -not [string]::IsNullOrWhiteSpace($existing.Text)) {
    Write-Host "  Service principal already exists for $($entry.Name)."
    continue
  }

  $created = Invoke-Az -Arguments @('ad', 'sp', 'create', '--id', $entry.AppId)
  if ($created.Ok) {
    Write-Host "  Created the service principal for $($entry.Name)."
  }
  else {
    Write-Host "  Could not create the service principal for $($entry.Name). Not fatal, Entra creates it on first sign-in."
    if ($created.Error) {
      Write-Host "    $($created.Error -split "`n" | Select-Object -First 1)"
    }
  }
}

Write-Host ''
Write-Host 'Done. Feed these into azd:'
Write-Host ''
Write-Host "  azd env set AZURE_TENANT_ID $tenantId"
Write-Host "  azd env set API_CLIENT_ID   $($api.appId)"
Write-Host "  azd env set SPA_CLIENT_ID   $($spa.appId)"
Write-Host "  azd env set REQUIRED_SCOPE  $ScopeName"
Write-Host ''
Write-Host "Scope requested by the SPA: api://$($api.appId)/$ScopeName"
Write-Host "Redirect URIs currently registered as type spa: $($RedirectUris -join ', ')"
Write-Host ''
Write-Host 'After azd up, re-run with the deployed URL added as a second redirect URI:'
Write-Host '  $uri = azd env get-value AZURE_SPA_REDIRECT_URI'
Write-Host '  ./register-apps.ps1 -RedirectUris @(''http://localhost:3000/'', $uri)'
Write-Host ''
Write-Host 'Use AZURE_SPA_REDIRECT_URI rather than AZURE_WEB_URI. It already carries the'
Write-Host 'trailing slash the SPA sends, and a redirect URI has to match exactly.'
