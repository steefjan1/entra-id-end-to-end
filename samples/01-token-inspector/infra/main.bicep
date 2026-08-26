// Subscription scoped entry point, the standard azd shape: this template owns
// the resource group and delegates everything inside it to resources.bicep.

targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the azd environment. Used to name and tag every resource.')
param environmentName string

@minLength(1)
@description('Azure region for all resources.')
param location string

@description('Directory (tenant) ID that issues the tokens this API validates. Leave empty to use the tenant azd is signed in to.')
param entraTenantId string = ''

@description('Client ID (GUID) of the API app registration. This is the aud value a v2.0 access token must carry.')
param apiClientId string = ''

@description('Client ID (GUID) of the single page app registration.')
param spaClientId string = ''

@description('Delegated scope the API requires on an incoming token.')
param requiredScope string = 'Inspect.Read'

@description('App Service Linux Node runtime, without the NODE| prefix. Node 20 reached end of life on 30 April 2026. Check what your subscription offers with: az webapp list-runtimes --os linux | grep NODE')
@allowed([
  '24-lts'
  '22-lts'
  '20-lts'
])
param nodeVersion string = '24-lts'

var tags = {
  'azd-env-name': environmentName
}

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

// azd substitutes an empty string for an environment variable it does not
// have, so fall back rather than deploying an app with a blank tenant.
var tenantId = empty(entraTenantId) ? tenant().tenantId : entraTenantId

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    entraTenantId: tenantId
    apiClientId: apiClientId
    spaClientId: spaClientId
    requiredScope: requiredScope
    nodeVersion: nodeVersion
  }
}

output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = tenantId
output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_API_CLIENT_ID string = apiClientId
output AZURE_SPA_CLIENT_ID string = spaClientId
output AZURE_WEB_APP_NAME string = resources.outputs.webAppName
output AZURE_WEB_URI string = resources.outputs.webUri
output AZURE_SPA_REDIRECT_URI string = '${resources.outputs.webUri}/'
output AZURE_APP_INSIGHTS_NAME string = resources.outputs.appInsightsName
output AZURE_LOG_ANALYTICS_NAME string = resources.outputs.logAnalyticsName
output AZURE_WEB_PRINCIPAL_ID string = resources.outputs.webPrincipalId
