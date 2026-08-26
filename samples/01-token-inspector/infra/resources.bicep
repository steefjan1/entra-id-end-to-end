// Everything inside the resource group: Log Analytics, Application Insights,
// a Linux App Service plan and the app that hosts the inspector.

@description('Azure region for all resources.')
param location string

@description('Tags applied to every resource, including the azd environment tag.')
param tags object

@description('Deterministic suffix so names stay unique inside the subscription.')
param resourceToken string

@description('Directory (tenant) ID that issues the tokens this API validates.')
param entraTenantId string

@description('Client ID (GUID) of the API app registration.')
param apiClientId string

@description('Client ID (GUID) of the single page app registration.')
param spaClientId string

@description('Delegated scope the API requires on an incoming token.')
param requiredScope string

@description('App Service Linux Node runtime, without the NODE| prefix.')
param nodeVersion string = '24-lts'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      searchVersion: 1
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${resourceToken}'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: 'plan-${resourceToken}'
  location: location
  tags: tags
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// azd matches this tag to the service named "web" in azure.yaml.
resource web 'Microsoft.Web/sites@2023-12-01' = {
  name: 'app-${resourceToken}'
  location: location
  tags: union(tags, {
    'azd-service-name': 'web'
  })
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      // Node 20 reached end of life on 30 April 2026. App Service keeps
      // running an app on a retired runtime but stops shipping security
      // patches for it, and the portal flags the app as deprecated.
      // Node 24 is in active LTS support until October 2026 and reaches
      // end of life in April 2028.
      //
      // Parameterised because runtime availability varies by region and
      // subscription, and finding that out should not mean editing Bicep:
      //   azd env set NODE_VERSION 22-lts && azd up
      linuxFxVersion: 'NODE|${nodeVersion}'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/api/token-facts'
      appCommandLine: 'npm start'
      appSettings: [
        {
          // The Entra application this API is. @azure/identity reads
          // AZURE_CLIENT_ID and AZURE_TENANT_ID by convention, and the same
          // client ID is the aud value every incoming v2.0 token must carry.
          name: 'AZURE_CLIENT_ID'
          value: apiClientId
        }
        {
          name: 'AZURE_TENANT_ID'
          value: entraTenantId
        }
        {
          name: 'API_CLIENT_ID'
          value: apiClientId
        }
        {
          name: 'SPA_CLIENT_ID'
          value: spaClientId
        }
        {
          name: 'REQUIRED_SCOPE'
          value: requiredScope
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          // Dependencies are installed on the server by Oryx, because
          // node_modules is excluded from the deployment package. The two
          // settings are a pair: see .webappignore.
          //
          // The first build is slow, and slower than azd waits for. A run that
          // ends with "azd observed no App Service deployment status change"
          // has often still succeeded a couple of minutes later. Check the app
          // before concluding anything from that warning.
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          // Give a cold start room. The default container start time limit is
          // 230 seconds, and a first start that has to page in a freshly
          // installed node_modules can get close to it.
          name: 'WEBSITES_CONTAINER_START_TIME_LIMIT'
          value: '600'
        }
      ]
    }
  }
}

resource webDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: web
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
      {
        category: 'AppServiceAppLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output webAppName string = web.name
output webUri string = 'https://${web.properties.defaultHostName}'
output webPrincipalId string = web.identity.principalId
output appInsightsName string = appInsights.name
output logAnalyticsName string = logAnalytics.name
output diagnosticSettingsName string = webDiagnostics.name
