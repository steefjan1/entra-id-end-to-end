// Subscription scoped entry point, the standard azd shape: this template owns
// the resource group and delegates everything inside it to resources.bicep.
//
// What this deploys is the half of workload identity federation that ARM can
// actually do:
//
//   Microsoft.ManagedIdentity/userAssignedIdentities
//   Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials
//
// That second type is the ARM resource type for a federated credential on a
// USER ASSIGNED MANAGED IDENTITY. An APP REGISTRATION is not an ARM resource,
// it is a directory object, so a federated credential on an app registration is
// created through Microsoft Graph instead:
//
//   POST https://graph.microsoft.com/v1.0/applications/{objectId}/federatedIdentityCredentials
//
// Bicep cannot reach that. src/create-fic.mjs is the other half of this sample
// and does exactly that call.

targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the azd environment. Used to name and tag every resource.')
param environmentName string

@minLength(1)
@description('Azure region for all resources.')
param location string

@minLength(1)
@description('GitHub organization or user that owns the repository, the Org in repo:Org/Repo.')
param githubOrg string

@minLength(1)
@description('GitHub repository name, the Repo in repo:Org/Repo.')
param githubRepo string

@description('Which GitHub subject shape to trust. Prefer environment or branch. Read the README before you choose pullRequest.')
@allowed([
  'branch'
  'environment'
  'tag'
  'pullRequest'
])
param githubSubjectKind string = 'environment'

@description('Branch name, environment name or tag name, depending on githubSubjectKind. Ignored when githubSubjectKind is pullRequest, because that subject carries no name.')
param githubRefName string = 'production'

@description('Name of the federated identity credential. 3 to 120 characters, URL friendly, and immutable after creation.')
@minLength(3)
@maxLength(120)
param federatedCredentialName string = 'github-deploy'

var tags = {
  'azd-env-name': environmentName
}

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

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
    githubOrg: githubOrg
    githubRepo: githubRepo
    githubSubjectKind: githubSubjectKind
    githubRefName: githubRefName
    federatedCredentialName: federatedCredentialName
  }
}

output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = tenant().tenantId
output AZURE_SUBSCRIPTION_ID string = subscription().subscriptionId
output AZURE_RESOURCE_GROUP string = rg.name

// AZURE_CLIENT_ID is what azure/login@v2 wants in the workflow. It is the
// client ID of the managed identity, not its principal ID and not its
// resource ID. Getting those three confused is the single most common
// federated credential failure.
output AZURE_CLIENT_ID string = resources.outputs.identityClientId
output AZURE_IDENTITY_NAME string = resources.outputs.identityName
output AZURE_IDENTITY_PRINCIPAL_ID string = resources.outputs.identityPrincipalId
output AZURE_STORAGE_ACCOUNT_NAME string = resources.outputs.storageAccountName
output AZURE_STORAGE_CONTAINER_NAME string = resources.outputs.storageContainerName
output AZURE_FEDERATED_CREDENTIAL_NAME string = resources.outputs.federatedCredentialName
output AZURE_FEDERATED_CREDENTIAL_ISSUER string = resources.outputs.federatedCredentialIssuer
output AZURE_FEDERATED_CREDENTIAL_SUBJECT string = resources.outputs.federatedCredentialSubject
output AZURE_FEDERATED_CREDENTIAL_AUDIENCE string = resources.outputs.federatedCredentialAudience
