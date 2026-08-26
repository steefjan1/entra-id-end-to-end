// Everything inside the resource group.
//
// Three resources and one role assignment, which is the whole of a working
// secretless pipeline identity:
//
//   1. A user assigned managed identity. This is the thing GitHub becomes.
//   2. A federated identity credential on it. This is the trust statement:
//      "a token from this issuer, with this subject, for this audience, may
//      be exchanged for a token for this identity."
//   3. A storage account the pipeline can prove it reached.
//   4. Storage Blob Data Reader for the identity on that storage account.
//
// Note the resource type on the credential:
//
//   Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials
//
// That is the ARM type, and it only exists for user assigned managed
// identities. An app registration has no ARM resource type at all. Its
// federated credentials live on the application object in the directory and
// are created through Microsoft Graph. See src/create-fic.mjs.

@description('Azure region for all resources.')
param location string

@description('Tags applied to every resource, including the azd environment tag.')
param tags object

// uniqueString() always returns 13 characters. The bounds are declared so the
// compiler can prove 'st${resourceToken}' fits a storage account name, which
// is 3 to 24 lowercase alphanumeric characters.
@description('Deterministic suffix so names stay unique inside the subscription.')
@minLength(1)
@maxLength(22)
param resourceToken string

@description('GitHub organization or user that owns the repository.')
param githubOrg string

@description('GitHub repository name.')
param githubRepo string

@description('Which GitHub subject shape to trust.')
@allowed([
  'branch'
  'environment'
  'tag'
  'pullRequest'
])
param githubSubjectKind string

@description('Branch name, environment name or tag name. Ignored for pullRequest.')
param githubRefName string

@description('Name of the federated identity credential. 3 to 120 characters, URL friendly, and immutable after creation.')
@minLength(3)
@maxLength(120)
param federatedCredentialName string

// The GitHub Actions OIDC issuer. This value is the same for every repository
// on github.com. GitHub Enterprise Server has its own issuer URL.
var githubIssuer = 'https://token.actions.githubusercontent.com'

// The audience is api://AzureADTokenExchange for every provider: GitHub,
// GitLab, Kubernetes, Terraform Cloud, all of them. It is not a per tenant
// or per application value.
var tokenExchangeAudience = 'api://AzureADTokenExchange'

var repoSlug = '${githubOrg}/${githubRepo}'

// The subject is the entire security decision. Everything else in the
// credential is fixed by the provider.
//
//   branch        repo:Org/Repo:ref:refs/heads/<branch>
//   tag           repo:Org/Repo:ref:refs/tags/<tag>
//   environment   repo:Org/Repo:environment:<Name>
//   pullRequest   repo:Org/Repo:pull-request
//
// pull-request carries no branch and no environment. It means every pull
// request against the repository, including one opened by somebody who has
// never had write access. Read the README section on this before using it.
var subjectByKind = {
  branch: 'repo:${repoSlug}:ref:refs/heads/${githubRefName}'
  tag: 'repo:${repoSlug}:ref:refs/tags/${githubRefName}'
  environment: 'repo:${repoSlug}:environment:${githubRefName}'
  pullRequest: 'repo:${repoSlug}:pull-request'
}

var federatedSubject = subjectByKind[githubSubjectKind]

// Storage Blob Data Reader. Read only, data plane, and deliberately not a
// control plane role: the pipeline should be able to list blobs and nothing
// more. Role definition IDs are constant across every Azure tenant.
var storageBlobDataReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'

var blobContainerName = 'proof'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${resourceToken}'
  location: location
  tags: tags
}

// The trust statement. There is no secret here, and there is no secret
// anywhere else either. The only thing that authenticates the pipeline is a
// token GitHub minted, matched against these three fields.
//
// Limit: 20 federated identity credentials per user assigned managed identity,
// and 20 per application. That is a real constraint on a monorepo with many
// environments.
resource federatedCredential 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: federatedCredentialName
  parent: identity
  properties: {
    issuer: githubIssuer
    subject: federatedSubject
    audiences: [
      tokenExchangeAudience
    ]
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st${resourceToken}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    // No anonymous blob access. The whole point of this sample is that access
    // is a token decision, so leaving a public read path open would undo it.
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    // Shared keys are the credential this sample exists to remove. Turning
    // them off means the identity is the only way in.
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: storage
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: blobContainerName
  parent: blobService
  properties: {
    publicAccess: 'None'
  }
}

// Scoped to the storage account, not the resource group and not the
// subscription. A pipeline identity that can read one container is a much
// smaller problem than a pipeline identity that can read the subscription.
resource blobReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, storageBlobDataReaderRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataReaderRoleId
    )
    principalId: identity.properties.principalId
    // ServicePrincipal, not User. A managed identity is a service principal in
    // the directory, and setting this explicitly avoids the replication race
    // where ARM cannot yet see a brand new principal.
    principalType: 'ServicePrincipal'
  }
}

output identityName string = identity.name
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output identityResourceId string = identity.id
output storageAccountName string = storage.name
output storageContainerName string = container.name
output roleAssignmentName string = blobReaderAssignment.name
output federatedCredentialName string = federatedCredential.name
output federatedCredentialIssuer string = federatedCredential.properties.issuer
output federatedCredentialSubject string = federatedCredential.properties.subject
output federatedCredentialAudience string = federatedCredential.properties.audiences[0]
