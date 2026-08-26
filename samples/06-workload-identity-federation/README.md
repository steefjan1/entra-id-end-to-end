# 06. Step 1 says "User Signs In", and most sign-ins are not users

**What the diagram shows:** a person at the top of the flow, signing in, with Conditional Access, MFA and risk detection drawn neatly around them, and everything downstream flowing from that one human decision.

**What it hides:** in a real tenant, most of the principals that sign in are not people. They are service principals and managed identities: pipelines, daemons, function apps, monitoring agents, the integration somebody stood up in 2022 with a two year secret. They authenticate constantly, they hold broader permissions than any individual user in the directory, and almost none of the controls drawn around step 1 apply to them. There is no MFA for them, because there is nobody to prompt. Conditional Access reaches only some of them, with three conditions and exactly one grant control. Mandatory MFA enforcement explicitly exempts them. Run `src/workload-inventory.mjs` and count the rows.

This sample builds the good version of a workload identity (federated, secretless, one role, one container) and then measures how far the controls actually reach.

## What is in here

| Path | What it does |
| --- | --- |
| `src/workload-inventory.mjs` | **Start here.** Every service principal and application in the tenant, ranked worst first: tenancy, credential type, days to the nearest secret or certificate expiry, federated credential count, application permissions on Microsoft Graph resolved to names, which of those are high impact, and a computed verdict. `--json` for a pipeline gate |
| `src/create-fic.mjs` | Creates a federated identity credential on an **app registration** through Graph, which is the path Bicep cannot take. Presets for GitHub branch, pull request, environment and tag subjects, and for Kubernetes. Prints the remaining quota out of 20, validates the field limits before Graph does, and refuses a duplicate name because `name` is immutable |
| `src/ca-workload-policy.mjs` | Creates a Conditional Access policy scoped to service principals, in report only, blocking sign-in from outside a named location. Refuses to run without a named location ID, prints the licensing text verbatim, and checks whether the principals you targeted are even covered |
| `infra/main.bicep` | Subscription scoped azd entry point. Creates the resource group, calls `resources.bicep`, outputs everything the workflow needs prefixed `AZURE_` |
| `infra/resources.bicep` | A user assigned managed identity, a federated identity credential on it for GitHub Actions, a locked down storage account and one Storage Blob Data Reader assignment scoped to that account |
| `.github/workflows/deploy.yml` | Signs in with `azure/login@v2` and `permissions: id-token: write`, no secret anywhere, then proves data plane access by listing a blob container. The comment block at the top is the explanation of the exchange |

## The two halves, and why there are two

A federated identity credential is the same idea in both places and a completely different object depending on what you attach it to.

| | User assigned managed identity | App registration |
| --- | --- | --- |
| What it is | An Azure resource | A directory object |
| Created by | ARM, so Bicep, Terraform, CLI | Microsoft Graph |
| Type or endpoint | `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials` | `POST /applications/{objectId}/federatedIdentityCredentials` |
| In this sample | `infra/resources.bicep` | `src/create-fic.mjs` |
| Limit | 20 per identity | 20 per application |
| Flexible credentials (preview) | Not supported | Supported, beta only |
| Conditional Access | Never covered | Covered if single tenant |

Both accept exactly the same three fields, and those three fields are the entire trust decision:

```json
{
  "name": "testing02",
  "issuer": "https://login.microsoftonline.com/3d1e2be9-a10a-4a0c-8380-7ce190f98ed9/v2.0",
  "subject": "a7d388c3-5e3f-4959-ac7d-786b3383006a",
  "audiences": [ "api://AzureADTokenExchange" ]
}
```

Field limits Graph enforces: `name` is 3 to 120 characters, URL friendly, **immutable after creation**, and supports `$filter eq`. `issuer`, `subject`, each `audiences` value and `description` are 600 characters each, and `subject` also supports `$filter eq`. Immutable means what it says: if the name is wrong, you delete and recreate. There is no PATCH for it, and `create-fic.mjs` tells you so instead of letting Graph return a confusing error.

## The subject strings, which are the whole security model

The audience is `api://AzureADTokenExchange` for every provider. The issuer is fixed per provider. So the subject is the only thing that separates your pipeline from anybody else's.

GitHub Actions, issuer `https://token.actions.githubusercontent.com`:

| Preset | Subject | Trusts |
| --- | --- | --- |
| `github-branch` | `repo:octo-org/octo-repo:ref:refs/heads/main` | any run on that branch |
| `github-environment` | `repo:octo-org/octo-repo:environment:production` | any run in that environment |
| `github-tag` | `repo:octo-org/octo-repo:ref:refs/tags/v1.2.3` | any run on that tag |
| `github-pull-request` | `repo:octo-org/octo-repo:pull-request` | **every pull request against that repository** |

Kubernetes, issuer is the cluster OIDC issuer URL:

```
system:serviceaccount:<NAMESPACE>:<NAME>
```

Matching is exact. No wildcards, no prefixes. A credential for `refs/heads/main` does not match a run on `refs/heads/release`, and that is the feature, not a limitation to work around.

## Run it

```bash
npm install

# 1. What is actually in the tenant. Read only, no writes anywhere.
npm run inventory

# 2. Everything, including Microsoft first party and the low verdict rows.
npm run inventory -- --all --limit 500

# 3. Machine readable, for a pipeline gate or a week to week diff.
npm run inventory:json > workloads.json

# 4. Deploy the managed identity, its federated credential, the storage
#    account and the role assignment. See the note below on the RBAC
#    permission this step needs.
azd env set GITHUB_ORG octo-org
azd env set GITHUB_REPO octo-repo
azd env set GITHUB_SUBJECT_KIND environment
azd env set GITHUB_REF_NAME production
azd up

# 5. The other half: a federated credential on an APP REGISTRATION.
#    Plan first. Nothing is sent.
npm run fic:plan -- --app-id <clientId> --preset github-environment \
  --org octo-org --repo octo-repo --environment production

# 6. Do it for real.
npm run fic -- --app-id <clientId> --preset github-environment \
  --org octo-org --repo octo-repo --environment production

# 7. What is on that application now, and how much quota is left of 20.
npm run fic:list -- --app-id <clientId>

# 8. Kubernetes workload identity.
npm run fic -- --app-id <clientId> --preset kubernetes \
  --issuer https://oidc.prod-aks.azure.com/<guid>/ \
  --namespace default --service-account workload-identity-sa

# 9. Conditional Access for workload identities. Plan first, always.
npm run ca:plan -- --named-location <namedLocationId> --sp <spObjectId>

# 10. Create it, in report only, which is the default and the only state
#     that does not need --confirm.
npm run ca -- --named-location <namedLocationId> --sp <spObjectId>
```

Every write script honours `--dry-run`, or `DRY_RUN=1` if you prefer the environment variable. Authentication defaults to device code against the Microsoft Graph PowerShell first party app, so you can run it without registering anything. Set `ENTRA_AUTH_MODE=azurecli` to reuse an existing `az login`, or `ENTRA_AUTH_MODE=clientsecret` for an unattended run, which is a slightly awkward thing to do in this particular sample.

## What `azd up` needs that other templates do not

This template creates a role assignment, and creating a role assignment needs `Microsoft.Authorization/roleAssignments/write`. Contributor does not have it. If the identity running `azd up` is only Contributor on the subscription, the deployment provisions the managed identity, the federated credential and the storage account, and then fails on the last resource with `AuthorizationFailed`. You need **Owner** or **User Access Administrator** on the target scope.

Two other things to know before the first run:

- Microsoft's mandatory MFA enforcement for Azure management reached create, update and delete operations through the Azure CLI, Azure PowerShell, infrastructure as code tools and the ARM API on 1 October 2025. Reads are exempt. A sign-in that has not been MFA challenged will fail the provision, not the login.
- The federated credential name is immutable after creation. Changing `FEDERATED_CREDENTIAL_NAME` and rerunning `azd up` creates a second credential rather than renaming the first, and the limit is 20 per identity.

## Permissions

| Operation | Least privileged permission |
| --- | --- |
| Deploy the template (`azd up`) | Owner or User Access Administrator on the target scope, because of the role assignment |
| Read the workload inventory | `Application.Read.All`, `Directory.Read.All` |
| Create a federated credential (delegated) | `Application.ReadWrite.All` |
| Create a federated credential (app only) | `Application.ReadWrite.OwnedBy`, or `Application.ReadWrite.All` |
| Read and write Conditional Access policies | `Policy.Read.All` plus `Policy.ReadWrite.ConditionalAccess` |

`Application.ReadWrite.OwnedBy` is the least privileged option for the app only case and is worth the extra setup: an automation that can add a federated credential to **any** application in the tenant can add one pointing at its own repository, to the most privileged app you own. That is the shape of a real attack, not a theoretical one, and `Application.ReadWrite.All` is on the high impact list in `workload-inventory.mjs` for exactly this reason.

## Conditional Access for workload identities, stated precisely

Licensing, verbatim:

> "Workload Identities Premium licenses are required to create or modify Conditional Access policies scoped to service principals. In directories without appropriate licenses, existing Conditional Access policies for workload identities continue to function, but can't be modified."

Scope, verbatim:

> "Policy can be applied to single tenant service principals that are registered in your tenant. Microsoft and third-party SaaS applications, including multitenant apps, are not covered by these policies. Managed identities aren't covered by policy."

Service principals in groups are also not covered. Assign directly.

**Conditions available:** location, service principal risk, authentication contexts. That is the complete list.

**Grant controls available:** `block`. That is the complete list.

The policy condition that makes a policy a workload identity policy:

```json
"clientApplications": {
  "includeServicePrincipals": [ "ServicePrincipalsInMyTenant" ],
  "excludeServicePrincipals": [ "<sp-object-id>" ]
}
```

Creation is `POST /identity/conditionalAccess/policies` with `state` set to exactly one of `enabled`, `disabled` or `enabledForReportingButNotEnforced`.

Put the four facts together and the coverage is narrow. The managed identity this sample deploys in `infra/` is not covered. Every multitenant app in your tenant is not covered. For the single tenant service principals that are left, you can block them by location or by risk, and that is the entire toolkit.

## Continuous access evaluation for workload identities

Narrower again, and worth knowing before you build a revocation story on it:

- **Microsoft Graph only.** Not Azure Resource Manager, not your storage account, not your own APIs.
- Single tenant service principals only. Not managed identities, not multitenant apps.
- Long lived tokens, up to **24 hours**.
- Enforces **only** location and risk conditions.

So a compromised pipeline identity holding an Azure RBAC role is not something continuous access evaluation revokes. Removing the role assignment is.

## Mandatory MFA does not apply here, and that is the point

Phase 2 of Azure mandatory multifactor authentication started **1 October 2025**, covering Azure CLI, Azure PowerShell, the Azure mobile app, infrastructure as code tools, the ARM REST API and the Azure SDK, for **create, update and delete only**, with reads exempt.

**Workload identities are exempt.** Managed identities and service principals, plus Entra Connect and Cloud Sync accounts. Break glass accounts are **not** exempt, which surprises people in the other direction.

That exemption is correct and necessary, since there is nobody to prompt. It is also the clearest statement available that the control drawn around step 1 of the diagram was never designed to reach the principals doing most of the sign-ins. Whatever protects the pipeline, it is not MFA.

## The 20 credential limit, and the preview that fixes it

Twenty federated identity credentials per application, and twenty per user assigned managed identity. On a monorepo with one credential per environment per service, this runs out sooner than anyone plans for.

**Flexible federated identity credentials** are the answer and they are **preview**:

```json
{
  "name": "FlexFic1",
  "issuer": "https://token.actions.githubusercontent.com",
  "audiences": ["api://AzureADTokenExchange"],
  "claimsMatchingExpression": { "value": "claims['sub'] matches 'repo:contoso/contoso-repo:ref:refs/heads/*' and claims['repository_id'] eq '456789'", "languageVersion": 1 }
}
```

The constraints, all of which matter:

- `claimsMatchingExpression` is **mutually exclusive with `subject`**. Send one or the other, never both.
- `languageVersion` is always `1`.
- Operators are `matches` (with `?` and `*` wildcards), `eq` and `and`.
- **Beta endpoint only.**
- Preview support is limited to GitHub Actions, GitLab and Terraform Cloud tokens.
- **Application objects only.** Not user assigned managed identities.
- Microsoft Graph or the portal only. No Azure CLI, no PowerShell, no Terraform provider.

`create-fic.mjs` supports this with `--preset flexible` and prints that list every time, because a wildcard subject is exactly the kind of thing that gets copied into production and then widened by one character.

## Two things this report deliberately does not flag

Both were bugs first, found by running it against a real tenant with 348 service principals.

**A managed identity is not multitenant.** Graph returns `signInAudience` as `null` for a managed identity, and `null !== undefined`, so a check written as `signInAudience !== undefined && signInAudience !== 'AzureADMyOrg'` labels every managed identity in the tenant multitenant. On the tenant this was tested against, that was 27 rows of confident nonsense, and it inflated the multitenant count in the summary from a handful to 76. Absent audience means not applicable, never multitenant.

**Azure rotates a managed identity's certificate for you.** Stale `keyCredentials` entries linger on the service principal object, so the report was announcing certificates that expired two thousand days ago as HIGH risk. Five of them, above the one row in the tenant that actually mattered. A finding nobody can act on, crowding out one they can.

So managed identity rows now say `managed identity` in the tenancy column, are not scored on credential expiry, and carry one note instead:

> managed identity: no Conditional Access at all, and no credential to rotate. Its blast radius is entirely its Azure RBAC and Graph permissions

Which is the true and useful statement about them. The control surface for a managed identity is not its credential, because it does not really have one you own. It is the permissions and the RBAC scope.

## Where this is the wrong answer

- **Federated credentials remove the secret. They do not remove the trust decision.** A subject of `repo:org/repo:pull-request` means anyone who can open a pull request against that repository can obtain your Azure token. It carries no branch, no environment and no author. On a public repository, that is everyone with a GitHub account. Scope to a branch or a protected GitHub environment, not to pull requests, unless you know exactly what that means and have decided you want it. `create-fic.mjs` prints a warning for that preset and creates it anyway, because sometimes you do want it, and because a tool that silently refuses is a tool people work around.
- **Conditional Access for workload identities does not cover managed identities at all, and its only grant control is block.** If your plan was "require MFA for the pipeline", there is no such thing. There is no prompt, no device compliance, no terms of use, no approved client app. There is a location condition, a risk condition, an authentication context, and the word block. Plan the control you can actually build, which is a small RBAC scope and a narrow federated subject, rather than the policy you wish existed.
- **The 20 credential per application limit is a real design constraint, not a footnote.** A monorepo with twelve services and four environments does not fit, and neither does one identity per branch on a busy repository. Flexible federated credentials solve it, and they are preview and application objects only, so they cannot help the managed identity in `infra/` at all. If you are near the limit today, the answer is more app registrations with narrower scopes, which is better design anyway, not a preview feature in a production pipeline.
- **A workload identity inventory is a snapshot, and nobody reads a report twice.** Secrets expire on their own schedule, new service principals appear the week after you run it, and a spreadsheet from last quarter is worse than nothing because it feels like coverage. The useful control is a scheduled job that consumes `--json` and fails the build 30 days before anything expires. Building that job is the actual deliverable. Running `npm run inventory` once and pasting the table into a document is not.
- **A federated credential does not make the identity less privileged.** It changes how the workload proves who it is, and nothing else. An identity with `Directory.ReadWrite.All` and a federated credential is exactly as dangerous as the same identity with a client secret, and it is now harder to notice because the secret expiry that used to force an annual conversation about it is gone. Every credential you federate is one fewer reason anyone will ever look at that principal's permissions again. That is what the `highImpact` column in the inventory is for.
- **If you have one pipeline and one subscription, most of this is overhead.** Deploy the managed identity, wire up the workflow, scope the role assignment tightly, and stop. The inventory script matters when you have a hundred principals and no idea what they hold. It does not matter when you have three and you made all of them last month.

## Reference

- [What are workload identities](https://learn.microsoft.com/entra/workload-id/workload-identities-overview)
- [Workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
- [Configure an application to trust an external identity provider](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust)
- [Configure a user assigned managed identity to trust an external identity provider](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity)
- [Flexible federated identity credentials (preview)](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-config-app-trust-managed-identity)
- [Create federatedIdentityCredential](https://learn.microsoft.com/graph/api/application-post-federatedidentitycredentials)
- [federatedIdentityCredential resource type](https://learn.microsoft.com/graph/api/resources/federatedidentitycredential)
- [Conditional Access for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/workload-identity)
- [Create conditionalAccessPolicy](https://learn.microsoft.com/graph/api/conditionalaccessroot-post-policies)
- [Continuous access evaluation for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)
- [Mandatory multifactor authentication for Azure, including the workload identity exemption](https://learn.microsoft.com/entra/identity/authentication/concept-mandatory-multifactor-authentication)
- [Securing workload identities with Microsoft Entra ID Protection](https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk)
- [servicePrincipal resource type](https://learn.microsoft.com/graph/api/resources/serviceprincipal)
- [List appRoleAssignments granted to a service principal](https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)
- [Configure OpenID Connect in Azure from GitHub Actions](https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect)
- [Azure built-in roles for storage, including Storage Blob Data Reader](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/storage)
