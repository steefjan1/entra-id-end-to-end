# 03. Conditional Access as code, with tests

**What the diagram shows:** a shield labelled "Evaluate Access".

**What it hides:** that shield is a set of policies someone clicked together in a portal, with no history, no review, no test, and no way to answer "what breaks if I turn this on" other than turning it on.

This sample treats Conditional Access the way you would treat any other production control plane. Policies are files. Changes go through a pull request. A guard refuses to ship anything that could lock you out. And the tenant gets tested against a set of expected verdicts before and after every change.

## What is in here

| Path | What it does |
| --- | --- |
| `policies/*.json` | Five policies as declarative Graph payloads, with `${ENV_VAR}` placeholders instead of hard coded object IDs |
| `src/bootstrap-prereqs.mjs` | Creates the break glass group, the device code exception group and the named location the policies refer to, and checks the tenant's licences |
| `src/guard.mjs` | Refuses to ship a policy that does not exclude your break glass group, and downgrades `enabled` to report only unless you opt in |
| `src/deploy.mjs` | Creates or updates by `displayName`, so it is idempotent |
| `src/whatif.mjs` | Runs `tests/scenarios.json` through the Graph What If API and fails the build on an unexpected verdict |
| `tests/scenarios.json` | Five hypothetical sign ins and what you expect Conditional Access to do with each |
| `.github/workflows/conditional-access.yml` | Pull request plan, merge deploy, then test. No secrets, uses workload identity federation |

## Why report only is the default here

Every policy file ships as `enabledForReportingButNotEnforced`. That is one of exactly three values Graph accepts for `state`, and it is the one that logs a verdict without acting on it. You then read the "Report-only" tab in the sign-in logs to see what the policy would have done to real traffic.

Turning that off takes two deliberate acts: set `"state": "enabled"` in the file *and* set `ALLOW_ENABLED=1` in the environment. One without the other gets downgraded with a warning.

## The break glass rule

`guard.mjs` fails the build if a policy with a grant control targets human users and does not exclude the group in `BREAK_GLASS_GROUP_ID`.

This is not paranoia. Conditional Access has no "except the person who wrote it" fallback. A policy that requires a compliant device, applied to All users and All apps, locks out every administrator in the tenant including the one who created it, and the only route back is a Microsoft support case.

Note that break glass accounts are **not** exempt from Microsoft's mandatory MFA enforcement for admin portals and Azure management. Use FIDO2 or certificate based authentication on them rather than a long password in a safe.

## Conditional Access unit tests

`POST /identity/conditionalAccess/evaluate` is the API behind the portal's What If button. It answers "given this user, this app, this device and this risk level, which policies apply and what would they require" without anyone signing in.

Each scenario asserts three things, all optional:

```json
"expect": {
  "policiesApply": ["CAC002 Require MFA for admin portals"],
  "policiesDoNotApply": ["CAC001 Block legacy authentication"],
  "grantControls": ["mfa"]
}
```

When a scenario fails, the script prints the `analysisReasons` value Graph returned, which tells you *why* a policy did not apply: `users`, `application`, `devicePlatform`, `location`, `signInRisk`, `policyNotEnabled` and so on. That is usually the whole diagnosis.

The most valuable scenario in the file is the second one. It asserts that the break glass account is not caught by any of your own policies. Run it on every change, forever.

## Run it

```bash
npm install    # at the repository root, see the note in the top level README

# 0. Create the objects the policies refer to, and check this tenant can
#    actually run them. Creates two groups and a named location, all inert.
#    It never creates a Conditional Access policy.
npm run bootstrap:plan                      # show what it would do
npm run bootstrap -- --egress 203.0.113.0/24

# It prints the environment variables to set next.

# 1. Lint the files. Nothing touches the tenant.
BREAK_GLASS_GROUP_ID=<group-object-id> \
DEVICE_CODE_EXCEPTION_GROUP_ID=<group-object-id> \
CORPORATE_NAMED_LOCATION_ID=<named-location-id> \
npm run lint

# 2. Print the exact Graph calls without sending them.
BREAK_GLASS_GROUP_ID=... npm run plan

# 3. Deploy in report only.
BREAK_GLASS_GROUP_ID=... npm run deploy

# 4. Evaluate the scenarios.
TEST_USER_ID=<user-object-id> BREAK_GLASS_USER_ID=<user-object-id> npm test
```

Authentication defaults to device code against the Microsoft Graph PowerShell first party app, so you can run it without registering anything. Set `ENTRA_AUTH_MODE=azurecli` to reuse an existing `az login`, or `ENTRA_AUTH_MODE=clientsecret` for an unattended run.

## Who you have to be signed in as

Two different things are being asked of the account at the device code prompt, and both need an administrator:

1. **Consent.** `Group.ReadWrite.All` and `Policy.ReadWrite.ConditionalAccess` are admin consent permissions. A member account gets "Need admin approval" and stops there.
2. **The operations themselves.** Creating groups needs Groups Administrator. Creating Conditional Access policies needs Conditional Access Administrator or Security Administrator. Consent alone would not be enough.

So sign in as an account holding those roles, or Global Administrator. Consent happens once per tenant, and afterwards other administrators run these scripts without seeing the prompt again.

A test account created for sample 02 is the wrong account here. That one exists to have its sessions revoked, and it should stay unprivileged.

### The shortcut: reuse your Azure CLI sign-in

If you are already signed in to the Azure CLI as an account with the right roles, skip the device code prompt and the consent question entirely:

```powershell
az login                              # as the administrator
az ad signed-in-user show --query userPrincipalName -o tsv   # confirm who that is
$env:ENTRA_AUTH_MODE = "azurecli"
npm run bootstrap:plan
```

This works because the token then comes from the Azure CLI's own first party application, which already carries broad delegated Microsoft Graph consent in most tenants. Nothing new is granted, no prompt appears, and the account you are signed in to `az` with is the account the script acts as.

It is also the honest answer to "who is the administrator here". If `az ad user create` and `az ad app create` worked for you earlier, the identity behind them holds the roles, and that is the identity to use.

### If you would rather not consent the Graph PowerShell app

The default client is the Microsoft Graph PowerShell first party application, because it needs no setup. Granting it `Group.ReadWrite.All` and `Policy.ReadWrite.ConditionalAccess` tenant wide is a real privilege grant, applying to everyone who uses that client, and `samples/06`'s inventory script would rank the result as high impact. That is a fair thing to hesitate over.

The alternative is a dedicated app registration with exactly these permissions, which is revocable on its own and shows up under its own name in Enterprise applications:

```powershell
az ad app create --display-name "entra-samples-cli" --is-fallback-public-client true `
  --public-client-redirect-uris "http://localhost"
$env:ENTRA_CLIENT_ID = "<the appId it prints>"
$env:ENTRA_TENANT_ID = "<your tenant id>"
```

Every script in this repository reads `ENTRA_CLIENT_ID`, so that is the only change needed.

## Licences, and what to do without them

`npm run bootstrap` reads `/subscribedSkus` and prints a table before it creates anything, because discovering a licence gap from a 403 halfway through a deployment is a worse experience than being told up front.

| Policy | Needs |
| --- | --- |
| 01, 02, 03 | Entra ID P1 |
| 04 | Entra ID P2, for the sign-in risk condition |
| 05 | Workload Identities Premium, on top of P1 |

Most lab tenants do not have Workload Identities Premium, and one unlicensed policy should not block the other four:

```bash
SKIP_POLICIES=05 npm run deploy
```

`SKIP_POLICIES` takes a comma separated list of filename prefixes and applies to the guard, the plan and the deploy alike.

With no P1 at all, the guard and the plan still work offline. They are pure file operations, and linting policy as code without a tenant is a perfectly reasonable thing to do in CI.

## Permissions

| Operation | Least privileged permission |
| --- | --- |
| Read policies | `Policy.Read.All` |
| Create and update policies | `Policy.ReadWrite.ConditionalAccess` |
| What If evaluation | `Policy.Read.ConditionalAccess` |

Delegated callers also need the Conditional Access Administrator or Security Administrator role. Application permissions work for all three, which is what the pipeline uses.

## Where this is the wrong answer

- **Small tenant, few policies, one administrator.** The portal is fine. This machinery pays for itself when several people change policy and nobody can reconstruct why.
- **You have not solved identity for the pipeline itself.** A CA deployment pipeline holding a client secret is a worse risk than the drift it fixes. Use workload identity federation (sample 06) or do not automate it.
- **The `authenticationStrength` grant control.** It is a navigation property, not a plain field, so it needs an `@odata.bind` reference to an authentication strength policy. These files deliberately stay on `builtInControls` to keep the deploy script readable. Extend it if you need phishing resistant strength.
- **Continuous access evaluation session controls.** `continuousAccessEvaluation`, `secureSignInSession` and the Global Secure Access filtering profile only exist in the `/beta` endpoint. This sample stays on `v1.0`.
- **Session token lifetimes.** Configurable Token Lifetime for refresh and session tokens was retired in January 2021. Sign-in frequency in a session control is the replacement, and it is what `policies/02` and `policies/04` use.

## Reference

- [Create conditionalAccessPolicy](https://learn.microsoft.com/graph/api/conditionalaccessroot-post-policies)
- [conditionalAccessConditionSet resource](https://learn.microsoft.com/graph/api/resources/conditionalaccessconditionset)
- [conditionalAccessRoot: evaluate (What If)](https://learn.microsoft.com/graph/api/conditionalaccessroot-evaluate)
- [whatIfAnalysisResult resource](https://learn.microsoft.com/graph/api/resources/whatifanalysisresult)
- [Conditional Access for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/workload-identity)
- [Block authentication flows with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)
