# 01. Token inspector

**What the diagram shows:** a box labelled "Issue Token" with an arrow coming out of it.

**What it hides:** that box produced a specific set of claims with a specific lifetime, and almost every security decision downstream depends on claims most people have never looked at. The arrow is not a token. It is a signed JSON document that your API is now trusting, and if you cannot name what is inside it, you cannot say what your API is actually enforcing.

This sample signs a user in, gets an access token for its own API, and shows you the token from the only place entitled to open it: the resource. Every claim is annotated with what it is for and whether you are allowed to make a decision with it. A live countdown runs against `exp`, because the second most common misconception about tokens is that you can take one back.

## What is in here

| Path | What it does |
| --- | --- |
| `src/server.mjs` | The resource. Validates the bearer token with `jose` against the tenant JWKS: signature, `iss`, `aud`, `exp`, `nbf`, `tid`, `ver` and `scp` |
| `src/claims.mjs` | The claim catalogue: every claim, one line on what it is for, and a verdict of authorization, display only, internal or protocol |
| `src/facts.mjs` | The verified facts behind `GET /api/token-facts`, each with the Microsoft Learn page it came from |
| `src/public/index.html` | Single page app, no framework, no build step, MSAL Browser v3 from jsDelivr |
| `src/public/app.js` | Auth code with PKCE, `cp1` client capability, the countdown, and the side by side claim tables |
| `infra/main.bicep` | Subscription scoped azd entry point. Creates the resource group, delegates the rest |
| `infra/resources.bicep` | Log Analytics, Application Insights, Linux B1 plan, App Service on Node 24 LTS with system assigned identity, HTTPS only, TLS 1.2, FTPS disabled |
| `scripts/register-apps.sh` | Creates both app registrations, exposes `Inspect.Read`, pre-authorizes the SPA, registers `xms_cc` and `idtyp` |
| `scripts/register-apps.ps1` | The same thing for PowerShell |

## Two apps, and which one is allowed to read what

There are two registrations here on purpose.

The **SPA** is the client. It signs the user in and holds tokens. It reads its own ID token, because an ID token is issued to a client as a sign-in receipt and reading it is the entire point. It never parses the access token: it forwards it and renders what comes back.

The **API** is the resource. Its client ID is the `aud` value on the access token, so it is the only party that may validate and read one. This asymmetry is not pedantry. A client that validates a token it did not receive as `aud` is a confused deputy waiting to happen, and Microsoft Graph tokens use a proprietary format that these rules cannot validate at all.

That is why this page has a prominent warning and no Graph token anywhere in it.

## The claims that decide things

| Claim | Why it is on the panel |
| --- | --- |
| `tid` + `oid` | The only safe composite identity key. Unique, immutable, not administrator editable |
| `scp` vs `roles` | `scp` means a user is present and the call is delegated. `roles` with no `scp` means app-only, and there is nobody to filter for |
| `idtyp` | Optional claim. Value `app` is what makes authorizing on `azp` safe. Without it you cannot tell an app-only token from a user token from the same client |
| `azp` / `azpacr` | Which client asked, and how it authenticated: 0 public client, 1 client secret, 2 certificate. A resource can insist on 2 |
| `amr` | How the user proved who they are. A statement about the past, not a guarantee about now |
| `acrs` | Conditional Access authentication context already satisfied. Missing plus a sensitive operation equals a claims challenge, not a 403 |
| `xms_cc` | Whether the client can survive a claims challenge. Needs `cp1` from the client AND the optional claim on the resource |
| `aio`, `rh` | Internal to Entra ID. Present in the token, off limits to you |
| `email`, `preferred_username`, `upn`, `unique_name` | Mutable, reassignable, administrator controllable. UI labels only, never authorization keys |

Optional claims are registered on the **resource's** application object, never the client's, because access tokens are always generated from the resource manifest. `scripts/register-apps.sh` does it with a single `PATCH /applications/{objectId}` carrying an `optionalClaims` object with `idToken`, `accessToken` and `saml2Token` arrays of `{name, source, essential, additionalProperties}`.

## Lifetime, which is the part nobody checks

The countdown in the UI is the real `exp`, and it is unusual to see the number twice in a row.

- The default access token lifetime is randomized between **60 and 90 minutes**, averaging 75. That is deliberate: if every token expired on a round number, every client on earth would refresh in the same second and spike traffic to Entra ID.
- Tenants with no Conditional Access get a **2 hour** default for clients such as Teams and Microsoft 365.
- **Revoking sessions does not reach an access token already issued.** That call invalidates refresh tokens and browser session cookies. Microsoft guidance on removing a user's access says that for applications using access tokens, the user loses access when the access token expires. A continuous access evaluation aware client is the exception, because the resource rejects the token early.
- In a **continuous access evaluation** session the picture inverts. The access token becomes long lived, **20 to 28 hours**, because revocation moves from expiry to a signal from the resource. Configurable Token Lifetime policy is not honored for CAE-aware sessions.
- Refresh tokens last 90 days by default, but **24 hours** when the redirect URI is registered as type `spa`, which this one is. They also rotate on every use, so the one the browser holds now is not the one it received at sign-in.

## Run it

### 1. Register the apps (needs an admin, once)

This step writes to the directory, so it needs Application Administrator, Cloud Application Administrator or Global Administrator. It is not an azd hook and should not be: application objects outlive the resource group, and `azd down` should never delete them.

```bash
az login --allow-no-subscriptions
./scripts/register-apps.sh
```

or

```powershell
az login --allow-no-subscriptions
./scripts/register-apps.ps1
```

Both print the four values you need next. They are idempotent: re-running finds the apps by display name and patches them, reusing the existing scope ID so consent already granted stays valid.

### 2. Run it locally

```bash
npm install
AZURE_TENANT_ID=<tenant-guid> \
API_CLIENT_ID=<api-app-id> \
SPA_CLIENT_ID=<spa-app-id> \
npm start
```

Open http://localhost:3000 and sign in. That redirect URI is registered by default.

### 3. Deploy it

```bash
azd env new token-inspector
azd env set AZURE_TENANT_ID <tenant-guid>
azd env set API_CLIENT_ID   <api-app-id>
azd env set SPA_CLIENT_ID   <spa-app-id>
azd up
```

### If `register-apps` fails on pre-authorization

If you ran an early version of this script you may have seen:

```
Property api.preAuthorizedApplications.delegatedPermissionIds has a
Permission Id that cannot be found in the AppPermissions sets.
```

Entra validates `preAuthorizedApplications.delegatedPermissionIds` against the scopes that **already exist** on the application, not against the scopes being created in the same request. Creating the scope and pre-authorizing a client for it in one PATCH therefore fails on a new app registration. It is a race rather than a schema error, which is why it sometimes succeeds on a retry.

The script now does it in two PATCH calls, waits for the scope to become readable in between, and retries the second call five times with a backoff. Re-running is safe: it finds the existing app registrations by display name and reuses the scope ID if one is already there, so consent already granted is not invalidated.

The second call sends the whole `api` object, scope included, rather than just `preAuthorizedApplications`. PATCH replaces a complex property instead of merging into it, so a minimal body would delete the scope that was just created.

If the pre-authorization still does not take, the script says so and carries on. It is not fatal. The only consequence is a consent prompt on first sign-in instead of a silent one.

### Why the PowerShell version does not use `ErrorActionPreference = 'Stop'`

Because `az` is a native command, and Windows PowerShell 5.1 turns everything a native command writes to stderr into an `ErrorRecord`. Under `Stop`, that terminates the script. And `az` writes to stderr routinely: deprecation notices, survey prompts, and the perfectly ordinary "this resource does not exist" answer to an existence check. Neither `2>$null` nor `-ErrorAction SilentlyContinue` reliably prevents it.

So every `az` call in this script goes through one `Invoke-Az` helper that reads the exit code and returns `Ok`, `Text` and `Error`. Calls that genuinely must succeed are marked `-Required` and throw with a message naming what failed and what Graph said. Everything else, including service principal creation, degrades to a warning.

Service principal creation is in that second category on purpose. Entra creates the service principal on first sign-in regardless. The script does it early only so the apps appear under Enterprise applications before anyone has used them.

### If azd warns "no App Service deployment status change"

Read this before you change anything, because the warning is not a failure and reacting to it can break a deployment that was about to succeed.

`node_modules` is excluded from the deployment package, and Oryx installs the dependencies on the server. That first install is slow. On this sample it has taken over five minutes, which is longer than azd waits before it stops watching and prints:

```
WARNING: Service 'web': Deployment completed, but azd observed no App Service
deployment status change for 5m0s.
```

That means azd gave up watching. The build carries on without it. While it is still running, the container can start against a `wwwroot` that has the application and not yet its dependencies, and you will see this in the log:

```
Could not find build manifest file at '/home/site/wwwroot/oryx-manifest.toml'
Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'express'
```

That is a snapshot of a build in progress, not a verdict. Wait, then check the app itself:

```bash
az webapp show -g <rg> -n <app-name> --query "{state:state, runtime:siteConfig.linuxFxVersion}" -o table
curl -s -i https://<app-name>.azurewebsites.net/api/token-facts
```

The line that tells you it genuinely worked is in the startup log, and it is worth knowing what to look for:

```
> node src/server.mjs
Token inspector listening on port 8080
Site startup probe succeeded
Site started.
```

`WEBSITES_CONTAINER_START_TIME_LIMIT` is set to 600 seconds in `infra/resources.bicep` to give a cold start room against the 230 second default.

If the app really has failed, a container that exits during startup leaves the site **stopped**, not running. `azd up` starts it again, or `az webapp start -g <rg> -n <app-name>` does it directly.

### Do not "fix" this by shipping node_modules

It is tempting, and it was tried here, and it made things worse. Excluding `node_modules` and `SCM_DO_BUILD_DURING_DEPLOYMENT` are a matched pair. Changing one without the other gives you the missing dependency error for real. Changing both, so that the package carries dependencies installed on a developer machine, replaced a working deployment with a container that exited with code 1 in under a minute.

The remote build is the supported path for a Node app on App Service Linux. It is slow the first time. Slow is not broken.

### If the deploy hangs on "Starting runtime process, 0 successful instances"

The resources are provisioned by this point. What is stuck is the container start, and azd will keep polling until it gives up. Ctrl+C is safe: nothing is half-created, and the next `azd up` picks up where this one stopped.

Read the logs before changing anything. Guessing at a startup failure is slower than looking at it.

```bash
az webapp log tail --resource-group rg-<env-name> --name <app-name>
```

If that shows nothing, the container is failing before the app writes a line, and the Docker log has it instead:

```bash
az webapp log download --resource-group rg-<env-name> --name <app-name> --log-file logs.zip
```

The three causes worth checking first, in order:

1. **The Node runtime is not available in your region or subscription.** Runtime availability is not uniform, and a `linuxFxVersion` App Service accepts at deployment time can still fail to start. Check what you actually have, then pin it:

   ```bash
   az webapp list-runtimes --os linux | grep NODE
   azd env set NODE_VERSION 22-lts
   azd up
   ```

   `NODE_VERSION` accepts `24-lts`, `22-lts` or `20-lts`. It is a parameter rather than a hard coded string precisely so this is one command instead of a Bicep edit.

2. **The app crashed on startup.** The log shows the stack. This app is deliberately tolerant: it starts and warns rather than exiting when configuration is missing, so a crash here means a genuine fault rather than a missing environment variable.

3. **The health check path is failing.** `healthCheckPath` is `/api/token-facts`. If the app is listening but that route returns anything other than 200, App Service keeps restarting the instance and the deployment never reports a successful one. Test it directly once the app is up: `curl -i https://<app-name>.azurewebsites.net/api/token-facts`.

An app that listens on the wrong port produces exactly this symptom too, which is why `src/server.mjs` reads `process.env.PORT` and falls back to 3000 only for local runs. App Service sets `PORT` and routes to it. Hard coding 3000 in a container is one of the most common ways to get an infinite warmup.

### A note on the runtime

The template pins `NODE|24-lts`. It used to pin `NODE|20-lts`, which App Service now flags in the portal with "your app is targeting a runtime that is deprecated".

That warning is worth reading carefully, because it does not mean what people assume. Node 20 reached end of life on 30 April 2026. App Service follows the community support timeline, and its policy is that an app on a retired runtime keeps running unchanged. What stops is the security patching and the support. So nothing breaks, the app carries on serving traffic, and the only signal is a banner.

That is a reasonable thing for a sample about identity to be precise about. An unpatched runtime under a correctly validated token is still an unpatched runtime.

Node 24 is in active LTS support until October 2026 and reaches end of life in April 2028. To see what your subscription actually offers: `az webapp list-runtimes --os linux | grep NODE`.

### Deploy order

The order matters, and a `preprovision` hook enforces it. The Bicep tolerates empty client IDs so that `bicep build` and a what-if run never need real values, which means a deployment with them unset would otherwise succeed and then serve an app whose audience is an empty string. The hook fails the run before anything is provisioned and tells you which value is missing.

The hook is `scripts/preprovision.mjs`, and it runs under Node on both platforms for a reason worth borrowing. A `.ps1` hook is blocked on most Windows machines by the PowerShell execution policy, because the file is not digitally signed:

```
SecurityError: File ...\preprovision.ps1 cannot be loaded. The file is not
digitally signed. You cannot run this script on the current system.
```

Setting the policy at `CurrentUser` scope often does not stick, because Windows PowerShell 5.1 and PowerShell 7 keep separate stores and Group Policy can pin the machine value. A `.sh` hook is worse, because azd's `shell: sh` on Windows frequently resolves to WSL bash, which cannot see the repository path it was handed.

Running `node ./scripts/preprovision.mjs` sidesteps all of it. That is a command rather than a script file, so no execution policy applies, and Node is already a prerequisite here. One implementation instead of two, and nothing to sign.

If you are stuck on an older copy of this sample that still has the `.ps1` hook, this unblocks it for the current window only, which is the variant that survives the shell-version split and usually survives Group Policy too:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
azd up
```

`azd up` prints `AZURE_WEB_URI`. Add it as a second redirect URI, because a `spa` redirect URI has to match exactly:

```bash
REDIRECT_URIS="http://localhost:3000/ $(azd env get-value AZURE_WEB_URI)/" ./scripts/register-apps.sh
```

## What the API checks, in order

1. **Signature**, against `https://login.microsoftonline.com/{tid}/discovery/v2.0/keys` through `createRemoteJWKSet`. Never against a pinned key: Entra ID rolls signing keys without asking.
2. **`iss`**, which must be `https://login.microsoftonline.com/{tid}/v2.0`.
3. **`aud`**, which must equal this API's client ID GUID. A v1.0 token would carry the App ID URI instead, which is why the API also pins `ver` to `2.0`.
4. **`exp` and `nbf`**, with 60 seconds of clock skew.
5. **`tid`**, cross checked against the expected tenant.
6. **`scp`**, because a valid token and a permitted call are different questions.

Failures come back as `401` or `403` with a `WWW-Authenticate: Bearer` header, which is what a client needs in order to tell "sign in again" apart from "you are not allowed".

## Where this is the wrong answer

- **This app decodes a token it owns.** That is the only reason it is allowed to. Do not build token decoding into a client, and never into a client for a resource you do not own. Clients treat access tokens as opaque strings. `jwt.ms` is sanctioned for debugging, not for runtime behaviour.
- **A token inspector is a debugging tool, not a security control.** It tells you what your policy produced. It does not enforce anything. Do not leave it deployed on a public endpoint with real user data in the tokens.
- **App Service B1 with a public endpoint is a demo shape.** A real deployment of anything that reads tokens wants Private Endpoints, a WAF in front and no public inbound at all. This template optimizes for "you can see it working in ten minutes", which is a different goal.
- **If your tenant enforces token protection or a device compliance grant**, this browser SPA on an unmanaged machine will not get a token at all. That is not a bug in the sample. That is the policy working, and the empty page is the correct outcome.
- **`xms_cc` will probably be missing the first time.** It needs the client to declare `cp1` and the resource to register the optional claim. The sample does both, but if you registered the apps by hand in the portal, expect the blank.

## Reference

- [Access tokens in the Microsoft identity platform](https://learn.microsoft.com/entra/identity-platform/access-tokens)
- [Access token claims reference](https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference)
- [ID token claims reference](https://learn.microsoft.com/entra/identity-platform/id-token-claims-reference)
- [Secure applications and APIs by validating claims](https://learn.microsoft.com/entra/identity-platform/claims-validation)
- [Provide optional claims to your app](https://learn.microsoft.com/entra/identity-platform/optional-claims)
- [Claims challenges, claims requests and client capabilities](https://learn.microsoft.com/entra/identity-platform/claims-challenge)
- [Refresh tokens in the Microsoft identity platform](https://learn.microsoft.com/entra/identity-platform/refresh-tokens)
- [Continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Single-page application: app registration](https://learn.microsoft.com/entra/identity-platform/scenario-spa-app-registration)
- [Azure Developer CLI: azure.yaml schema](https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-schema)
