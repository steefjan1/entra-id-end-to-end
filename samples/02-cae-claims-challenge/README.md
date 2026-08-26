# 02. Continuous access evaluation, measured

**What the diagram shows:** a dashed arrow looping back from "Access Application" to "Authenticate", labelled "Token renewal / Continuous access evaluation".

**What it hides:** that arrow only exists for clients that asked for it, against resources that support it, for five specific events. Everything else waits for the token to expire, and the token decides when that is.

This sample turns the argument into a number you can put in a slide.

## What is in here

| Path | What it does |
| --- | --- |
| `src/stopwatch.mjs` | Signs the same user in twice, once declaring the `cp1` capability and once not, revokes their sessions, then polls Microsoft Graph with both tokens and reports how long each kept working |
| `src/claims-challenge.mjs` | Parses and builds the `WWW-Authenticate` claims challenge, with a self test you can run without a tenant |
| `src/step-up-api.mjs` | The resource side: an API that answers a token missing an authentication context with a proper claims challenge instead of a bare 401 |
| `src/setup-auth-context.mjs` | Creates the `c1` authentication context and the Conditional Access policy that gives it meaning |

## The measurement

```bash
npm install
npm run selftest    # no tenant needed, exercises the parser

# The recommended path: no extra Graph permission, you revoke from the portal.
node src/stopwatch.mjs --tenant <tenant-id>

# If device code flow is blocked in your tenant, use the browser instead.
node src/stopwatch.mjs --tenant <tenant-id> --interactive

# Or let the script revoke, which needs User.ReadWrite.All.
node src/stopwatch.mjs --tenant <tenant-id> --revoke
```

### What you need before it will tell you anything

| Requirement | Why |
| --- | --- |
| A **member** account, not a guest | Continuous access evaluation does not support B2B or guest accounts, and `revokeSignInSessions` does nothing for external users. The script checks and refuses |
| Sign-in that is not blocked | Device code flow is the first thing a hardened tenant blocks, including by a Microsoft-managed policy. Use `--interactive` if so |
| A tenant that issues CAE tokens | The script tells you: client A should come back with a lifetime measured in hours, not minutes |
| Permission to revoke | Only if you use `--revoke`. Otherwise revoke from the Entra admin center, which is the simpler path |

The default client is the Microsoft Graph PowerShell first party app, which is pre-consented in most tenants and already carries a loopback redirect URI, so `--interactive` works without registering anything. Pass `--client <app-id>` to use your own.

Sign in twice with the same account when prompted. This is a real run against a real tenant, trimmed in the middle:

```
Tokens acquired.
  client A lifetime remaining: 1439 minutes
  client B lifetime remaining: 65 minutes
  Client A got a long lived token, so this tenant is issuing CAE sessions.

07:54:27  t+0s    A: 200   B: 200
07:54:37  t+10s   A: 200   B: 200
      ... revokeSignInSessions called by an administrator at 07:57:38 ...
07:57:42  t+195s  client A (cp1, CAE aware) stopped working: claims challenge,
                  error=insufficient_claims,
                  claims={"access_token":{"nbf":{"essential":true,"value":"1787731058"}}}
07:57:42  t+195s  A: 401 STOPPED   B: 200
```

Read the numbers rather than the elapsed time. The `nbf` value in that challenge, 1787731058, decodes to **07:57:38Z**, which is the instant the revocation was stamped. Client A was rejected at **07:57:42**. Four seconds. The 195 on the clock is mostly the administrator getting round to running the command.

Client B carried on answering 200 for the remainder of its 65 minutes, and nothing in the tenant could shorten that.

Two clients, same user, same tenant, same revocation. One line of configuration between them:

```js
new PublicClientApplication({ auth: { clientId, authority, clientCapabilities: ['cp1'] } })
```

![Sequence diagram of a session revocation showing a CAE aware client cut off in four seconds and an ordinary client continuing to receive 200 OK](../../docs/revocation-sequence.svg)

## The claims challenge is not the one you expect

Most write-ups about CAE show the capability negotiation challenge, which asks the client to prove it can handle challenges at all:

```json
{"access_token":{"xms_cc":{"values":["cp1"]}}}
```

The revocation challenge is a different shape, and it is the one you will actually see:

```json
{"access_token":{"nbf":{"essential":true,"value":"1787731058"}}}
```

That is the resource saying: the token you presented was issued before the revocation instant, so bring me one issued at or after it. `nbf` is "not before", the value is the `signInSessionsValidFromDateTime` that `revokeSignInSessions` just stamped on the user, and `essential: true` means the client cannot negotiate it away.

It is worth understanding the difference, because a client that only knows how to answer the `xms_cc` shape will loop against the `nbf` one. Both arrive through the same `WWW-Authenticate` header, both decode from the same base64 `claims` parameter, and `src/claims-challenge.mjs` parses both without caring which it got.

## What continuous access evaluation actually covers

Five critical events, pushed from Entra to the resource provider:

1. The user account is deleted or disabled
2. The password is changed or reset
3. MFA is enabled for the user
4. An administrator explicitly revokes all refresh tokens for the user
5. Microsoft Entra ID Protection detects high user risk (SharePoint Online does not support this one)

Plus one policy condition, evaluated at the resource: IP based named locations. Nothing else.

That means a group membership change, a role assignment, a new Conditional Access policy or a changed one are **not** continuous. Microsoft documents replication for those as taking up to one day. An optimization brings that down to two hours, it applies to policy updates rather than to group membership, and the documentation says it does not cover all scenarios yet. The documented workaround is to revoke the user's sessions by hand.

Microsoft's own documentation on the point: policies targeting roles or groups are evaluated only when a token is issued, and if a user already has a valid token before being added to the role or group, the policy does not apply retroactively.

## Which resources and clients

Continuous access evaluation is not a tenant wide switch that either works or does not. Support is per resource, per client, per platform:

- **Resource providers:** Exchange Online, SharePoint Online, Teams and Microsoft Graph, with footnotes on each. Teams is marked partially supported in every row of the client matrix, and SharePoint Online does not support the user risk critical event. Azure Resource Manager is not on the list at all. Application Proxy has its own CAE implementation, GA and on by default, which works even when the on premises app knows nothing about it. Global Secure Access "Universal CAE" extends the reach to Private Access, Internet Access and Microsoft services that do not support it natively. Power Platform is Dataverse only and in preview. Azure DevOps rolled out through 2025 and 2026.
- **Clients:** the support matrix has real gaps. Office on the web is not supported. Teams to Exchange Online is partially supported. Office on the Semi-Annual Enterprise Channel loses CAE entirely if `DisableADALatopWAMOverride` or `DisableAADWAM` is set.
- **Guests:** CAE does not support B2B or guest accounts at all.

## The location trap

CAE understands IP based named locations only. Country and region conditions and MFA trusted IPs are invisible to it. If Entra sees an allowed IP and the resource provider sees a different one, which happens routinely with split tunnelling or an IPv4 versus IPv6 mismatch, Entra issues a one hour token that **suspends IP checks at the resource** until it expires. The same fallback happens if the total IP ranges across your location policies exceed 5,000.

Strict location enforcement fixes this, and it is in public preview, and it needs dedicated enumerable egress IPs for both authentication and resource traffic. Turning it on with shared egress is how you take yourself offline.

When you are diagnosing this, the two fields that matter are the "Is CAE Token" filter and "IP address (seen by resource)" in the sign-in logs, and you have to check the non-interactive tab as well as the interactive one.

## The step up demo

```bash
BREAK_GLASS_GROUP_ID=<group-id> node src/setup-auth-context.mjs --id c1 --confirm
API_CLIENT_ID=<api-app-id> ENTRA_TENANT_ID=<tenant-id> AUTH_CONTEXT_ID=c1 npm run api
curl -i -H "Authorization: Bearer <ordinary-token>" http://localhost:3000/api/sensitive
```

The 401 comes back with a header, and that header is the entire contract:

```
WWW-Authenticate: Bearer realm="", authorization_uri="https://login.microsoftonline.com/<tid>/oauth2/v2.0/authorize", error="insufficient_claims", claims="eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiYzEifX19"

{"access_token":{"acrs":{"essential":true,"value":"c1"}}}
```

`setup-auth-context.mjs` is the one script in this repository that will enable a policy for real rather than deploying it report only, and it explains why in its own header: a report only authentication context policy never issues the `acrs` claim, so the client can never satisfy the challenge. Its blast radius is limited to requests that explicitly ask for `c1`, which today is nothing except this API.

## Where this is the wrong answer

- **The account has to be a member of the tenant, not a guest.** Continuous access evaluation does not support B2B or guest accounts, and `revokeSignInSessions` does nothing for external users because they sign in through their home tenant. Run the stopwatch with a guest and both clients keep working, which reads as a broken script and is actually the documented behaviour. The tell is an `idp` claim on the ID token, or a home tenant that is not the one you targeted. `stopwatch.mjs` checks for this and refuses to run, with `--allow-guest` to override if you want to see the null result yourself.
- **Do not run the stopwatch against a colleague without telling them.** You are revoking a real person's sessions.
- **Declaring `cp1` is a commitment, not a flag.** A client that declares the capability and then does not handle claims challenges for every API it calls does not fail cleanly. It retries a token the resource has already rejected, in a loop. Declare it only when you have implemented the handler.
- **CAE is not a replacement for short lived credentials elsewhere.** It covers five events on four resource providers. Your database, your ERP and your SaaS applications are not in that list.
- **If your goal is fast revocation everywhere**, the honest answer today is Global Secure Access with Universal CAE for coverage, plus accepting that anything outside it waits up to 90 minutes.
- **`revokeSignInSessions` is not a kill switch.** It invalidates refresh tokens and browser session cookies by stamping `signInSessionsValidFromDateTime`. It does not invalidate access tokens already issued, it can take a few minutes, and it does nothing for external or B2B users because they sign in through their home tenant.

## Reference

- [Continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Strict location enforcement](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation-strict-enforcement)
- [Claims challenges, claims requests and client capabilities](https://learn.microsoft.com/entra/identity-platform/claims-challenge)
- [Build resilience with continuous access evaluation](https://learn.microsoft.com/entra/identity-platform/app-resilience-continuous-access-evaluation)
- [Access tokens](https://learn.microsoft.com/entra/identity-platform/access-tokens)
- [user: revokeSignInSessions](https://learn.microsoft.com/graph/api/user-revokesigninsessions)
- [Troubleshoot continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/howto-continuous-access-evaluation-troubleshoot)
