# Microsoft Entra ID: end to end, including the parts the diagram leaves out

Every few weeks a Microsoft Entra ID architecture poster goes around LinkedIn. User signs in, request is redirected, authenticate, evaluate access, issue token, access application, with a dashed arrow looping back labelled "token renewal / continuous access evaluation".

None of it is wrong. All of it is true on the happy path. The problem is that the happy path is not where identity projects go wrong, and a diagram with six boxes and no failure states quietly suggests that six things are all there is.

This repository is the other half of that picture. Six samples, each one taking a single box from that flow and showing what it looks like when you have to operate it: what the token actually contains, how long a revoked user really keeps working, what a Conditional Access policy looks like when it is a file under review instead of a click in a portal, what privileged access management does not cover, where authority actually lives in a hybrid tenant, and what happens to all of this when the thing signing in is not a person.

Everything here runs against a real tenant. Nothing here is a slide.

## The map

| The diagram says | What it hides | Sample |
| --- | --- | --- |
| Issue Token | A specific set of claims with a randomized 60 to 90 minute lifetime, most of which nobody has looked at, and one composite key that is the only safe way to identify the caller | [01 token inspector](samples/01-token-inspector) |
| Token renewal / continuous access evaluation | Five critical events, four resource providers, and only for clients that opted in. Everything else waits for the token to expire | [02 continuous access evaluation, measured](samples/02-cae-claims-challenge) |
| Evaluate Access | A set of policies with no history, no test and no way to answer "what breaks if I enable this" other than enabling it | [03 Conditional Access as code, with tests](samples/03-conditional-access-as-code) |
| Privileged Identity Management | The activation window, and nothing at all about what the role can do once it is active | [04 PIM controls the window, not the payload](samples/04-pim-payload) |
| Hybrid Identity with Active Directory | A two directional authority gap, measured in minutes in one direction and in "never" in the other | [05 the hybrid authority gap](samples/05-hybrid-authority-gap) |
| User Signs In | Most sign-ins in a real Azure tenant are not users, and most of the controls in the diagram do not apply to the ones that are not | [06 workload identity federation](samples/06-workload-identity-federation) |

![Microsoft Entra ID end to end flow with its authority boundaries and failure paths](docs/entra-end-to-end-architecture.svg)

And the mechanism behind that dashed arrow, measured rather than described:

![Sequence diagram of a session revocation showing a CAE aware client cut off in four seconds and an ordinary client continuing to receive 200 OK](docs/revocation-sequence.svg)

## Five things in here that are worth the read even if you never run the code

1. **A revoked user keeps working for up to 90 minutes** unless the client asked for continuous access evaluation, which is one line of MSAL configuration. Measured on a real tenant: the CAE aware client was granted 1439 minutes and cut off 4 seconds after revocation, the other was granted 65 minutes and kept working for all of them. `samples/02` runs that measurement on your own tenant.
2. **Group and role changes are not continuous.** Continuous access evaluation covers five critical events. A group membership change is not one of them, and Microsoft documents the wait as up to one day.
3. **Disabling an account in Active Directory does not immediately end cloud access.** With password hash synchronization that takes up to 30 minutes, and password expiry and lockout states are not synchronized at all.
4. **Nothing writes a cloud disable back to Active Directory.** Neither Connect Sync nor Cloud Sync provisions user disable to AD, so Kerberos and LDAP access on premises continues after the cloud account is gone.
5. **PIM shortens the window, not the blast radius.** `samples/04` prints, per role, the activation limit next to the count of actions the role actually grants. A one hour window on a role with 400 allowed actions is not a control, it is a schedule.

## Getting started

Each sample stands alone and has its own README with its own prerequisites, permissions and "where this is the wrong answer" section. Start with whichever box in the diagram you are least sure about.

```bash
git clone https://github.com/steefjan1/entra-id-end-to-end.git
cd entra-id-end-to-end

# Install once, at the ROOT. This is an npm workspace.
npm install

# Samples 01 and 06 deploy Azure resources with the Azure Developer CLI.
cd samples/01-token-inspector && azd up

# Samples 02, 03, 04 and 05 are Node scripts against Microsoft Graph.
cd samples/03-conditional-access-as-code
BREAK_GLASS_GROUP_ID=<group-object-id> npm run lint
```

**Install at the root, not inside a sample.** The samples share `shared/js/graph.mjs`, and Node resolves a bare import like `@azure/identity` by walking up from the file doing the importing. From `shared/js/` that walk never reaches `samples/03/node_modules`, so a per sample install leaves the shared helper unable to find its own dependency:

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@azure/identity'
imported from ...\shared\js\graph.mjs
```

The root `package.json` declares an npm workspace covering `shared/js` and all six samples, so one `npm install` at the root puts everything where every file can see it. Running `npm install` inside a sample also works, because npm walks up, finds the workspace root and installs there instead.

### Prerequisites

| Tool | Needed for |
| --- | --- |
| Node.js 22 or later | Every sample |
| [Azure Developer CLI](https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd) | Samples 01 and 06 |
| Azure CLI or a device code sign-in | Graph authentication in every script |
| An Entra ID tenant you are allowed to break | All of it |

Every script defaults to device code authentication against the Microsoft Graph PowerShell first party application, so you can run these without registering anything. Set `ENTRA_AUTH_MODE=azurecli` to reuse an existing `az login`, or `ENTRA_AUTH_MODE=clientsecret` for an unattended run.

**Expect a consent prompt on first run, and read it.** Each script declares the delegated permissions it needs in its own source, right under the imports:

```js
useScopes(
  'Group.ReadWrite.All',
  'Policy.ReadWrite.ConditionalAccess',
  'Organization.Read.All',
);
```

That list is what the sign-in asks for, and an administrator consents to it once per tenant. The alternative, asking for `.default`, means "whatever this client was already consented for", which against the Graph PowerShell app is often `User.Read` and nothing else. Every interesting call then returns `403 Authorization_RequestDenied`, which reads as a role problem when it is really a consent problem. The shared helper says so explicitly when it sees a 403.

## Safety rules this repository follows

These are not decoration. Two of the six samples can lock you out of your own tenant if you skip them.

- **Every write supports a dry run**, which prints the exact Graph call and sends nothing. Pass `--dry-run` or set `DRY_RUN=1`. The `:plan` npm scripts use the argument form, because `DRY_RUN=1 node script.mjs` is POSIX shell syntax that npm cannot run through cmd.exe on Windows. Run every script dry first.
- **Conditional Access policies deploy in `enabledForReportingButNotEnforced`.** Turning that off takes two deliberate acts: `"state": "enabled"` in the file and `ALLOW_ENABLED=1` in the environment.
- **A break glass exclusion is enforced in code.** `samples/03` refuses to ship a policy that targets users, carries a grant control and does not exclude the group in `BREAK_GLASS_GROUP_ID`. There is no "except me" fallback in Conditional Access. If you block everyone, you are included.
- **Break glass accounts are not exempt from Microsoft's mandatory MFA enforcement.** Put FIDO2 or certificate based authentication on them, not a password in a safe.
- **Expected fallbacks print on stdout, not stderr.** On Windows, PowerShell renders anything a Node script writes to stderr as a red `NativeCommandError` block wrapped in a stack trace. A handled, documented fallback then looks exactly like a crash. Only genuinely fatal conditions here use `console.error`.
- **No sample deletes anything.** The most destructive operations here are a Conditional Access policy in report only, an eligible role assignment with an expiry, and a session revocation.

## Licences you will need

Not everything in here runs on Entra ID Free, and the READMEs say so per sample. Roughly:

| Capability | Licence |
| --- | --- |
| Conditional Access, named locations, token protection | Entra ID P1 |
| Identity Protection risk conditions, PIM, access reviews | Entra ID P2 |
| Access reviews of PIM for Groups, ML assisted certification, PIM custom extensions | Entra ID Governance |
| Conditional Access for workload identities | Workload Identities Premium |
| Entra Private Access and Internet Access | Entra ID P1 or P2, or the Entra Suite |
| Source of authority conversion | Entra ID Free |

## Status of the code

Sample 01 has been deployed to a real subscription and tenant, signed into, and verified end to end: app registrations created, token issued, validated by the API and rendered. Sample 06 compiles clean with `bicep build` and has not been deployed yet. The Graph payloads follow the documented request shapes and are cited in each README. If something does not behave the way a README claims on your tenant, that is a bug worth an issue, and the fix belongs here rather than in a comment thread.

## Reading order if you only have an hour

1. `samples/02` README, the measurement section. It is the shortest route to why this repository exists.
2. Run `samples/04/src/entitlement-report.mjs` against your own tenant. Most people find something.
3. Run `samples/05/src/sync-report.mjs`. Look at the last column.

## Licence

MIT. See [LICENSE](LICENSE).
