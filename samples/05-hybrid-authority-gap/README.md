# 05. Hybrid identity is a boundary, and Conditional Access only guards one side of it

**What the diagram shows:** "Hybrid Identity with Active Directory" sitting quietly in a highlights list, one bullet among a dozen, with a tidy arrow from an on-premises directory into a cloud one.

**What it hides:** that arrow is a boundary between two systems that each believe they own the account, and only one of them has Conditional Access. Every object in your tenant is on one side of it. On the on-premises side, a disabled account keeps working in the cloud for up to about thirty minutes. On the cloud side, disabling the account does nothing at all to Kerberos, NTLM and LDAP, because there is no user disable writeback in either sync product. The arrow is not a pipe. It is a delay with a direction.

This sample exists because of a comment made under the LinkedIn post this repository responds to:

> "'Hybrid Identity with Active Directory' sitting quietly in the highlights list is doing more work than it looks like. Most orgs running this exact flow still have a slice of infrastructure straddling the AD-to-Entra boundary that never gets the same Conditional Access rigor as the cloud-native side."

That comment is correct. This sample turns it into numbers you can take to a meeting.

## What this sample is, and what it is not

There is no Active Directory to deploy here, and no Azure subscription in the build environment. So unlike samples 01 to 03, this one has no `azd up`, no Bicep and no infrastructure. It is two things instead:

1. **A measurement and reporting tool.** Point it at a real tenant and it tells you where authority actually lives for every user and group, which synced objects are stale right now, and which synced principals hold privileged Entra roles.
2. **A documented experiment.** `disable-propagation-watch.mjs` needs an operator with access to a domain controller, standing at a keyboard, disabling a test account. The script cannot do that part. It measures what happens after.

Nothing here closes the gap. Read the last section before you assume otherwise.

## What is in here

| Path | What it does |
| --- | --- |
| `src/sync-report.mjs` | **Start here.** Every user and group, with a computed `authority` column: `on-premises`, `cloud`, `cloud (converted)` or `stale sync`. Flags objects whose last sync is older than a threshold, because that is the window in which an Active Directory disable has not yet reached the cloud. Then joins synced principals against privileged Entra roles |
| `src/soa-inspect.mjs` | Reads `onPremisesSyncBehavior` for a user or a group, and optionally converts source of authority to the cloud with `PATCH { "isCloudManaged": true }`. Tries `/v1.0` first and falls back to `/beta`, and tells you which one answered |
| `src/disable-propagation-watch.mjs` | The experiment. Polls one user until `accountEnabled` flips to false and reports the elapsed time in minutes. Optional `--revoke` calls `revokeSignInSessions` and explains exactly what that does and does not invalidate |
| `src/control-coverage.mjs` | Which control reaches which surface, as a grid with a one line reason per cell. Static, no tenant contacted, driven from a JSON file you can adapt |
| `config/coverage.json` | The matrix behind `control-coverage.mjs`. Surfaces, controls, cells and footnotes. Edit it |

## The gap, in both directions

### On premises to cloud: the disable that has not arrived yet

Microsoft's own words about password hash synchronization, verbatim:

> "password hash synchronization doesn't immediately enforce changes in on-premises account states... a user has access to cloud apps until the user account state is synchronized to Microsoft Entra ID"

That is up to about **30 minutes** for a disabled account. Everything inside that window is working cloud access for an account your Active Directory already considers dead.

Two states never arrive at all, also verbatim:

> "The password expired and account locked-out states aren't currently synced to Microsoft Entra ID with Microsoft Entra Connect."

Pass-through authentication and federation do not have this window. They check disabled, locked out, expired password and sign-in hours in Active Directory **at sign-in time**. That is the actual difference between the authentication methods, and it is not the one that usually gets discussed.

Note the trap that follows: Microsoft still recommends enabling password hash synchronization whichever authentication method you choose, for resilience and for Identity Protection leaked credential detection. So most tenants have it enabled as a backup even when pass-through authentication or federation is primary. Having it on is right. Assuming it enforces account state is wrong.

### Cloud to on premises: the disable that goes nowhere

There is **no user disable writeback** in Entra Connect Sync or in Entra Cloud Sync. Disabling or deleting the cloud object does not disable the Active Directory account. Kerberos, NTLM and LDAP access on premises carries on exactly as before.

This is the half people forget, and `sync-report.mjs` cannot measure it, because Graph is on the wrong side of the boundary. If your offboarding runbook says "disable in Entra", somebody still has a file share.

## Run it

```bash
npm install

# 1. Where does authority live. Read only.
npm run report

# 2. Tighten the staleness threshold to the number that actually worries you.
npm run report -- --stale-minutes 30

# 3. Machine readable, for a pipeline gate or a diff between two weeks.
npm run report -- --json > authority.json

# 4. Inspect source of authority for one object. Read only.
npm run soa -- --user someone@contoso.com

# 5. Plan a conversion. Prints the exact PATCH, sends nothing.
npm run soa:plan -- --user <object-id> --set cloud

# 6. Do it for real. --confirm is required.
npm run soa -- --user <object-id> --set cloud --confirm

# 7. Revert it.
npm run soa -- --user <object-id> --set onprem --confirm

# 8. The experiment. Read the warnings first. Use a TEST account.
npm run watch -- --user <object-id> --interval 30 --max-minutes 45

# 9. Same, and revoke sessions the moment the disable lands.
npm run watch -- --user <object-id> --revoke

# 10. The coverage matrix. No tenant is contacted.
npm run coverage -- --notes
npm run coverage -- --surface kerberos
```

Every write script honours `--dry-run`, or `DRY_RUN=1` if you prefer the environment variable. Authentication defaults to device code against the Microsoft Graph PowerShell first party app, so you can run it without registering anything. Set `ENTRA_AUTH_MODE=azurecli` to reuse an existing `az login`, or `ENTRA_AUTH_MODE=clientsecret` for an unattended run.

## If your tenant is cloud only

Then `sync-report.mjs` has nothing to measure, and it says so rather than printing zeroes at you. No synchronized objects means no authority boundary, which means none of the gaps in this sample can exist. That is the best possible answer to the question it asks, and most organizations cannot give it.

Two things still apply:

- `npm run coverage -- --notes` contacts no tenant at all. The Kerberos column is `no` for every single control, which is the whole of Ernie's point in one column of a table.
- The moment somebody stands up Entra Connect to bring one legacy application along, every gap above goes live. Staying cloud only is a decision worth making on purpose rather than by default.

## Permissions

| Operation | Least privileged permission |
| --- | --- |
| Read the user and group inventory | `User.Read.All`, `Group.Read.All` |
| Read privileged role holders | `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` |
| Read and write user source of authority | `User-OnPremisesSyncBehavior.ReadWrite.All` |
| Read and write group source of authority | `Group-OnPremisesSyncBehavior.ReadWrite.All` |
| Revoke sign-in sessions | `User.RevokeSessions.All` or `User.ReadWrite.All` |

Source of authority conversion additionally requires the **Hybrid Administrator** role. The licence requirement is Microsoft Entra ID Free, which is unusual and worth noting: this is not a P1 or P2 feature.

## The endpoint version problem in `soa-inspect.mjs`

This is the single most confusing thing about source of authority in Graph today, so the script handles it in code rather than making you find out.

The Microsoft Entra how-to pages show these calls against `/v1.0`:

```
GET   /v1.0/users/{id}/onPremisesSyncBehavior
PATCH /v1.0/users/{id}/onPremisesSyncBehavior   { "isCloudManaged": true }
```

But every Microsoft Graph **reference** page for the `onPremisesSyncBehavior` resource is **beta only**, and the PowerShell cmdlet has Beta in its name: `Update-MgBetaUserOnPremiseSyncBehavior`. Those two facts cannot both be the whole truth for every tenant.

So `soa-inspect.mjs` does not pick a side. It tries `v1.0`, falls back to `beta` on a **400 or a 404**, and prints which endpoint actually answered. Record that line. It is the answer for your tenant on the day you ran it, and it is worth more than either documentation page.

A 400 rather than a 404 is normal here: when a Graph version does not know a navigation property, the router can reject the URL before anything reads the body. A **403 is not a fallback case** and the script does not retry it, because that means the endpoint exists and your permissions or role are wrong. Retrying on beta would fail the same way with a worse message.

## Source of authority conversion, honestly

Converting a synced Active Directory **user** to a cloud user went **GA in January 2026**, at object level, supported by both Connect Sync and Cloud Sync. Group conversion works the same way.

Prerequisites the script will remind you of and Graph will not check:

- Entra Connect Sync **2.5.76.0** or later, or Entra Cloud Sync **1.1.1370.0** or later
- No on-premises Exchange workloads for that user
- No AD FS or third party federation in the sign-in path
- No applications that depend on that user having an on-premises password

What happens after a successful conversion:

- `isCloudManaged` becomes `true` and `onPremisesSyncEnabled` becomes `null`
- The `onPremises*` attributes are **retained**, but from then on nothing maintains them except you, through Graph
- The Active Directory object is **not modified, not disabled and not deleted**
- **Event ID 6956** is logged on the sync server
- It is reversible with `{ "isCloudManaged": false }`

The consequence that catches people: a converted user **loses password based authentication** unless it keeps a hybrid presence. For Kerberos applications that means passwordless, specifically Windows Hello for Business or FIDO2 with Cloud Kerberos Trust, and the account has to **remain in Active Directory** for Kerberos single sign-on to keep working. Conversion moves who owns the object. It does not remove the object from Active Directory, and it does not close the cloud to on-premises direction of the gap.

## sourceAnchor, and the one field you must never touch

`sourceAnchor`, exposed in Graph as `onPremisesImmutableId`, is "an attribute immutable during the lifetime of an object". Since Connect 1.1.524.0 the default for User objects is `ms-DS-ConsistencyGuid`.

Microsoft is explicit:

> "The sourceAnchor attribute value can't be changed after the object is created in Microsoft Entra ID and the identity is synchronized."

Change it later and Connect Sync throws and **blocks every further change on that object**. `sync-report.mjs` prints it so you can see it and confirm it is populated. It is not there to be edited. Source of authority conversion does not change it, and neither should you.

## Connect Sync or Cloud Sync in 2026

The April 2026 Plan for Change says Microsoft will migrate tenants from Entra Connect Sync to Entra Cloud Sync, **phased starting July 2026**, beginning with tenants where Cloud Sync already meets every need. Verbatim from the documentation:

> "New identity and synchronization features are being developed primarily on the Cloud Sync platform, making it the recommended path forward for most organizations."

Cloud Sync is described as "Microsoft's strategic direction for hybrid identity". That is the direction. Here is the part that decides whether it applies to you this year.

| Still Connect Sync only | Still Cloud Sync only |
| --- | --- |
| Device synchronization and Hybrid Entra Join | Disconnected forests |
| Pass-through authentication configuration | Multiple active sync instances |
| AD FS setup | Group provisioning to Active Directory |
| Advanced sync rules | On demand provisioning |
| Device writeback | |
| Cross forest references | |
| Merging attributes from multiple domains | |
| Full attribute based filtering | |

Scale: Connect Sync is unlimited objects with 250K member groups. Cloud Sync is 150K objects per domain with 50K member groups.

Two more dated items worth putting in a calendar:

- **1 June 2026**: Connect Sync blocks hard match of new Active Directory users onto cloud users that hold Entra roles. This is privilege escalation hardening, and it closes one specific path onto exactly the principals `sync-report.mjs` lists in its privileged table. Soft match and ongoing sync are unaffected.
- **May 2026**: interactive admin sign-in is required for Connect Sync configuration changes.

## Bringing Conditional Access closer to on premises

Conditional Access is a token issuance time control. It does not sit in the Kerberos, NTLM or LDAP path natively, and no amount of policy authoring changes that. What has changed is where you can put an Entra decision point.

**Entra Private Access for Domain Controllers went GA in January 2026.** This is the significant one. The Global Secure Access client tunnels to Private Access Sensors installed on domain controllers. The sensor intercepts Kerberos requests for configured service principal names and evaluates Conditional Access before forwarding them. That enables MFA for on-premises application access, including local to local, with Kerberos support. Practically: a Quick Access app segment on TCP 88, and the sensor needs inbound TCP 1337 on the domain controller.

**Continuous access evaluation for Entra Application Proxy is GA and on by default**, and it works for on-premises apps **without** the published application being CAE aware. Without strict enforcement it is opportunistic and can fall back to a regular token.

**Global Secure Access Universal CAE** extends continuous access evaluation to Private Access, Internet Access and Microsoft services that do not natively support it, enforcing at the network edge. Without it, revocation waits up to **90 minutes** for token expiry.

Licensing: Private Access and Internet Access require Entra ID P1 or P2. Both are included in the Microsoft Entra Suite and both are available standalone. Internet Access for Microsoft services is included in P1 and P2. Both are GA.

And the control everyone reaches for first, stated precisely. `POST /users/{id}/revokeSignInSessions` invalidates all refresh tokens and browser session cookies by stamping `signInSessionsValidFromDateTime`. There can be a small delay of a few minutes. It does **not** invalidate access tokens already issued, so "revoked" and "has no access" are different sentences. It also does not work for external or B2B users, because they sign in through their home tenant.

## Worth knowing while you are here

**Microsoft Entra Backup and Recovery went GA in June 2026**, covering users, groups, applications, service principals, managed identities, Conditional Access policies and named locations, with 7 day retention on P1 and P2. Relevant to this sample for one reason: if a source of authority conversion or a sync scoping change goes wrong at scale, restoring the cloud object is now a supported operation rather than a rebuild. It does not restore anything in Active Directory.

## Where this is the wrong answer

- **This sample measures a gap. It does not close it.** Closing it means choosing an authentication method that enforces account state at sign-in, which is pass-through authentication or federation, or moving source of authority to the cloud, or putting Entra Private Access in front of the on-premises applications. All three are projects with change advisory boards and rollback plans, not scripts. If you run `sync-report.mjs`, print the output and file it as "done", you have made the problem more visible and no smaller.
- **Do not run `disable-propagation-watch.mjs` against a real person's account without telling them.** You are deliberately disabling somebody. Use a test account. If it has to be a real account for the result to mean anything, get the person's agreement first, in writing, with a time window, and tell them what `--revoke` will do to their open sessions. "It was for a security experiment" is not a defence anybody enjoys giving.
- **If you are already on Cloud Sync and everything works, the July 2026 migration is not a project you need to start.** It is a thing that will happen to you, in a good way. Read the Plan for Change, confirm nothing in the Connect Sync only column applies to you, and move on. Conversely, if you depend on device writeback, advanced sync rules or pass-through authentication configuration, you are staying on Connect Sync for now. Say that out loud, in writing, to the people planning your roadmap, rather than discovering it during a forced migration.
- **Source of authority conversion is a one object at a time decision with real prerequisites. It is not a migration strategy on its own.** It has no bulk mode in this sample by design. A user with an on-premises Exchange mailbox, an AD FS dependency or an application that needs their on-premises password is not a candidate, and Graph will happily convert them anyway. Converting a thousand users because the API worked on one is how you find out which of those three applied.
- **The coverage matrix is a starting point, not an audit.** `config/coverage.json` describes how the protocols behave. It does not know whether your Application Proxy apps use Entra pre-authentication or passthrough, whether your P2 licences cover the people who need the risk conditions, or which of your line of business applications quietly accepts NTLM. Go and check those four things specifically, then edit the file.
- **If you have no Active Directory at all, close this tab.** A cloud only tenant has none of these problems, and adding the vocabulary of hybrid identity to a greenfield environment is a way of importing a boundary you do not have.

## Reference

- [Choose the right authentication method for your Microsoft Entra hybrid identity solution](https://learn.microsoft.com/entra/identity/hybrid/connect/choose-ad-authn)
- [Microsoft Entra Connect: Design concepts, including sourceAnchor](https://learn.microsoft.com/entra/identity/hybrid/connect/plan-connect-design-concepts)
- [Microsoft Entra Connect: User sign-in options](https://learn.microsoft.com/entra/identity/hybrid/connect/plan-connect-user-signin)
- [Cloud Sync: which sync tool to use, and the feature comparison](https://learn.microsoft.com/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide)
- [What is Microsoft Entra Cloud Sync](https://learn.microsoft.com/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)
- [What's new in Microsoft Entra, including the Plan for Change entries](https://learn.microsoft.com/entra/fundamentals/whats-new)
- [Source of authority overview](https://learn.microsoft.com/entra/identity/hybrid/concept-source-of-authority-overview)
- [Convert source of authority for a synced user](https://learn.microsoft.com/entra/identity/hybrid/how-to-user-source-of-authority-configure)
- [Convert source of authority for a synced group](https://learn.microsoft.com/entra/identity/hybrid/how-to-group-source-of-authority-configure)
- [onPremisesSyncBehavior resource type (beta)](https://learn.microsoft.com/graph/api/resources/onpremisessyncbehavior?view=graph-rest-beta)
- [Update onPremisesSyncBehavior (beta)](https://learn.microsoft.com/graph/api/onpremisessyncbehavior-update?view=graph-rest-beta)
- [user resource type, including the onPremises properties](https://learn.microsoft.com/graph/api/resources/user)
- [user: revokeSignInSessions](https://learn.microsoft.com/graph/api/user-revokesigninsessions)
- [Configure Microsoft Entra Private Access for domain controllers](https://learn.microsoft.com/entra/global-secure-access/how-to-configure-domain-controllers)
- [What is Microsoft Entra Private Access](https://learn.microsoft.com/entra/global-secure-access/concept-private-access)
- [Universal continuous access evaluation for Global Secure Access](https://learn.microsoft.com/entra/global-secure-access/concept-universal-continuous-access-evaluation)
- [Continuous access evaluation for Microsoft Entra application proxy](https://learn.microsoft.com/entra/identity/app-proxy/concept-continuous-access-evaluation)
- [Continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [What is Microsoft Entra application proxy](https://learn.microsoft.com/entra/identity/app-proxy/overview-what-is-app-proxy)
- [Conditional Access for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/workload-identity)
- [What is Microsoft Entra ID Protection](https://learn.microsoft.com/entra/id-protection/overview-identity-protection)
