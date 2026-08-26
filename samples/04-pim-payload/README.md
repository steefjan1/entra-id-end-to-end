# 04. PIM solves the activation window, not the payload

**What the diagram shows:** a clock labelled "Just In Time Access", with an eligible user activating a role for one hour and a green tick next to the audit log.

**What it hides:** the clock says nothing about what the role can do while it is ticking. A one hour window on a role that grants four hundred resource actions, including a wildcard, the ability to add a credential to any application, or write to any group membership, is not secured access. It is an over privileged account with a clean audit trail.

This sample exists because of a comment made under the LinkedIn post this repository responds to:

> "PIM only solves the activation window, not the payload. If your Entra eligible group just assigns System Admin or unfiltered duties inside your ERP, you haven't secured access, you've just scheduled a clean audit trail for an over-privileged account."

That comment is correct, and it is the spine of everything below. Scripts 1, 2 and 4 do the part everyone already does: shorten the window, require MFA and an approval, expire the eligibility, review the holders. Script 3 does the part almost nobody does: enumerate what the role actually grants, and score it.

## What is in here

| Path | What it does |
| --- | --- |
| `config/roles.json` | The roles this sample operates on, by role template ID, with the activation policy and review settings you want. Declarative and re-runnable |
| `src/configure-policy.mjs` | Sets the PIM policy rules for each role: maximum activation duration, MFA plus justification on activation, and an approval stage. Prints before and after |
| `src/assign-eligible.mjs` | Creates an eligible assignment with an expiry using the `adminAssign` action. `--validate-only` maps to `isValidationOnly: true` so Graph validates without persisting |
| `src/entitlement-report.mjs` | **The important one.** Every eligible and active Entra role assignment in the tenant, with the activation window next to the count and the shape of the allowed resource actions, and a computed payload risk |
| `src/access-review.mjs` | A recurring access review over the role holders, with auto apply, a default decision, and manager plus fallback reviewers |

## The two halves of the problem

| Question | Who answers it | Where it lives |
| --- | --- | --- |
| When can this principal hold the role | PIM policy, activation, approval, MFA | `/policies/roleManagementPolicies` |
| For how long is it eligible at all | Eligibility schedule with an expiry | `/roleManagement/directory/roleEligibilitySchedules` |
| Who should still hold it next quarter | Access review | `/identityGovernance/accessReviews/definitions` |
| **What can it do while active** | **Nothing in PIM. The role definition** | `/roleManagement/directory/roleDefinitions` |
| What can it do inside your ERP, SaaS tenant or database | Nothing in Microsoft Graph at all | That application's own authorization model |

The last two rows are the payload. The first three are the window.

## Mind the path root

Assignments live under `/roleManagement/directory`. The policies that govern those assignments live under `/policies/roleManagementPolicies`. Two different trees, and confusing them is the single most common reason a PIM automation attempt stalls.

Reading a policy also needs a `$filter`. It is required, not optional, and omitting it returns a 400:

```
GET /policies/roleManagementPolicyAssignments
  ?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{id}'
  &$expand=policy($expand=rules)
```

Rule IDs are well known composites of `{RuleType}_{Caller}_{Level}`, so you patch them by name rather than discovering them: `Expiration_EndUser_Assignment`, `Enablement_EndUser_Assignment`, `Approval_EndUser_Assignment`.

## Payload risk, and what it does not measure

`entitlement-report.mjs` marks a role **high** when its `rolePermissions[].allowedResourceActions` contain any wildcard action (anything with a `*`, including `microsoft.directory/*`), or any action on a short hard coded list: application and service principal credential management, role assignment write, role definition write, directory role write, tenant and Conditional Access policy write, user password and authentication method write, and group membership write. **Medium** means it writes something but nothing on that list. **Low** means read only.

Two honest limits of that score:

1. **Action strings do not express every boundary.** Nothing in `microsoft.directory/users/password/update` tells you that User Administrator cannot reset a privileged user's password while Privileged Authentication Administrator can. That limit comes from the role assignable group and protected user rules. Treat the column as a prompt to go and check, not a verdict.
2. **Action counts are a bad proxy for blast radius.** Groups Administrator has a small action list and an enormous payload, because `microsoft.directory/groups/members/update` is exactly how somebody gets added to the Entra group that maps to System Administrator inside your ERP. A large count with no high impact action can be safer than a list of three. Read the notes in `config/roles.json`.

## Run it

```bash
npm install

# 1. See what you already have. Read only, nothing is sent.
npm run report

# 2. The uncomfortable version: full action lists for the roles in the report.
npm run report -- --risk high --actions

# 3. Plan the policy changes. Prints the exact PATCH calls, sends nothing.
PIM_APPROVER_GROUP_ID=<group-object-id> npm run policy:plan

# 4. Apply them.
PIM_APPROVER_GROUP_ID=<group-object-id> npm run policy

# 5. Make somebody eligible for 90 days, validated by Graph but not persisted.
npm run assign -- --role "User Administrator" --principal <object-id> --days 90 --validate-only

# 6. Then for real.
npm run assign -- --role "User Administrator" --principal <object-id> --days 90

# 7. Create the recurring reviews.
PIM_FALLBACK_REVIEWER_GROUP_ID=<group-object-id> npm run review:plan
PIM_FALLBACK_REVIEWER_GROUP_ID=<group-object-id> npm run review
```

Every script honours `--dry-run`, or `DRY_RUN=1` if you prefer the environment variable. Authentication defaults to device code against the Microsoft Graph PowerShell first party app, so you can run it without registering anything. Set `ENTRA_AUTH_MODE=azurecli` to reuse an existing `az login`, or `ENTRA_AUTH_MODE=clientsecret` for an unattended run.

Machine readable output for a pipeline gate:

```bash
npm run report -- --json > entitlements.json
```

## Permissions

| Operation | Least privileged permission |
| --- | --- |
| Read eligibility and assignment schedules | `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory` |
| Read role definitions | `RoleManagement.Read.Directory` |
| Read PIM policies | `RoleManagementPolicy.Read.Directory` |
| Write PIM policy rules | `RoleManagementPolicy.ReadWrite.Directory` |
| Create an eligible assignment | `RoleEligibilitySchedule.ReadWrite.Directory` |
| Create an active assignment | `RoleAssignmentSchedule.ReadWrite.Directory` |
| Create an access review | `AccessReview.ReadWrite.All` |

A delegated caller writing PIM policy or assignments also needs Privileged Role Administrator. Creating an active assignment additionally requires the caller to have MFA enforced and to have been MFA challenged in the current session, or Graph rejects the request. Application only is supported for the eligibility and assignment endpoints.

## Licensing

Core PIM, including PIM for Groups, and core access reviews require **Microsoft Entra ID P2**. **Microsoft Entra ID Governance** is required on top of that for access reviews of PIM for Groups, inactive user scoped reviews, machine learning assisted certification, catalog reviews, and PIM custom extensions.

Licences are counted per user in scope, not per administrator running the script. Check the licensing fundamentals page before you scope a review at `/users`.

## The deprecation you have about two months to deal with

The old beta `privilegedAccess` API stops returning data on **28 October 2026**.

```
/beta/privilegedAccess/aadRoles       deprecated, stops returning data 28 Oct 2026
/beta/privilegedAccess/azureResources deprecated, stops returning data 28 Oct 2026
```

If anything you own still calls those paths, including PowerShell that wraps them, it has weeks left, not quarters. The replacement for Entra roles is `/roleManagement/directory/*` plus `/policies/roleManagementPolicies`, which is what this sample uses throughout.

## Three more traps worth knowing

**Azure resource roles are not in Microsoft Graph.** `roleManagement/directory` covers Entra roles only. PIM for Azure subscriptions and resource groups lives in the Azure Resource Manager REST API under `Microsoft.Authorization/roleEligibilityScheduleRequests`. If your privileged access story includes Owner on a production subscription, none of the scripts in this sample can see it, and the entitlement report will look reassuringly short.

**PIM for Groups uses a different root again.** Not `/roleManagement`, but:

```
/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests
/identityGovernance/privilegedAccess/group/assignmentScheduleRequests
```

with an `accessId` of `member` or `owner`. This is the root that matters most for the LinkedIn comment, because a PIM enabled group is usually how an ERP or SaaS administrator role gets granted. The window is managed by Entra. The payload is defined inside the application, where Entra cannot see it.

**Requiring an authentication context on activation went GA in April 2026.** You can now bind every PIM activation to a Conditional Access authentication context, so activation requires phishing resistant MFA, a compliant device, or whatever else that context demands. In Graph this is the `unifiedRoleManagementPolicyAuthenticationContextRule` rule type, and `entitlement-report.mjs` shows it as `authctx` in the mfa column. It is the strongest control in this whole sample, and it still does not shrink the payload by a single action.

## Without Entra ID P2

The PIM endpoints need P2. `entitlement-report.mjs` does not stop when they refuse, and the reason is the sample's own argument turned back on itself.

PIM governs the activation **window**. The **payload**, meaning what the role can do once active, lives in the role definition, and every tenant has those for free. So without P2 the report falls back to `/roleManagement/directory/roleAssignments`, prints `no PIM` in the window columns, and still gives you the number that matters: how many actions each assignment actually grants.

A tenant without PIM is the more alarming case, not the less. Every assignment is standing: permanently active, no window, no approval, no expiry. The report says so before printing the table.

So the read only report is worth running on any tenant, licensed or not.

## A note on counting actions

Entra writes some of its wildcards in words rather than asterisks. Global Administrator's entire payload is a single action:

```
microsoft.directory/allEntities/allProperties/allTasks
```

One action. No asterisk. An earlier version of this script matched wildcards on `*` alone and therefore ranked Global Administrator as medium risk, below a billing role that listed twelve read actions. The action count is the wrong measure for a wildcard row, because one `allTasks` is every action there will ever be.

`allEntities`, `allProperties`, `allTasks` and `*` all count as wildcards now, and a wildcard row says out loud that its own action count understates it. Worth knowing if you write your own version of this: the naive count inverts the ranking at exactly the row you most need to see.

## Where this is the wrong answer

- **You do not have the licence.** PIM plus access reviews is Entra ID P2 or Governance money, counted across every user in scope. If that is not signed off, standing assignments with a tight scope, an administrative unit boundary and a documented quarterly manual review beat pretending you have just in time access. A half configured PIM tenant is worse than an honest standing one, because everybody assumes the window is doing work it is not.
- **PIM does not touch application internal authorization.** An Entra group that maps to System Administrator inside an ERP, a SaaS tenant or a database is still a standing super user for the duration of every activation, and often for longer if that application caches its own session. The entitlement report shows Entra's side only. The duty separation work inside the ERP is a different project with different people, and this sample cannot start it for you.
- **Automating policy changes on Entra roles is itself privileged.** The identity running `configure-policy.mjs` and `assign-eligible.mjs` needs Privileged Role Administrator, which is exactly the kind of standing privilege PIM exists to remove. Run these from an approved pipeline using workload identity federation with a just in time activation, not from a laptop with a permanently assigned role. If the answer is "we will just run it as a Global Admin from someone's machine", stop and do the manual version instead.
- **Auto apply plus a Deny default will remove access from people who ignore email.** `autoApplyDecisionsEnabled` with `defaultDecision: Deny` is often exactly correct and occasionally an outage, especially over a holiday period or when the reviewer is the manager of somebody in a different time zone. Pilot it on one non critical role, watch one full instance complete, then widen.
- **Very small tenants.** Two administrators and one break glass account do not need a recurring review pipeline. They need the two administrators to be on FIDO2 keys. Come back to this when the list of privileged principals stops fitting on one screen.

## Reference

- [Overview of role management through the privileged identity management (PIM) API](https://learn.microsoft.com/graph/api/resources/privilegedidentitymanagementv3-overview)
- [Create roleEligibilityScheduleRequest](https://learn.microsoft.com/graph/api/rbacapplication-post-roleeligibilityschedulerequests)
- [Create roleAssignmentScheduleRequest](https://learn.microsoft.com/graph/api/rbacapplication-post-roleassignmentschedulerequests)
- [unifiedRoleEligibilityScheduleRequest resource](https://learn.microsoft.com/graph/api/resources/unifiedroleeligibilityschedulerequest)
- [List roleManagementPolicyAssignments](https://learn.microsoft.com/graph/api/policyroot-list-rolemanagementpolicyassignments)
- [Update unifiedRoleManagementPolicyRule](https://learn.microsoft.com/graph/api/unifiedrolemanagementpolicyrule-update)
- [unifiedRoleManagementPolicyRule resource types](https://learn.microsoft.com/graph/api/resources/unifiedrolemanagementpolicyrule)
- [unifiedRoleDefinition resource](https://learn.microsoft.com/graph/api/resources/unifiedroledefinition)
- [Microsoft Entra built-in roles and their permissions](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference)
- [Create accessReviewScheduleDefinition](https://learn.microsoft.com/graph/api/accessreviewset-post-definitions)
- [accessReviewScheduleDefinition resource](https://learn.microsoft.com/graph/api/resources/accessreviewscheduledefinition)
- [accessReviewInstance resource and its actions](https://learn.microsoft.com/graph/api/resources/accessreviewinstance)
- [Microsoft Entra ID Governance licensing fundamentals](https://learn.microsoft.com/entra/id-governance/licensing-fundamentals)
- [Privileged Identity Management for groups API overview](https://learn.microsoft.com/graph/api/resources/privilegedidentitymanagement-for-groups-api-overview)
- [Configure PIM role settings, including authentication context](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings)
- [Azure resource role eligibility, in ARM and not in Graph](https://learn.microsoft.com/rest/api/authorization/role-eligibility-schedule-requests)
