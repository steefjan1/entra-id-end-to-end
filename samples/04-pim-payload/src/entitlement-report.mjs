/**
 * The point of this sample.
 *
 * PIM answers one question: WHEN is this role active. This script answers the
 * question PIM never asks: what can the role DO once it is active.
 *
 * For every eligible and every active Entra role assignment in the tenant it
 * prints the principal, the role, whether the assignment expires, the
 * activation window from the role's PIM policy, whether MFA and approval are
 * required, and then the thing that actually matters: how many resource
 * actions the role definition grants and which of them are dangerous.
 *
 * A role with a one hour activation window and four hundred allowed actions,
 * including a wildcard, is not "secured". It is an over privileged account
 * with a clean audit trail. That is the whole argument.
 *
 * Reads only. Nothing here writes to the tenant.
 *
 *   GET /roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition
 *   GET /roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition
 *   GET /roleManagement/directory/roleDefinitions
 *   GET /policies/roleManagementPolicyAssignments?$filter=... ($filter is REQUIRED)
 *
 * Permissions: RoleEligibilitySchedule.Read.Directory,
 * RoleAssignmentSchedule.Read.Directory, RoleManagement.Read.Directory and
 * RoleManagementPolicy.Read.Directory.
 *
 *   npm run report
 *   npm run report -- --risk high
 *   npm run report -- --role "Application Administrator" --actions
 *   npm run report -- --json > entitlements.json
 *
 * https://learn.microsoft.com/graph/api/resources/unifiedroledefinition
 * https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphGetAll, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'RoleManagement.Read.Directory',
  'RoleManagementPolicy.Read.Directory',
  'Directory.Read.All',
);

const here = dirname(fileURLToPath(import.meta.url));
const configFile = process.env.ROLES_FILE || join(here, '..', 'config', 'roles.json');

const { values: args } = parseArgs({
  options: {
    role: { type: 'string' },
    risk: { type: 'string' },
    actions: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/entitlement-report.mjs [--role "<name>"] [--risk high|medium|low]\n' +
      '                                      [--actions] [--json]\n' +
      '\n' +
      '  --actions  print every allowed resource action for each role in the report\n' +
      '  --json     print the rows as JSON instead of tables, full action lists included\n',
  );
  process.exit(0);
}

if (isDryRun()) {
  console.log('DRY_RUN=1 is set. This script only reads, so it behaves identically.\n');
}

/**
 * A small hard coded list of actions that change the answer to "how bad is one
 * activation of this role". These are not the only dangerous actions. They are
 * the ones that let a holder extend their own access beyond the activation
 * window, which is precisely the failure PIM cannot see.
 *
 * Note what allowedResourceActions does NOT express: the limit that stops
 * User Administrator from resetting the password of a privileged user is
 * enforced by the role assignable group and protected user rules, not by the
 * action string. So password/update reads as broader here than it is for some
 * roles, and exactly as broad as it looks for Privileged Authentication
 * Administrator. Treat this column as a prompt to go and check, not a verdict.
 */
const HIGH_IMPACT_ACTIONS = [
  ['microsoft.directory/applications/credentials/update', 'application credential management'],
  ['microsoft.directory/applications/allProperties/allTasks', 'full control of every application'],
  [
    'microsoft.directory/servicePrincipals/credentials/update',
    'service principal credential management',
  ],
  [
    'microsoft.directory/servicePrincipals/allProperties/allTasks',
    'full control of every service principal',
  ],
  [
    'microsoft.directory/servicePrincipals/appRoleAssignedTo/update',
    'can grant application permissions to any app',
  ],
  [
    'microsoft.directory/roleAssignments/allProperties/allTasks',
    'role assignment write, can grant itself anything',
  ],
  [
    'microsoft.directory/roleDefinitions/allProperties/allTasks',
    'role definition write, can redefine what a role means',
  ],
  ['microsoft.directory/directoryRoles/allProperties/allTasks', 'directory role write'],
  ['microsoft.directory/users/password/update', 'user password reset'],
  [
    'microsoft.directory/users/authenticationMethods/',
    'authentication method write, account takeover',
  ],
  ['microsoft.directory/policies/allProperties/allTasks', 'tenant policy write'],
  [
    'microsoft.directory/conditionalAccessPolicies/allProperties/allTasks',
    'conditional access write, can disable the controls above',
  ],
  ['microsoft.directory/authorizationPolicy/allProperties/allTasks', 'tenant authorization policy write'],
  [
    'microsoft.directory/groups/members/update',
    'group membership write, how downstream application access is granted',
  ],
  [
    'microsoft.directory/groups/allProperties/allTasks',
    'full control of every group, including groups that map to application roles',
  ],
];

const WRITE_SUFFIX = /\/(create|update|delete|allTasks)$/;

let notes = new Map();
try {
  const config = JSON.parse(await readFile(configFile, 'utf8'));
  notes = new Map(
    (config.roles || []).filter((role) => role.note).map((role) => [role.templateId, role.note]),
  );
} catch {
  // The report works without config/roles.json. It just loses the commentary.
}

const definitions = await graphGetAll('/roleManagement/directory/roleDefinitions');
const definitionById = new Map(definitions.map((definition) => [definition.id, definition]));

/**
 * The PIM schedule endpoints need Entra ID P2. A tenant without it either
 * returns nothing or refuses outright.
 *
 * That is not a reason to stop, and the reason why is the point of this whole
 * sample. PIM governs the activation WINDOW. The PAYLOAD, meaning what the
 * role can actually do once active, lives in the role definition, which every
 * tenant has for free. So when PIM is unavailable we fall back to the plain
 * role assignment endpoint, report the window columns as unavailable, and
 * still print the number that matters: how many actions each role grants.
 *
 * A tenant with no PIM is in fact the more alarming case. Every assignment is
 * standing, permanently active, with no window at all.
 */
async function tryGet(path, label) {
  try {
    return { ok: true, value: await graphGetAll(path) };
  } catch (error) {
    return { ok: false, value: [], label, message: error.message };
  }
}

const [eligibleResult, activeResult] = await Promise.all([
  tryGet(
    '/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition',
    'roleEligibilitySchedules',
  ),
  tryGet(
    '/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition',
    'roleAssignmentSchedules',
  ),
]);

let pimAvailable = eligibleResult.ok && activeResult.ok;
let schedules = [
  ...eligibleResult.value.map((item) => ({ ...item, assignmentType: 'eligible' })),
  ...activeResult.value.map((item) => ({ ...item, assignmentType: 'active' })),
];

if (schedules.length === 0) {
  const reason = pimAvailable
    ? 'The PIM endpoints answered, and this tenant has no PIM managed roles.'
    : 'The PIM endpoints refused, which usually means no Entra ID P2 on this tenant.';

  console.log(`${reason}`);
  console.log('Falling back to /roleManagement/directory/roleAssignments, which every');
  console.log('tenant has. The activation window columns will read "no PIM". The action');
  console.log('counts are unaffected, because a role definition grants what it grants');
  console.log('regardless of how the assignment was made.\n');

  // Only ONE property may be expanded on this endpoint. The PIM schedule
  // endpoints happily take $expand=principal,roleDefinition, this one answers
  // "Only one property can be expanded in a single query". So expand the
  // principal, which is the part that needs a round trip, and resolve the role
  // definition from the roleDefinitions collection already loaded above.
  const plain = await tryGet(
    '/roleManagement/directory/roleAssignments?$expand=principal',
    'roleAssignments',
  );

  if (!plain.ok) {
    const looksLikePermissions = /Authorization_RequestDenied|403|Insufficient privileges/i.test(
      plain.message,
    );
    console.error(
      'That fell over too, so there is nothing to report:\n' +
        `  ${plain.message}\n\n` +
        (looksLikePermissions
          ? 'This needs RoleManagement.Read.Directory at minimum.'
          : 'That is a request problem rather than a permissions problem. The query\n' +
            'above is what needs fixing, not your access.'),
    );
    process.exit(1);
  }

  pimAvailable = false;
  schedules = plain.value.map((item) => ({ ...item, assignmentType: 'active (standing)' }));

  if (schedules.length === 0) {
    console.log('No directory role assignments at all. That is unusual, but not an error.');
    process.exit(0);
  }

  console.log(
    `Every one of the ${schedules.length} assignments below is standing: permanently\n` +
      'active, with no activation window, no approval and no expiry. That is what\n' +
      'PIM would be shortening, and it is worth seeing before deciding whether the\n' +
      'licence is worth it.\n',
  );
}

const policyCache = new Map();
const rows = [];

for (const schedule of schedules) {
  const definition =
    definitionById.get(schedule.roleDefinitionId) || schedule.roleDefinition || null;
  const roleName = definition?.displayName || schedule.roleDefinitionId;

  if (args.role && roleName.toLowerCase() !== args.role.toLowerCase()) continue;

  const actions = allowedActions(definition);
  const risk = classify(actions);
  const policy = pimAvailable
    ? await policyFor(schedule.roleDefinitionId)
    : { maxActivation: 'no PIM', mfa: 'no PIM', approval: 'no PIM' };

  rows.push({
    principal: schedule.principal?.displayName || schedule.principalId,
    principalId: schedule.principalId,
    type: principalType(schedule.principal),
    memberType: schedule.memberType || 'Direct',
    role: roleName,
    roleTemplateId: definition?.templateId || '',
    scope: schedule.directoryScopeId || '/',
    assignment: schedule.assignmentType,
    expires: describeExpiry(schedule),
    maxActivation: policy.maxActivation,
    mfa: policy.mfa,
    approval: policy.approval,
    actionCount: actions.length,
    actionsSummary: summarizeActions(actions),
    risk: risk.level,
    riskReasons: risk.reasons,
    allowedResourceActions: actions,
    note: notes.get(definition?.templateId) || '',
  });
}

const filtered = args.risk
  ? rows.filter((row) => row.risk === args.risk.toLowerCase())
  : rows;

if (args.json) {
  console.log(JSON.stringify(filtered, null, 2));
  process.exit(0);
}

const table = filtered
  .slice()
  .sort(
    (a, b) =>
      rank(b.risk) - rank(a.risk) ||
      b.actionCount - a.actionCount ||
      a.role.localeCompare(b.role) ||
      a.principal.localeCompare(b.principal),
  )
  .map((row) => ({
    principal: trim(row.principal, 26),
    type: row.type === 'servicePrincipal' ? 'sp' : row.type,
    role: trim(row.role, 28),
    assignment: row.assignment.replace('active (standing)', 'standing'),
    expires: row.expires,
    maxActivation: row.maxActivation,
    mfa: row.mfa,
    approval: row.approval,
    actions: String(row.actionCount),
    payloadRisk: row.risk.toUpperCase(),
  }));

// Without PIM the three window columns read "no PIM" on every single row, and
// they push the table past any terminal width for no information at all. The
// banner above already said it once. Drop them and keep the line readable,
// because a table that wraps is a table nobody reads.
const columns = pimAvailable
  ? ['principal', 'type', 'role', 'assignment', 'expires', 'maxActivation', 'mfa', 'approval', 'actions', 'payloadRisk']
  : ['principal', 'type', 'role', 'assignment', 'expires', 'actions', 'payloadRisk'];

console.log(
  pimAvailable
    ? 'Entra role entitlements: the activation window and the payload behind it\n'
    : 'Entra role entitlements: no activation window at all, and the payload behind it\n',
);
printTable(table, columns);

// One block per distinct role, so the action detail is not repeated per holder.
const seen = new Set();
console.log('\nPayload detail\n');
for (const row of filtered.slice().sort((a, b) => rank(b.risk) - rank(a.risk))) {
  if (seen.has(row.role)) continue;
  seen.add(row.role);

  console.log(`${row.role}  [${row.risk.toUpperCase()}]  ${row.actionCount} allowed resource actions`);
  console.log(
    pimAvailable
      ? `  activation: max ${row.maxActivation}, mfa ${row.mfa}, approval ${row.approval}`
      : '  activation: none, this assignment is standing',
  );
  console.log(
    `  by resource: ${wrap(summarizeActions(row.allowedResourceActions, 6) || 'none returned', 76, '    ')}`,
  );
  if (row.riskReasons.length > 0) {
    console.log('  why this is the payload:');
    row.riskReasons.forEach((reason) => console.log(`    ${wrap(reason, 76, '      ')}`));
  }
  if (row.note) console.log(`  note: ${wrap(row.note, 74, '        ')}`);
  if (args.actions) {
    console.log('  every allowed resource action:');
    row.allowedResourceActions.forEach((action) => console.log(`    ${action}`));
  }
  console.log('');
}

const shortWindowBigPayload = filtered.filter(
  (row) => row.risk === 'high' && isShortWindow(row.maxActivation),
);
const isActive = (row) => row.assignment.startsWith('active');

const standing = filtered.filter(
  (row) => isActive(row) && row.expires === 'never' && row.risk === 'high',
);
const viaGroup = filtered.filter((row) => row.type === 'group');

console.log('Summary\n');
printTable(
  [
    { measure: 'assignments in scope', count: String(filtered.length) },
    {
      measure: 'eligible',
      count: String(filtered.filter((row) => row.assignment === 'eligible').length),
    },
    {
      measure: 'active',
      count: String(filtered.filter(isActive).length),
    },
    { measure: 'payload risk high', count: String(filtered.filter((r) => r.risk === 'high').length) },
    {
      measure: 'payload risk medium',
      count: String(filtered.filter((r) => r.risk === 'medium').length),
    },
    { measure: 'short activation window, high payload', count: String(shortWindowBigPayload.length) },
    { measure: 'standing active, never expires, high payload', count: String(standing.length) },
    { measure: 'assigned to a group rather than a person', count: String(viaGroup.length) },
  ],
  ['measure', 'count'],
);

if (shortWindowBigPayload.length > 0) {
  console.log(
    `\n${shortWindowBigPayload.length} assignment(s) have a tight activation window and a payload\n` +
      'that can outlive it. A two hour window on a role that can add an application\n' +
      'credential, write a role assignment or change a group membership buys you an\n' +
      'audit trail, not a boundary. Fix the payload: narrower role, administrative\n' +
      'unit scope, or a custom role with the actions you actually need.',
  );
}

if (standing.length > 0) {
  console.log(
    `\n${standing.length} assignment(s) are active, permanent and high payload. PIM is not\n` +
      'involved in these at all. They are standing privilege wearing a PIM shaped hat.',
  );
}

if (viaGroup.length > 0) {
  console.log(
    `\n${viaGroup.length} assignment(s) go to a group. The report shows the group as the\n` +
      'principal because that is what Entra assigned. The real holders are its members,\n' +
      'today and every day after. This is the exact shape the LinkedIn comment was\n' +
      'about: an eligible group whose payload nobody enumerated.',
  );
}

console.log(
  '\nEverything above is the Entra side. If any of these roles or groups maps to an\n' +
    'administrator role inside an ERP, a SaaS tenant or a database, that payload is\n' +
    'invisible to Microsoft Graph and to this script. Go and enumerate it there.',
);

function allowedActions(definition) {
  const permissions = definition?.rolePermissions || [];
  const all = permissions.flatMap((permission) => permission.allowedResourceActions || []);
  return [...new Set(all)].sort();
}

/**
 * Payload risk.
 *   high    a wildcard action, or any of the hard coded high impact actions
 *   medium  writes something, but nothing on the list
 *   low     read only
 */
function classify(actions) {
  const reasons = [];

  // Entra writes its wildcards in words, not asterisks.
  //
  // Global Administrator's entire payload is one action:
  //
  //   microsoft.directory/allEntities/allProperties/allTasks
  //
  // No asterisk anywhere in it. Matching on '*' alone ranked the single most
  // powerful role in Entra ID below a billing role, because a naive action
  // count says 1 versus 12. The count is the wrong measure for a wildcard:
  // one allTasks action is every action there will ever be.
  const WILDCARD_TOKENS = ['*', 'allEntities', 'allProperties', 'allTasks'];
  const wildcards = actions.filter((action) =>
    WILDCARD_TOKENS.some((token) => action.includes(token)),
  );
  if (wildcards.length > 0) {
    reasons.push(
      `${wildcards.length} wildcard action(s), for example ${wildcards[0]} ` +
        '(grants everything under it, so the action count below understates this row)',
    );
  }

  for (const [pattern, why] of HIGH_IMPACT_ACTIONS) {
    const hit = actions.find((action) => action === pattern || action.startsWith(pattern));
    if (hit) reasons.push(`${hit} (${why})`);
  }

  if (reasons.length > 0) return { level: 'high', reasons };

  const writes = actions.filter((action) => WRITE_SUFFIX.test(action));
  if (writes.length > 0) {
    return { level: 'medium', reasons: [`${writes.length} write action(s), none on the high impact list`] };
  }

  if (actions.length === 0) {
    return { level: 'unknown', reasons: ['the role definition returned no allowed resource actions'] };
  }
  return { level: 'low', reasons: ['read only'] };
}

/**
 * Wrap prose at a readable width with a hanging indent. The payload detail is
 * the part of this report people screenshot, and a line that breaks mid-word
 * at column 137 is not quotable.
 */
function wrap(text, width = 78, indent = '    ') {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line && (line + ' ' + word).length > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((entry, index) => (index === 0 ? entry : indent + entry)).join('\n');
}

function summarizeActions(actions, limit = 4) {
  if (actions.length === 0) return '';
  const counts = new Map();
  for (const action of actions) {
    const parts = action.split('/');
    const resource = parts.length > 1 ? `${parts[0]}/${parts[1]}` : action;
    counts.set(resource, (counts.get(resource) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const head = sorted.slice(0, limit).map(([resource, count]) => `${resource} ${count}`);
  const rest = sorted.length - head.length;
  return head.join(', ') + (rest > 0 ? `, plus ${rest} more resource(s)` : '');
}

/**
 * Read the PIM policy that governs a role, cached per role definition.
 * The $filter on this endpoint is required, not optional.
 */
async function policyFor(roleDefinitionId) {
  if (policyCache.has(roleDefinitionId)) return policyCache.get(roleDefinitionId);

  const unavailable = { maxActivation: 'unknown', mfa: 'unknown', approval: 'unknown' };
  const filter =
    `scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '${roleDefinitionId}'`;
  const path =
    '/policies/roleManagementPolicyAssignments' +
    `?$filter=${encodeURIComponent(filter)}&$expand=policy($expand=rules)`;

  let summary = unavailable;
  try {
    const response = await graphGet(path);
    const rules = response.value?.[0]?.policy?.rules || [];
    const expiration = rules.find((rule) => rule.id === 'Expiration_EndUser_Assignment');
    const enablement = rules.find((rule) => rule.id === 'Enablement_EndUser_Assignment');
    const approval = rules.find((rule) => rule.id === 'Approval_EndUser_Assignment');
    const authContext = rules.find((rule) => rule.id === 'AuthenticationContext_EndUser_Assignment');

    const enabled = enablement?.enabledRules || [];
    const mfaParts = [];
    if (enabled.includes('MultiFactorAuthentication')) mfaParts.push('yes');
    if (authContext?.isEnabled) mfaParts.push('authctx');
    if (mfaParts.length === 0) mfaParts.push('no');

    summary = {
      maxActivation: expiration?.maximumDuration || 'not set',
      mfa: mfaParts.join('+'),
      approval: approval?.setting?.isApprovalRequired ? 'yes' : 'no',
    };
  } catch (error) {
    console.error(
      `Could not read the policy for role ${roleDefinitionId}: ${error.message.slice(0, 120)}`,
    );
  }

  policyCache.set(roleDefinitionId, summary);
  return summary;
}

function principalType(principal) {
  const type = principal?.['@odata.type'] || '';
  if (type.includes('servicePrincipal')) return 'servicePrincipal';
  if (type.includes('group')) return 'group';
  if (type.includes('user')) return 'user';
  return 'unknown';
}

function describeExpiry(schedule) {
  const expiration = schedule.scheduleInfo?.expiration;
  if (!expiration || expiration.type === 'noExpiration') return 'never';
  if (expiration.type === 'afterDuration') return expiration.duration || 'duration';
  const end = expiration.endDateTime || schedule.endDateTime;
  return end ? String(end).slice(0, 10) : 'never';
}

function isShortWindow(duration) {
  const match = /^PT(?:(\d+)H)?(?:(\d+)M)?$/.exec(duration || '');
  if (!match) return false;
  const hours = Number(match[1] || 0) + Number(match[2] || 0) / 60;
  return hours > 0 && hours <= 4;
}

function rank(level) {
  return { high: 3, medium: 2, low: 1, unknown: 0 }[level] ?? 0;
}

function trim(value, length) {
  const text = String(value ?? '');
  return text.length > length ? `${text.slice(0, length - 1)}.` : text;
}
