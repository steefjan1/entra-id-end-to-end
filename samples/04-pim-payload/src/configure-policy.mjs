/**
 * Set the PIM role management policy for the Entra roles listed in
 * config/roles.json: maximum activation duration, what the requester has to
 * prove on activation, and whether somebody has to approve it.
 *
 * This is the part of PIM everyone means when they say "we have PIM". It is
 * the activation window and nothing else. Run src/entitlement-report.mjs
 * afterwards to see what the role can actually do inside that window.
 *
 *   DRY_RUN=1 npm run policy:plan   print the exact PATCH calls, send nothing
 *   npm run policy                  read the current rules, patch, read back
 *   npm run policy -- --role "Global Administrator"
 *
 * Note the path root. Assignments live under /roleManagement/directory but the
 * policies that govern them live under /policies/roleManagementPolicies. They
 * are two different trees and this is where most people get lost.
 *
 *   GET  /policies/roleManagementPolicyAssignments?$filter=... ($filter is REQUIRED)
 *   PATCH /policies/roleManagementPolicies/{policyId}/rules/{ruleId}
 *
 * Permissions: RoleManagementPolicy.Read.Directory to read,
 * RoleManagementPolicy.ReadWrite.Directory to write. A delegated caller also
 * needs the Privileged Role Administrator role, which is itself the kind of
 * standing privilege PIM exists to remove. Read the README before you decide
 * where to run this from.
 * https://learn.microsoft.com/graph/api/policyroot-list-rolemanagementpolicyassignments
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphGetAll, graphWrite, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'RoleManagementPolicy.ReadWrite.Directory',
  'RoleManagement.Read.Directory',
);

const here = dirname(fileURLToPath(import.meta.url));
const configFile = process.env.ROLES_FILE || join(here, '..', 'config', 'roles.json');

const { values: args } = parseArgs({
  options: {
    role: { type: 'string' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/configure-policy.mjs [--role "<display name or template id>"]\n' +
      '       DRY_RUN=1 to print the calls without sending them.',
  );
  process.exit(0);
}

const config = JSON.parse(await readFile(configFile, 'utf8'));
const scope = config.scope || { scopeId: '/', scopeType: 'DirectoryRole' };
const missingVariables = new Set();

let wanted = config.roles || [];
if (args.role) {
  const needle = args.role.toLowerCase();
  wanted = wanted.filter(
    (role) => role.name.toLowerCase() === needle || role.templateId.toLowerCase() === needle,
  );
  if (wanted.length === 0) {
    console.error(`No role in ${configFile} matches "${args.role}".`);
    process.exit(2);
  }
}

// Built in role definitions carry a templateId. Resolve names locally rather
// than guessing whether $filter is supported on every property.
const definitions = await graphGetAll(
  '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn',
);
const byTemplate = new Map(definitions.map((definition) => [definition.templateId, definition]));

const before = [];
const after = [];
const plan = [];

for (const role of wanted) {
  const definition = byTemplate.get(role.templateId);
  if (!definition) {
    console.error(
      `Role template ${role.templateId} (${role.name}) is not present in this tenant. Skipping.`,
    );
    continue;
  }

  const policy = await readPolicy(definition.id);
  if (!policy) {
    console.error(`No role management policy assignment found for ${definition.displayName}.`);
    continue;
  }

  before.push({ role: definition.displayName, ...summarize(policy.rules) });

  const desired = mergeActivation(config.defaults?.policy?.activation, role.policy?.activation);
  const approvers = resolveApprovers(desired.approval?.primaryApprovers);

  const bodies = [
    expirationRule(desired),
    enablementRule(desired),
    approvalRule(desired, approvers),
  ];

  for (const body of bodies) {
    await graphWrite('PATCH', `/policies/roleManagementPolicies/${policy.policyId}/rules/${body.id}`, body);
    plan.push({
      role: definition.displayName,
      rule: body.id,
      change: describeRule(body),
      action: isDryRun() ? 'would patch' : 'patched',
    });
  }

  if (!isDryRun()) {
    const reread = await readPolicy(definition.id);
    after.push({ role: definition.displayName, ...summarize(reread.rules) });
  } else {
    after.push({
      role: definition.displayName,
      maxActivation: desired.maximumDuration,
      expiryRequired: String(desired.isExpirationRequired),
      onActivation: (desired.enabledRules || []).join('+') || 'none',
      approval: desired.approval?.isApprovalRequired ? 'required' : 'no',
      approvers: !desired.approval?.isApprovalRequired
        ? 'n/a'
        : approvers.length > 0
          ? String(approvers.length)
          : 'default (privileged role admins)',
      authContext: 'unchanged',
    });
  }
}

const columns = [
  'role',
  'maxActivation',
  'expiryRequired',
  'onActivation',
  'approval',
  'approvers',
  'authContext',
];

console.log('\nBefore\n');
printTable(before, columns);

console.log('\nChanges\n');
printTable(plan, ['action', 'role', 'rule', 'change']);

console.log(isDryRun() ? '\nPlanned (not sent)\n' : '\nAfter\n');
printTable(after, columns);

if (missingVariables.size > 0) {
  console.log(
    `\nThese environment variables were referenced by ${configFile} but are not set: ` +
      `${[...missingVariables].join(', ')}.\n` +
      'Approver entries that depend on them were dropped. With an empty approver list\n' +
      'Entra falls back to Privileged Role Administrators and Global Administrators as\n' +
      'the approvers, which is a real configuration but probably not the one you meant.',
  );
}

console.log(
  '\nThis script configured WHEN these roles can be active. It said nothing about\n' +
    'what they can do once they are. Run npm run report next.',
);

/**
 * Read the policy that governs a role at a scope, with its rules expanded.
 * The $filter is required by the API. Without it you get a 400.
 */
async function readPolicy(roleDefinitionId) {
  const filter =
    `scopeId eq '${scope.scopeId}' and scopeType eq '${scope.scopeType}' ` +
    `and roleDefinitionId eq '${roleDefinitionId}'`;
  const path =
    '/policies/roleManagementPolicyAssignments' +
    `?$filter=${encodeURIComponent(filter)}&$expand=policy($expand=rules)`;
  const response = await graphGet(path);
  const assignment = response.value?.[0];
  if (!assignment) return null;
  return {
    assignmentId: assignment.id,
    policyId: assignment.policyId || assignment.policy?.id,
    rules: assignment.policy?.rules || [],
  };
}

function rule(rules, id) {
  return rules.find((item) => item.id === id) || null;
}

function summarize(rules) {
  const expiration = rule(rules, 'Expiration_EndUser_Assignment');
  const enablement = rule(rules, 'Enablement_EndUser_Assignment');
  const approval = rule(rules, 'Approval_EndUser_Assignment');
  const authContext = rule(rules, 'AuthenticationContext_EndUser_Assignment');
  const approverCount = approval?.setting?.approvalStages?.[0]?.primaryApprovers?.length ?? 0;

  return {
    maxActivation: expiration?.maximumDuration || 'not set',
    expiryRequired: String(expiration?.isExpirationRequired ?? 'not set'),
    onActivation: (enablement?.enabledRules || []).join('+') || 'nothing',
    approval: approval?.setting?.isApprovalRequired ? 'required' : 'no',
    approvers: approval?.setting?.isApprovalRequired
      ? approverCount > 0
        ? String(approverCount)
        : 'default (privileged role admins)'
      : 'n/a',
    authContext: authContext?.isEnabled ? authContext.claimValue || 'enabled' : 'no',
  };
}

function mergeActivation(base = {}, override = {}) {
  return {
    ...base,
    ...override,
    approval: {
      ...(base.approval || {}),
      ...(override.approval || {}),
      stage: { ...(base.approval?.stage || {}), ...(override.approval?.stage || {}) },
    },
  };
}

function resolveApprovers(approvers = []) {
  const resolved = [];
  for (const approver of approvers) {
    const id = substitute(approver.id);
    if (!id || id.includes('${')) continue;
    resolved.push({ ...approver, id });
  }
  return resolved;
}

function substitute(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([A-Z0-9_]+)\}/g, (match, name) => {
    const found = process.env[name];
    if (!found) {
      missingVariables.add(name);
      return match;
    }
    return found;
  });
}

/**
 * The three rule bodies below are the documented shapes, kept verbatim so you
 * can diff them against learn.microsoft.com without translating anything.
 * https://learn.microsoft.com/graph/api/unifiedrolemanagementpolicyrule-update
 */
function expirationRule(desired) {
  return {
    '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule',
    id: 'Expiration_EndUser_Assignment',
    isExpirationRequired: desired.isExpirationRequired !== false,
    maximumDuration: desired.maximumDuration || 'PT2H',
    target: {
      '@odata.type': 'microsoft.graph.unifiedRoleManagementPolicyRuleTarget',
      caller: 'EndUser',
      operations: ['All'],
      level: 'Assignment',
      inheritableSettings: [],
      enforcedSettings: [],
    },
  };
}

function enablementRule(desired) {
  return {
    '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule',
    id: 'Enablement_EndUser_Assignment',
    enabledRules: desired.enabledRules || ['MultiFactorAuthentication', 'Justification'],
    target: {
      caller: 'EndUser',
      operations: ['All'],
      level: 'Assignment',
      inheritableSettings: [],
      enforcedSettings: [],
    },
  };
}

function approvalRule(desired, approvers) {
  const approval = desired.approval || {};
  const stage = approval.stage || {};
  return {
    '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule',
    id: 'Approval_EndUser_Assignment',
    setting: {
      isApprovalRequired: approval.isApprovalRequired === true,
      approvalStages: [
        {
          approvalStageTimeoutInDays: stage.approvalStageTimeoutInDays ?? 1,
          isApproverJustificationRequired: stage.isApproverJustificationRequired !== false,
          escalationTimeoutInMinutes: stage.escalationTimeoutInMinutes ?? 0,
          primaryApprovers: approvers,
          isEscalationEnabled: stage.isEscalationEnabled === true,
          escalationApprovers: [],
        },
      ],
      isRequestorJustificationRequired: approval.isRequestorJustificationRequired !== false,
    },
    target: {
      caller: 'EndUser',
      operations: ['All'],
      level: 'Assignment',
      inheritableSettings: [],
      enforcedSettings: [],
    },
  };
}

function describeRule(body) {
  if (body.id === 'Expiration_EndUser_Assignment') {
    return `max activation ${body.maximumDuration}, expiry required ${body.isExpirationRequired}`;
  }
  if (body.id === 'Enablement_EndUser_Assignment') {
    return `on activation require ${body.enabledRules.join(' plus ') || 'nothing'}`;
  }
  const setting = body.setting;
  const count = setting.approvalStages[0].primaryApprovers.length;
  return setting.isApprovalRequired
    ? `approval required, ${count > 0 ? `${count} primary approver group(s)` : 'default approvers'}, ` +
        `${setting.approvalStages[0].approvalStageTimeoutInDays} day timeout`
    : 'approval not required';
}
