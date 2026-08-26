/**
 * Deploy the Conditional Access policies in ./policies to a tenant.
 *
 * Policies are matched to existing tenant policies by displayName, so running
 * this twice updates rather than duplicates. Everything lands in report only
 * unless ALLOW_ENABLED=1 is set and the file itself asks for "enabled".
 *
 *   DRY_RUN=1 npm run plan     print the exact Graph calls, send nothing
 *   npm run deploy             create or update, report only
 *   ALLOW_ENABLED=1 npm run deploy
 *
 * Graph permissions: Policy.Read.All and Policy.ReadWrite.ConditionalAccess.
 * Delegated callers also need the Conditional Access Administrator or
 * Security Administrator role.
 * https://learn.microsoft.com/graph/api/conditionalaccessroot-post-policies
 */

import { useScopes, graphGetAll, graphWrite, isDryRun, printTable } from '../../../shared/js/graph.mjs';
import { checkAll } from './guard.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Policy.Read.All',
  'Policy.ReadWrite.ConditionalAccess',
);


const options = {
  breakGlassGroupId: process.env.BREAK_GLASS_GROUP_ID,
  allowEnabled: process.env.ALLOW_ENABLED === '1',
};

let checked;
try {
  checked = await checkAll(options);
} catch (error) {
  console.error(`\nGuard failed, nothing was sent.\n${error.message}`);
  process.exit(1);
}

if (options.allowEnabled) {
  console.log('ALLOW_ENABLED=1 is set. Policies marked "enabled" will be enforced for real.\n');
}

const existing = await graphGetAll('/identity/conditionalAccess/policies?$select=id,displayName,state');
const byName = new Map(existing.map((policy) => [policy.displayName, policy]));

const results = [];

for (const entry of checked) {
  entry.warnings.forEach((warning) => console.log(`${entry.file}: warning: ${warning}`));

  const desired = entry.policy;
  const match = byName.get(desired.displayName);

  // id, createdDateTime and modifiedDateTime are read only. Strip them before sending.
  const { id, createdDateTime, modifiedDateTime, ...payload } = desired;

  if (match) {
    await graphWrite('PATCH', `/identity/conditionalAccess/policies/${match.id}`, payload);
    results.push({
      file: entry.file,
      action: isDryRun() ? 'would update' : 'updated',
      state: desired.state,
      policy: desired.displayName,
    });
  } else {
    const created = await graphWrite('POST', '/identity/conditionalAccess/policies', payload);
    results.push({
      file: entry.file,
      action: isDryRun() ? 'would create' : 'created',
      state: desired.state,
      policy: desired.displayName,
    });
  }
}

// Kept narrow enough to read in a terminal. The full state enum is 33
// characters and the file name repeats the policy name, so neither earns its
// column. "report only" is enabledForReportingButNotEnforced.
const SHORT_STATE = {
  enabledForReportingButNotEnforced: 'report only',
  enabled: 'ENABLED',
  disabled: 'disabled',
};

console.log('');
printTable(
  results.map((row) => ({
    action: row.action,
    state: SHORT_STATE[row.state] ?? row.state,
    policy: row.policy,
  })),
  ['action', 'state', 'policy'],
);

if (!isDryRun()) {
  console.log(
    '\nReport only policies do not block anything. Check the sign-in logs\n' +
      '"Report-only" tab after a day of real traffic, then run npm test to\n' +
      'evaluate specific sign-ins against them before you enable anything.',
  );
}
