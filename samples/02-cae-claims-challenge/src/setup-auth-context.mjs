/**
 * Create the Conditional Access authentication context that step-up-api.mjs
 * demands, and the policy that gives it meaning.
 *
 * An authentication context on its own does nothing. It is a label, c1 through
 * c25, that an application can ask for. It only becomes a control when a
 * Conditional Access policy targets that label and requires something extra.
 *
 * This is the one place in this repository where report only is not the right
 * default, and the reason is worth understanding rather than working around:
 * a report only policy never issues the acrs claim, so the API would challenge
 * the client forever and the client would never be able to satisfy it. An
 * authentication context policy also has an unusually small blast radius,
 * because it applies to nothing except requests that explicitly ask for that
 * context. It cannot lock anybody out of anything they are doing today.
 *
 * The script still refuses to enable anything without --confirm.
 *
 *   POST /identity/conditionalAccess/authenticationContextClassReferences
 *   Permission: AuthenticationContext.ReadWrite.All (least privileged)
 *   https://learn.microsoft.com/graph/api/conditionalaccessroot-post-authenticationcontextclassreferences
 */

import { useScopes, graphGet, graphGetAll, graphWrite, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'AuthenticationContext.ReadWrite.All',
  'Policy.ReadWrite.ConditionalAccess',
  'Policy.Read.All',
);

const argv = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith('--') ? argv[index + 1] : fallback;
};
const has = (name) => argv.includes(`--${name}`);

const contextId = flag('id', process.env.AUTH_CONTEXT_ID || 'c1');
const displayName = flag('name', 'Step up required');
const breakGlassGroupId = process.env.BREAK_GLASS_GROUP_ID;
const confirmed = has('confirm');

if (!/^c([1-9]|1[0-9]|2[0-5])$/.test(contextId)) {
  console.error(`Authentication context ID must be c1 through c25. Got "${contextId}".`);
  process.exit(2);
}

// 1. The authentication context itself.
const contextBody = {
  id: contextId,
  displayName,
  description: 'Requires multifactor authentication for sensitive operations in the sample API.',
  isAvailable: true,
};

const existingContexts = await graphGetAll('/identity/conditionalAccess/authenticationContextClassReferences');
const alreadyThere = existingContexts.find((entry) => entry.id === contextId);

if (alreadyThere) {
  console.log(`Authentication context ${contextId} already exists: "${alreadyThere.displayName}".`);
  if (alreadyThere.isAvailable !== true) {
    await graphWrite(
      'PATCH',
      `/identity/conditionalAccess/authenticationContextClassReferences/${contextId}`,
      { isAvailable: true },
    );
    console.log('Published it (isAvailable was false, so no application could request it).');
  }
} else {
  await graphWrite('POST', '/identity/conditionalAccess/authenticationContextClassReferences', contextBody);
  console.log(`Created authentication context ${contextId}.`);
}

// 2. The policy that gives it meaning.
const policyName = `CAC010 Require MFA for authentication context ${contextId}`;
const policy = {
  displayName: policyName,
  state: confirmed ? 'enabled' : 'enabledForReportingButNotEnforced',
  conditions: {
    users: {
      includeUsers: ['All'],
      ...(breakGlassGroupId ? { excludeGroups: [breakGlassGroupId] } : {}),
    },
    applications: {
      includeAuthenticationContextClassReferences: [contextId],
    },
    clientAppTypes: ['all'],
    signInRiskLevels: [],
    userRiskLevels: [],
  },
  grantControls: {
    operator: 'OR',
    builtInControls: ['mfa'],
  },
};

if (!breakGlassGroupId) {
  console.log(
    '\nBREAK_GLASS_GROUP_ID is not set, so the policy has no break glass exclusion.\n' +
      'That is survivable for an authentication context policy and unacceptable for\n' +
      'anything else. Set it anyway.',
  );
}

if (!confirmed) {
  console.log(
    `\nWithout --confirm the policy is created in report only, which means Entra will\n` +
      `never issue the acrs claim for ${contextId} and the API will challenge forever.\n` +
      'Rerun with --confirm once you have read the policy below.',
  );
}

const existingPolicies = await graphGetAll(
  '/identity/conditionalAccess/policies?$select=id,displayName,state',
);
const match = existingPolicies.find((entry) => entry.displayName === policyName);

if (match) {
  await graphWrite('PATCH', `/identity/conditionalAccess/policies/${match.id}`, policy);
} else {
  await graphWrite('POST', '/identity/conditionalAccess/policies', policy);
}

printTable(
  [
    { item: 'authentication context', value: `${contextId} (${displayName})` },
    { item: 'policy', value: policyName },
    { item: 'state', value: policy.state },
    { item: 'mode', value: isDryRun() ? 'dry run, nothing sent' : 'applied' },
  ],
  ['item', 'value'],
);

console.log(
  '\nNext: start the API with AUTH_CONTEXT_ID=' + contextId + ', call /api/sensitive with an\n' +
    'ordinary token, and read the WWW-Authenticate header on the 401.',
);
