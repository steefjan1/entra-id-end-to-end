/**
 * Conditional Access for workload identities, in report only.
 *
 * Step 1 of the infographic says "User Signs In". This script exists because
 * of everything in your tenant that signs in and is not a user. The policy it
 * creates blocks a single tenant service principal that authenticates from
 * anywhere outside a named location.
 *
 * Read all four of these before you run it, because they are the reasons most
 * plans for "Conditional Access on the pipeline" do not survive contact:
 *
 * 1. LICENSING, verbatim from Microsoft:
 *
 *      "Workload Identities Premium licenses are required to create or modify
 *      Conditional Access policies scoped to service principals. In directories
 *      without appropriate licenses, existing Conditional Access policies for
 *      workload identities continue to function, but can't be modified."
 *
 * 2. THE CONDITIONS ARE THREE. Location, service principal risk, and
 *    authentication contexts. That is the whole list. There is no device
 *    condition, no client app condition, no user risk.
 *
 * 3. THE GRANT CONTROL IS BLOCK, AND NOTHING ELSE. There is no "require MFA"
 *    for a workload identity, no "require compliant device", no terms of use.
 *    A workload identity has no human to prompt.
 *
 * 4. SCOPE, verbatim from Microsoft:
 *
 *      "Policy can be applied to single tenant service principals that are
 *      registered in your tenant. Microsoft and third-party SaaS applications,
 *      including multitenant apps, are not covered by these policies. Managed
 *      identities aren't covered by policy."
 *
 *    Service principals in groups are also not covered. Assign directly.
 *
 * The API:
 *   POST /identity/conditionalAccess/policies
 *   Permissions: Policy.Read.All plus Policy.ReadWrite.ConditionalAccess
 *   state is exactly one of: enabled, disabled, enabledForReportingButNotEnforced
 *
 *   npm run ca -- --named-location <namedLocationId> --sp <servicePrincipalObjectId>
 *
 * https://learn.microsoft.com/entra/identity/conditional-access/workload-identity
 * https://learn.microsoft.com/graph/api/conditionalaccessroot-post-policies
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphGetAll, graphWrite, isDryRun } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Policy.Read.All',
  'Policy.ReadWrite.ConditionalAccess',
);

/** The exact enum Graph accepts. Anything else is a 400. */
const STATES = ['enabled', 'disabled', 'enabledForReportingButNotEnforced'];
const REPORT_ONLY = 'enabledForReportingButNotEnforced';

const LICENSING_NOTICE =
  'Workload Identities Premium licenses are required to create or modify Conditional ' +
  'Access policies scoped to service principals. In directories without appropriate ' +
  "licenses, existing Conditional Access policies for workload identities continue to " +
  "function, but can't be modified.";

const SCOPE_NOTICE =
  'Policy can be applied to single tenant service principals that are registered in ' +
  'your tenant. Microsoft and third-party SaaS applications, including multitenant ' +
  "apps, are not covered by these policies. Managed identities aren't covered by policy.";

const { values: args } = parseArgs({
  options: {
    'named-location': { type: 'string' },
    sp: { type: 'string', multiple: true },
    exclude: { type: 'string', multiple: true },
    name: { type: 'string' },
    state: { type: 'string' },
    confirm: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/ca-workload-policy.mjs --named-location <id> [options]\n' +
      '\n' +
      '  --named-location <id>  REQUIRED. Object ID of the named location the workload\n' +
      '                         is allowed to sign in from. This script refuses to run\n' +
      '                         without one, because a policy with no excluded location\n' +
      '                         blocks the workload from everywhere including the place\n' +
      '                         it actually runs.\n' +
      '  --sp <objectId>        Service principal OBJECT ID to include. Repeatable.\n' +
      '                         Omit to target ServicePrincipalsInMyTenant, which is\n' +
      '                         every single tenant service principal you own.\n' +
      '  --exclude <objectId>   Service principal object ID to exclude. Repeatable.\n' +
      '                         Use this for the break glass automation account.\n' +
      '  --name <string>        Policy display name.\n' +
      `  --state <state>        One of ${STATES.join(', ')}.\n` +
      `                         Defaults to ${REPORT_ONLY}.\n` +
      '                         Anything else requires --confirm.\n' +
      '  --confirm              Required to create a policy that is actually enforcing.\n' +
      '  --json                 Emit the policy JSON instead of prose.\n' +
      '\n' +
      'DRY_RUN=1 prints the exact POST body and sends nothing.\n',
  );
  process.exit(0);
}

function fail(message) {
  console.error(`\n${message}\n`);
  process.exit(1);
}

const namedLocationId = args['named-location'] || process.env.CORPORATE_NAMED_LOCATION_ID;

if (!namedLocationId) {
  fail(
    'A named location ID is required. Pass --named-location <id> or set\n' +
      'CORPORATE_NAMED_LOCATION_ID.\n' +
      '\n' +
      'This is not defensive coding for its own sake. The policy shape is "include All\n' +
      'locations, exclude the one you trust". Without an exclusion it becomes "block\n' +
      'this workload from every location", which is a policy that blocks the workload\n' +
      'from the place it runs. In report only that shows up as a report full of blocks.\n' +
      'Enabled, it is an outage.\n' +
      '\n' +
      'List your named locations with:\n' +
      '  GET /identity/conditionalAccess/namedLocations\n',
  );
}

const state = args.state || REPORT_ONLY;
if (!STATES.includes(state)) {
  fail(`--state must be one of ${STATES.join(', ')}. Got "${state}".`);
}
if (state !== REPORT_ONLY && !args.confirm) {
  fail(
    `--state ${state} creates a policy that is not report only. Pass --confirm if that\n` +
      'is genuinely what you want. The only grant control available here is block, so\n' +
      'the failure mode of getting this wrong is a workload that stops working, with\n' +
      'no prompt and no fallback, at whatever hour the pipeline next runs.',
  );
}

function printNotices() {
  console.log('\nLicensing, verbatim from Microsoft:');
  console.log(`  "${LICENSING_NOTICE}"`);
  console.log('\nScope, verbatim from Microsoft:');
  console.log(`  "${SCOPE_NOTICE}"`);
  console.log(
    '\nIn plain terms: this policy cannot touch a managed identity at all. If the\n' +
      'workload you are worried about is the user assigned managed identity from\n' +
      'infra/, Conditional Access is not the control. Azure RBAC scope and the\n' +
      'federated credential subject are.\n',
  );
  console.log(
    'The available conditions for workload identities are location, service principal\n' +
      'risk and authentication contexts. That is the complete list.\n',
  );
  console.log(
    'The available grant control is block. Not "require MFA", not "require compliant\n' +
      'device", not "require approved client app". Just block. If your plan was to\n' +
      'require multifactor authentication for a pipeline identity, there is no such\n' +
      'thing to configure.\n',
  );
}

/**
 * Warn about the service principals that will silently do nothing.
 * Graph accepts these object IDs happily and the policy simply never applies.
 */
async function checkTargets(objectIds) {
  const rows = [];
  for (const id of objectIds) {
    try {
      const sp = await graphGet(
        `/servicePrincipals/${id}?$select=id,appId,displayName,servicePrincipalType,signInAudience`,
      );
      const isManagedIdentity = sp.servicePrincipalType === 'ManagedIdentity';
      const isMultitenant = sp.signInAudience !== 'AzureADMyOrg';
      let covered = 'yes';
      if (isManagedIdentity) covered = 'NO, managed identity';
      else if (isMultitenant) covered = `NO, signInAudience is ${sp.signInAudience}`;
      rows.push({ id: sp.id, displayName: sp.displayName, covered });
    } catch (error) {
      rows.push({ id, displayName: `(lookup failed: ${error.message})`, covered: 'unknown' });
    }
  }
  const uncovered = rows.filter((row) => row.covered.startsWith('NO'));
  const width = Math.max(...rows.map((row) => row.covered.length));
  for (const row of rows) {
    console.log(`  ${row.covered.padEnd(width)}  ${row.displayName} (${row.id})`);
  }
  if (uncovered.length > 0) {
    console.log(
      `\n${uncovered.length} of the principals above are NOT covered by workload identity\n` +
        'Conditional Access. The policy will be created and it will do nothing for them.\n',
    );
  }
  return rows;
}

async function main() {
  printNotices();

  const includes = args.sp && args.sp.length > 0 ? args.sp : ['ServicePrincipalsInMyTenant'];
  const excludes = args.exclude || [];

  if (args.sp && args.sp.length > 0) {
    console.log('Checking the targeted service principals:');
    await checkTargets(args.sp);
  } else {
    console.log(
      'No --sp given, so this targets ServicePrincipalsInMyTenant: every single tenant\n' +
        'service principal registered in this tenant. That is a wide blast radius even in\n' +
        'report only, because it is also every automation account somebody set up years\n' +
        'ago and forgot. Run src/workload-inventory.mjs first and know what is in there.\n',
    );
  }

  // Confirm the named location exists rather than finding out from a report
  // full of blocks a week later.
  try {
    const location = await graphGet(
      `/identity/conditionalAccess/namedLocations/${namedLocationId}`,
    );
    console.log(`Named location: ${location.displayName} (${location.id})`);
  } catch (error) {
    fail(
      `The named location ${namedLocationId} could not be read: ${error.message}\n` +
        'Fix that before creating a policy that excludes it.',
    );
  }

  const displayName =
    args.name || 'Workload identities: block sign-in from outside the corporate network';

  const policy = {
    displayName,
    state,
    conditions: {
      // clientApplications is what makes this a workload identity policy.
      // A policy with a users condition is a user policy, and the two are
      // not interchangeable.
      clientApplications: {
        includeServicePrincipals: includes,
        excludeServicePrincipals: excludes,
      },
      applications: {
        includeApplications: ['All'],
      },
      locations: {
        includeLocations: ['All'],
        excludeLocations: [namedLocationId],
      },
    },
    grantControls: {
      operator: 'OR',
      // block is the only value available for workload identities.
      builtInControls: ['block'],
    },
  };

  // Under DRY_RUN, graphWrite prints the request itself, so printing it here
  // as well would just show it twice.
  if (!isDryRun()) {
    console.log('\nPOST /identity/conditionalAccess/policies');
    console.log(JSON.stringify(policy, null, 2));
  }

  if (state === REPORT_ONLY) {
    console.log(
      '\nstate is enabledForReportingButNotEnforced. The policy evaluates and logs, and\n' +
        'blocks nothing. Read the sign-in logs, filter to service principal sign-ins,\n' +
        'and look at what would have been blocked before you change this.',
    );
  }

  const created = await graphWrite('POST', '/identity/conditionalAccess/policies', policy);

  if (created.dryRun) {
    console.log('\nDRY_RUN=1 was set. Nothing was created.');
    return;
  }

  if (args.json) {
    console.log(JSON.stringify(created, null, 2));
  } else {
    console.log(`\nCreated policy ${created.displayName}`);
    console.log(`  id    ${created.id}`);
    console.log(`  state ${created.state}`);
  }

  console.log(
    '\nWhere to look next: sign-in logs, the Service Principal Sign-Ins tab. Workload\n' +
      'identity sign-ins are a separate log from interactive user sign-ins, and a policy\n' +
      'that looks like it is doing nothing usually means you are reading the wrong one.',
  );

  console.log(
    '\nAlso worth knowing: continuous access evaluation for workload identities covers\n' +
      'Microsoft Graph ONLY, single tenant service principals only, not managed\n' +
      'identities and not multitenant apps. It issues long lived tokens of up to 24\n' +
      'hours and enforces only location and risk conditions. So the near real time\n' +
      'revocation story for workloads is narrower than it is for users, and it does not\n' +
      'reach whatever Azure resource your pipeline is actually touching.',
  );
}

async function listExisting() {
  // Show what is already there. Two overlapping block policies on the same
  // service principal is an easy accident and a bad afternoon.
  try {
    const policies = await graphGetAll(
      '/identity/conditionalAccess/policies?$select=id,displayName,state,conditions',
    );
    const workload = policies.filter((policy) => policy.conditions?.clientApplications);
    if (workload.length > 0) {
      console.log('\nExisting workload identity Conditional Access policies in this tenant:');
      for (const policy of workload) {
        console.log(`  ${policy.state.padEnd(34)} ${policy.displayName}`);
      }
    } else {
      console.log('\nNo existing workload identity Conditional Access policies in this tenant.');
    }
  } catch (error) {
    console.log(`\nCould not list existing policies: ${error.message}`);
  }
}

if (isDryRun()) {
  console.log('DRY_RUN=1 is set. The policy body will be printed and nothing will be sent.');
}

await listExisting();
await main();
