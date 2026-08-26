/**
 * Create the directory objects the policy files refer to, and report whether
 * this tenant can actually run them.
 *
 * The policies in ./policies do not hard code object IDs. They carry
 * ${ENV_VAR} placeholders, so the same files work against a lab tenant and a
 * production one. Something still has to create those objects the first time,
 * and clicking through the portal to collect four GUIDs is exactly the kind of
 * undocumented prerequisite that makes a sample repository useless.
 *
 * This is read mostly. It creates two groups and one named location, all of
 * which are inert on their own: a group with no members grants nothing, and a
 * named location that no policy references does nothing. It never creates a
 * Conditional Access policy. That is deploy.mjs, and it is a separate,
 * deliberate act.
 *
 *   npm run bootstrap:plan         show what it would create
 *   npm run bootstrap              create it
 *   npm run bootstrap -- --egress 203.0.113.0/24,198.51.100.7/32
 *
 * Permissions: Group.ReadWrite.All, Policy.ReadWrite.ConditionalAccess,
 * Organization.Read.All (for the licence check), User.Read.All.
 */

import { useScopes, graphGet, graphGetAll, graphWrite, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Group.ReadWrite.All',
  'Policy.ReadWrite.ConditionalAccess',
  'Policy.Read.All',
  'Organization.Read.All',
);

const argv = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith('--') ? argv[index + 1] : fallback;
};

const breakGlassName = flag('break-glass-group', 'CA Break Glass Exclusion');
const deviceCodeName = flag('device-code-group', 'CA Device Code Flow Exception');
const locationName = flag('location', 'Corporate egress');
const egress = (flag('egress', '') || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const results = [];
const env = {};

// ---------------------------------------------------------------------------
// 1. Can this tenant do Conditional Access at all?
//
// Conditional Access needs Entra ID P1. The risk conditions in policy 04 need
// P2. Policy 05 targets workload identities, which needs Workload Identities
// Premium on top. Finding that out from a 403 halfway through a deployment is
// a worse experience than being told now.
// ---------------------------------------------------------------------------
let skus = [];
let skuReadSucceeded = false;
try {
  skus = await graphGetAll('/subscribedSkus?$select=skuPartNumber,servicePlans,prepaidUnits');
  skuReadSucceeded = true;
} catch (error) {
  // Do not truncate this. The first run of anything here is where the real
  // cause shows up, and an 80 character slice cuts it in half.
  console.log('Could not read the subscribed SKUs, so the licence check is skipped.');
  console.log(`  ${error.message}\n`);

  // A credential that cannot issue a token at all will fail every call after
  // this one, so stop here rather than repeating the same error four times.
  if (/token|az login|credential/i.test(error.message)) {
    console.error('Nothing else in this script can work without a token. Stopping.');
    process.exit(4);
  }
}

const planNames = new Set(
  skus.flatMap((sku) => (sku.servicePlans ?? []).map((plan) => plan.servicePlanName)),
);

const has = (name) => planNames.has(name);
const licences = [
  { capability: 'Conditional Access', plan: 'AAD_PREMIUM', needed_for: 'every policy here' },
  { capability: 'Identity Protection risk', plan: 'AAD_PREMIUM_P2', needed_for: 'policy 04' },
  {
    capability: 'Workload Identities Premium',
    plan: 'Workload_Identities',
    needed_for: 'policy 05',
  },
];

// An empty list is not "no answer". It is an answer: this tenant holds no
// licences at all, which means Entra ID Free, which means no Conditional
// Access. Saying nothing here is how somebody spends an hour wondering why
// deploy.mjs returns 403.
if (skuReadSucceeded && skus.length === 0) {
  console.log('This tenant has no subscribed SKUs, so it is on Entra ID Free.\n');
  console.log('Conditional Access needs Entra ID P1, and policy creation will be');
  console.log('rejected without it. The guard and the plan still work offline, and');
  console.log('an Entra ID P2 trial from the Entra admin center under Identity,');
  console.log('Overview, Licenses is the usual way to try the rest.\n');
}

if (skus.length > 0) {
  printTable(
    licences.map((entry) => ({
      capability: entry.capability,
      present: has(entry.plan) ? 'yes' : 'NO',
      'needed for': entry.needed_for,
    })),
    ['capability', 'present', 'needed for'],
  );

  if (!has('AAD_PREMIUM')) {
    console.log(
      '\nThis tenant does not appear to have Entra ID P1, so Conditional Access\n' +
        'policy creation will fail. A P2 trial from the Entra admin center is the\n' +
        'usual way to try this out. The guard and the plan still work offline.',
    );
  }
  if (!has('Workload_Identities')) {
    console.log(
      '\nNo Workload Identities Premium, so policy 05 will be rejected. Skip it:\n' +
        '  SKIP_POLICIES=05 npm run deploy',
    );
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// 2. Groups.
// ---------------------------------------------------------------------------
async function ensureGroup(displayName, description) {
  const existing = await graphGetAll(
    `/groups?$filter=displayName eq '${displayName.replace(/'/g, "''")}'&$select=id,displayName`,
  );
  if (existing.length > 0) {
    results.push({ object: 'group', name: displayName, action: 'existing', id: existing[0].id });
    return existing[0].id;
  }

  const created = await graphWrite('POST', '/groups', {
    displayName,
    description,
    mailEnabled: false,
    mailNickname: displayName.toLowerCase().replace(/[^a-z0-9]/g, ''),
    securityEnabled: true,
  });

  const id = created.id ?? '(dry run)';
  results.push({
    object: 'group',
    name: displayName,
    action: isDryRun() ? 'would create' : 'created',
    id,
  });
  return id;
}

env.BREAK_GLASS_GROUP_ID = await ensureGroup(
  breakGlassName,
  'Excluded from every Conditional Access policy in this tenant. Membership is the last line of defence against a lockout, so it is reviewed, small, and its members use phishing resistant credentials.',
);

env.DEVICE_CODE_EXCEPTION_GROUP_ID = await ensureGroup(
  deviceCodeName,
  'Narrow exception to the device code flow block, for the specific cases that genuinely need it. Empty is the correct default.',
);

// ---------------------------------------------------------------------------
// 3. Named location.
//
// CAE only understands IP based named locations. Country and region conditions
// are invisible to it, which is why this creates an ipNamedLocation and not a
// countryNamedLocation.
// ---------------------------------------------------------------------------
const existingLocations = await graphGetAll(
  '/identity/conditionalAccess/namedLocations?$select=id,displayName',
);
const foundLocation = existingLocations.find((entry) => entry.displayName === locationName);

if (foundLocation) {
  env.CORPORATE_NAMED_LOCATION_ID = foundLocation.id;
  results.push({ object: 'named location', name: locationName, action: 'existing', id: foundLocation.id });
} else if (egress.length === 0) {
  results.push({
    object: 'named location',
    name: locationName,
    action: 'SKIPPED, no --egress given',
    id: '',
  });
} else {
  const created = await graphWrite('POST', '/identity/conditionalAccess/namedLocations', {
    '@odata.type': '#microsoft.graph.ipNamedLocation',
    displayName: locationName,
    isTrusted: false,
    ipRanges: egress.map((cidr) => ({
      '@odata.type': cidr.includes(':')
        ? '#microsoft.graph.iPv6CidrRange'
        : '#microsoft.graph.iPv4CidrRange',
      cidrAddress: cidr,
    })),
  });
  env.CORPORATE_NAMED_LOCATION_ID = created.id ?? '(dry run)';
  results.push({
    object: 'named location',
    name: locationName,
    action: isDryRun() ? 'would create' : 'created',
    id: env.CORPORATE_NAMED_LOCATION_ID,
  });
}

// ---------------------------------------------------------------------------
// 4. Report.
// ---------------------------------------------------------------------------
console.log('');
printTable(results, ['action', 'object', 'name', 'id']);

const realIds = Object.entries(env).filter(([, value]) => value && value !== '(dry run)');

if (realIds.length > 0) {
  console.log('\nSet these before running the guard, the plan or the deploy:\n');
  for (const [name, value] of realIds) {
    console.log(`  $env:${name} = "${value}"`);
  }
} else if (isDryRun()) {
  console.log(
    '\nNo object IDs to print: this was a dry run, so nothing was created and\n' +
      'there is nothing to copy yet. Run it for real to get the values:\n' +
      '  npm run bootstrap -- --egress <your-egress-cidr>',
  );
}

if (!env.CORPORATE_NAMED_LOCATION_ID) {
  console.log(
    '\nNo named location was created, so policy 05 cannot resolve\n' +
      'CORPORATE_NAMED_LOCATION_ID. Either rerun with --egress <cidr,cidr> using\n' +
      'your real outbound addresses, or skip that policy:\n' +
      '  SKIP_POLICIES=05',
  );
}

console.log(
  '\nNothing above enforces anything. Two empty groups and a named location are\n' +
    'inert until a policy references them, and creating policies is deploy.mjs.',
);
