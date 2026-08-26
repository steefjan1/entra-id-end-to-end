/**
 * Every workload identity in the tenant, ranked by how exposed it is.
 *
 * This is the useful script in this sample. Step 1 of the infographic says
 * "User Signs In". Run this and count the rows. In most tenants there are more
 * non-human principals than people, they hold broader permissions than any
 * individual, several of them authenticate with a secret somebody pasted into
 * a pipeline in 2022, and almost none of the controls drawn around step 1
 * apply to them.
 *
 * For every service principal it reports:
 *
 *   tenancy      single tenant or multitenant, from signInAudience. Multitenant
 *                matters twice: it is outside workload identity Conditional
 *                Access, and its app registration lives in somebody's tenant.
 *   credential   secret, certificate, federated, or none. Federated is the good
 *                answer, because there is nothing to leak and nothing to expire.
 *   expiresIn    days to the NEAREST secret or certificate expiry. Negative
 *                means it already expired and something is already failing, or
 *                worse, is not failing because there is a second credential.
 *   fics         count of federated identity credentials on the application
 *                object. Managed identities show as n/a: their credentials are
 *                ARM resources, not directory objects, so Graph cannot see them.
 *   appRoles     application permissions held on Microsoft Graph, resolved from
 *                role IDs to names against the Graph service principal.
 *   highImpact   how many of those are on the list below.
 *   verdict      a computed opinion. Sorted worst first.
 *
 * Reads only. Nothing here writes to the tenant.
 *
 *   GET /servicePrincipals?$select=...
 *   GET /applications?$select=...
 *   GET /servicePrincipals/{id}/appRoleAssignments
 *   GET /applications/{id}/federatedIdentityCredentials
 *   GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=appRoles
 *
 * Permissions: Application.Read.All plus Directory.Read.All. Read only ones,
 * deliberately: an inventory script should not be able to change anything.
 *
 *   npm run inventory
 *   npm run inventory -- --all --limit 500
 *   npm run inventory -- --json > workloads.json
 *
 * https://learn.microsoft.com/graph/api/resources/serviceprincipal
 * https://learn.microsoft.com/entra/identity/conditional-access/workload-identity
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphGetAll, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Application.Read.All',
  'Directory.Read.All',
);

/**
 * Microsoft Graph's well known application ID. Constant in every tenant.
 * Its service principal carries the appRoles that every application
 * permission on Graph resolves against.
 */
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';

/**
 * Application permissions that hand over the directory, or a large part of it.
 * This is a judgement call encoded as a list, not a Microsoft classification.
 * Read it, disagree with it, edit it.
 *
 * The first three are the ones that matter most, because each of them is a
 * path back to every other permission: an identity holding any of them can
 * grant itself the rest and you will not see it happen unless you are watching
 * the audit log.
 */
const HIGH_IMPACT_APP_ROLES = new Set([
  'RoleManagement.ReadWrite.Directory',
  'AppRoleAssignment.ReadWrite.All',
  'Application.ReadWrite.All',
  'Directory.ReadWrite.All',
  'PrivilegedAccess.ReadWrite.AzureADGroup',
  'User.ReadWrite.All',
  'Group.ReadWrite.All',
  'Policy.ReadWrite.ConditionalAccess',
  'Mail.ReadWrite',
  'Files.ReadWrite.All',
]);

/** Tenants that own the Microsoft first party applications. */
const MICROSOFT_TENANTS = new Set([
  'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
  '72f988bf-86f1-41af-91ab-2d7cd011db47',
]);

const { values: args } = parseArgs({
  options: {
    all: { type: 'boolean' },
    'include-microsoft': { type: 'boolean' },
    'skip-managed-identities': { type: 'boolean' },
    limit: { type: 'string' },
    top: { type: 'string' },
    'expiry-days': { type: 'string' },
    concurrency: { type: 'string' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/workload-inventory.mjs [options]\n' +
      '\n' +
      '  --all                      print every row, not just the ones with a verdict\n' +
      '                             above low. Implies --include-microsoft.\n' +
      '  --include-microsoft        include Microsoft first party service principals.\n' +
      '                             There are hundreds and you did not create them.\n' +
      '  --skip-managed-identities  leave managed identity service principals out.\n' +
      '  --limit <n>                stop after n service principals. Use this first in\n' +
      '                             a large tenant: the app role lookup is one call per\n' +
      '                             principal.\n' +
      '  --top <n>                  print only the worst n rows.\n' +
      '  --expiry-days <n>          how many days ahead counts as expiring soon.\n' +
      '                             Default 30.\n' +
      '  --concurrency <n>          parallel Graph reads. Default 8.\n' +
      '  --json                     emit the full rows as JSON instead of tables.\n',
  );
  process.exit(0);
}

/**
 * Progress goes to stderr under --json, so that `npm run inventory:json >
 * workloads.json` produces a file that actually parses. A report tool whose
 * machine readable mode is not machine readable is not a pipeline gate.
 */
const note = (...parts) => (args.json ? console.error(...parts) : console.log(...parts));

if (isDryRun()) {
  note('DRY_RUN=1 is set. This script only reads, so it behaves identically.\n');
}

const EXPIRY_WARN_DAYS = Number(args['expiry-days'] ?? 30);
const LIMIT = args.limit ? Number(args.limit) : Infinity;
const TOP = args.top ? Number(args.top) : Infinity;
const CONCURRENCY = Math.max(1, Number(args.concurrency ?? 8));
const INCLUDE_MICROSOFT = Boolean(args.all || args['include-microsoft']);

/**
 * appRoleAssignedTo is the other direction: who has been assigned an app role
 * ON this service principal, which is what you read to audit a resource API.
 * What this script wants is what this principal holds ON somebody else, and
 * that is appRoleAssignments. They are easy to confuse and the difference is
 * the entire meaning of the report.
 */
const SP_SELECT = [
  'id',
  'appId',
  'displayName',
  'servicePrincipalType',
  'signInAudience',
  'accountEnabled',
  'appOwnerOrganizationId',
  'keyCredentials',
  'passwordCredentials',
].join(',');

const APP_SELECT = ['id', 'appId', 'displayName', 'signInAudience', 'createdDateTime'].join(',');

/** Run an async mapper over items with a fixed number of workers in flight. */
async function pooled(items, worker, concurrency) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

function daysUntil(iso) {
  if (!iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  return Math.floor((then - Date.now()) / 86400000);
}

/** The nearest expiry across every secret and certificate on the principal. */
function nearestExpiry(servicePrincipal) {
  const all = [
    ...(servicePrincipal.passwordCredentials || []),
    ...(servicePrincipal.keyCredentials || []),
  ];
  const days = all.map((credential) => daysUntil(credential.endDateTime)).filter((d) => d !== null);
  if (days.length === 0) return null;
  return Math.min(...days);
}

function credentialKind(servicePrincipal, ficCount) {
  const kinds = [];
  if ((servicePrincipal.passwordCredentials || []).length > 0) kinds.push('secret');
  if ((servicePrincipal.keyCredentials || []).length > 0) kinds.push('certificate');
  if (ficCount > 0) kinds.push('federated');
  if (kinds.length === 0) return 'none';
  return kinds.join('+');
}

/**
 * A managed identity has no signInAudience. Graph returns null, not undefined,
 * and null !== undefined, so an earlier version of this check labelled every
 * managed identity in the tenant as multitenant. On a real tenant that was 27
 * rows of confident nonsense.
 *
 * Absent audience means "not applicable", never "multitenant".
 */
function isMultitenant(signInAudience) {
  if (signInAudience === undefined || signInAudience === null || signInAudience === '') {
    return false;
  }
  return signInAudience !== 'AzureADMyOrg';
}

function tenancyOf(sp) {
  if (sp.servicePrincipalType === 'ManagedIdentity') return 'managed identity';
  return isMultitenant(sp.signInAudience) ? 'multitenant' : 'single tenant';
}

/**
 * The verdict. A number so it sorts, a label so it reads.
 *
 * The weighting is opinionated on purpose. A single high impact application
 * permission outranks everything else here, because Directory.ReadWrite.All on
 * a service principal with a shared secret in a pipeline is a tenant takeover
 * waiting for one leaked variable, and an expired certificate is an outage.
 */
function verdictFor(row) {
  let score = 0;
  const reasons = [];

  if (row.highImpactRoles.length > 0) {
    score += 50 + (row.highImpactRoles.length - 1) * 10;
    reasons.push(`${row.highImpactRoles.length} high impact application permission(s)`);
  }
  if (row.appRoleNames.length > 0 && row.highImpactRoles.length === 0) {
    score += Math.min(15, row.appRoleNames.length * 3);
    reasons.push(`${row.appRoleNames.length} application permission(s) on Graph`);
  }

  const hasSecret = row.credential.includes('secret');
  const hasCertificate = row.credential.includes('certificate');
  const hasFederated = row.credential.includes('federated');

  if (hasSecret) {
    score += 15;
    reasons.push('authenticates with a client secret');
  }
  if (hasCertificate && !hasSecret) {
    score += 5;
  }
  if (hasFederated && !hasSecret && !hasCertificate) {
    // Nothing to leak and nothing to rotate. This is the target state.
    score -= 10;
    reasons.push('federated credential only, nothing to leak');
  }
  if (hasFederated && (hasSecret || hasCertificate)) {
    score += 10;
    reasons.push('has a federated credential AND a secret or certificate, so the secret is still a way in');
  }

  // Azure rotates a managed identity's certificate itself, and old entries linger
  // on the service principal. Scoring that expiry reports a problem nobody has
  // and cannot fix, and it drowns out the rows that are real.
  const rotatesItself = row.type === 'ManagedIdentity';

  if (row.expiresInDays !== null && !rotatesItself) {
    if (row.expiresInDays < 0) {
      score += 20;
      reasons.push(`credential expired ${Math.abs(row.expiresInDays)} days ago`);
    } else if (row.expiresInDays <= EXPIRY_WARN_DAYS) {
      score += 10;
      reasons.push(`credential expires in ${row.expiresInDays} days`);
    }
  }

  if (row.tenancy === 'multitenant') {
    score += 10;
    reasons.push('multitenant, so workload identity Conditional Access does not cover it');
  }
  if (row.type === 'ManagedIdentity') {
    reasons.push(
      'managed identity: no Conditional Access at all, and no credential to rotate. ' +
        'Its blast radius is entirely its Azure RBAC and Graph permissions',
    );
  }
  if (row.accountEnabled === false) {
    score -= 15;
    reasons.push('disabled');
  }

  let label = 'low';
  if (score >= 60) label = 'critical';
  else if (score >= 35) label = 'high';
  else if (score >= 15) label = 'medium';

  return { score, label, reasons };
}

/**
 * Resolve appRoleAssignment rows into permission names.
 *
 * An assignment carries resourceId (the object ID of the API's service
 * principal) and appRoleId (a GUID scoped to that API). The name only exists
 * on the resource's appRoles collection, so it has to be looked up. Graph is
 * fetched by its well known appId; anything else is fetched by resourceId and
 * cached.
 */
class AppRoleResolver {
  constructor() {
    this.byResourceId = new Map();
    this.graphResourceId = null;
  }

  async loadGraph() {
    const graphSp = await graphGet(
      `/servicePrincipals(appId='${GRAPH_APP_ID}')?$select=id,appId,displayName,appRoles`,
    );
    this.graphResourceId = graphSp.id;
    this.byResourceId.set(graphSp.id, {
      displayName: graphSp.displayName,
      roles: new Map((graphSp.appRoles || []).map((role) => [role.id, role.value])),
    });
  }

  async resource(resourceId) {
    if (this.byResourceId.has(resourceId)) return this.byResourceId.get(resourceId);
    let entry = { displayName: resourceId, roles: new Map() };
    try {
      const sp = await graphGet(`/servicePrincipals/${resourceId}?$select=id,displayName,appRoles`);
      entry = {
        displayName: sp.displayName,
        roles: new Map((sp.appRoles || []).map((role) => [role.id, role.value])),
      };
    } catch {
      // A resource we cannot read still counts. Leave the GUID in place rather
      // than dropping the assignment and under reporting.
    }
    this.byResourceId.set(resourceId, entry);
    return entry;
  }

  async resolve(assignments) {
    const graph = [];
    const other = [];
    for (const assignment of assignments) {
      const entry = await this.resource(assignment.resourceId);
      const name = entry.roles.get(assignment.appRoleId) || `unresolved:${assignment.appRoleId}`;
      if (assignment.resourceId === this.graphResourceId) graph.push(name);
      else other.push(`${entry.displayName}/${name}`);
    }
    return { graph: graph.sort(), other: other.sort() };
  }
}

async function main() {
  const resolver = new AppRoleResolver();
  await resolver.loadGraph();

  note('Reading service principals and applications.');

  let servicePrincipals = await graphGetAll(`/servicePrincipals?$select=${SP_SELECT}&$top=999`);
  const applications = await graphGetAll(`/applications?$select=${APP_SELECT}&$top=999`);

  const totalBeforeFilter = servicePrincipals.length;
  const microsoftCount = servicePrincipals.filter((sp) =>
    MICROSOFT_TENANTS.has(sp.appOwnerOrganizationId),
  ).length;

  if (!INCLUDE_MICROSOFT) {
    servicePrincipals = servicePrincipals.filter(
      (sp) => !MICROSOFT_TENANTS.has(sp.appOwnerOrganizationId),
    );
  }
  if (args['skip-managed-identities']) {
    servicePrincipals = servicePrincipals.filter(
      (sp) => sp.servicePrincipalType !== 'ManagedIdentity',
    );
  }
  if (Number.isFinite(LIMIT)) servicePrincipals = servicePrincipals.slice(0, LIMIT);

  // appId is the join key between a service principal and its application
  // object. The application is where federated identity credentials live.
  const appByAppId = new Map(applications.map((app) => [app.appId, app]));

  note(
    `${totalBeforeFilter} service principals in the tenant, ${microsoftCount} of them Microsoft ` +
      `first party. ${applications.length} application objects. Inspecting ` +
      `${servicePrincipals.length}.\n`,
  );

  const rows = await pooled(
    servicePrincipals,
    async (sp) => {
      let assignments = [];
      try {
        assignments = await graphGetAll(`/servicePrincipals/${sp.id}/appRoleAssignments`);
      } catch {
        // Usually a permissions problem on one object rather than all of them.
      }

      const app = appByAppId.get(sp.appId);
      let ficCount = 0;
      let ficKnown = false;
      if (app) {
        ficKnown = true;
        try {
          const fics = await graphGetAll(`/applications/${app.id}/federatedIdentityCredentials`);
          ficCount = fics.length;
        } catch {
          ficKnown = false;
        }
      }

      const resolved = await resolver.resolve(assignments);
      const highImpactRoles = resolved.graph.filter((name) => HIGH_IMPACT_APP_ROLES.has(name));

      const row = {
        displayName: sp.displayName || '(no name)',
        appId: sp.appId,
        objectId: sp.id,
        type: sp.servicePrincipalType,
        signInAudience: sp.signInAudience,
        tenancy: tenancyOf(sp),
        accountEnabled: sp.accountEnabled,
        hasApplicationObject: Boolean(app),
        credential: credentialKind(sp, ficCount),
        expiresInDays: nearestExpiry(sp),
        secretCount: (sp.passwordCredentials || []).length,
        certificateCount: (sp.keyCredentials || []).length,
        // A managed identity's federated credentials are ARM resources on the
        // userAssignedIdentities object, not Graph objects, so this column is
        // genuinely unknowable from here rather than zero.
        federatedCredentials: ficKnown ? ficCount : null,
        appRoleNames: resolved.graph,
        otherResourceAppRoles: resolved.other,
        highImpactRoles,
      };

      const verdict = verdictFor(row);
      return { ...row, score: verdict.score, verdict: verdict.label, reasons: verdict.reasons };
    },
    CONCURRENCY,
  );

  rows.sort((a, b) => b.score - a.score || a.displayName.localeCompare(b.displayName));

  if (args.json) {
    console.log(
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          expiryWarnDays: EXPIRY_WARN_DAYS,
          highImpactAppRoles: [...HIGH_IMPACT_APP_ROLES],
          totalServicePrincipals: totalBeforeFilter,
          inspected: rows.length,
          workloads: rows,
        },
        null,
        2,
      ),
    );
    return;
  }

  const shown = (args.all ? rows : rows.filter((row) => row.verdict !== 'low')).slice(0, TOP);

  const table = shown.map((row) => ({
    verdict: row.verdict,
    score: row.score,
    displayName: row.displayName.slice(0, 44),
    appId: row.appId,
    tenancy: row.tenancy,
    credential: row.credential,
    expiresIn: row.expiresInDays === null ? '' : `${row.expiresInDays}d`,
    fics: row.federatedCredentials === null ? 'n/a' : String(row.federatedCredentials),
    graphRoles: row.appRoleNames.length,
    highImpact: row.highImpactRoles.length,
  }));

  printTable(table, [
    'verdict',
    'score',
    'displayName',
    'appId',
    'tenancy',
    'credential',
    'expiresIn',
    'fics',
    'graphRoles',
    'highImpact',
  ]);

  if (!args.all && rows.length > shown.length) {
    console.log(
      `\n${rows.length - shown.length} row(s) with a verdict of low are hidden. Add --all.`,
    );
  }

  const worst = shown.filter((row) => row.verdict === 'critical' || row.verdict === 'high');
  if (worst.length > 0) {
    console.log('\nWhy the worst rows scored the way they did:\n');
    for (const row of worst) {
      console.log(`${row.displayName} (${row.appId})`);
      for (const reason of row.reasons) console.log(`  - ${reason}`);
      if (row.highImpactRoles.length > 0) {
        console.log(`  high impact on Microsoft Graph: ${row.highImpactRoles.join(', ')}`);
      }
      if (row.otherResourceAppRoles.length > 0) {
        console.log(`  application permissions elsewhere: ${row.otherResourceAppRoles.join(', ')}`);
      }
      console.log('');
    }
  }

  const summary = {
    inspected: rows.length,
    withHighImpactPermission: rows.filter((row) => row.highImpactRoles.length > 0).length,
    withClientSecret: rows.filter((row) => row.credential.includes('secret')).length,
    federatedOnly: rows.filter((row) => row.credential === 'federated').length,
    expired: rows.filter((row) => row.expiresInDays !== null && row.expiresInDays < 0).length,
    expiringSoon: rows.filter(
      (row) =>
        row.expiresInDays !== null &&
        row.expiresInDays >= 0 &&
        row.expiresInDays <= EXPIRY_WARN_DAYS,
    ).length,
    managedIdentities: rows.filter((row) => row.type === 'ManagedIdentity').length,
    multitenant: rows.filter((row) => row.tenancy === 'multitenant').length,
  };

  const summaryLines = [
    ['inspected', summary.inspected],
    ['hold a high impact permission', summary.withHighImpactPermission],
    ['authenticate with a secret', summary.withClientSecret],
    ['federated credential only', summary.federatedOnly],
    ['already expired', summary.expired],
    [`expire within ${EXPIRY_WARN_DAYS} days`, summary.expiringSoon],
    ['managed identities', summary.managedIdentities],
    ['multitenant', summary.multitenant],
  ];
  const labelWidth = Math.max(...summaryLines.map(([label]) => label.length));
  console.log('Summary');
  for (const [label, value] of summaryLines) {
    console.log(`  ${label.padEnd(labelWidth)}  ${value}`);
  }

  console.log(
    '\nRead the multitenant and managed identity counts alongside\n' +
      'ca-workload-policy.mjs in this sample. Every principal in those two counts\n' +
      'is outside workload identity Conditional Access entirely: policy covers\n' +
      'single tenant service principals only, never managed identities and never\n' +
      'multitenant apps. For those, the only controls that apply are the\n' +
      'permissions in the columns above and the Azure RBAC scope they hold, which\n' +
      'is why this report leads with permissions rather than with policy.',
  );

  console.log(
    '\nThis is a snapshot, taken now. Secrets expire on their own schedule and nobody\n' +
      'reads a report twice. Pipe --json into a scheduled job that fails the build when\n' +
      `anything is inside ${EXPIRY_WARN_DAYS} days of expiry, and the number above stops mattering.`,
  );
}

await main();
