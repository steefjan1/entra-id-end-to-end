/**
 * Read and optionally move the source of authority for a synced user or group.
 *
 * Converting source of authority is the one move that actually closes the
 * on-premises to cloud half of the gap for a given object. Instead of Active
 * Directory owning the object and Microsoft Entra ID holding a replica, Entra
 * owns it. The Active Directory object is left completely untouched.
 *
 *   GET   /users/{id}/onPremisesSyncBehavior
 *   GET   /groups/{id}/onPremisesSyncBehavior
 *   PATCH /users/{id}/onPremisesSyncBehavior   { "isCloudManaged": true }
 *   PATCH /groups/{id}/onPremisesSyncBehavior  { "isCloudManaged": true }
 *
 * THE ENDPOINT VERSION PROBLEM, which is why this script is longer than it
 * looks like it needs to be.
 *
 * The Microsoft Entra how-to pages show these calls against /v1.0. Every
 * Microsoft Graph reference page for the onPremisesSyncBehavior resource is
 * beta only, and the PowerShell cmdlet is Update-MgBetaUserOnPremiseSyncBehavior,
 * with Beta in the name. Those two facts cannot both be the whole truth for
 * every tenant, so this script does not pick a side: it tries v1.0 first, falls
 * back to beta on a 400 or a 404, and prints which endpoint actually answered.
 * Record that line. It is the answer for your tenant on the day you ran it, and
 * it is worth more than either doc page.
 *
 * Permissions: User-OnPremisesSyncBehavior.ReadWrite.All and
 * Group-OnPremisesSyncBehavior.ReadWrite.All. Role: Hybrid Administrator.
 * Licence: Microsoft Entra ID Free is enough.
 *
 * Prerequisites: Entra Connect Sync 2.5.76.0 or later, or Entra Cloud Sync
 * 1.1.1370.0 or later. Converting a USER is GA as of January 2026, and group
 * conversion is supported the same way. No on-premises Exchange workloads, no
 * AD FS or third party federation, and no password dependent applications for
 * that user.
 *
 * After a successful conversion: isCloudManaged is true, onPremisesSyncEnabled
 * becomes null, the onPremises* attributes are RETAINED but from then on you
 * maintain them yourself through Graph, the Active Directory object is not
 * modified, and Event ID 6956 is logged on the sync server.
 *
 *   npm run soa -- --user <object-id-or-upn>
 *   npm run soa -- --group <object-id>
 *   DRY_RUN=1 npm run soa -- --user <id> --set cloud
 *   npm run soa -- --user <id> --set cloud --confirm
 *   npm run soa -- --user <id> --set onprem --confirm     (revert)
 *
 * https://learn.microsoft.com/entra/identity/hybrid/concept-source-of-authority-overview
 * https://learn.microsoft.com/graph/api/resources/onpremisessyncbehavior?view=graph-rest-beta
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphWrite, isDryRun } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'User-OnPremisesSyncBehavior.ReadWrite.All',
  'Group-OnPremisesSyncBehavior.ReadWrite.All',
  'User.Read.All',
  'Group.Read.All',
);

const { values: args } = parseArgs({
  options: {
    user: { type: 'string' },
    group: { type: 'string' },
    set: { type: 'string' },
    confirm: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help || (!args.user && !args.group)) {
  console.log(
    'Usage: node src/soa-inspect.mjs (--user <id|upn> | --group <id>) [--set cloud|onprem]\n' +
      '                               [--confirm] [--json]\n' +
      '\n' +
      '  --user <id|upn>  the user to inspect. Object ID or user principal name.\n' +
      '  --group <id>     the group to inspect. Object ID.\n' +
      '  --set cloud      PATCH isCloudManaged: true. Entra becomes the source of\n' +
      '                   authority. The Active Directory object is not touched.\n' +
      '  --set onprem     PATCH isCloudManaged: false. Reverts to Active Directory.\n' +
      '  --confirm        required for a real write. Without it the write is refused.\n' +
      '  --json           emit the before and after state as JSON.\n' +
      '\n' +
      'Run it with DRY_RUN=1 first. Every write goes through the shared helper, so\n' +
      'DRY_RUN=1 prints the exact request and sends nothing.\n',
  );
  process.exit(args.help ? 0 : 1);
}

if (args.user && args.group) {
  console.error('Pass --user or --group, not both. Source of authority is a per object decision.');
  process.exit(1);
}

const target = args.user
  ? { kind: 'user', collection: 'users', id: args.user }
  : { kind: 'group', collection: 'groups', id: args.group };

let desired = null;
if (args.set !== undefined) {
  const normalized = String(args.set).toLowerCase();
  if (normalized === 'cloud' || normalized === 'true') desired = true;
  else if (normalized === 'onprem' || normalized === 'on-premises' || normalized === 'false')
    desired = false;
  else {
    console.error(`--set must be "cloud" or "onprem". Got "${args.set}".`);
    process.exit(1);
  }
}

/* ----------------------------------------------------------- the object */

const objectSelect =
  target.kind === 'user'
    ? 'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesImmutableId,onPremisesDistinguishedName'
    : 'id,displayName,securityEnabled,mailEnabled,groupTypes,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier';

let object;
try {
  object = await graphGet(`/${target.collection}/${encodeURIComponent(target.id)}?$select=${objectSelect}`);
} catch (error) {
  console.error(`Could not read the ${target.kind}: ${error.message}`);
  process.exit(1);
}

console.log(`${target.kind}: ${object.displayName || object.id}`);
console.log(`  id                          ${object.id}`);
if (target.kind === 'user') {
  console.log(`  userPrincipalName           ${object.userPrincipalName || ''}`);
  console.log(`  accountEnabled              ${object.accountEnabled}`);
  console.log(`  onPremisesImmutableId       ${object.onPremisesImmutableId || '(none)'}`);
  console.log(`  onPremisesDistinguishedName ${object.onPremisesDistinguishedName || '(none)'}`);
}
console.log(`  onPremisesSyncEnabled       ${describeFlag(object.onPremisesSyncEnabled)}`);
console.log(`  onPremisesSamAccountName    ${object.onPremisesSamAccountName || '(none)'}`);
console.log(`  onPremisesDomainName        ${object.onPremisesDomainName || '(none)'}`);
console.log(`  onPremisesLastSyncDateTime  ${object.onPremisesLastSyncDateTime || '(none)'}`);
console.log('');

/* ------------------------------------------------- onPremisesSyncBehavior */

const behaviorPath = `/${target.collection}/${object.id}/onPremisesSyncBehavior`;

const before = await readBehavior();
printBehavior('current source of authority', before);

if (desired === null) {
  console.log(
    '\nNo --set given, so nothing was changed. Add --set cloud to move source of\n' +
      'authority to Microsoft Entra ID, or --set onprem to move it back.\n',
  );
  if (args.json) {
    console.log(JSON.stringify({ object, before: before.body, endpoint: before.version }, null, 2));
  }
  process.exit(0);
}

if (before.body && before.body.isCloudManaged === desired) {
  console.log(
    `\nisCloudManaged is already ${desired}. Nothing to do.\n`,
  );
  process.exit(0);
}

preflight(desired);

if (!isDryRun() && !args.confirm) {
  console.error(
    '\nRefusing to write without --confirm.\n' +
      'Run it with DRY_RUN=1 first, read the request, then add --confirm.\n',
  );
  process.exit(1);
}

const after = await writeBehavior(desired);

if (isDryRun()) {
  console.log(
    '\nDRY_RUN=1, so nothing was sent. Note that the v1.0 to beta fallback cannot be\n' +
      'exercised in a dry run, because no response comes back to fall back from. On a\n' +
      'real run this script prints the endpoint that answered.\n',
  );
  process.exit(0);
}

console.log(`\nPATCH answered on ${after.version}.`);

const confirmed = await readBehavior();
printBehavior('source of authority after the change', confirmed);

const objectAfter = await graphGet(
  `/${target.collection}/${object.id}?$select=${objectSelect}`,
);
console.log('');
console.log(`  onPremisesSyncEnabled       ${describeFlag(objectAfter.onPremisesSyncEnabled)}`);
console.log(`  onPremisesSamAccountName    ${objectAfter.onPremisesSamAccountName || '(none)'}`);
console.log(`  onPremisesLastSyncDateTime  ${objectAfter.onPremisesLastSyncDateTime || '(none)'}`);

if (desired === true) {
  console.log(
    '\nWhat just happened, and what did not.\n' +
      '\n' +
      '  Microsoft Entra ID is now the source of authority for this object.\n' +
      '  onPremisesSyncEnabled goes to null. The onPremises* attributes are retained,\n' +
      '  but from now on nothing maintains them except you, through Graph.\n' +
      '  The Active Directory object was NOT modified, NOT disabled and NOT deleted.\n' +
      '  Event ID 6956 is logged on the sync server. Go and check it there.\n' +
      '\n' +
      '  Kerberos and LDAP access on premises is unchanged, because the Active\n' +
      '  Directory account is still there and still enabled. If you wanted this to be\n' +
      '  a lifecycle control, it is not one on its own.\n' +
      '\n' +
      '  A converted user loses password based authentication unless it keeps a hybrid\n' +
      '  presence. For Kerberos applications that means passwordless: Windows Hello for\n' +
      '  Business or FIDO2 with Cloud Kerberos Trust, and the account must remain in\n' +
      '  Active Directory for Kerberos single sign-on to keep working.\n' +
      '\n' +
      '  Reversible: run this again with --set onprem --confirm.\n',
  );
} else {
  console.log(
    '\nReverted. Active Directory is the source of authority again, and the object\n' +
      'will be picked up by the next sync cycle. Confirm that with sync-report.mjs\n' +
      'once a cycle has run, rather than assuming it.\n',
  );
}

if (args.json) {
  console.log(
    JSON.stringify(
      {
        object: objectAfter,
        before: before.body,
        beforeEndpoint: before.version,
        after: confirmed.body,
        afterEndpoint: confirmed.version,
        patchEndpoint: after.version,
      },
      null,
      2,
    ),
  );
}

/* ---------------------------------------------------------------- helpers */

/**
 * Try v1.0, fall back to beta on a 400 or a 404.
 *
 * A 400 here is not always "bad request" in the ordinary sense. When a Graph
 * version does not know a navigation property, the router can reject the URL
 * before anything looks at the body, and that surfaces as a 400 rather than a
 * 404. So both statuses mean the same thing for our purposes: this version does
 * not serve this resource, try the other one.
 *
 * A 403 is NOT a fallback case. That means the endpoint exists and your
 * permissions or your role are wrong, and retrying on beta will fail the same
 * way with a more confusing message.
 */
async function tryVersions(operation, label) {
  const attempts = [];
  for (const version of ['v1.0', 'beta']) {
    try {
      const body = await operation(version);
      if (attempts.length > 0) {
        console.log(
          `  ${label} on v1.0 returned ${attempts[0].status}. Fell back to beta, which worked.`,
        );
      }
      return { body, version, attempts };
    } catch (error) {
      attempts.push({ version, status: error.status ?? 0, message: error.message });
      const retryable = error.status === 400 || error.status === 404;
      if (!retryable || version === 'beta') {
        console.error(`\n${label} failed on every endpoint tried.`);
        attempts.forEach((attempt) =>
          console.error(`  ${attempt.version}: ${attempt.status} ${short(attempt.message)}`),
        );
        if (error.status === 403 || error.status === 401) {
          console.error(
            '\nThat status is a permissions answer, not a versioning one. You need\n' +
              `${target.kind === 'user' ? 'User' : 'Group'}-OnPremisesSyncBehavior.ReadWrite.All ` +
              'and the Hybrid Administrator role.\n',
          );
        } else {
          console.error(
            '\nIf both versions rejected the path, the most likely cause is a sync agent\n' +
              'below the minimum: Entra Connect Sync 2.5.76.0 or Entra Cloud Sync\n' +
              '1.1.1370.0. Check the agent version before you blame Graph.\n',
          );
        }
        process.exit(1);
      }
    }
  }
  return null;
}

async function readBehavior() {
  return tryVersions((version) => graphGet(behaviorPath, { version }), 'GET onPremisesSyncBehavior');
}

async function writeBehavior(isCloudManaged) {
  const body = { isCloudManaged };
  console.log(`\nPATCH ${behaviorPath}`);
  console.log(JSON.stringify(body, null, 2));
  return tryVersions(
    (version) => graphWrite('PATCH', behaviorPath, body, { version }),
    'PATCH onPremisesSyncBehavior',
  );
}

function printBehavior(title, result) {
  if (!result) return;
  console.log(`${title}  [endpoint: ${result.version}]`);
  const body = result.body || {};
  if (body.dryRun) {
    console.log('  (dry run, no response body)');
    return;
  }
  const keys = Object.keys(body).filter((key) => !key.startsWith('@odata'));
  if (keys.length === 0) {
    // A PATCH can legitimately answer 204 No Content, which the shared helper
    // turns into an empty object. That is a success, not a silent failure.
    console.log('  (empty response body. 204 No Content is a valid answer here.)');
    return;
  }
  for (const key of keys) {
    console.log(`  ${key.padEnd(28)}${JSON.stringify(body[key])}`);
  }
  if (typeof body.isCloudManaged === 'boolean') {
    console.log(
      `  => source of authority is ${body.isCloudManaged ? 'MICROSOFT ENTRA ID' : 'ACTIVE DIRECTORY'}`,
    );
  }
}

function preflight(isCloudManaged) {
  if (!isCloudManaged) {
    console.log(
      '\nReverting to Active Directory as source of authority. Confirm the object is\n' +
        'still in the scope of a sync configuration, or it will simply stop being\n' +
        'maintained by anything.\n',
    );
    return;
  }

  console.log('\nBefore you convert, confirm all of these. Graph will not check them for you.\n');
  const checks =
    target.kind === 'user'
      ? [
          'Entra Connect Sync 2.5.76.0 or later, or Entra Cloud Sync 1.1.1370.0 or later',
          'no on-premises Exchange workloads for this user',
          'no AD FS or third party federation in the sign-in path',
          'no applications that depend on this user having an on-premises password',
          'a passwordless plan for any Kerberos application this user needs: Windows Hello',
          '  for Business or FIDO2 with Cloud Kerberos Trust, with the account staying in AD',
          'you accept that the onPremises* attributes become yours to maintain via Graph',
        ]
      : [
          'Entra Connect Sync 2.5.76.0 or later, or Entra Cloud Sync 1.1.1370.0 or later',
          'nothing on premises depends on this group being written by Active Directory',
          'you know which on-premises resources reference this group by its SID',
          'you accept that the onPremises* attributes become yours to maintain via Graph',
        ];
  // A line starting with two spaces is a continuation of the check above it, so
  // it gets indented rather than given a checkbox of its own.
  checks.forEach((check) =>
    console.log(check.startsWith('  ') ? `      ${check.trim()}` : `  [ ] ${check}`),
  );

  if (object.onPremisesSyncEnabled !== true) {
    console.log(
      '\n  Warning: onPremisesSyncEnabled is not true on this object, so it may not be\n' +
        '  a currently synced object at all. Converting source of authority is a move\n' +
        '  for objects Active Directory currently owns.',
    );
  }

  console.log(
    '\n  Note on sourceAnchor. The immutableId, sourceAnchor in Connect Sync terms, is\n' +
      '  "an attribute immutable during the lifetime of an object". Microsoft is\n' +
      '  explicit: "The sourceAnchor attribute value can\'t be changed after the object\n' +
      '  is created in Microsoft Entra ID and the identity is synchronized." Changing it\n' +
      '  later makes Connect Sync throw and block every further change on that object.\n' +
      '  Source of authority conversion does not change it, and neither should you.\n',
  );
}

function describeFlag(value) {
  if (value === true) return 'true';
  if (value === false) return 'false  (previously synced, no longer synced)';
  return 'null   (never synced, or converted to cloud managed)';
}

function short(message) {
  return String(message || '').slice(0, 200);
}
