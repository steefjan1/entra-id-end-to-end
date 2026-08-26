/**
 * Where does authority for this object actually live?
 *
 * "Hybrid Identity with Active Directory" in a highlights list looks like one
 * checkbox. It is not. Every user and every group in the tenant is on one side
 * of a boundary, and the side it is on decides which system can turn it off.
 *
 * This script inventories users and groups and computes an authority column:
 *
 *   on-premises        onPremisesSyncEnabled is true and the last sync is recent.
 *                      Active Directory owns this object. Entra is a replica.
 *   stale sync         Still synced, but the last sync is older than the
 *                      threshold. This is the window in which an AD disable has
 *                      not yet reached the cloud and the account still works.
 *   cloud (converted)  Previously synced, no longer synced. Either source of
 *                      authority was converted, or the object fell out of sync
 *                      scope, which is a very different problem with the same
 *                      shape in Graph. Both leave the AD object untouched.
 *   cloud              Never synced. Cloud native, and the only kind of object
 *                      where disabling in Entra is the whole story.
 *
 * Then it does the join that matters most: which SYNCED principals hold a
 * PRIVILEGED Entra role. A principal whose authority is on premises but whose
 * privilege is in the cloud is the sharpest form of this gap. Whoever can write
 * to that AD object can take the Entra role with it.
 *
 * Reads only. Nothing here writes to the tenant.
 *
 *   GET /users?$select=...
 *   GET /groups?$select=...
 *   GET /roleManagement/directory/roleDefinitions
 *   GET /roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition
 *   GET /roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition
 *   GET /directoryRoles + /directoryRoles/{id}/members      (fallback)
 *
 * Permissions: User.Read.All, Group.Read.All, RoleManagement.Read.Directory,
 * and RoleAssignmentSchedule.Read.Directory plus
 * RoleEligibilitySchedule.Read.Directory for the PIM path.
 *
 *   npm run report
 *   npm run report -- --stale-minutes 30
 *   npm run report -- --all
 *   npm run report -- --json > authority.json
 *
 * https://learn.microsoft.com/entra/identity/hybrid/connect/choose-ad-authn
 * https://learn.microsoft.com/graph/api/resources/user
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGetAll, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'User.Read.All',
  'Group.Read.All',
  'RoleManagement.Read.Directory',
);

const { values: args } = parseArgs({
  options: {
    'stale-minutes': { type: 'string' },
    limit: { type: 'string' },
    all: { type: 'boolean' },
    'users-only': { type: 'boolean' },
    'groups-only': { type: 'boolean' },
    'skip-roles': { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/sync-report.mjs [options]\n' +
      '\n' +
      '  --stale-minutes <n>  how old a last sync has to be before it is called stale.\n' +
      '                       Default 60. With password hash synchronization an\n' +
      '                       on-premises disable can take up to about 30 minutes to\n' +
      '                       arrive, so 60 is a deliberately forgiving number.\n' +
      '  --limit <n>          stop after n users and n groups. Useful in a big tenant.\n' +
      '  --all                print every object, not just the interesting ones.\n' +
      '  --users-only         skip the group inventory.\n' +
      '  --groups-only        skip the user inventory.\n' +
      '  --skip-roles         skip the privileged role join.\n' +
      '  --json               emit the full rows as JSON instead of tables.\n',
  );
  process.exit(0);
}

if (isDryRun()) {
  console.log('DRY_RUN=1 is set. This script only reads, so it behaves identically.\n');
}

const STALE_MINUTES = Number(args['stale-minutes'] ?? process.env.STALE_MINUTES ?? 60);
if (!Number.isFinite(STALE_MINUTES) || STALE_MINUTES <= 0) {
  console.error('--stale-minutes must be a positive number.');
  process.exit(1);
}
const LIMIT = args.limit ? Number(args.limit) : Infinity;

/**
 * Role names treated as privileged when a tenant's roleDefinitions do not carry
 * the isPrivileged flag. isPrivileged is the authoritative answer when Graph
 * returns it, and this list is only the fallback.
 */
const PRIVILEGED_ROLE_NAMES = new Set(
  [
    'Global Administrator',
    'Privileged Role Administrator',
    'Privileged Authentication Administrator',
    'Security Administrator',
    'Conditional Access Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'Hybrid Identity Administrator',
    'Hybrid Administrator',
    'Directory Synchronization Accounts',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Intune Administrator',
    'User Administrator',
    'Authentication Administrator',
    'Domain Name Administrator',
    'Partner Tier2 Support',
    'Partner Tier1 Support',
  ].map((name) => name.toLowerCase()),
);

const USER_SELECT = [
  'id',
  'displayName',
  'userPrincipalName',
  'accountEnabled',
  'userType',
  'createdDateTime',
  'onPremisesSyncEnabled',
  'onPremisesSamAccountName',
  'onPremisesDomainName',
  'onPremisesUserPrincipalName',
  'onPremisesDistinguishedName',
  'onPremisesLastSyncDateTime',
  'onPremisesImmutableId',
  'onPremisesSecurityIdentifier',
  'onPremisesProvisioningErrors',
].join(',');

const GROUP_SELECT = [
  'id',
  'displayName',
  'mailNickname',
  'securityEnabled',
  'mailEnabled',
  'groupTypes',
  'isAssignableToRole',
  'createdDateTime',
  'onPremisesSyncEnabled',
  'onPremisesSamAccountName',
  'onPremisesDomainName',
  'onPremisesLastSyncDateTime',
  'onPremisesSecurityIdentifier',
  'onPremisesProvisioningErrors',
].join(',');

const now = Date.now();

const users = args['groups-only'] ? [] : await readUsers();
const groups = args['users-only'] ? [] : await readGroups();

const userRows = users.map((user) => classifyUser(user));
const groupRows = groups.map((group) => classifyGroup(group));

const byId = new Map();
userRows.forEach((row) => byId.set(row.id, row));
groupRows.forEach((row) => byId.set(row.id, row));

const roleHoldings = args['skip-roles'] ? { source: 'skipped', rows: [] } : await readRoleHoldings();
const privilegedSynced = joinPrivilegedSynced(roleHoldings.rows);

if (args.json) {
  console.log(
    JSON.stringify(
      {
        generatedAt: new Date(now).toISOString(),
        staleMinutes: STALE_MINUTES,
        roleSource: roleHoldings.source,
        users: userRows,
        groups: groupRows,
        privilegedSyncedPrincipals: privilegedSynced,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

report();

/* ------------------------------------------------------------------ reading */

async function readUsers() {
  const rows = await graphGetAll(`/users?$select=${USER_SELECT}&$top=999`);
  return Number.isFinite(LIMIT) ? rows.slice(0, LIMIT) : rows;
}

async function readGroups() {
  let rows;
  try {
    rows = await graphGetAll(`/groups?$select=${GROUP_SELECT}&$top=999`);
  } catch (error) {
    // Some tenants reject isAssignableToRole in a plain $select. Retry without it.
    console.log(`Group read with the full $select failed (${short(error.message)}). Retrying.`);
    const fallbackSelect = GROUP_SELECT.split(',')
      .filter((field) => field !== 'isAssignableToRole')
      .join(',');
    rows = await graphGetAll(`/groups?$select=${fallbackSelect}&$top=999`);
  }
  return Number.isFinite(LIMIT) ? rows.slice(0, LIMIT) : rows;
}

/**
 * Who holds an Entra role, and is that role privileged.
 *
 * Preferred source is the PIM schedule endpoints, because they cover both
 * active and eligible holders and a role somebody can activate on demand is a
 * role they hold. If those are not readable, fall back to directoryRoles
 * members, which only ever shows currently active holders.
 */
async function readRoleHoldings() {
  const definitions = await safeDefinitions();
  const definitionById = new Map(definitions.map((definition) => [definition.id, definition]));

  try {
    const [active, eligible] = await Promise.all([
      graphGetAll(
        '/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition',
      ),
      graphGetAll(
        '/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition',
      ),
    ]);

    const rows = [
      ...active.map((item) => ({ ...item, holding: 'active' })),
      ...eligible.map((item) => ({ ...item, holding: 'eligible' })),
    ].map((item) => {
      const definition =
        definitionById.get(item.roleDefinitionId) || item.roleDefinition || null;
      return {
        principalId: item.principalId,
        principalName: item.principal?.displayName || item.principalId,
        principalKind: principalKind(item.principal),
        role: definition?.displayName || item.roleDefinitionId,
        roleTemplateId: definition?.templateId || '',
        privileged: isPrivilegedRole(definition),
        holding: item.holding,
        scope: item.directoryScopeId || '/',
      };
    });

    return { source: 'roleAssignmentSchedules + roleEligibilitySchedules', rows };
  } catch (error) {
    // console.log, not console.error. This is an expected fallback, and on
    // Windows PowerShell renders anything on stderr as a red NativeCommandError
    // block, which makes a handled condition look like a crash.
    console.log(
      `PIM schedule endpoints were not readable: ${short(error.message)}\n` +
        'That normally means no Entra ID P2 on this tenant.\n' +
        'Falling back to /directoryRoles members, which shows active holders only,\n' +
        'so any eligible-but-not-active privileged holder will be missing.\n',
    );
  }

  try {
    const rows = [];
    const activatedRoles = await graphGetAll('/directoryRoles');
    for (const role of activatedRoles) {
      const definition =
        definitions.find((item) => item.templateId === role.roleTemplateId) || null;
      const members = await graphGetAll(`/directoryRoles/${role.id}/members`);
      for (const member of members) {
        rows.push({
          principalId: member.id,
          principalName: member.displayName || member.id,
          principalKind: principalKind(member),
          role: role.displayName,
          roleTemplateId: role.roleTemplateId || '',
          privileged: isPrivilegedRole(definition, role.displayName),
          holding: 'active',
          scope: '/',
        });
      }
    }
    return { source: 'directoryRoles members (fallback)', rows };
  } catch (error) {
    console.error(`Could not read role holders at all: ${short(error.message)}\n`);
    return { source: 'unavailable', rows: [] };
  }
}

async function safeDefinitions() {
  try {
    return await graphGetAll('/roleManagement/directory/roleDefinitions');
  } catch (error) {
    console.error(
      `Could not read role definitions (${short(error.message)}). ` +
        'Falling back to a role name list for the privileged test.\n',
    );
    return [];
  }
}

/* ------------------------------------------------------------- classifying */

function minutesSince(value) {
  if (!value) return null;
  const then = Date.parse(value);
  if (Number.isNaN(then)) return null;
  return Math.max(0, Math.round((now - then) / 60000));
}

/**
 * Graph semantics for onPremisesSyncEnabled:
 *   true   currently synced from an on-premises directory
 *   false  previously synced, no longer synced
 *   null   never synced
 *
 * Source of authority conversion sets isCloudManaged to true and leaves
 * onPremisesSyncEnabled null while RETAINING the onPremises* attributes. So a
 * null flag next to a populated onPremisesSamAccountName or immutableId is the
 * signature of a converted object, not of a cloud native one. Both of those
 * cases land in "cloud (converted)" here, and soa-inspect.mjs is how you tell
 * them apart for certain.
 */
function authorityOf({ syncEnabled, lastSync, footprint }) {
  const minutes = minutesSince(lastSync);

  if (syncEnabled === true) {
    if (minutes === null) {
      return { authority: 'stale sync', why: 'synced, but no onPremisesLastSyncDateTime returned' };
    }
    if (minutes > STALE_MINUTES) {
      return {
        authority: 'stale sync',
        why: `synced, last sync ${minutes} minutes ago, over the ${STALE_MINUTES} minute threshold`,
      };
    }
    return { authority: 'on-premises', why: `synced, last sync ${minutes} minutes ago` };
  }

  if (syncEnabled === false) {
    return {
      authority: 'cloud (converted)',
      why: 'previously synced, no longer synced. Check whether this was a source of authority conversion or a scoping accident',
    };
  }

  if (footprint) {
    return {
      authority: 'cloud (converted)',
      why: 'onPremisesSyncEnabled is null but on-premises attributes are populated, which is what a source of authority conversion looks like',
    };
  }

  return { authority: 'cloud', why: 'never synced' };
}

function classifyUser(user) {
  const footprint = Boolean(
    user.onPremisesSamAccountName ||
      user.onPremisesImmutableId ||
      user.onPremisesSecurityIdentifier ||
      user.onPremisesDistinguishedName,
  );
  const { authority, why } = authorityOf({
    syncEnabled: user.onPremisesSyncEnabled,
    lastSync: user.onPremisesLastSyncDateTime,
    footprint,
  });

  return {
    kind: 'user',
    id: user.id,
    displayName: user.displayName || '',
    userPrincipalName: user.userPrincipalName || '',
    accountEnabled: user.accountEnabled,
    userType: user.userType || '',
    onPremisesSyncEnabled: user.onPremisesSyncEnabled ?? null,
    onPremisesSamAccountName: user.onPremisesSamAccountName || '',
    onPremisesDomainName: user.onPremisesDomainName || '',
    onPremisesUserPrincipalName: user.onPremisesUserPrincipalName || '',
    onPremisesDistinguishedName: user.onPremisesDistinguishedName || '',
    onPremisesLastSyncDateTime: user.onPremisesLastSyncDateTime || null,
    onPremisesImmutableId: user.onPremisesImmutableId || '',
    onPremisesSecurityIdentifier: user.onPremisesSecurityIdentifier || '',
    minutesSinceLastSync: minutesSince(user.onPremisesLastSyncDateTime),
    provisioningErrors: (user.onPremisesProvisioningErrors || []).length,
    authority,
    authorityWhy: why,
    stale: authority === 'stale sync',
  };
}

function classifyGroup(group) {
  const footprint = Boolean(group.onPremisesSamAccountName || group.onPremisesSecurityIdentifier);
  const { authority, why } = authorityOf({
    syncEnabled: group.onPremisesSyncEnabled,
    lastSync: group.onPremisesLastSyncDateTime,
    footprint,
  });

  return {
    kind: 'group',
    id: group.id,
    displayName: group.displayName || '',
    groupKind: describeGroupKind(group),
    isAssignableToRole: group.isAssignableToRole ?? null,
    onPremisesSyncEnabled: group.onPremisesSyncEnabled ?? null,
    onPremisesSamAccountName: group.onPremisesSamAccountName || '',
    onPremisesDomainName: group.onPremisesDomainName || '',
    onPremisesLastSyncDateTime: group.onPremisesLastSyncDateTime || null,
    onPremisesSecurityIdentifier: group.onPremisesSecurityIdentifier || '',
    minutesSinceLastSync: minutesSince(group.onPremisesLastSyncDateTime),
    provisioningErrors: (group.onPremisesProvisioningErrors || []).length,
    authority,
    authorityWhy: why,
    stale: authority === 'stale sync',
  };
}

function describeGroupKind(group) {
  const types = group.groupTypes || [];
  if (types.includes('Unified')) return 'microsoft365';
  if (group.securityEnabled && group.mailEnabled) return 'mail-enabled security';
  if (group.securityEnabled) return 'security';
  if (group.mailEnabled) return 'distribution';
  return 'other';
}

function principalKind(principal) {
  const type = principal?.['@odata.type'] || '';
  if (type.includes('servicePrincipal')) return 'servicePrincipal';
  if (type.includes('group')) return 'group';
  if (type.includes('user')) return 'user';
  return 'unknown';
}

function isPrivilegedRole(definition, fallbackName) {
  if (definition && typeof definition.isPrivileged === 'boolean') return definition.isPrivileged;
  const name = (definition?.displayName || fallbackName || '').toLowerCase();
  return PRIVILEGED_ROLE_NAMES.has(name);
}

/**
 * The join the whole sample exists for. A principal whose authority is on
 * premises but whose privilege is in the cloud has two owners, and the one
 * with the SAM account name wins.
 */
function joinPrivilegedSynced(holdings) {
  const out = [];
  for (const holding of holdings) {
    if (!holding.privileged) continue;
    const object = byId.get(holding.principalId);
    if (!object) continue;
    if (object.authority === 'cloud') continue;
    out.push({
      ...holding,
      objectKind: object.kind,
      displayName: object.displayName || holding.principalName,
      userPrincipalName: object.userPrincipalName || '',
      authority: object.authority,
      onPremisesSamAccountName: object.onPremisesSamAccountName,
      onPremisesDomainName: object.onPremisesDomainName,
      minutesSinceLastSync: object.minutesSinceLastSync,
      accountEnabled: object.accountEnabled ?? null,
    });
  }
  return out.sort(
    (a, b) =>
      rankAuthority(b.authority) - rankAuthority(a.authority) ||
      a.role.localeCompare(b.role) ||
      a.displayName.localeCompare(b.displayName),
  );
}

function rankAuthority(authority) {
  return { 'stale sync': 3, 'on-premises': 2, 'cloud (converted)': 1, cloud: 0 }[authority] ?? 0;
}

/* -------------------------------------------------------------- reporting */

function report() {
  console.log('Where authority actually lives\n');
  console.log(
    `Stale threshold: ${STALE_MINUTES} minutes. ` +
      `Snapshot taken ${new Date(now).toISOString()}.\n`,
  );

  if (userRows.length > 0) {
    const interesting = args.all ? userRows : userRows.filter((row) => row.authority !== 'cloud');
    console.log(`Users (${interesting.length} shown of ${userRows.length})\n`);
    printTable(
      interesting
        .slice()
        .sort(
          (a, b) =>
            rankAuthority(b.authority) - rankAuthority(a.authority) ||
            (b.minutesSinceLastSync ?? -1) - (a.minutesSinceLastSync ?? -1) ||
            a.displayName.localeCompare(b.displayName),
        )
        .map((row) => ({
          displayName: trim(row.displayName, 24),
          userPrincipalName: trim(row.userPrincipalName, 32),
          enabled: String(row.accountEnabled),
          syncEnabled: describeFlag(row.onPremisesSyncEnabled),
          samAccountName: trim(row.onPremisesSamAccountName, 20),
          domain: trim(row.onPremisesDomainName, 20),
          lastSync: shortTime(row.onPremisesLastSyncDateTime),
          minsAgo: row.minutesSinceLastSync === null ? '' : String(row.minutesSinceLastSync),
          immutableId: trim(row.onPremisesImmutableId, 14),
          authority: row.authority,
        })),
      [
        'displayName',
        'userPrincipalName',
        'enabled',
        'syncEnabled',
        'samAccountName',
        'domain',
        'lastSync',
        'minsAgo',
        'immutableId',
        'authority',
      ],
    );
    if (!args.all) {
      console.log('\n(cloud native users are hidden. Pass --all to see them.)');
    }
    console.log('');
  }

  if (groupRows.length > 0) {
    const interesting = args.all ? groupRows : groupRows.filter((row) => row.authority !== 'cloud');
    console.log(`Groups (${interesting.length} shown of ${groupRows.length})\n`);
    printTable(
      interesting
        .slice()
        .sort(
          (a, b) =>
            rankAuthority(b.authority) - rankAuthority(a.authority) ||
            (b.minutesSinceLastSync ?? -1) - (a.minutesSinceLastSync ?? -1) ||
            a.displayName.localeCompare(b.displayName),
        )
        .map((row) => ({
          displayName: trim(row.displayName, 32),
          type: row.groupKind,
          roleAssignable: describeFlag(row.isAssignableToRole),
          syncEnabled: describeFlag(row.onPremisesSyncEnabled),
          samAccountName: trim(row.onPremisesSamAccountName, 20),
          domain: trim(row.onPremisesDomainName, 20),
          lastSync: shortTime(row.onPremisesLastSyncDateTime),
          minsAgo: row.minutesSinceLastSync === null ? '' : String(row.minutesSinceLastSync),
          authority: row.authority,
        })),
      [
        'displayName',
        'type',
        'roleAssignable',
        'syncEnabled',
        'samAccountName',
        'domain',
        'lastSync',
        'minsAgo',
        'authority',
      ],
    );
    if (!args.all) {
      console.log('\n(cloud native groups are hidden. Pass --all to see them.)');
    }
    console.log('');
  }

  const staleUsers = userRows.filter((row) => row.stale);
  const staleGroups = groupRows.filter((row) => row.stale);

  if (staleUsers.length > 0 || staleGroups.length > 0) {
    console.log(
      `Stale sync: ${staleUsers.length} user(s) and ${staleGroups.length} group(s) past ` +
        `${STALE_MINUTES} minutes\n`,
    );
    printTable(
      [...staleUsers, ...staleGroups]
        .slice()
        .sort((a, b) => (b.minutesSinceLastSync ?? 0) - (a.minutesSinceLastSync ?? 0))
        .slice(0, 50)
        .map((row) => ({
          kind: row.kind,
          displayName: trim(row.displayName, 30),
          identifier: trim(row.userPrincipalName || row.onPremisesSamAccountName || row.id, 34),
          lastSync: shortTime(row.onPremisesLastSyncDateTime),
          minsAgo: row.minutesSinceLastSync === null ? 'never' : String(row.minutesSinceLastSync),
          errors: String(row.provisioningErrors),
        })),
      ['kind', 'displayName', 'identifier', 'lastSync', 'minsAgo', 'errors'],
    );
    console.log(
      '\nThis is the gap, measured. For every object above, a change made in Active\n' +
        'Directory has not reached Microsoft Entra ID yet. If that change was a disable,\n' +
        'and the tenant uses password hash synchronization, the account still works in\n' +
        'the cloud right now. Microsoft documents that as up to a 30 minute delay.\n' +
        'Pass-through authentication and federation do not have this window, because\n' +
        'they check the account state in Active Directory at sign-in time.\n',
    );
  }

  if (!args['skip-roles']) {
    console.log(`Privileged roles held by synced principals  [source: ${roleHoldings.source}]\n`);
    if (privilegedSynced.length === 0) {
      console.log(
        '(none found. Either every privileged holder is cloud native, which is the\n' +
          'answer you want, or the signed in identity could not read role holdings.)\n',
      );
    } else {
      printTable(
        privilegedSynced.map((row) => ({
          displayName: trim(row.displayName, 26),
          identifier: trim(row.userPrincipalName || row.onPremisesSamAccountName || row.principalId, 30),
          objectKind: row.objectKind,
          role: trim(row.role, 30),
          holding: row.holding,
          authority: row.authority,
          samAccountName: trim(row.onPremisesSamAccountName, 18),
          minsAgo: row.minutesSinceLastSync === null ? '' : String(row.minutesSinceLastSync),
        })),
        [
          'displayName',
          'identifier',
          'objectKind',
          'role',
          'holding',
          'authority',
          'samAccountName',
          'minsAgo',
        ],
      );
      console.log(
        `\n${privilegedSynced.length} privileged holding(s) belong to a principal whose source of\n` +
          'authority is not purely the cloud. Read that as: anyone who can write to that\n' +
          'object in Active Directory can influence a privileged cloud identity, and\n' +
          'nothing in Conditional Access sits between them and the domain controller.\n' +
          'The standard answer is that privileged accounts are cloud only, separate from\n' +
          'the synced daily driver account, on phishing resistant credentials.\n' +
          '\n' +
          'One dated detail that helps here: effective 1 June 2026, Entra Connect Sync\n' +
          'blocks hard matching a new Active Directory user onto a cloud user that holds\n' +
          'an Entra role. Soft match and ongoing sync are unaffected. That closes one\n' +
          'specific escalation path onto the objects in this table. It does not close the\n' +
          'others.\n',
      );
    }
  }

  const counts = new Map();
  for (const row of [...userRows, ...groupRows]) {
    const key = `${row.kind} ${row.authority}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  console.log('Summary\n');
  printTable(
    [
      ...[...counts.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([measure, count]) => ({ measure, count: String(count) })),
      { measure: 'stale sync, users + groups', count: String(staleUsers.length + staleGroups.length) },
      {
        measure: 'objects with on-premises provisioning errors',
        count: String([...userRows, ...groupRows].filter((row) => row.provisioningErrors > 0).length),
      },
      {
        measure: 'disabled in Entra but still synced',
        count: String(
          userRows.filter((row) => row.accountEnabled === false && row.onPremisesSyncEnabled === true)
            .length,
        ),
      },
      { measure: 'privileged holdings on non cloud-only principals', count: String(privilegedSynced.length) },
    ],
    ['measure', 'count'],
  );

  // A tenant with nothing synced is not a null result. It is the best possible
  // answer to the question this sample asks, and saying "0" eight times does
  // not communicate that.
  const syncedCount = [...userRows, ...groupRows].filter(
    (row) => row.onPremisesSyncEnabled === true,
  ).length;

  if (syncedCount === 0) {
    console.log(
      '\nNothing in this tenant is synchronized from Active Directory.\n' +
        '\n' +
        'That is the finding, and it is the good one. There is no authority\n' +
        'boundary here, so none of the gaps this sample measures can exist: no\n' +
        'thirty minute window where a disabled account still works in the cloud,\n' +
        'no lockout and password expiry states that never arrive, and no cloud\n' +
        'disable that leaves Kerberos untouched, because there is no Kerberos.\n' +
        '\n' +
        'Every object here is cloud managed, which means Conditional Access is\n' +
        'the whole of your access control rather than the half of it that faces\n' +
        'the internet. Most organizations reading this cannot say that.\n' +
        '\n' +
        'Two things are still worth your time:\n' +
        '\n' +
        '  npm run coverage -- --notes\n' +
        '      Which control reaches which surface. It contacts no tenant, and it\n' +
        '      is the part of this sample that applies to everyone.\n' +
        '\n' +
        '  Keep it this way deliberately. The moment somebody stands up Entra\n' +
        '  Connect to bring one legacy application along, every gap above becomes\n' +
        '  live, and this report starts having something to say.\n',
    );
    return;
  }

  console.log(
    '\nThe other direction is not measurable from here, and it is the half people\n' +
      'forget. There is no user disable writeback in Entra Connect Sync or in Entra\n' +
      'Cloud Sync. Disabling or deleting the cloud object does not disable the Active\n' +
      'Directory account, so Kerberos, NTLM and LDAP access on premises carries on\n' +
      'exactly as before. Graph cannot show you that, because Graph is on the wrong\n' +
      'side of the boundary. Go and look in Active Directory.\n',
  );
}

function describeFlag(value) {
  if (value === true) return 'true';
  if (value === false) return 'false';
  return 'null';
}

function shortTime(value) {
  if (!value) return '';
  return String(value).replace('T', ' ').slice(0, 16);
}

function trim(value, length) {
  const text = String(value ?? '');
  return text.length > length ? `${text.slice(0, length - 1)}.` : text;
}

/**
 * Graph error messages are mostly URL. The useful half is the code and text
 * after "failed:", so keep that and drop the query string, rather than
 * truncating at a fixed width and cutting the reason off entirely.
 */
function short(message) {
  const text = String(message || '');
  const afterFailed = text.split(/ failed: /)[1];
  const useful = (afterFailed || text).trim();
  return useful.length > 160 ? `${useful.slice(0, 157)}...` : useful;
}
