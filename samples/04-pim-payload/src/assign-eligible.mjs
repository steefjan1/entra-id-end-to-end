/**
 * Make a principal eligible for an Entra role, with an expiry.
 *
 * Eligible means the principal can activate the role later, subject to the
 * policy that configure-policy.mjs sets. It does not mean the principal holds
 * the role now. That distinction is the entire value of PIM, and it is also
 * the limit of it: eligibility says nothing about what the role grants.
 *
 *   POST /roleManagement/directory/roleEligibilityScheduleRequests
 *   Least privileged: RoleEligibilitySchedule.ReadWrite.Directory
 *   (RoleManagement.ReadWrite.Directory also works). A delegated caller needs
 *   the Privileged Role Administrator role. Application only is supported.
 *   https://learn.microsoft.com/graph/api/rbacapplication-post-roleeligibilityschedulerequests
 *
 * With --active this posts to roleAssignmentScheduleRequests instead, which
 * creates a real active assignment. That endpoint additionally requires the
 * caller to have MFA enforced AND to have been MFA challenged in the current
 * session, otherwise Graph rejects the request.
 *
 *   DRY_RUN=1 npm run assign:plan -- --role "User Administrator" --principal <id>
 *   npm run assign -- --role "User Administrator" --principal <id> --days 90
 *   npm run assign -- --role "User Administrator" --principal <id> --validate-only
 *
 * --validate-only maps to isValidationOnly: true, which asks Graph to run the
 * request through validation and return the result without persisting it.
 * That is the closest thing to a server side dry run, and it catches things a
 * local dry run cannot, such as a policy that forbids permanent eligibility.
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { useScopes, graphGetAll, graphWrite, isDryRun, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'RoleEligibilitySchedule.ReadWrite.Directory',
  'RoleAssignmentSchedule.ReadWrite.Directory',
  'RoleManagement.Read.Directory',
);

const here = dirname(fileURLToPath(import.meta.url));
const configFile = process.env.ROLES_FILE || join(here, '..', 'config', 'roles.json');

const { values: args } = parseArgs({
  options: {
    role: { type: 'string' },
    principal: { type: 'string' },
    days: { type: 'string' },
    until: { type: 'string' },
    duration: { type: 'string' },
    start: { type: 'string' },
    scope: { type: 'string' },
    justification: { type: 'string' },
    ticket: { type: 'string' },
    'ticket-system': { type: 'string' },
    'no-expiry': { type: 'boolean' },
    active: { type: 'boolean' },
    'validate-only': { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help || !args.role || !args.principal) {
  console.log(
    'Usage: node src/assign-eligible.mjs --role "<name or template id>" --principal <object id>\n' +
      '\n' +
      '  --days <n>            expire n days from the start (default comes from config/roles.json)\n' +
      '  --until <iso8601>     expire at an explicit UTC instant, for example 2026-12-31T00:00:00Z\n' +
      '  --duration <iso8601>  expire after a duration, for example PT5H or P30D\n' +
      '  --no-expiry           create a permanent eligibility (read the warning it prints)\n' +
      '  --start <iso8601>     start at an explicit instant instead of now\n' +
      '  --scope </ or /administrativeUnits/{id}>   directory scope, default /\n' +
      '  --justification "<text>"\n' +
      '  --ticket <number> --ticket-system <name>\n' +
      '  --active              create an ACTIVE assignment instead of an eligibility\n' +
      '  --validate-only       send isValidationOnly: true, persist nothing\n' +
      '  DRY_RUN=1             print the request, send nothing\n',
  );
  process.exit(args.help ? 0 : 2);
}

const guid = /^[0-9a-fA-F-]{36}$/;
if (!guid.test(args.principal)) {
  console.error(
    `--principal must be an object ID (a GUID). Got "${args.principal}".\n` +
      'This is the object ID of a user, group or service principal, not a UPN or app ID.',
  );
  process.exit(2);
}

const config = JSON.parse(await readFile(configFile, 'utf8'));
const defaults = config.defaults?.eligibility || {};

const definitions = await graphGetAll(
  '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn',
);

const needle = args.role.toLowerCase();
const fromConfig = (config.roles || []).find(
  (role) => role.name.toLowerCase() === needle || role.templateId.toLowerCase() === needle,
);
const definition = definitions.find(
  (item) =>
    item.id.toLowerCase() === needle ||
    item.templateId?.toLowerCase() === needle ||
    item.displayName?.toLowerCase() === needle ||
    (fromConfig && item.templateId === fromConfig.templateId),
);

if (!definition) {
  console.error(`No role definition in this tenant matches "${args.role}".`);
  process.exit(2);
}

const startDateTime = args.start ? new Date(args.start).toISOString() : new Date().toISOString();
const expiration = buildExpiration(startDateTime);

const body = {
  action: 'adminAssign',
  justification: args.justification || defaults.justification || 'Managed by the 04-pim-payload sample',
  roleDefinitionId: definition.id,
  directoryScopeId: args.scope || '/',
  principalId: args.principal,
  scheduleInfo: {
    startDateTime,
    expiration,
  },
  ticketInfo: {
    ticketNumber: args.ticket ?? null,
    ticketSystem: args['ticket-system'] ?? null,
  },
  isValidationOnly: args['validate-only'] === true,
  appScopeId: null,
};

const path = args.active
  ? '/roleManagement/directory/roleAssignmentScheduleRequests'
  : '/roleManagement/directory/roleEligibilityScheduleRequests';

if (args.active) {
  console.log(
    'Creating an ACTIVE assignment, not an eligibility. The role is live from the\n' +
      'start instant with no activation step, no justification prompt and no approval.\n' +
      'The caller must have MFA enforced and have been MFA challenged in this session.\n',
  );
}

if (expiration.type === 'noExpiration') {
  console.log(
    'This assignment has no expiry. A permanent eligibility is still better than a\n' +
      'permanent active assignment, but it will never appear in a joiner mover leaver\n' +
      'process on its own. An access review is the only thing that will ever remove it.\n',
  );
}

let result;
try {
  result = await graphWrite('POST', path, body);
} catch (error) {
  console.error(`\nRequest rejected.\n${error.message}`);
  process.exit(1);
}

const rows = [
  {
    action: args['validate-only']
      ? isDryRun()
        ? 'would validate'
        : 'validated only'
      : isDryRun()
        ? 'would create'
        : args.active
          ? 'created active'
          : 'created eligible',
    role: definition.displayName,
    principal: args.principal,
    scope: body.directoryScopeId,
    starts: startDateTime,
    expires: describeExpiration(expiration),
    status: result?.status || (isDryRun() ? 'n/a (dry run)' : 'unknown'),
    requestId: result?.id || 'n/a',
  },
];

console.log('');
printTable(rows, [
  'action',
  'role',
  'principal',
  'scope',
  'starts',
  'expires',
  'status',
  'requestId',
]);

if (!isDryRun() && !args['validate-only']) {
  console.log(
    `\nRead it back with:\n` +
      `  GET /roleManagement/directory/role${args.active ? 'Assignment' : 'Eligibility'}Schedules` +
      `?$expand=principal,roleDefinition\n` +
      '\nThen run npm run report to see what this principal can do once the role is active.',
  );
}

/**
 * scheduleInfo.expiration accepts exactly three shapes:
 *   afterDateTime  with endDateTime
 *   afterDuration  with an ISO 8601 duration
 *   noExpiration
 */
function buildExpiration(start) {
  if (args['no-expiry']) return { type: 'noExpiration' };
  if (args.until) {
    return { type: 'afterDateTime', endDateTime: new Date(args.until).toISOString() };
  }
  if (args.duration) {
    return { type: 'afterDuration', duration: args.duration };
  }
  const days = Number(args.days ?? defaults.maximumEligibilityDays ?? 180);
  if (!Number.isFinite(days) || days <= 0) {
    console.error(`--days must be a positive number. Got "${args.days}".`);
    process.exit(2);
  }
  const end = new Date(new Date(start).getTime() + days * 24 * 60 * 60 * 1000);
  return { type: 'afterDateTime', endDateTime: end.toISOString() };
}

function describeExpiration(value) {
  if (value.type === 'noExpiration') return 'never (permanent)';
  if (value.type === 'afterDuration') return `after ${value.duration}`;
  return value.endDateTime;
}
