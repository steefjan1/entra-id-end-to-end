/**
 * Create a recurring access review over the principals holding the roles in
 * config/roles.json.
 *
 * PIM shortens the window. An access review is the only thing in this sample
 * that ever removes an entitlement. Eligibility with no expiry and no review
 * is a permanent grant with extra steps.
 *
 *   POST /identityGovernance/accessReviews/definitions
 *   PUT  /identityGovernance/accessReviews/definitions/{id}   (with --replace)
 *   Permission: AccessReview.ReadWrite.All, the same one for delegated and
 *   application. A delegated caller also needs an appropriate administrator
 *   role, for example Identity Governance Administrator or Privileged Role
 *   Administrator for reviews of privileged roles.
 *   https://learn.microsoft.com/graph/api/accessreviewset-post-definitions
 *
 *   DRY_RUN=1 npm run review:plan
 *   npm run review
 *   npm run review -- --role "Global Administrator" --replace
 *
 * Reviewing role holders uses a principalResourceMembershipsScope: the
 * principals to review on one side, the resources whose access is under review
 * on the other. For a group membership review the scope is a plain
 * accessReviewQueryScope over /groups/{id}/transitiveMembers instead.
 *
 * Instances of a definition live at
 *   /identityGovernance/accessReviews/definitions/{id}/instances
 * and support stop, applyDecisions, resetDecisions, sendReminder,
 * batchRecordDecisions and acceptRecommendations.
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
  'AccessReview.ReadWrite.All',
  'RoleManagement.Read.Directory',
);

const here = dirname(fileURLToPath(import.meta.url));
const configFile = process.env.ROLES_FILE || join(here, '..', 'config', 'roles.json');

const { values: args } = parseArgs({
  options: {
    role: { type: 'string' },
    reviewer: { type: 'string' },
    'start-date': { type: 'string' },
    replace: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/access-review.mjs [--role "<name or template id>"]\n' +
      '\n' +
      '  --reviewer <group object id>  review by the members of this group instead of\n' +
      '                                by each principal\'s manager\n' +
      '  --start-date <YYYY-MM-DD>     first occurrence, default today\n' +
      '  --replace                     PUT over an existing definition with the same name\n' +
      '  DRY_RUN=1                     print the request, send nothing\n',
  );
  process.exit(0);
}

const config = JSON.parse(await readFile(configFile, 'utf8'));
const defaults = config.defaults?.accessReview || {};
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

const definitions = await graphGetAll(
  '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId',
);
const byTemplate = new Map(definitions.map((definition) => [definition.templateId, definition]));

const existing = await graphGetAll(
  '/identityGovernance/accessReviews/definitions?$select=id,displayName,status',
);
const existingByName = new Map(existing.map((item) => [item.displayName, item]));

const startDate = args['start-date'] || new Date().toISOString().slice(0, 10);
const rows = [];

for (const role of wanted) {
  const definition = byTemplate.get(role.templateId);
  if (!definition) {
    console.error(`Role template ${role.templateId} (${role.name}) is not in this tenant. Skipping.`);
    continue;
  }

  const settings = { ...defaults, ...(role.accessReview || {}) };
  const displayName = `PIM payload review: ${definition.displayName}`;
  const body = buildDefinition(displayName, definition, settings);
  const match = existingByName.get(displayName);

  if (match && !args.replace) {
    rows.push({
      action: 'exists, skipped',
      role: definition.displayName,
      review: displayName,
      recurrence: describeRecurrence(settings.recurrence),
      autoApply: String(settings.autoApplyDecisionsEnabled === true),
      defaultDecision: settings.defaultDecision || 'None',
      id: match.id,
    });
    continue;
  }

  let result;
  try {
    result = match
      ? await graphWrite('PUT', `/identityGovernance/accessReviews/definitions/${match.id}`, body)
      : await graphWrite('POST', '/identityGovernance/accessReviews/definitions', body);
  } catch (error) {
    console.error(`\n${displayName}: rejected.\n${error.message}\n`);
    continue;
  }

  rows.push({
    action: isDryRun() ? (match ? 'would replace' : 'would create') : match ? 'replaced' : 'created',
    role: definition.displayName,
    review: displayName,
    recurrence: describeRecurrence(settings.recurrence),
    autoApply: String(settings.autoApplyDecisionsEnabled === true),
    defaultDecision: settings.defaultDecision || 'None',
    id: result?.id || match?.id || 'n/a',
  });
}

console.log('');
printTable(rows, [
  'action',
  'role',
  'review',
  'recurrence',
  'autoApply',
  'defaultDecision',
  'id',
]);

if (missingVariables.size > 0) {
  console.log(
    `\nThese environment variables were referenced by ${configFile} but are not set: ` +
      `${[...missingVariables].join(', ')}.`,
  );
}

console.log(
  '\nautoApplyDecisionsEnabled removes access automatically when the instance ends.\n' +
    'With defaultDecision Deny, a reviewer who ignores every reminder email revokes\n' +
    'the access of everyone they were asked about. That is usually what you want and\n' +
    'occasionally an outage. Pilot it on one non critical role before you roll it out.\n' +
    '\n' +
    'A review decides WHO keeps the entitlement. It does not shrink the entitlement.\n' +
    'Run npm run report to see what each surviving holder can still do.',
);

function buildDefinition(displayName, roleDefinition, settings) {
  const reviewers = args.reviewer
    ? [
        {
          '@odata.type': '#microsoft.graph.accessReviewReviewerScope',
          query: `/groups/${args.reviewer}/transitiveMembers`,
          queryType: 'MicrosoftGraph',
        },
      ]
    : [
        // queryRoot "decisions" means "resolve ./manager relative to the
        // principal in each decision item", not relative to the definition.
        {
          '@odata.type': '#microsoft.graph.accessReviewReviewerScope',
          query: './manager',
          queryType: 'MicrosoftGraph',
          queryRoot: 'decisions',
        },
      ];

  const fallbackReviewers = resolveFallbackReviewers(settings.fallbackReviewers);
  if (!args.reviewer && fallbackReviewers.length === 0) {
    console.error(
      'Manager is the reviewer but no fallback reviewer resolved. Graph will reject\n' +
        'this, because a principal with no manager would have nobody to review it.\n' +
        'Set PIM_FALLBACK_REVIEWER_GROUP_ID, or pass --reviewer <group object id>.',
    );
    if (!isDryRun()) process.exit(2);
  }

  return {
    displayName,
    descriptionForAdmins:
      `Quarterly review of ${roleDefinition.displayName} holders. Created by the ` +
      '04-pim-payload sample. Reviewing the holder list does not reduce what the role grants.',
    descriptionForReviewers:
      `Does this person still need to be able to activate ${roleDefinition.displayName}? ` +
      'If you are not certain what that role can do, deny and ask. Re approving is cheap.',
    scope: {
      '@odata.type': '#microsoft.graph.principalResourceMembershipsScope',
      principalScopes: [
        {
          '@odata.type': '#microsoft.graph.accessReviewQueryScope',
          query: settings.principalScopeQuery || '/users',
          queryType: 'MicrosoftGraph',
        },
      ],
      resourceScopes: [
        {
          '@odata.type': '#microsoft.graph.accessReviewQueryScope',
          query: `/roleManagement/directory/roleDefinitions/${roleDefinition.id}`,
          queryType: 'MicrosoftGraph',
        },
      ],
    },
    reviewers,
    fallbackReviewers,
    settings: {
      mailNotificationsEnabled: settings.mailNotificationsEnabled !== false,
      reminderNotificationsEnabled: settings.reminderNotificationsEnabled !== false,
      justificationRequiredOnApproval: settings.justificationRequiredOnApproval !== false,
      defaultDecisionEnabled: settings.defaultDecisionEnabled === true,
      // Approve, Deny, Recommendation or None. This is the decision applied to
      // anyone the reviewer never got round to. It is not the same enum as a
      // recorded decision, which is Approve, Deny, NotReviewed or DontKnow.
      defaultDecision: settings.defaultDecision || 'None',
      instanceDurationInDays: settings.instanceDurationInDays ?? 14,
      autoApplyDecisionsEnabled: settings.autoApplyDecisionsEnabled === true,
      recommendationsEnabled: settings.recommendationsEnabled !== false,
      recurrence: buildRecurrence(settings.recurrence),
    },
  };
}

function buildRecurrence(recurrence = {}) {
  const pattern = recurrence.pattern || { type: 'absoluteMonthly', interval: 3, dayOfMonth: 1 };
  const range = recurrence.range || { type: 'noEnd' };
  return {
    pattern,
    range: {
      ...range,
      type: range.type || 'noEnd',
      startDate: range.startDate || startDate,
    },
  };
}

function describeRecurrence(recurrence = {}) {
  const pattern = recurrence.pattern || {};
  if (pattern.type === 'weekly') return `every ${pattern.interval || 1} week(s)`;
  if (pattern.type === 'absoluteMonthly') {
    return `every ${pattern.interval || 1} month(s) on day ${pattern.dayOfMonth || 1}`;
  }
  return pattern.type || 'one off';
}

function resolveFallbackReviewers(reviewers = []) {
  const resolved = [];
  for (const reviewer of reviewers) {
    const query = substitute(reviewer.query);
    if (!query || query.includes('${')) continue;
    resolved.push({ ...reviewer, query });
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
