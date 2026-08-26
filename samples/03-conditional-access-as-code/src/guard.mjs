/**
 * Safety guard for Conditional Access policy files.
 *
 * Two rules, both of which exist because people have locked themselves out of
 * their own tenant with a single PowerShell line:
 *
 *   1. Every policy must exclude the break glass group. A Conditional Access
 *      policy has no "except me" fallback. If you block everyone, you are
 *      blocked too, and the only way back in is a support case.
 *
 *   2. Nothing deploys in "enabled" state unless the operator opts in twice:
 *      ALLOW_ENABLED=1 in the environment and "state": "enabled" in the file.
 *      Everything else is downgraded to enabledForReportingButNotEnforced.
 *
 * Run this on its own (npm run lint) or let deploy.mjs call it.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const POLICY_DIR = join(here, '..', 'policies');

const VALID_STATES = new Set(['enabled', 'disabled', 'enabledForReportingButNotEnforced']);
const REPORT_ONLY = 'enabledForReportingButNotEnforced';

/**
 * Policy files carry ${ENV_VAR} placeholders instead of hard coded object IDs,
 * so the same files work against a lab tenant and a production tenant.
 */
export function substituteEnv(text, file) {
  const missing = new Set();
  const result = text.replace(/\$\{([A-Z0-9_]+)\}/g, (match, name) => {
    const value = process.env[name];
    if (!value) {
      missing.add(name);
      return match;
    }
    return value;
  });
  if (missing.size > 0) {
    throw new Error(
      `${file} references ${[...missing].join(', ')} but ${missing.size === 1 ? 'that variable is' : 'those variables are'} not set.`,
    );
  }
  return result;
}

/**
 * SKIP_POLICIES is a comma separated list of filename prefixes, so
 * SKIP_POLICIES=05 drops 05-workload-identity-location-block.json. It exists
 * because policy 05 needs a Workload Identities Premium licence that most lab
 * tenants do not have, and one unlicensed policy should not block the other
 * four from deploying.
 */
function skipList() {
  return (process.env.SKIP_POLICIES || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

export async function loadPolicies() {
  const skips = skipList();
  const all = (await readdir(POLICY_DIR)).filter((name) => name.endsWith('.json')).sort();
  const files = all.filter((name) => !skips.some((prefix) => name.startsWith(prefix)));

  for (const name of all.filter((name) => !files.includes(name))) {
    console.log(`skipping ${name} (SKIP_POLICIES)`);
  }
  const policies = [];
  for (const file of files) {
    const raw = await readFile(join(POLICY_DIR, file), 'utf8');
    const resolved = substituteEnv(raw, file);
    let parsed;
    try {
      parsed = JSON.parse(resolved);
    } catch (error) {
      throw new Error(`${file} is not valid JSON: ${error.message}`);
    }
    policies.push({ file, policy: parsed });
  }
  return policies;
}

function excludedPrincipals(policy) {
  const users = policy?.conditions?.users ?? {};
  return [
    ...(users.excludeUsers ?? []),
    ...(users.excludeGroups ?? []),
    ...(users.excludeRoles ?? []),
  ].map((value) => String(value).toLowerCase());
}

/**
 * Returns { policy, warnings }. Throws on anything that would be unsafe to send.
 */
export function checkPolicy(file, policy, options = {}) {
  const breakGlassGroupId = (options.breakGlassGroupId || '').toLowerCase();
  const allowEnabled = options.allowEnabled === true;
  const warnings = [];
  const errors = [];

  if (!policy.displayName) errors.push('displayName is required');
  if (!policy.state) errors.push('state is required');
  if (policy.state && !VALID_STATES.has(policy.state)) {
    errors.push(
      `state "${policy.state}" is not one of enabled, disabled, enabledForReportingButNotEnforced`,
    );
  }
  if (!policy.conditions) errors.push('conditions is required');

  // Graph requires these condition properties, plus either users or
  // clientApplications. A workload identity policy targets the latter.
  const conditions = policy.conditions ?? {};
  for (const key of ['clientAppTypes', 'applications']) {
    if (!conditions[key]) errors.push(`conditions.${key} is required by Microsoft Graph`);
  }
  if (!conditions.users && !conditions.clientApplications) {
    errors.push('conditions needs either users or clientApplications');
  }

  const hasControl = Boolean(policy.grantControls || policy.sessionControls);
  if (!hasControl) {
    errors.push('a policy needs grantControls or sessionControls to do anything');
  }

  // Rule 1: break glass exclusion. Only meaningful for policies that target
  // human users. A workload identity policy targets service principals, which
  // cannot be a break glass account.
  const targetsUsers = (conditions.users?.includeUsers ?? []).some(
    (value) => String(value).toLowerCase() !== 'none',
  ) ||
    (conditions.users?.includeGroups ?? []).length > 0 ||
    (conditions.users?.includeRoles ?? []).length > 0;

  if (breakGlassGroupId) {
    const hasGrantControl = (policy.grantControls?.builtInControls ?? []).length > 0;
    if (targetsUsers && hasGrantControl && !excludedPrincipals(policy).includes(breakGlassGroupId)) {
      errors.push(
        `does not exclude the break glass group ${options.breakGlassGroupId}. ` +
          'Add it to conditions.users.excludeGroups.',
      );
    }
  } else if (targetsUsers) {
    warnings.push(
      'BREAK_GLASS_GROUP_ID is not set, so the break glass exclusion check was skipped. ' +
        'Do not run this against a production tenant without it.',
    );
  }

  // Rule 2: report only unless the operator opted in.
  let effective = { ...policy };
  if (policy.state === 'enabled' && !allowEnabled) {
    warnings.push('state "enabled" downgraded to report only. Set ALLOW_ENABLED=1 to override.');
    effective = { ...policy, state: REPORT_ONLY };
  }

  if (errors.length > 0) {
    throw new Error(`${file}:\n  - ${errors.join('\n  - ')}`);
  }

  return { policy: effective, warnings };
}

export async function checkAll(options = {}) {
  const loaded = await loadPolicies();
  const checked = loaded.map(({ file, policy }) => ({
    file,
    ...checkPolicy(file, policy, options),
  }));
  return checked;
}

const invokedDirectly = process.argv[1] && process.argv[1].endsWith('guard.mjs');

if (invokedDirectly) {
  const options = {
    breakGlassGroupId: process.env.BREAK_GLASS_GROUP_ID,
    allowEnabled: process.env.ALLOW_ENABLED === '1',
  };
  try {
    const checked = await checkAll(options);
    for (const entry of checked) {
      console.log(`${entry.file}: ${entry.policy.displayName} [${entry.policy.state}]`);
      entry.warnings.forEach((warning) => console.log(`  warning: ${warning}`));
    }
    console.log(`\n${checked.length} policy file(s) passed the guard.`);
  } catch (error) {
    console.error(`\nGuard failed.\n${error.message}`);
    process.exit(1);
  }
}
