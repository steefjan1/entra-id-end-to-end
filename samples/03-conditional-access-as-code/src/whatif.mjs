/**
 * Unit tests for Conditional Access.
 *
 * Every scenario in tests/scenarios.json describes a hypothetical sign in and
 * what you expect to happen to it. This script sends each one to the Graph
 * What If API and compares the answer against your expectation. A failing
 * assertion exits non zero, which makes it usable as a pull request gate.
 *
 *   POST /identity/conditionalAccess/evaluate
 *   Permission: Policy.Read.ConditionalAccess (least privileged)
 *   https://learn.microsoft.com/graph/api/conditionalaccessroot-evaluate
 *
 * This is the API behind the What If button in the portal. It evaluates
 * policies without signing anyone in, which is the only safe way to answer
 * "will this policy lock out the service desk" before you enable it.
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { useScopes, graphWrite, printTable } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Policy.Read.ConditionalAccess',
);

const here = dirname(fileURLToPath(import.meta.url));
const scenarioFile = process.env.SCENARIO_FILE || join(here, '..', 'tests', 'scenarios.json');

const raw = await readFile(scenarioFile, 'utf8');
const substituted = raw.replace(/\$\{([A-Z0-9_]+)\}/g, (match, name) => {
  const value = process.env[name];
  if (!value) {
    console.error(`Scenario file references \${${name}} but that variable is not set.`);
    process.exit(2);
  }
  return value;
});

const { scenarios } = JSON.parse(substituted);

const rows = [];
let failures = 0;

for (const scenario of scenarios) {
  let response;
  try {
    // appliedPoliciesOnly: false returns every policy plus the reason it did
    // not apply, which is what you want when a test fails and you need to know
    // whether the policy was skipped because of the user, the app or the risk.
    response = await graphWrite(
      'POST',
      '/identity/conditionalAccess/evaluate',
      { ...scenario.request, appliedPoliciesOnly: false },
      { headers: {} },
    );
  } catch (error) {
    rows.push({ scenario: scenario.name, result: 'ERROR', detail: error.message.slice(0, 90) });
    failures += 1;
    continue;
  }

  const results = response.value ?? [];
  const applied = results.filter((item) => item.policyApplies === true);
  const appliedNames = applied.map((item) => item.displayName);

  const problems = [];

  for (const name of scenario.expect?.policiesApply ?? []) {
    if (!appliedNames.includes(name)) {
      const found = results.find((item) => item.displayName === name);
      const reason = found ? (found.analysisReasons ?? []).join(', ') : 'policy not found in tenant';
      problems.push(`"${name}" did not apply (${reason || 'no reason given'})`);
    }
  }

  for (const name of scenario.expect?.policiesDoNotApply ?? []) {
    if (appliedNames.includes(name)) {
      problems.push(`"${name}" applied but was expected not to`);
    }
  }

  const expectedControls = scenario.expect?.grantControls;
  if (expectedControls) {
    const actual = new Set(
      applied.flatMap((item) => item.grantControls?.builtInControls ?? []),
    );
    for (const control of expectedControls) {
      if (!actual.has(control)) {
        problems.push(`grant control "${control}" was not required by any applying policy`);
      }
    }
  }

  if (problems.length > 0) failures += 1;

  rows.push({
    scenario: scenario.name,
    result: problems.length === 0 ? 'pass' : 'FAIL',
    applied: appliedNames.length,
    detail: problems.join('; ').slice(0, 120),
  });
}

printTable(rows, ['result', 'scenario', 'applied', 'detail']);

console.log(`\n${rows.length - failures}/${rows.length} scenarios passed.`);

if (failures > 0) {
  console.error(
    '\nA failing scenario means the tenant does not behave the way this repository claims.\n' +
      'Either the policy files drifted from the tenant, or the expectation is wrong.',
  );
  process.exit(1);
}
