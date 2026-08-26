/**
 * Preflight for azd up.
 *
 * The Bicep tolerates empty client IDs on purpose, so that `bicep build` and a
 * what-if run never need real values. The cost of that is a deployment which
 * succeeds and then serves an app that cannot validate a single token, because
 * its audience is an empty string. This turns that silent failure into a loud
 * one before anything is provisioned.
 *
 * Why Node rather than PowerShell or sh:
 *
 *   A .ps1 hook is blocked on most Windows machines by the execution policy,
 *   because the file is not digitally signed, and neither `2>$null` nor a
 *   CurrentUser scope change reliably clears it. A .sh hook is worse, because
 *   azd's `shell: sh` on Windows often resolves to WSL bash, which cannot see
 *   the repository path it was handed.
 *
 *   Node is already a prerequisite for this sample, and running `node file.mjs`
 *   is a command rather than a script file, so no execution policy applies.
 *   One implementation, both platforms, nothing to sign.
 */

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const required = ['API_CLIENT_ID', 'SPA_CLIENT_ID'];
const problems = [];

console.log('Checking the app registrations this deployment depends on.');

for (const name of required) {
  const value = (process.env[name] || '').trim();
  if (!value) {
    problems.push(`  missing: ${name}`);
  } else if (!GUID.test(value)) {
    problems.push(`  not a GUID: ${name}=${value}`);
  }
}

if (problems.length > 0) {
  console.log(problems.join('\n'));
  console.log(
    '\nThis sample needs two app registrations before it can deploy anything\n' +
      'useful. They are a separate step because creating them needs an\n' +
      'administrator, and azd does not have that scope.\n' +
      '\n' +
      '  ./scripts/register-apps.ps1      (or register-apps.sh)\n' +
      '  azd env set API_CLIENT_ID <api-app-client-id>\n' +
      '  azd env set SPA_CLIENT_ID <spa-app-client-id>\n' +
      '  azd up\n' +
      '\n' +
      'AZURE_TENANT_ID is optional. Left unset, the template uses the tenant\n' +
      'azd is signed in to.',
  );
  process.exit(1);
}

console.log('  API_CLIENT_ID and SPA_CLIENT_ID look like GUIDs. Continuing.');
