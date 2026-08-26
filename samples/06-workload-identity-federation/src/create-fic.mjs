/**
 * Create a federated identity credential on an APP REGISTRATION.
 *
 * This is the path Bicep cannot take. A user assigned managed identity has an
 * ARM resource type for its federated credentials:
 *
 *   Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials
 *
 * An app registration does not. It is a directory object, so its federated
 * credentials are created through Microsoft Graph:
 *
 *   POST /applications/{objectId}/federatedIdentityCredentials
 *   POST /applications(appId='{appId}')/federatedIdentityCredentials
 *
 * Both addressing forms work. The second one is useful because the client ID
 * is the value you already have in a pipeline, and the object ID is the one
 * you have to go and look up.
 *
 * Permissions:
 *   Delegated: Application.ReadWrite.All
 *   App only:  Application.ReadWrite.OwnedBy (least privileged) or
 *              Application.ReadWrite.All
 *
 * Field limits, which Graph enforces and which nobody reads until they fail:
 *   name        3 to 120 characters, URL friendly, IMMUTABLE after creation,
 *               supports $filter eq. Get it wrong and you delete and recreate.
 *   issuer      600 characters
 *   subject     600 characters, supports $filter eq
 *   audiences   600 characters per value
 *   description 600 characters
 *
 * Limit: 20 federated identity credentials per application, and 20 per user
 * assigned managed identity. This script prints how many you have left.
 *
 *   npm run fic -- --app-id <clientId> --preset github-environment \
 *                  --org octo-org --repo octo-repo --environment production
 *
 * https://learn.microsoft.com/graph/api/application-post-federatedidentitycredentials
 * https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphGetAll, graphWrite, isDryRun } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'Application.ReadWrite.All',
);

/** Graph refuses the 21st credential on an application. */
const FIC_LIMIT = 20;

/** The same for every provider. Not per tenant, not per application. */
const TOKEN_EXCHANGE_AUDIENCE = 'api://AzureADTokenExchange';

/** github.com. GitHub Enterprise Server has its own issuer URL. */
const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';

const { values: args } = parseArgs({
  options: {
    'app-object-id': { type: 'string' },
    'app-id': { type: 'string' },
    preset: { type: 'string' },
    name: { type: 'string' },
    description: { type: 'string' },
    org: { type: 'string' },
    repo: { type: 'string' },
    branch: { type: 'string' },
    environment: { type: 'string' },
    tag: { type: 'string' },
    namespace: { type: 'string' },
    'service-account': { type: 'string' },
    issuer: { type: 'string' },
    subject: { type: 'string' },
    audience: { type: 'string' },
    expression: { type: 'string' },
    list: { type: 'boolean' },
    delete: { type: 'string' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/create-fic.mjs --app-id <clientId> --preset <preset> [options]\n' +
      '\n' +
      'Target the application (one of these is required):\n' +
      '  --app-object-id <guid>   object ID, addresses /applications/{id}\n' +
      '  --app-id <guid>          client ID, addresses /applications(appId=\'{id}\')\n' +
      '\n' +
      'Presets:\n' +
      '  github-branch            --org --repo --branch\n' +
      '                           repo:Org/Repo:ref:refs/heads/<branch>\n' +
      '  github-pull-request      --org --repo\n' +
      '                           repo:Org/Repo:pull-request\n' +
      '  github-environment       --org --repo --environment\n' +
      '                           repo:Org/Repo:environment:<Name>\n' +
      '  github-tag               --org --repo --tag\n' +
      '                           repo:Org/Repo:ref:refs/tags/<tag>\n' +
      '  kubernetes               --issuer <clusterOidcIssuerUrl> --namespace --service-account\n' +
      '                           system:serviceaccount:<NAMESPACE>:<NAME>\n' +
      '  manual                   --issuer --subject, for anything else\n' +
      '  flexible                 --issuer --expression, beta only, preview,\n' +
      '                           application objects only. See the notes below.\n' +
      '\n' +
      'Other options:\n' +
      '  --name <string>          credential name, 3 to 120 chars, IMMUTABLE.\n' +
      '                           Defaults to something derived from the preset.\n' +
      '  --description <string>   up to 600 characters.\n' +
      '  --audience <string>      defaults to api://AzureADTokenExchange. You almost\n' +
      '                           certainly should not change this.\n' +
      '  --list                   list the existing credentials and the quota, then exit.\n' +
      '  --delete <name>          delete the credential with this name, then exit.\n' +
      '  --json                   emit JSON instead of prose.\n' +
      '\n' +
      'DRY_RUN=1 prints the exact POST body and sends nothing.\n',
  );
  process.exit(0);
}

/**
 * Both addressing forms are documented and both work. Object ID wins when
 * given, because it is one fewer alternate key lookup for Graph to do.
 */
function applicationPath() {
  if (args['app-object-id']) return `/applications/${args['app-object-id']}`;
  if (args['app-id']) return `/applications(appId='${args['app-id']}')`;
  fail(
    'One of --app-object-id or --app-id is required.\n' +
      'This script creates credentials on an APP REGISTRATION. For a user assigned\n' +
      'managed identity, use infra/resources.bicep instead: the credential is an ARM\n' +
      'resource there, not a Graph object.',
  );
  return '';
}

function fail(message) {
  console.error(`\n${message}\n`);
  process.exit(1);
}

function requireArg(value, name, hint) {
  if (!value) fail(`${name} is required${hint ? `. ${hint}` : '.'}`);
  return value;
}

/**
 * Slugify a name into something inside the 3 to 120 character, URL friendly
 * window Graph enforces. Remember: this value is immutable after creation.
 */
function slug(parts) {
  const raw = parts
    .filter(Boolean)
    .join('-')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  const trimmed = raw.slice(0, 120);
  return trimmed.length >= 3 ? trimmed : `fic-${trimmed}`.slice(0, 120);
}

/**
 * Build issuer, subject and name from a preset.
 *
 * The subject is the entire security decision. Issuer and audience are fixed
 * by the provider, so the only thing standing between a GitHub Actions run and
 * a token for your application is whether its sub claim matches this string
 * exactly. There is no wildcard here outside the flexible preview.
 */
function buildCredential() {
  const preset = (args.preset || 'manual').toLowerCase();
  const audience = args.audience || TOKEN_EXCHANGE_AUDIENCE;

  const repoSlug = () => {
    const org = requireArg(args.org, '--org', 'The Org in repo:Org/Repo.');
    const repo = requireArg(args.repo, '--repo', 'The Repo in repo:Org/Repo.');
    return `${org}/${repo}`;
  };

  switch (preset) {
    case 'github-branch': {
      const slugged = repoSlug();
      const branch = requireArg(args.branch, '--branch', 'For example main.');
      return {
        name: args.name || slug(['gh', args.repo, 'branch', branch]),
        issuer: GITHUB_ISSUER,
        subject: `repo:${slugged}:ref:refs/heads/${branch}`,
        audiences: [audience],
      };
    }

    case 'github-pull-request': {
      const slugged = repoSlug();
      return {
        name: args.name || slug(['gh', args.repo, 'pull-request']),
        issuer: GITHUB_ISSUER,
        // No branch. No environment. No author. Anyone who can open a pull
        // request against this repository can obtain a token for this
        // application. That is not a bug in the subject format, it is what
        // the subject format means.
        subject: `repo:${slugged}:pull-request`,
        audiences: [audience],
        warning:
          'repo:' +
          slugged +
          ':pull-request trusts EVERY pull request against that repository,\n' +
          'including one opened by somebody who has never had write access to it. If the\n' +
          'workflow that consumes this token runs on pull_request_target, or checks out\n' +
          'and runs code from the pull request head, this credential is a handover of your\n' +
          'Azure access to anyone with a GitHub account. Prefer a protected environment.',
      };
    }

    case 'github-environment': {
      const slugged = repoSlug();
      const environment = requireArg(
        args.environment,
        '--environment',
        'The GitHub environment name, for example production.',
      );
      return {
        name: args.name || slug(['gh', args.repo, 'env', environment]),
        issuer: GITHUB_ISSUER,
        subject: `repo:${slugged}:environment:${environment}`,
        audiences: [audience],
      };
    }

    case 'github-tag': {
      const slugged = repoSlug();
      const tag = requireArg(args.tag, '--tag', 'For example v1.2.3.');
      return {
        name: args.name || slug(['gh', args.repo, 'tag', tag]),
        issuer: GITHUB_ISSUER,
        subject: `repo:${slugged}:ref:refs/tags/${tag}`,
        audiences: [audience],
        warning:
          'Tags are mutable in git. Anyone who can force push a tag in that repository\n' +
          'can move it onto a commit of their choosing and satisfy this subject.',
      };
    }

    case 'kubernetes': {
      // The issuer is the cluster OIDC issuer URL, which is per cluster.
      // On AKS: az aks show -n <cluster> -g <rg> --query oidcIssuerProfile.issuerUrl -o tsv
      const issuer = requireArg(
        args.issuer,
        '--issuer',
        'The cluster OIDC issuer URL. On AKS this is oidcIssuerProfile.issuerUrl.',
      );
      const namespace = requireArg(args.namespace, '--namespace');
      const serviceAccount = requireArg(args['service-account'], '--service-account');
      return {
        name: args.name || slug(['k8s', namespace, serviceAccount]),
        issuer,
        subject: `system:serviceaccount:${namespace}:${serviceAccount}`,
        audiences: [audience],
      };
    }

    case 'flexible': {
      // Preview. Beta endpoint only. See the notes printed below.
      const issuer = requireArg(args.issuer, '--issuer');
      const expression = requireArg(
        args.expression,
        '--expression',
        "For example: claims['sub'] matches 'repo:contoso/contoso-repo:ref:refs/heads/*'",
      );
      return {
        name: requireArg(args.name, '--name', 'Flexible credentials get no derived default name.'),
        issuer,
        audiences: [audience],
        // claimsMatchingExpression is mutually exclusive with subject. Sending
        // both is an error, and languageVersion is always 1.
        claimsMatchingExpression: { value: expression, languageVersion: 1 },
        flexible: true,
      };
    }

    case 'manual': {
      return {
        name: requireArg(args.name, '--name'),
        issuer: requireArg(args.issuer, '--issuer'),
        subject: requireArg(args.subject, '--subject'),
        audiences: [audience],
      };
    }

    default:
      fail(`Unknown preset "${preset}". Run with --help for the list.`);
      return null;
  }
}

/** Graph rejects these, but a clear message beats a 400 with a schema URL. */
function validate(credential) {
  const problems = [];
  if (credential.name.length < 3 || credential.name.length > 120) {
    problems.push(`name must be 3 to 120 characters, got ${credential.name.length}.`);
  }
  if (!/^[A-Za-z0-9._~-]+$/.test(credential.name)) {
    problems.push(`name must be URL friendly, got "${credential.name}".`);
  }
  for (const [field, value] of [
    ['issuer', credential.issuer],
    ['subject', credential.subject],
    ['description', args.description],
  ]) {
    if (value && value.length > 600) {
      problems.push(`${field} must be 600 characters or fewer, got ${value.length}.`);
    }
  }
  for (const audience of credential.audiences) {
    if (audience.length > 600) {
      problems.push(`each audiences value must be 600 characters or fewer.`);
    }
  }
  if (credential.audiences[0] !== TOKEN_EXCHANGE_AUDIENCE) {
    console.warn(
      `\nWarning: audience is "${credential.audiences[0]}", not ${TOKEN_EXCHANGE_AUDIENCE}.\n` +
        'Every documented provider uses api://AzureADTokenExchange. If you did not change\n' +
        'this on purpose, the token exchange will fail with an audience mismatch.\n',
    );
  }
  if (problems.length > 0) fail(`The credential is not valid:\n  ${problems.join('\n  ')}`);
}

async function listCredentials(basePath, version) {
  return graphGetAll(`${basePath}/federatedIdentityCredentials`, { version });
}

function printQuota(existing) {
  const used = existing.length;
  const remaining = FIC_LIMIT - used;
  console.log(`\nFederated identity credentials on this application: ${used} of ${FIC_LIMIT}.`);
  console.log(`Remaining: ${remaining}.`);
  if (remaining <= 0) {
    console.log(
      'You are at the limit. Graph will reject the next one. The options are: delete a\n' +
        'credential you no longer need, split the workloads across more than one app\n' +
        'registration, or use a flexible federated identity credential, which is preview.',
    );
  } else if (remaining <= 3) {
    console.log(
      'Close to the limit. On a monorepo with one credential per environment this runs\n' +
        'out sooner than people expect. See the README.',
    );
  }
}

function printFlexibleNotes() {
  console.log(
    '\nFlexible federated identity credentials are PREVIEW. What that means here:\n' +
      '  - Beta endpoint only. This request goes to /beta, not /v1.0.\n' +
      "  - claimsMatchingExpression is mutually exclusive with subject. You cannot send both.\n" +
      '  - languageVersion is always 1.\n' +
      '  - Operators are matches (with ? and * wildcards), eq, and and.\n' +
      '  - Preview support is limited to GitHub Actions, GitLab and Terraform Cloud tokens.\n' +
      '  - APPLICATION OBJECTS ONLY. Not user assigned managed identities.\n' +
      '  - Microsoft Graph or the portal only. No Azure CLI, no PowerShell, no Terraform provider.\n' +
      '\nThis is the answer to the 20 credential limit, and it is not one you should put in\n' +
      'a production pipeline until it is generally available.\n',
  );
}

async function main() {
  const basePath = applicationPath();

  if (args.list) {
    const v1 = await listCredentials(basePath, 'v1.0');
    if (args.json) {
      console.log(JSON.stringify({ credentials: v1, used: v1.length, limit: FIC_LIMIT }, null, 2));
      return;
    }
    if (v1.length === 0) {
      console.log('No federated identity credentials on this application.');
    }
    for (const credential of v1) {
      console.log(`\n${credential.name}`);
      console.log(`  issuer    ${credential.issuer}`);
      console.log(`  subject   ${credential.subject ?? '(none, flexible credential)'}`);
      console.log(`  audiences ${(credential.audiences || []).join(', ')}`);
      if (credential.description) console.log(`  note      ${credential.description}`);
      console.log(`  id        ${credential.id}`);
    }
    printQuota(v1);
    return;
  }

  if (args.delete) {
    // name supports $filter eq, which is the only reason deleting by name is
    // possible without listing everything first.
    const matches = await graphGetAll(
      `${basePath}/federatedIdentityCredentials?$filter=name eq '${args.delete}'`,
    );
    if (matches.length === 0) fail(`No federated identity credential named "${args.delete}".`);
    for (const match of matches) {
      await graphWrite('DELETE', `${basePath}/federatedIdentityCredentials/${match.id}`);
      console.log(`Deleted ${match.name} (${match.id}).`);
    }
    printQuota(await listCredentials(basePath, 'v1.0'));
    return;
  }

  const built = buildCredential();
  validate(built);

  const version = built.flexible ? 'beta' : 'v1.0';
  if (built.flexible) printFlexibleNotes();

  const existing = await listCredentials(basePath, version);
  if (existing.length >= FIC_LIMIT && !isDryRun()) {
    fail(
      `This application already has ${existing.length} federated identity credentials, and the\n` +
        `limit is ${FIC_LIMIT}. Graph will reject this request. Delete one with --delete <name>.`,
    );
  }

  const duplicate = existing.find((item) => item.name === built.name);
  if (duplicate) {
    fail(
      `A credential named "${built.name}" already exists on this application (${duplicate.id}).\n` +
        'name is immutable, so there is no update path for it: delete and recreate, or\n' +
        'pass a different --name.',
    );
  }

  // The exact request body. Nothing is added, nothing is defaulted server side.
  const body = {
    name: built.name,
    issuer: built.issuer,
    audiences: built.audiences,
  };
  if (built.subject) body.subject = built.subject;
  if (built.claimsMatchingExpression) body.claimsMatchingExpression = built.claimsMatchingExpression;
  if (args.description) body.description = args.description;

  // Under DRY_RUN, graphWrite prints the request itself, so printing it here
  // as well would just show it twice.
  if (!isDryRun()) {
    console.log(`\nPOST ${basePath}/federatedIdentityCredentials`);
    console.log(JSON.stringify(body, null, 2));
  }

  if (built.warning) {
    console.warn(`\nRead this before you continue:\n${built.warning}\n`);
  }

  const created = await graphWrite('POST', `${basePath}/federatedIdentityCredentials`, body, {
    version,
  });

  if (created.dryRun) {
    console.log('\nDRY_RUN=1 was set. Nothing was created.');
    printQuota(existing);
    return;
  }

  if (args.json) {
    console.log(JSON.stringify(created, null, 2));
  } else {
    console.log('\nCreated:');
    console.log(`  name      ${created.name}`);
    console.log(`  id        ${created.id}`);
    console.log(`  issuer    ${created.issuer}`);
    console.log(`  subject   ${created.subject ?? '(flexible, see claimsMatchingExpression)'}`);
    console.log(`  audiences ${(created.audiences || []).join(', ')}`);
    if (created.claimsMatchingExpression) {
      console.log(`  expression ${created.claimsMatchingExpression.value}`);
    }
    console.log(
      '\nname is immutable. If that string is wrong, the fix is delete and recreate,\n' +
        'not a PATCH.',
    );
  }

  printQuota(await listCredentials(basePath, version));

  // A federated credential replaces the secret. It does not replace the
  // authorization decision, and this script has not made one.
  const roleTarget = args['app-object-id'] || args['app-id'];
  console.log(
    '\nWhat this did NOT do: give the workload any permission to anything. The\n' +
      'credential is only how the application proves who it is. Go and assign the\n' +
      `Azure RBAC roles and the Graph app roles it actually needs, for ${roleTarget},\n` +
      'and keep them as small as the job allows. src/workload-inventory.mjs will show\n' +
      'you what it ends up holding.',
  );
}

async function whoAmI() {
  // A cheap read that also proves the token works before a write is attempted.
  try {
    const org = await graphGet('/organization?$select=id,displayName');
    const first = org.value?.[0];
    if (first) console.log(`Tenant: ${first.displayName} (${first.id})`);
  } catch {
    // Not fatal. If the token is broken the next call says so properly.
  }
}

await whoAmI();
await main();
