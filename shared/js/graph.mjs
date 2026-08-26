/**
 * Shared Microsoft Graph helper for every sample in this repository.
 *
 * Design notes that matter:
 *
 * 1. We never parse a Microsoft Graph access token. Graph tokens use a
 *    proprietary format and Microsoft documents them as opaque to clients.
 *    See https://learn.microsoft.com/entra/identity-platform/access-tokens
 *
 * 2. Credential selection is explicit, not magic. Set ENTRA_AUTH_MODE to
 *    "devicecode", "azurecli" or "clientsecret". Device code is the default
 *    because most of these samples need delegated admin consent.
 *
 * 3. Every write call goes through graphWrite(), which honors DRY_RUN=1 and
 *    prints the request it would have made. Run every sample dry first.
 */

import {
  DeviceCodeCredential,
  AzureCliCredential,
  ClientSecretCredential,
} from '@azure/identity';

const GRAPH_V1 = 'https://graph.microsoft.com/v1.0';
const GRAPH_BETA = 'https://graph.microsoft.com/beta';
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';

/**
 * Which delegated permissions to ask for.
 *
 * The default is .default, which means "everything already consented for this
 * client". Against the Microsoft Graph PowerShell first party app that is
 * usually User.Read and nothing else, so every interesting call comes back
 * 403 Authorization_RequestDenied and it looks like a role problem when it is
 * really a consent problem.
 *
 * So each script declares what it needs, in code, next to the operations that
 * need it:
 *
 *   useScopes('Group.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess');
 *
 * Short names are expanded to the full Graph URI. The device code prompt then
 * asks for exactly those, and an administrator consents once.
 */
let requestedScopes = [GRAPH_SCOPE];

export function useScopes(...scopes) {
  const flat = scopes.flat().filter(Boolean);
  if (flat.length === 0) return;
  requestedScopes = flat.map((scope) =>
    scope.includes('://') ? scope : `https://graph.microsoft.com/${scope}`,
  );
}

export function currentScopes() {
  return [...requestedScopes];
}

/**
 * Dry run is set either way, and the reason is Windows.
 *
 * "DRY_RUN=1 node script.mjs" is POSIX shell syntax. npm runs scripts through
 * cmd.exe on Windows, where that line fails with "DRY_RUN=1 is not recognized
 * as an internal or external command". Accepting --dry-run as an argument lets
 * every package.json script in this repository work on both platforms without
 * adding cross-env as a dependency.
 */
export const isDryRun = () =>
  process.env.DRY_RUN === '1' || process.argv.includes('--dry-run');

let cachedCredential = null;
let cachedToken = null;

function authMode() {
  return (process.env.ENTRA_AUTH_MODE || 'devicecode').toLowerCase();
}

function buildCredential() {
  const mode = authMode();
  const tenantId = process.env.ENTRA_TENANT_ID;

  if (mode === 'azurecli') {
    return new AzureCliCredential(tenantId ? { tenantId } : {});
  }

  if (mode === 'clientsecret') {
    const clientId = requireEnv('ENTRA_CLIENT_ID');
    const clientSecret = requireEnv('ENTRA_CLIENT_SECRET');
    return new ClientSecretCredential(requireEnv('ENTRA_TENANT_ID'), clientId, clientSecret);
  }

  // Device code. The client ID defaults to the Microsoft Graph PowerShell
  // first-party app, which is pre-consented in most tenants and is the
  // fastest way to run these samples without registering anything first.
  const clientId = process.env.ENTRA_CLIENT_ID || '14d82eec-204b-4c2f-b7e8-296a70dab67e';
  return new DeviceCodeCredential({
    tenantId: tenantId || 'organizations',
    clientId,
    userPromptCallback: (info) => {
      console.log(`\n${info.message}\n`);
    },
  });
}

export function credential() {
  if (!cachedCredential) cachedCredential = buildCredential();
  return cachedCredential;
}

async function accessToken() {
  const skewSeconds = 300;
  const now = Date.now();
  if (cachedToken && cachedToken.expiresOnTimestamp - now > skewSeconds * 1000) {
    return cachedToken.token;
  }
  // The Azure CLI credential is a special case, twice over.
  //
  // It cannot take a list of granular scopes: @azure/identity's dev time
  // credentials resolve a single resource, and passing several throws. And it
  // does not need them, because the token comes from the Azure CLI's own
  // first party application, which already carries broad delegated Graph
  // consent in most tenants. So ask it for .default and let the CLI's existing
  // consent decide, which is also why ENTRA_AUTH_MODE=azurecli is the fastest
  // way past an admin consent prompt you would rather not grant tenant wide.
  const scopes = authMode() === 'azurecli' ? GRAPH_SCOPE : requestedScopes;

  try {
    cachedToken = await credential().getToken(scopes);
  } catch (error) {
    // A credential that cannot produce a token should say what to do about it
    // rather than surfacing a stack trace from inside @azure/identity.
    if (error?.name === 'CredentialUnavailableError' || /az login/i.test(error?.message ?? '')) {
      const mode = authMode();
      throw new Error(
        `Could not get a Microsoft Graph token using ENTRA_AUTH_MODE=${mode}.\n\n` +
          `${error.message}\n\n` +
          (mode === 'azurecli'
            ? 'Reproduce what this credential does, which usually shows the real cause:\n' +
              '  az account get-access-token --resource https://graph.microsoft.com\n\n' +
              'A signed in az CLI is not always enough. The CLI can hold a token for\n' +
              'Azure Resource Manager and still be unable to get one for Microsoft\n' +
              'Graph, which is common for guest and personal Microsoft accounts. If\n' +
              'that command fails, sign in again naming the tenant explicitly:\n' +
              '  az login --tenant <tenant-id> --allow-no-subscriptions\n\n' +
              'Or fall back to the interactive route, which asks Entra directly:\n' +
              '  $env:ENTRA_AUTH_MODE = "devicecode"'
            : 'Set ENTRA_AUTH_MODE to devicecode, azurecli or clientsecret.'),
      );
    }
    throw error;
  }

  if (!cachedToken) throw new Error('Failed to acquire a Microsoft Graph token.');
  return cachedToken.token;
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Environment variable ${name} is required.`);
  return value;
}

function base(version) {
  return version === 'beta' ? GRAPH_BETA : GRAPH_V1;
}

/**
 * Read from Graph. Returns parsed JSON.
 */
export async function graphGet(path, { version = 'v1.0', headers = {} } = {}) {
  const token = await accessToken();
  const url = path.startsWith('http') ? path : `${base(version)}${path}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, ...headers },
  });
  return handle(response, 'GET', url);
}

/**
 * Read every page of a Graph collection.
 */
export async function graphGetAll(path, options = {}) {
  const results = [];
  let next = path;
  while (next) {
    const page = await graphGet(next, options);
    if (Array.isArray(page.value)) results.push(...page.value);
    next = page['@odata.nextLink'] || null;
  }
  return results;
}

/**
 * Write to Graph. Respects DRY_RUN=1.
 */
export async function graphWrite(method, path, body, { version = 'v1.0', headers = {} } = {}) {
  const url = path.startsWith('http') ? path : `${base(version)}${path}`;

  if (isDryRun()) {
    console.log(`[dry run] ${method} ${url}`);
    if (body !== undefined) console.log(JSON.stringify(body, null, 2));
    return { dryRun: true };
  }

  const token = await accessToken();
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return handle(response, method, url);
}

async function handle(response, method, url) {
  if (response.status === 204) return {};
  const text = await response.text();
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
  }
  if (!response.ok) {
    const code = parsed?.error?.code || response.status;
    const message = parsed?.error?.message || text || response.statusText;
    let hint = '';

    if (response.status === 403 || code === 'Authorization_RequestDenied') {
      hint =
        `\n\nThis is usually consent rather than your directory role.\n` +
        `The token was requested with:\n` +
        requestedScopes.map((scope) => `  ${scope}`).join('\n') +
        `\n\nIf that list is just .default, the client only has whatever was\n` +
        `consented to it previously, which for the Microsoft Graph PowerShell\n` +
        `app is often User.Read alone. The script should call useScopes() with\n` +
        `the permissions it needs. If the list does name the right permission,\n` +
        `then an administrator has not consented to it yet: sign in again and\n` +
        `accept the consent prompt, or grant it in the portal under Enterprise\n` +
        `applications, Permissions.\n\n` +
        `Quickest way past this without granting anything tenant wide:\n` +
        `  az login          (as an account that holds the directory roles)\n` +
        `  ENTRA_AUTH_MODE=azurecli\n` +
        `The Azure CLI's own application already carries broad delegated Graph\n` +
        `consent, so no new consent is needed.`;
    }

    const error = new Error(`Graph ${method} ${url} failed: ${code}: ${message}${hint}`);
    error.status = response.status;
    error.body = parsed;
    throw error;
  }
  return parsed ?? {};
}

/**
 * Small console table helper so every sample reports the same way.
 */
export function printTable(rows, columns) {
  if (rows.length === 0) {
    console.log('(no rows)');
    return;
  }
  const keys = columns || Object.keys(rows[0]);
  const widths = keys.map((key) =>
    Math.max(key.length, ...rows.map((row) => String(row[key] ?? '').length)),
  );
  const line = (cells) => cells.map((cell, i) => String(cell ?? '').padEnd(widths[i])).join('  ');
  console.log(line(keys));
  console.log(line(widths.map((width) => '-'.repeat(width))));
  rows.forEach((row) => console.log(line(keys.map((key) => row[key]))));
}

export const GRAPH = { V1: GRAPH_V1, BETA: GRAPH_BETA, SCOPE: GRAPH_SCOPE };
