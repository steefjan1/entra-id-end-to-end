/**
 * The revocation stopwatch.
 *
 * The infographic draws a dashed line back from "Access Application" to
 * "Authenticate" and labels it "Token renewal / Continuous access evaluation".
 * One dashed line, one label, and the impression that revocation is instant.
 *
 * It is not. It depends entirely on whether the client asked for it.
 *
 * This script signs the same user in twice against Microsoft Graph:
 *
 *   client A  declares the cp1 client capability, so Entra treats the session
 *             as continuous access evaluation aware and issues a long lived
 *             token (20 to 28 hours) that the resource can reject early
 *   client B  declares nothing, so it gets an ordinary token with a lifetime
 *             randomized between 60 and 90 minutes that nobody can revoke
 *
 * Then it revokes the user's sessions and polls Graph with both tokens until
 * each one starts failing, and prints how long each took.
 *
 * Client A should fail within seconds, with a claims challenge in the
 * WWW-Authenticate header telling it what to do next. Client B keeps working
 * until its access token expires on its own, which is the number worth
 * putting in front of anyone who believes revocation is immediate.
 *
 * Usage:
 *   node src/stopwatch.mjs --tenant <tenant-id> --client <app-client-id>
 *     (then revoke by hand from the portal and watch the clock, which is the
 *      path that needs no extra Graph permission)
 *   node src/stopwatch.mjs --tenant <tenant-id> --revoke
 *     (revokes for you, needs User.ReadWrite.All)
 *   add --interactive to sign in through the browser instead of a device code
 *
 * The account must be a MEMBER of the tenant. Guests and personal Microsoft
 * accounts cannot demonstrate this: continuous access evaluation does not
 * support them and revokeSignInSessions does nothing for them. The script
 * checks and refuses.
 *
 * The app registration needs to be a public client with the device code flow
 * allowed, and the delegated permissions User.Read plus (for --revoke)
 * User.ReadWrite.All. You can also point it at the Microsoft Graph PowerShell
 * first party app if that is already consented in your tenant.
 */

import { PublicClientApplication } from '@azure/msal-node';
import { readClaimsChallenge } from './claims-challenge.mjs';

const argv = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 && argv[index + 1] && !argv[index + 1].startsWith('--')
    ? argv[index + 1]
    : fallback;
};
const has = (name) => argv.includes(`--${name}`);

const tenantId = flag('tenant', process.env.ENTRA_TENANT_ID);
const clientId = flag('client', process.env.ENTRA_CLIENT_ID || '14d82eec-204b-4c2f-b7e8-296a70dab67e');
const pollSeconds = Number(flag('poll', '15'));
const maxMinutes = Number(flag('max-minutes', '120'));
const probeUrl = flag('probe', 'https://graph.microsoft.com/v1.0/me');
const shouldRevoke = has('revoke');

if (!tenantId) {
  console.error('Pass --tenant <tenant-id> or set ENTRA_TENANT_ID.');
  process.exit(2);
}

const authority = `https://login.microsoftonline.com/${tenantId}`;

/**
 * Two MSAL clients, identical except for one line.
 *
 * clientCapabilities: ['cp1'] is the whole opt in. It tells Entra the client
 * knows how to handle a claims challenge, which is what makes a continuous
 * access evaluation session possible. A resource learns about it through the
 * xms_cc claim, which the resource must have registered as an optional claim.
 */
function makeClient(capable) {
  return new PublicClientApplication({
    auth: {
      clientId,
      authority,
      ...(capable ? { clientCapabilities: ['cp1'] } : {}),
    },
    system: {
      loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false },
    },
  });
}

/**
 * Two ways in, because one of them may be blocked.
 *
 * Device code is the default: nothing to register, works over SSH, and the
 * prompt is copy and paste. But device code flow is exactly what a hardened
 * tenant blocks first. Microsoft ships a managed Conditional Access policy
 * called "Block device code flow" and auto enables managed policies no less
 * than 30 days after introducing them, and sample 03 in this repository ships
 * a policy that blocks it too. If your sign in fails with AADSTS50199 or a
 * Conditional Access block, that is the control working.
 *
 * --interactive opens the system browser instead, which no device code policy
 * touches. It needs a loopback redirect URI on the app registration, which the
 * Microsoft Graph PowerShell first party app already has.
 */
const SCOPES = ['https://graph.microsoft.com/User.Read'];

async function signIn(app, label) {
  console.log(`\nSigning in ${label}. Use the same account for both.`);

  if (has('interactive')) {
    return app.acquireTokenInteractive({
      scopes: SCOPES,
      successTemplate: 'Signed in. You can close this tab and go back to the terminal.',
    });
  }

  return app.acquireTokenByDeviceCode({
    scopes: SCOPES,
    deviceCodeCallback: (response) => console.log(`  ${response.message}`),
  });
}

function minutesUntil(date) {
  return Math.round((new Date(date).getTime() - Date.now()) / 60000);
}

async function probe(token) {
  const response = await fetch(probeUrl, { headers: { Authorization: `Bearer ${token}` } });
  const challenge = response.status === 401 ? readClaimsChallenge(response) : null;
  return { ok: response.ok, status: response.status, challenge };
}

function stamp() {
  return new Date().toISOString().slice(11, 19);
}

// ---------------------------------------------------------------------------

const capableApp = makeClient(true);
const plainApp = makeClient(false);

const capable = await signIn(capableApp, 'client A (declares cp1, CAE aware)');
const plain = await signIn(plainApp, 'client B (declares nothing)');

if (!capable?.accessToken || !plain?.accessToken) {
  console.error('One of the sign ins did not return a token.');
  process.exit(1);
}

// expiresOn is metadata MSAL hands back. We never parse the Graph token
// itself: Graph access tokens use a proprietary format and Microsoft
// documents them as opaque to clients.
const capableMinutes = minutesUntil(capable.expiresOn);
const plainMinutes = minutesUntil(plain.expiresOn);

console.log('\nTokens acquired.');
console.log(`  client A lifetime remaining: ${capableMinutes} minutes`);
console.log(`  client B lifetime remaining: ${plainMinutes} minutes`);
if (capableMinutes > plainMinutes + 60) {
  console.log('  Client A got a long lived token, so this tenant is issuing CAE sessions.');
} else {
  console.log(
    '  Both lifetimes look ordinary. Either the resource or the tenant is not\n' +
      '  issuing a CAE session here, which is itself a finding worth chasing.',
  );
}

const userId = capable.account?.homeAccountId?.split('.')[0] ?? capable.account?.localAccountId;

// Refuse to waste your afternoon on an account this cannot measure.
//
// Continuous access evaluation does not support B2B or guest accounts, and
// revokeSignInSessions does nothing for external users, because they sign in
// through their home tenant rather than this one. Run the stopwatch with a
// guest and both clients keep working, which looks like a broken script and
// is actually the documented behaviour.
//
// The tell is the idp claim on the ID token, or a home tenant that is not the
// tenant you pointed this at. 9188040d-6c67-4c5b-b112-36a304b66dad is the
// well known personal Microsoft account tenant.
const MSA_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';
const homeTenant = capable.account?.tenantId ?? capable.account?.idTokenClaims?.tid;
const idp = capable.account?.idTokenClaims?.idp;

if (idp || (homeTenant && homeTenant.toLowerCase() !== tenantId.toLowerCase())) {
  const kind = homeTenant === MSA_TENANT ? 'a personal Microsoft account' : 'an external or guest account';
  console.error(
    `\nThis account is ${kind}, and the measurement will not work.\n\n` +
      `  idp claim:    ${idp ?? '(none)'}\n` +
      `  home tenant:  ${homeTenant ?? '(unknown)'}\n` +
      `  target tenant: ${tenantId}\n\n` +
      'Continuous access evaluation does not support B2B or guest accounts, and\n' +
      'revokeSignInSessions does nothing for external users because they sign in\n' +
      'through their home tenant. Both clients would keep working and the result\n' +
      'would tell you nothing.\n\n' +
      'Use a member account native to the tenant. Pass --allow-guest to run anyway\n' +
      'and see the null result for yourself, which is itself a fair demonstration\n' +
      'of the guest limitation.',
  );
  if (!has('allow-guest')) process.exit(3);
  console.error('\n--allow-guest set. Continuing, and expecting nothing to happen.\n');
}

if (shouldRevoke) {
  if (!userId) {
    console.error('Could not work out the signed in user object ID for revocation.');
    process.exit(1);
  }
  console.log(`\nRevoking sign in sessions for ${userId}.`);
  const response = await fetch(
    `https://graph.microsoft.com/v1.0/users/${userId}/revokeSignInSessions`,
    { method: 'POST', headers: { Authorization: `Bearer ${plain.accessToken}` } },
  );
  if (!response.ok) {
    console.error(
      `revokeSignInSessions returned ${response.status}. It needs User.ReadWrite.All.\n` +
        'Revoke from the portal instead and rerun without --revoke.',
    );
  } else {
    console.log('Revocation accepted. Microsoft documents a delay of a few minutes on this call.');
  }
} else {
  console.log(
    '\nNow revoke the session yourself: Entra admin center, the user, Revoke sessions.\n' +
      'Or disable the account in on premises Active Directory if you want to measure\n' +
      'the hybrid path instead (see sample 05).',
  );
}

const started = Date.now();
const state = {
  A: { label: 'A (cp1, CAE aware)', token: capable.accessToken, failedAt: null, detail: '' },
  B: { label: 'B (no capability)', token: plain.accessToken, failedAt: null, detail: '' },
};

console.log(`\nPolling ${probeUrl} every ${pollSeconds}s. Ctrl+C to stop.\n`);

while (Date.now() - started < maxMinutes * 60000) {
  const elapsed = Math.round((Date.now() - started) / 1000);
  const line = [];

  for (const key of ['A', 'B']) {
    const entry = state[key];
    if (entry.failedAt !== null) {
      line.push(`${key}: failed at ${entry.failedAt}s`);
      continue;
    }
    const result = await probe(entry.token);
    if (result.ok) {
      line.push(`${key}: 200`);
    } else {
      entry.failedAt = elapsed;
      if (result.challenge) {
        entry.detail =
          `claims challenge, error=${result.challenge.error}, ` +
          `claims=${JSON.stringify(result.challenge.claimsJson)}`;
      } else {
        entry.detail = `plain ${result.status} with no claims challenge`;
      }
      line.push(`${key}: ${result.status} STOPPED`);
      console.log(`${stamp()}  t+${elapsed}s  client ${entry.label} stopped working: ${entry.detail}`);
    }
  }

  console.log(`${stamp()}  t+${elapsed}s  ${line.join('   ')}`);

  if (state.A.failedAt !== null && state.B.failedAt !== null) break;
  await new Promise((resolve) => setTimeout(resolve, pollSeconds * 1000));
}

console.log('\nResult');
console.log('------');
for (const key of ['A', 'B']) {
  const entry = state[key];
  const when = entry.failedAt === null ? `still working after ${maxMinutes} minutes` : `${entry.failedAt} seconds`;
  console.log(`client ${entry.label}: ${when}`);
  if (entry.detail) console.log(`  ${entry.detail}`);
}

console.log(
  '\nThe gap between those two numbers is the part of the picture the arrow hides.\n' +
    'Client A is told to go back and get a new token. Client B is never told anything,\n' +
    'and keeps its access until the token expires on its own schedule.\n' +
    '\n' +
    'Note what this does NOT measure: a group membership change, a role assignment or\n' +
    'a new Conditional Access policy. None of those are critical events. They wait for\n' +
    'the next token, which Microsoft documents as up to one day.',
);
