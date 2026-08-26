/**
 * The experiment that turns the argument into a number.
 *
 * Somebody in a meeting says "we disable the account in Active Directory, so
 * they lose access". This script measures how long "so they lose access"
 * actually takes in your tenant, in minutes, with timestamps.
 *
 * How to run it:
 *
 *   1. Pick a test account that is synced from Active Directory. A test account.
 *      Not a person. See the warning below and mean it.
 *   2. Start this script. It prints a baseline and waits.
 *   3. When it says so, disable the account in on-premises Active Directory.
 *      That moment is t=0.
 *   4. Watch. It polls until accountEnabled flips to false in Microsoft Entra ID
 *      and then reports the elapsed time.
 *
 * What you are measuring: with password hash synchronization, Microsoft's own
 * words are that it "doesn't immediately enforce changes in on-premises account
 * states" and that "a user has access to cloud apps until the user account state
 * is synchronized to Microsoft Entra ID". That is up to about 30 minutes for a
 * disabled account. Everything inside that window is working cloud access for an
 * account your Active Directory considers dead.
 *
 * Pass-through authentication and federation do not have this window. They check
 * disabled, locked out, expired password and sign-in hours in Active Directory
 * at sign-in time. Separately, and worth knowing: "The password expired and
 * account locked-out states aren't currently synced to Microsoft Entra ID with
 * Microsoft Entra Connect." Those two never arrive at all.
 *
 *   GET  /users/{id}?$select=accountEnabled,onPremisesLastSyncDateTime,
 *                            signInSessionsValidFromDateTime
 *   POST /users/{id}/revokeSignInSessions        (--revoke, --revoke-now)
 *
 * Permissions: User.Read.All to watch. User.ReadWrite.All or
 * User.RevokeSessions.All to revoke.
 *
 *   npm run watch -- --user <object-id-or-upn>
 *   npm run watch -- --user <id> --interval 15 --max-minutes 45
 *   npm run watch -- --user <id> --revoke
 *   npm run watch -- --user <id> --json > propagation.json
 *
 * https://learn.microsoft.com/entra/identity/hybrid/connect/choose-ad-authn
 * https://learn.microsoft.com/graph/api/user-revokesigninsessions
 */

import { parseArgs } from 'node:util';
import { useScopes, graphGet, graphWrite, isDryRun } from '../../../shared/js/graph.mjs';

// The permissions this script needs, declared where you can see them.
// Without this the token carries only .default, which against the Graph
// PowerShell app is usually User.Read, and every call returns 403.
useScopes(
  'User.Read.All',
  'User.ReadWrite.All',
);

const { values: args } = parseArgs({
  options: {
    user: { type: 'string' },
    interval: { type: 'string' },
    'max-minutes': { type: 'string' },
    revoke: { type: 'boolean' },
    'revoke-now': { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help || !args.user) {
  console.log(
    'Usage: node src/disable-propagation-watch.mjs --user <id|upn> [options]\n' +
      '\n' +
      '  --user <id|upn>     the account to watch. Use a TEST account.\n' +
      '  --interval <s>      seconds between polls. Default 30.\n' +
      '  --max-minutes <m>   give up after this many minutes. Default 45.\n' +
      '  --revoke            call revokeSignInSessions the moment the disable lands.\n' +
      '  --revoke-now        call revokeSignInSessions immediately at t=0, then keep\n' +
      '                      watching. Use this to measure the two controls separately.\n' +
      '  --json              print a machine readable result at the end.\n' +
      '\n' +
      'DRY_RUN=1 makes the revoke a printed request that is never sent. The polling\n' +
      'is read only and runs either way.\n',
  );
  process.exit(args.help ? 0 : 1);
}

const INTERVAL_SECONDS = Math.max(5, Number(args.interval ?? 30));
const MAX_MINUTES = Math.max(1, Number(args['max-minutes'] ?? 45));
const SELECT =
  'id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,' +
  'onPremisesSamAccountName,onPremisesDomainName,onPremisesLastSyncDateTime,' +
  'signInSessionsValidFromDateTime';

const samples = [];
let revoked = null;
let startedAt = null;

const baseline = await read();

console.log('Disable propagation watch\n');
console.log(`  user                             ${baseline.displayName} <${baseline.userPrincipalName}>`);
console.log(`  id                               ${baseline.id}`);
console.log(`  accountEnabled                   ${baseline.accountEnabled}`);
console.log(`  onPremisesSyncEnabled            ${describeFlag(baseline.onPremisesSyncEnabled)}`);
console.log(`  onPremisesSamAccountName         ${baseline.onPremisesSamAccountName || '(none)'}`);
console.log(`  onPremisesDomainName             ${baseline.onPremisesDomainName || '(none)'}`);
console.log(`  onPremisesLastSyncDateTime       ${baseline.onPremisesLastSyncDateTime || '(none)'}`);
console.log(`  signInSessionsValidFromDateTime  ${baseline.signInSessionsValidFromDateTime || '(none)'}`);
console.log('');

if (baseline.accountEnabled === false) {
  console.error(
    'accountEnabled is already false in Microsoft Entra ID. There is nothing to watch.\n' +
      'Re-enable the account, wait for a sync cycle, then start again.',
  );
  process.exit(1);
}

if (baseline.onPremisesSyncEnabled !== true) {
  console.error(
    'Warning: onPremisesSyncEnabled is not true on this account, so it is probably not\n' +
      'synced from Active Directory. Disabling it in AD will change nothing here, and\n' +
      'this watch will simply time out. Pick a synced account.\n',
  );
}

if (baseline.userType && baseline.userType.toLowerCase() === 'guest') {
  console.error(
    'Warning: this is a guest. revokeSignInSessions does not work for external or B2B\n' +
      'users, because they sign in through their home tenant, and the disable path is\n' +
      'different too. This experiment will not tell you what you think it does.\n',
  );
}

console.log(
  'THIS DISABLES SOMEBODY. Use a test account, or an account whose owner has agreed\n' +
    'to it in advance and knows they will lose access. Do not run this on a real\n' +
    'person as a demonstration.\n',
);
console.log(
  `Polling every ${INTERVAL_SECONDS}s for up to ${MAX_MINUTES} minutes.\n` +
    'Disable the account in on-premises Active Directory NOW. That is t=0.\n' +
    'Press Ctrl+C to stop early and print what was collected.\n',
);

startedAt = Date.now();

process.on('SIGINT', () => {
  console.log('\n\nStopped early.');
  finish(null, 'interrupted');
});

if (args['revoke-now']) {
  await revoke('t=0, before the disable had a chance to propagate');
}

const deadline = startedAt + MAX_MINUTES * 60 * 1000;
let previous = baseline;

while (Date.now() < deadline) {
  await sleep(INTERVAL_SECONDS * 1000);

  let current;
  try {
    current = await read();
  } catch (error) {
    log(`read failed: ${String(error.message).slice(0, 140)}`);
    continue;
  }

  samples.push({
    at: new Date().toISOString(),
    elapsedSeconds: Math.round((Date.now() - startedAt) / 1000),
    accountEnabled: current.accountEnabled,
    onPremisesLastSyncDateTime: current.onPremisesLastSyncDateTime || null,
    signInSessionsValidFromDateTime: current.signInSessionsValidFromDateTime || null,
  });

  const changes = [];
  if (current.accountEnabled !== previous.accountEnabled) {
    changes.push(`accountEnabled ${previous.accountEnabled} -> ${current.accountEnabled}`);
  }
  if (current.onPremisesLastSyncDateTime !== previous.onPremisesLastSyncDateTime) {
    changes.push(`sync cycle at ${current.onPremisesLastSyncDateTime}`);
  }
  if (current.signInSessionsValidFromDateTime !== previous.signInSessionsValidFromDateTime) {
    changes.push(`signInSessionsValidFromDateTime -> ${current.signInSessionsValidFromDateTime}`);
  }

  log(
    `accountEnabled=${current.accountEnabled}  ` +
      `lastSync=${current.onPremisesLastSyncDateTime || 'none'}` +
      (changes.length > 0 ? `   <<< ${changes.join('; ')}` : ''),
  );

  previous = current;

  if (current.accountEnabled === false) {
    console.log('');
    if (args.revoke) {
      await revoke('the moment the disable landed in Microsoft Entra ID');
    }
    finish(current, 'disabled');
  }
}

console.log('');
finish(previous, 'timeout');

/* ---------------------------------------------------------------- helpers */

async function read() {
  return graphGet(`/users/${encodeURIComponent(args.user)}?$select=${SELECT}`);
}

async function revoke(when) {
  console.log(`\nrevokeSignInSessions  (${when})`);
  const result = await graphWrite(
    'POST',
    `/users/${encodeURIComponent(args.user)}/revokeSignInSessions`,
    {},
  );
  revoked = {
    at: new Date().toISOString(),
    elapsedSeconds: startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0,
    dryRun: Boolean(result?.dryRun),
    value: result?.value ?? null,
  };
  console.log(
    '\n  What revokeSignInSessions does: it stamps signInSessionsValidFromDateTime,\n' +
      '  which invalidates every refresh token and every browser session cookie for\n' +
      '  this user. There can be a small delay of a few minutes before it takes hold.\n' +
      '\n' +
      '  What it does NOT do: it does not invalidate access tokens that have already\n' +
      '  been issued. Those stay valid until they expire, typically around an hour,\n' +
      '  unless the resource supports continuous access evaluation. So "revoked" and\n' +
      '  "has no access" are not the same sentence.\n' +
      '\n' +
      '  It also does not work for external or B2B users, because they authenticate\n' +
      '  against their home tenant, not yours.\n',
  );
}

function finish(final, reason) {
  const elapsedSeconds = startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0;
  const minutes = (elapsedSeconds / 60).toFixed(1);

  console.log('Result\n');
  if (reason === 'disabled') {
    console.log(
      `  accountEnabled went false after ${elapsedSeconds} seconds (${minutes} minutes)\n` +
        '  measured from the moment you were told to disable the account in AD.\n' +
        '\n' +
        `  For ${minutes} minutes, an account that Active Directory considered disabled\n` +
        '  could still sign in to cloud applications. That number is the gap. It is not\n' +
        '  a bug, it is how password hash synchronization works, and Microsoft documents\n' +
        '  it as up to about 30 minutes.\n' +
        '\n' +
        '  And the clock does not stop there. A user who signed in shortly before the\n' +
        '  disable landed still holds an access token, valid until it expires, unless\n' +
        '  the resource supports continuous access evaluation. Add that to the number\n' +
        '  above before you quote it to anyone.\n',
    );
  } else if (reason === 'timeout') {
    console.log(
      `  Gave up after ${MAX_MINUTES} minute(s) with accountEnabled still ` +
        `${final?.accountEnabled}.\n` +
        '\n' +
        '  Three things to check, in this order. Was the account actually disabled in\n' +
        '  Active Directory. Is the account in the scope of the sync configuration. Is\n' +
        '  the sync agent running at all. If the answer to all three is yes and this\n' +
        `  still timed out, your propagation window is longer than ${MAX_MINUTES} minutes,\n` +
        '  which is a more interesting finding than the one you came for.\n',
    );
  } else {
    console.log(`  Interrupted after ${elapsedSeconds} seconds with ${samples.length} sample(s).\n`);
  }

  if (revoked) {
    console.log(
      `  revokeSignInSessions was called at +${revoked.elapsedSeconds}s` +
        `${revoked.dryRun ? ' (dry run, nothing sent)' : ''}.\n`,
    );
  }

  console.log(
    '  Closing this gap is not a script. It is one of: pass-through authentication or\n' +
      '  federation, so account state is checked in AD at sign-in. Or source of\n' +
      '  authority conversion, so there is no AD state to wait for. Or Entra Private\n' +
      '  Access in front of the on-premises apps, so there is a policy decision point\n' +
      '  where there was not one before. Pick one and plan it.\n',
  );

  if (args.json) {
    console.log(
      JSON.stringify(
        {
          user: {
            id: baseline.id,
            userPrincipalName: baseline.userPrincipalName,
            onPremisesSamAccountName: baseline.onPremisesSamAccountName || null,
            onPremisesDomainName: baseline.onPremisesDomainName || null,
          },
          reason,
          startedAt: startedAt ? new Date(startedAt).toISOString() : null,
          intervalSeconds: INTERVAL_SECONDS,
          maxMinutes: MAX_MINUTES,
          elapsedSeconds,
          propagationSeconds: reason === 'disabled' ? elapsedSeconds : null,
          revoked,
          dryRun: isDryRun(),
          samples,
        },
        null,
        2,
      ),
    );
  }

  process.exit(reason === 'disabled' ? 0 : 1);
}

function log(message) {
  const elapsed = startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0;
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`${stamp}  +${String(elapsed).padStart(5)}s  ${message}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function describeFlag(value) {
  if (value === true) return 'true';
  if (value === false) return 'false  (previously synced, no longer synced)';
  return 'null   (never synced, or converted to cloud managed)';
}
