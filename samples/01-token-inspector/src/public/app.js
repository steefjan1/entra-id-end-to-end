/*
 * Token inspector SPA. Plain browser JavaScript, no framework, no build step.
 *
 * Two rules this file follows on purpose, because they are the point:
 *
 *  1. It never decodes the access token. It sends it to the API that owns the
 *     audience and renders what that API reports back. Clients treat access
 *     tokens as opaque strings.
 *  2. It does decode the ID token, because the ID token was issued to this
 *     client. That is the whole difference between the two panels below.
 */

/* global msal */

const el = (id) => document.getElementById(id);

const state = {
  config: null,
  pca: null,
  account: null,
  catalogue: {},
  countdownTimer: null,
  expiresAt: null,
};

function setStatus(message, kind) {
  const node = el('status');
  node.textContent = message || '';
  node.className = `status${kind ? ` ${kind}` : ''}`;
}

function text(value) {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value) || typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function epochRow(name, value) {
  if (typeof value !== 'number') return '';
  return ` (${new Date(value * 1000).toISOString().replace('T', ' ').replace('.000Z', 'Z')})`;
}

const EPOCH_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time'];

function renderClaimTable(tableId, rows) {
  const body = el(tableId).querySelector('tbody');
  body.replaceChildren();

  rows.forEach((row) => {
    const tr = document.createElement('tr');
    tr.className = `verdict-${row.verdict}`;

    const nameCell = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = row.name;
    nameCell.appendChild(code);
    const badge = document.createElement('span');
    badge.className = `badge badge-${row.verdict}`;
    badge.textContent = row.verdictLabel;
    nameCell.appendChild(badge);

    const valueCell = document.createElement('td');
    valueCell.className = 'value';
    valueCell.textContent =
      text(row.value) + (EPOCH_CLAIMS.includes(row.name) ? epochRow(row.name, row.value) : '');

    const whatCell = document.createElement('td');
    whatCell.textContent = row.what;

    tr.append(nameCell, valueCell, whatCell);
    body.appendChild(tr);
  });
}

const VERDICT_LABEL = {
  authz: 'Safe for authorization',
  display: 'Display only, never authorization',
  internal: 'Internal to Entra ID, do not use',
  protocol: 'Token validation',
  context: 'Signal, only meaningful with context',
};

function annotateLocally(payload) {
  return Object.keys(payload)
    .sort()
    .map((name) => {
      const entry = state.catalogue[name];
      return {
        name,
        value: payload[name],
        verdict: entry ? entry.verdict : 'context',
        verdictLabel: entry ? VERDICT_LABEL[entry.verdict] : 'Not in this catalogue',
        // A few claims mean something different on an ID token than on an
        // access token. aud is the sharpest: on an access token it is the API,
        // on an ID token it is this client.
        what: entry
          ? entry.whatInIdToken || entry.what
          : 'Not in this sample catalogue. Check the claims reference before you rely on it.',
      };
    });
}

function card(title, value, ok, note) {
  const box = document.createElement('div');
  box.className = `summary-card ${ok === null ? '' : ok ? 'good' : 'bad'}`;

  const h = document.createElement('h3');
  h.textContent = title;

  const v = document.createElement('p');
  v.className = 'summary-value';
  v.textContent = value === null || value === undefined || value === '' ? 'not present' : value;

  const n = document.createElement('p');
  n.className = 'summary-note';
  n.textContent = note;

  box.append(h, v, n);
  return box;
}

function renderSummary(summary) {
  const host = el('summary');
  host.replaceChildren();

  host.appendChild(
    card(
      'Identity key: tid + oid',
      summary.identityKey.value,
      summary.identityKey.ok,
      summary.identityKey.note,
    ),
  );

  host.appendChild(
    card(
      'Caller type: scp vs roles',
      `${summary.callerType.value} (scp: ${summary.callerType.scp.join(' ') || 'none'}, roles: ${
        summary.callerType.roles.join(' ') || 'none'
      })`,
      summary.callerType.value !== 'unknown',
      summary.callerType.note,
    ),
  );

  host.appendChild(
    card(
      'App-only authorization: azp + azpacr + idtyp',
      `azp: ${summary.appOnlyAuthorization.azp || 'none'}, azpacr: ${
        summary.appOnlyAuthorization.azpacr || 'none'
      }, idtyp: ${summary.appOnlyAuthorization.idtyp || 'none'}`,
      summary.appOnlyAuthorization.idtyp ? summary.appOnlyAuthorization.safe : null,
      summary.appOnlyAuthorization.note,
    ),
  );

  host.appendChild(
    card(
      'Authentication methods: amr',
      summary.authenticationMethods.value
        ? summary.authenticationMethods.value.join(', ')
        : null,
      null,
      summary.authenticationMethods.note,
    ),
  );

  host.appendChild(
    card(
      'Authentication context: acrs',
      summary.authenticationContext.value
        ? summary.authenticationContext.value.join(', ')
        : null,
      null,
      summary.authenticationContext.note,
    ),
  );

  host.appendChild(
    card(
      'Claims challenge capability: xms_cc',
      summary.clientCapabilities.value ? summary.clientCapabilities.value.join(', ') : null,
      summary.clientCapabilities.canHandleClaimsChallenge ? true : null,
      summary.clientCapabilities.note,
    ),
  );

  host.appendChild(
    card(
      'Internal claims present',
      summary.internalClaims.value.join(', '),
      false,
      summary.internalClaims.note,
    ),
  );

  host.appendChild(
    card(
      'Present but never an authorization key',
      summary.neverAuthorizeOn.value.join(', '),
      false,
      summary.neverAuthorizeOn.note,
    ),
  );

  host.appendChild(
    card('Token version: ver', summary.version.value, null, summary.version.note),
  );
}

function renderValidation(validation) {
  const list = el('validationChecks');
  list.replaceChildren();
  validation.checks.forEach((check) => {
    const li = document.createElement('li');
    li.textContent = check;
    list.appendChild(li);
  });
  el('validationMeta').textContent =
    `Keys from ${validation.jwksUri}, signed with ${validation.algorithm}, kid ${validation.keyId}. ` +
    `Expected issuer ${validation.issuer} and audience ${validation.audience}. ` +
    `Clock skew allowance ${validation.clockToleranceSeconds} seconds.`;
}

function startCountdown(expiresAt, lifetimeMinutes, issuedAt) {
  state.expiresAt = expiresAt;
  el('lifetimeMinutes').textContent = lifetimeMinutes === null ? '--' : String(lifetimeMinutes);
  el('issuedAt').textContent =
    typeof issuedAt === 'number' ? new Date(issuedAt * 1000).toLocaleTimeString() : '--';

  if (state.countdownTimer) clearInterval(state.countdownTimer);

  const tick = () => {
    if (!state.expiresAt) return;
    const remaining = state.expiresAt - Math.floor(Date.now() / 1000);
    const node = el('countdown');
    if (remaining <= 0) {
      node.textContent = 'expired';
      node.className = 'metric-value expired';
      clearInterval(state.countdownTimer);
      state.countdownTimer = null;
      return;
    }
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    node.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    node.className = remaining < 300 ? 'metric-value warn-value' : 'metric-value';
  };

  tick();
  state.countdownTimer = setInterval(tick, 1000);
}

async function renderFacts() {
  const response = await fetch('/api/token-facts');
  const { facts } = await response.json();
  const host = el('facts');
  host.replaceChildren();

  facts.forEach((fact) => {
    const box = document.createElement('div');
    box.className = 'fact';

    const topic = document.createElement('span');
    topic.className = 'fact-topic';
    topic.textContent = fact.topic;

    const body = document.createElement('p');
    body.textContent = fact.fact;

    const link = document.createElement('a');
    link.href = fact.source;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = 'Microsoft Learn';

    box.append(topic, body, link);
    host.appendChild(box);
  });
}

async function inspect() {
  const request = { scopes: [state.config.apiScope], account: state.account };

  let result;
  try {
    result = await state.pca.acquireTokenSilent(request);
  } catch (error) {
    if (error instanceof msal.InteractionRequiredAuthError) {
      setStatus('Silent token acquisition failed, redirecting for an interactive sign-in.');
      await state.pca.acquireTokenRedirect(request);
      return;
    }
    throw error;
  }

  setStatus('Calling /api/whoami with the access token.');

  const response = await fetch('/api/whoami', {
    headers: { Authorization: `Bearer ${result.accessToken}` },
  });
  const body = await response.json();

  if (!response.ok) {
    // A real client inspects WWW-Authenticate here. If the API answered with a
    // claims challenge, the right move is to call acquireTokenRedirect with
    // that claims value, not to show the user an error.
    setStatus(`API rejected the token: ${body.error}. ${body.message}`, 'error');
    return;
  }

  el('lifetimePanel').hidden = false;
  el('summaryPanel').hidden = false;
  el('validationPanel').hidden = false;
  el('tokensPanel').hidden = false;

  renderClaimTable('accessClaims', body.claims);
  renderSummary(body.summary);
  renderValidation(body.validation);
  startCountdown(
    body.summary.lifetime.expiresAt,
    body.summary.lifetime.lifetimeMinutes,
    body.summary.lifetime.issuedAt,
  );

  const idClaims = state.account && state.account.idTokenClaims ? state.account.idTokenClaims : {};
  renderClaimTable('idClaims', annotateLocally(idClaims));

  setStatus('Token validated by the API. The countdown is real: nothing can revoke it early.');
}

function bindAccount(account) {
  state.account = account;
  state.pca.setActiveAccount(account);
  el('who').textContent = account ? `${account.name || ''} (${account.username})` : '';
  el('signIn').hidden = Boolean(account);
  el('signOut').hidden = !account;
  el('refresh').hidden = !account;
}

async function start() {
  await renderFacts();

  const [configResponse, catalogueResponse] = await Promise.all([
    fetch('/api/config'),
    fetch('/api/claim-catalogue'),
  ]);
  state.config = await configResponse.json();
  state.catalogue = (await catalogueResponse.json()).catalogue;

  if (!state.config.configured) {
    setStatus(
      'This deployment has no AZURE_TENANT_ID, SPA_CLIENT_ID or API_CLIENT_ID. Run scripts/register-apps.sh, then azd env set the values and redeploy.',
      'error',
    );
    el('signIn').disabled = true;
    return;
  }

  state.pca = new msal.PublicClientApplication({
    auth: {
      clientId: state.config.spaClientId,
      authority: `https://login.microsoftonline.com/${state.config.tenantId}`,
      redirectUri: `${window.location.origin}/`,
      navigateToLoginRequestUrl: false,
      // cp1 tells Entra ID this client can handle a claims challenge. Without
      // it the API never sees xms_cc, no matter what the resource registered.
      clientCapabilities: ['cp1'],
    },
    cache: {
      // sessionStorage, so closing the tab ends the local cache. The refresh
      // token behind a spa redirect URI only lasts 24 hours anyway.
      cacheLocation: 'sessionStorage',
      storeAuthStateInCookie: false,
    },
  });

  await state.pca.initialize();

  const redirectResult = await state.pca.handleRedirectPromise();
  if (redirectResult && redirectResult.account) {
    bindAccount(redirectResult.account);
  } else {
    const accounts = state.pca.getAllAccounts();
    bindAccount(accounts.length > 0 ? accounts[0] : null);
  }

  el('signIn').addEventListener('click', () => {
    state.pca.loginRedirect({ scopes: [state.config.apiScope] });
  });

  el('signOut').addEventListener('click', () => {
    state.pca.logoutRedirect({ account: state.account });
  });

  el('refresh').addEventListener('click', () => {
    inspect().catch((error) => setStatus(error.message, 'error'));
  });

  if (state.account) {
    await inspect();
  } else {
    setStatus('Sign in to see what the sign-in actually produced.');
  }
}

start().catch((error) => setStatus(error.message, 'error'));
