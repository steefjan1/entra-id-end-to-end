/**
 * Parsing and building the claims challenge.
 *
 * When a resource decides the token in front of it is no longer good enough,
 * it does not just return 401. It returns 401 with a WWW-Authenticate header
 * that tells the client exactly what to ask for next:
 *
 *   WWW-Authenticate: Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize",
 *     error="insufficient_claims", claims="eyJhY2Nlc3NfdG9rZW4iOnsieG1zX2NjIjp7InZhbHVlcyI6WyJjcDEiXX19fQ=="
 *
 * That base64 blob decodes to a claims request, for example:
 *
 *   {"access_token":{"xms_cc":{"values":["cp1"]}}}
 *   {"access_token":{"acrs":{"essential":true,"value":"c1"}}}
 *
 * The client is expected to clear its cached token and repeat the request with
 * the claims parameter. A client that declares the cp1 capability and then
 * ignores the challenge does not fail loudly. It loops, retrying a token the
 * resource has already rejected.
 *
 * Reference: https://learn.microsoft.com/entra/identity-platform/claims-challenge
 *
 * Run "node src/claims-challenge.mjs --selftest" to exercise the parser.
 */

/**
 * Parse a WWW-Authenticate header into its parameters.
 * Returns null when the header is absent or is not a Bearer challenge.
 */
export function parseWwwAuthenticate(header) {
  if (!header) return null;
  const trimmed = header.trim();
  if (!/^bearer\b/i.test(trimmed)) return null;

  const params = {};
  const body = trimmed.slice('bearer'.length);
  // key="value" pairs, comma separated. Values may contain commas and equals
  // signs, which is why this is a regex over quoted values rather than a split.
  const pattern = /([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = pattern.exec(body)) !== null) {
    params[match[1].toLowerCase()] = match[2];
  }
  return params;
}

/**
 * Pull the decoded claims request out of a 401 response.
 * Returns { error, claims, claimsJson, authorizationUri } or null.
 */
export function readClaimsChallenge(response) {
  const header =
    typeof response?.headers?.get === 'function'
      ? response.headers.get('www-authenticate')
      : response?.headers?.['www-authenticate'];

  const params = parseWwwAuthenticate(header);
  if (!params || !params.claims) return null;

  let claimsJson = null;
  try {
    claimsJson = JSON.parse(Buffer.from(params.claims, 'base64').toString('utf8'));
  } catch {
    claimsJson = null;
  }

  return {
    error: params.error ?? null,
    claims: params.claims,
    claimsJson,
    authorizationUri: params.authorization_uri ?? null,
  };
}

/**
 * Build the base64 claims value a resource should send in its challenge.
 * MSAL wants the decoded JSON string in the "claims" request property, so this
 * returns both forms.
 */
export function buildClaimsChallenge(claimsRequest) {
  const json = JSON.stringify(claimsRequest);
  return { json, base64: Buffer.from(json, 'utf8').toString('base64') };
}

/**
 * The claims request a resource sends when it needs a Conditional Access
 * authentication context that the presented token does not carry.
 */
export function stepUpChallenge(authContextId) {
  return buildClaimsChallenge({
    access_token: { acrs: { essential: true, value: authContextId } },
  });
}

/**
 * The header value itself, ready to write to the response.
 */
export function challengeHeader(claimsBase64, { authorizationUri, error = 'insufficient_claims' } = {}) {
  const parts = [
    'Bearer realm=""',
    authorizationUri ? `authorization_uri="${authorizationUri}"` : null,
    `error="${error}"`,
    `claims="${claimsBase64}"`,
  ].filter(Boolean);
  return parts.join(', ');
}

// ---------------------------------------------------------------------------

function selftest() {
  const cases = [];
  const assert = (name, condition, detail = '') => {
    cases.push({ result: condition ? 'pass' : 'FAIL', name, detail: condition ? '' : detail });
  };

  // The exact header shape Microsoft documents.
  const documented =
    'Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", ' +
    'error="insufficient_claims", claims="eyJhY2Nlc3NfdG9rZW4iOnsieG1zX2NjIjp7InZhbHVlcyI6WyJjcDEiXX19fQ=="';

  const parsed = readClaimsChallenge({ headers: { 'www-authenticate': documented } });
  assert('parses the documented CAE challenge', parsed !== null);
  assert('reads the error code', parsed?.error === 'insufficient_claims', parsed?.error);
  assert(
    'decodes the xms_cc claims request',
    JSON.stringify(parsed?.claimsJson) === JSON.stringify({ access_token: { xms_cc: { values: ['cp1'] } } }),
    JSON.stringify(parsed?.claimsJson),
  );

  // A plain 401 with no claims must not look like a claims challenge.
  assert(
    'ignores a bare Bearer 401',
    readClaimsChallenge({ headers: { 'www-authenticate': 'Bearer realm=""' } }) === null,
  );
  assert('ignores a missing header', readClaimsChallenge({ headers: {} }) === null);
  assert(
    'ignores a non Bearer scheme',
    readClaimsChallenge({ headers: { 'www-authenticate': 'Basic realm="x"' } }) === null,
  );

  // Round trip through the builder.
  const built = stepUpChallenge('c1');
  const header = challengeHeader(built.base64, {
    authorizationUri: 'https://login.microsoftonline.com/common/oauth2/authorize',
  });
  const roundTripped = readClaimsChallenge({ headers: { 'www-authenticate': header } });
  assert(
    'round trips a step up challenge',
    roundTripped?.claimsJson?.access_token?.acrs?.value === 'c1',
    JSON.stringify(roundTripped?.claimsJson),
  );
  assert('marks the acrs claim essential', roundTripped?.claimsJson?.access_token?.acrs?.essential === true);

  // A Headers object rather than a plain map.
  const headersObject = new Headers({ 'WWW-Authenticate': header });
  assert('accepts a fetch Headers object', readClaimsChallenge({ headers: headersObject }) !== null);

  const failures = cases.filter((entry) => entry.result === 'FAIL');
  const width = Math.max(...cases.map((entry) => entry.name.length));
  cases.forEach((entry) => {
    console.log(`${entry.result.padEnd(4)}  ${entry.name.padEnd(width)}  ${entry.detail}`);
  });
  console.log(`\n${cases.length - failures.length}/${cases.length} checks passed.`);
  if (failures.length > 0) process.exit(1);
}

if (process.argv.includes('--selftest')) selftest();
