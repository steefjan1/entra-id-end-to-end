/**
 * The resource side of a claims challenge.
 *
 * This is a small API with two routes. One is ordinary. One is sensitive, and
 * refuses to serve a token that does not carry a Conditional Access
 * authentication context in its acrs claim. When that happens it does not
 * return a bare 401. It returns a 401 with a WWW-Authenticate header that
 * tells the client exactly which claim to go and get.
 *
 * That is the mechanism behind step up authentication, and it is the same
 * mechanism continuous access evaluation uses to tell a client its token has
 * been rejected early. Writing it once by hand is the fastest way to
 * understand why a client that declares cp1 and then ignores the header ends
 * up in a retry loop rather than an error.
 *
 * Run:
 *   API_CLIENT_ID=<api-app-client-id> ENTRA_TENANT_ID=<tenant-id> \
 *   AUTH_CONTEXT_ID=c1 node src/step-up-api.mjs
 *
 * Reference: https://learn.microsoft.com/entra/identity-platform/claims-challenge
 */

import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { stepUpChallenge, challengeHeader } from './claims-challenge.mjs';

const tenantId = process.env.ENTRA_TENANT_ID;
const audience = process.env.API_CLIENT_ID;
const authContextId = process.env.AUTH_CONTEXT_ID || 'c1';
const port = Number(process.env.PORT || 3000);

if (!tenantId || !audience) {
  console.error('Set ENTRA_TENANT_ID and API_CLIENT_ID.');
  process.exit(2);
}

const issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
const authorizationUri = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`;
const jwks = createRemoteJWKSet(
  new URL(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`),
);

const app = express();

/**
 * Validate the token. This API validates only tokens issued for itself: the
 * aud claim must equal this API's own client ID. Accepting a token minted for
 * another resource is the confused deputy problem.
 */
async function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.toLowerCase().startsWith('bearer ')) {
    res.set('WWW-Authenticate', 'Bearer realm=""');
    return res.status(401).json({ error: 'no bearer token' });
  }

  try {
    const { payload } = await jwtVerify(header.slice(7).trim(), jwks, {
      issuer,
      audience,
      clockTolerance: 5,
    });
    req.claims = payload;
    return next();
  } catch (error) {
    res.set('WWW-Authenticate', 'Bearer realm="", error="invalid_token"');
    return res.status(401).json({ error: 'invalid token', detail: error.code || error.message });
  }
}

/**
 * The step up gate.
 *
 * acrs carries the authentication context values the bearer is eligible for.
 * If the required one is missing, answer with a claims challenge rather than
 * a flat refusal, so a well behaved client can recover without the user
 * having to work out what went wrong.
 */
function requireAuthContext(id) {
  return (req, res, next) => {
    const acrs = req.claims?.acrs;
    const held = Array.isArray(acrs) ? acrs : acrs ? [acrs] : [];
    if (held.includes(id)) return next();

    const challenge = stepUpChallenge(id);
    res.set('WWW-Authenticate', challengeHeader(challenge.base64, { authorizationUri }));
    return res.status(401).json({
      error: 'insufficient_claims',
      required: { acrs: id },
      held,
      hint:
        'Repeat the token request with the claims parameter from the WWW-Authenticate header. ' +
        'MSAL takes the decoded JSON, not the base64 string.',
      claimsRequest: challenge.json,
    });
  };
}

app.get('/api/ordinary', authenticate, (req, res) => {
  res.json({
    message: 'An ordinary read. A valid token is enough.',
    subject: { tid: req.claims.tid, oid: req.claims.oid },
    scopes: req.claims.scp ?? null,
    roles: req.claims.roles ?? null,
  });
});

app.get('/api/sensitive', authenticate, requireAuthContext(authContextId), (req, res) => {
  res.json({
    message: `A sensitive read. The token carried authentication context ${authContextId}.`,
    subject: { tid: req.claims.tid, oid: req.claims.oid },
    acrs: req.claims.acrs,
    amr: req.claims.amr ?? null,
    claimsChallengeCapableClient: req.claims.xms_cc ?? null,
  });
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(port, () => {
  console.log(`Step up API listening on http://localhost:${port}`);
  console.log(`  issuer:   ${issuer}`);
  console.log(`  audience: ${audience}`);
  console.log(`  required authentication context on /api/sensitive: ${authContextId}`);
  console.log(
    '\nCall /api/sensitive with an ordinary token and read the WWW-Authenticate\n' +
      'header on the 401. That header is the entire contract.',
  );
});
