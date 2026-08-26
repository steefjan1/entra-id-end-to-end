/**
 * Token inspector API.
 *
 * This process is the RESOURCE. It owns the audience it validates, which is
 * the entire justification for decoding anything at all. A client has no
 * business doing what this file does.
 *
 * Validation is deliberately explicit rather than delegated to a middleware
 * package, because the whole point of the sample is to show the checks.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader } from 'jose';

import { annotateClaims, summarize, claimCatalogue } from './claims.mjs';
import { TOKEN_FACTS } from './facts.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

const TENANT_ID = process.env.AZURE_TENANT_ID || '';
const API_CLIENT_ID = process.env.API_CLIENT_ID || process.env.AZURE_CLIENT_ID || '';
const SPA_CLIENT_ID = process.env.SPA_CLIENT_ID || '';
const REQUIRED_SCOPE = process.env.REQUIRED_SCOPE || 'Inspect.Read';
const PORT = Number(process.env.PORT || 3000);

// Entra ID publishes the signing keys per tenant. jose caches them and
// re-fetches on an unknown kid, which is what makes key rollover a non event.
let jwks = null;
function keySet() {
  if (!TENANT_ID) throw new Error('AZURE_TENANT_ID is not configured.');
  if (!jwks) {
    jwks = createRemoteJWKSet(
      new URL(`https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`),
    );
  }
  return jwks;
}

class TokenError extends Error {
  constructor(status, code, message, detail) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

function bearerFrom(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!match) {
    throw new TokenError(401, 'invalid_request', 'No bearer token on the request.');
  }
  return match[1].trim();
}

/**
 * The checks, in the order they matter.
 *
 * 1. Signature, against the tenant published JWKS. Never against a key you
 *    pinned yourself: Entra ID rolls signing keys without telling you.
 * 2. iss, which must be this tenant v2.0 issuer.
 * 3. aud, which must be THIS API client ID. A v2.0 token uses the GUID, not
 *    the App ID URI that v1.0 used.
 * 4. exp and nbf, with a small clock skew allowance. jose does both.
 * 5. tid, cross checked against the issuer so a token from another tenant
 *    cannot ride in on a wildcard issuer.
 * 6. scp, because a valid token is not the same thing as a permitted call.
 */
async function validate(token) {
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new TokenError(401, 'invalid_token', 'The bearer value is not a JWT.');
  }

  if (header.alg === 'none') {
    throw new TokenError(401, 'invalid_token', 'Unsigned token rejected.');
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(token, keySet(), {
      issuer: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
      audience: API_CLIENT_ID,
      algorithms: ['RS256'],
      clockTolerance: 60,
    }));
  } catch (error) {
    throw new TokenError(401, 'invalid_token', 'Token validation failed.', error.message);
  }

  if (payload.tid !== TENANT_ID) {
    throw new TokenError(401, 'invalid_token', 'The tid claim does not match the expected tenant.');
  }

  if (payload.ver !== '2.0') {
    throw new TokenError(
      401,
      'invalid_token',
      `Expected a v2.0 token, got ver=${String(payload.ver)}. A v1.0 token carries a different aud and different claim names.`,
    );
  }

  const scopes = typeof payload.scp === 'string' ? payload.scp.split(' ').filter(Boolean) : [];
  const roles = Array.isArray(payload.roles) ? payload.roles : [];

  if (scopes.length === 0 && roles.length === 0) {
    throw new TokenError(403, 'insufficient_scope', 'The token carries neither scp nor roles.');
  }

  if (scopes.length > 0 && !scopes.includes(REQUIRED_SCOPE)) {
    throw new TokenError(
      403,
      'insufficient_scope',
      `The delegated scope ${REQUIRED_SCOPE} is required. This token carries: ${scopes.join(', ')}.`,
    );
  }

  return { payload, header };
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));

// Everything is same origin, so the SPA reads its own configuration from the
// server rather than having client IDs baked into a static file at build time.
app.get('/api/config', (_req, res) => {
  res.json({
    tenantId: TENANT_ID,
    spaClientId: SPA_CLIENT_ID,
    apiClientId: API_CLIENT_ID,
    apiScope: API_CLIENT_ID ? `api://${API_CLIENT_ID}/${REQUIRED_SCOPE}` : null,
    requiredScope: REQUIRED_SCOPE,
    configured: Boolean(TENANT_ID && SPA_CLIENT_ID && API_CLIENT_ID),
  });
});

app.get('/api/token-facts', (_req, res) => {
  res.json({ facts: TOKEN_FACTS });
});

// The ID token belongs to the SPA, so the SPA is allowed to read it. It still
// borrows the annotations from here rather than shipping a second copy.
app.get('/api/claim-catalogue', (_req, res) => {
  res.json({ catalogue: claimCatalogue });
});

app.get('/api/whoami', async (req, res) => {
  try {
    const token = bearerFrom(req);
    const { payload, header } = await validate(token);
    const now = Math.floor(Date.now() / 1000);

    res.json({
      validated: true,
      validatedAt: now,
      validation: {
        issuer: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
        audience: API_CLIENT_ID,
        jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
        algorithm: header.alg,
        keyId: header.kid,
        requiredScope: REQUIRED_SCOPE,
        clockToleranceSeconds: 60,
        checks: [
          'signature against the tenant JWKS',
          'iss equals the tenant v2.0 issuer',
          'aud equals this API client ID',
          'exp and nbf, with 60 seconds of clock skew',
          'tid equals the expected tenant',
          `scp contains ${REQUIRED_SCOPE}`,
        ],
      },
      claims: annotateClaims(payload),
      summary: summarize(payload),
      secondsRemaining: typeof payload.exp === 'number' ? payload.exp - now : null,
    });
  } catch (error) {
    const status = error instanceof TokenError ? error.status : 500;
    const code = error instanceof TokenError ? error.code : 'server_error';
    if (status === 401 || status === 403) {
      res.set('WWW-Authenticate', `Bearer error="${code}", error_description="${error.message}"`);
    }
    res.status(status).json({
      validated: false,
      error: code,
      message: error.message,
      detail: error instanceof TokenError ? (error.detail ?? null) : null,
    });
  }
});

app.use(express.static(path.join(here, 'public'), { extensions: ['html'] }));

app.use((_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.listen(PORT, () => {
  console.log(`Token inspector listening on port ${PORT}`);
  if (!TENANT_ID || !API_CLIENT_ID || !SPA_CLIENT_ID) {
    console.warn(
      'Missing configuration. Set AZURE_TENANT_ID, API_CLIENT_ID and SPA_CLIENT_ID before signing in.',
    );
  }
});
