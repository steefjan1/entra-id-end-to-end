/**
 * Claim annotation catalogue.
 *
 * Every claim the Microsoft identity platform can put in a v2.0 access token
 * or ID token, with a one line explanation of what it is actually for, and a
 * verdict on whether a resource server is allowed to make decisions with it.
 *
 * Verdict values:
 *   'authz'     safe to use in an authorization decision
 *   'display'   safe to show a human, never safe to authorize with
 *   'internal'  Microsoft internal, the resource must not use it at all
 *   'protocol'  part of token validation itself
 *   'context'   useful signal, only meaningful together with something else
 *
 * Sources:
 *   https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 *   https://learn.microsoft.com/entra/identity-platform/id-token-claims-reference
 *   https://learn.microsoft.com/entra/identity-platform/claims-validation
 */

const CATALOGUE = {
  // Protocol and validation
  aud: {
    verdict: 'protocol',
    what: 'Who the token is for. In a v2.0 token this is the client ID (GUID) of the API. In a v1.0 token it was the App ID URI. If this is not your client ID, stop: the token is not yours to read.',
    whatInIdToken:
      'Who the token is for. On an ID token that is the CLIENT that signed the user in, not the API. Same claim name, different party, which is exactly why an ID token must never be sent to an API as a bearer token.',
  },
  iss: {
    verdict: 'protocol',
    what: 'Who minted the token. Must be https://login.microsoftonline.com/{tid}/v2.0 for a v2.0 token, and the {tid} inside it must match the tid claim.',
  },
  idp: {
    verdict: 'context',
    what:
      'The identity provider that actually authenticated the user, present only when it differs from the issuer. Its presence means the caller is external to this tenant: a guest, a federated identity, or a personal Microsoft account. ' +
      'The value 9188040d-6c67-4c5b-b112-36a304b66dad is the well known personal Microsoft account tenant. ' +
      'This matters more than it looks: continuous access evaluation does not support B2B or guest accounts, and revokeSignInSessions does nothing for them, because they sign in through their home tenant.',
  },
  exp: {
    verdict: 'protocol',
    what: 'Expiry, seconds since epoch. Nothing can revoke an access token before this moment. The client waits it out and refreshes.',
    whatInIdToken:
      'Expiry, seconds since epoch. On an ID token this bounds how long the sign-in receipt may be trusted. It says nothing about how long the access token lives, and nothing about whether the session is still valid.',
  },
  nbf: {
    verdict: 'protocol',
    what: 'Not valid before. Reject the token if the current time is earlier than this, allowing a small clock skew.',
  },
  iat: {
    verdict: 'protocol',
    what: 'Issued at. Subtract it from exp to see the lifetime this token was actually granted, which is not a fixed number.',
  },
  ver: {
    verdict: 'protocol',
    what: 'Token version, 1.0 or 2.0. It decides which claim names you get: appid or azp, appidacr or azpacr, unique_name or preferred_username.',
  },
  uti: {
    verdict: 'context',
    what: 'Token identifier used for correlation. Quote it in a support case. Do not treat it as a session ID.',
  },
  jti: {
    verdict: 'protocol',
    what: 'JWT ID. Unique per token, usable as a replay cache key on an ID token.',
  },

  // Identity
  tid: {
    verdict: 'authz',
    what: 'Tenant the identity lives in. Half of the only safe identity key. On its own it says nothing about who is calling.',
  },
  oid: {
    verdict: 'authz',
    what: 'Immutable object ID of the user or service principal inside that tenant. The other half of the safe key. Never reused, never renamed.',
  },
  sub: {
    verdict: 'authz',
    what: 'Pairwise subject: stable for this user in this application only. Good as a local primary key, useless for correlating across applications.',
  },
  idtyp: {
    verdict: 'authz',
    what: 'Optional claim. Value "app" means an app-only token with no user behind it. This is the claim that makes azp based authorization safe, and it must be registered on the resource app to appear.',
  },

  // Display only, never authorization
  name: {
    verdict: 'display',
    what: 'Human readable display name. Mutable, not unique, chosen by an administrator. Print it, do not branch on it.',
  },
  preferred_username: {
    verdict: 'display',
    what: 'The primary username. Mutable and reassignable to a different person. Never use it as an authorization key.',
  },
  email: {
    verdict: 'display',
    what: 'Addressable mail. Not guaranteed present, not verified by default for external identities, not unique over time.',
  },
  upn: {
    verdict: 'display',
    what: 'User principal name. Administrator controllable and reassignable. Same warning as email and preferred_username.',
  },
  unique_name: {
    verdict: 'display',
    what: 'v1.0 only, and unguaranteed. Present in v1.0 tokens for guests and some flows. Never an authorization key.',
  },
  ipaddr: {
    verdict: 'context',
    what: 'The public IP the user authenticated from. A network signal, not an identity, and wrong behind most proxies.',
  },

  // Authorization surface
  scp: {
    verdict: 'authz',
    what: 'Delegated permissions, space separated. Present means a user is present and the app is acting on that user behalf. Both the user and the app must be allowed to do the thing.',
  },
  roles: {
    verdict: 'authz',
    what: 'App roles. In an app-only token these are application permissions with no user behind them. In a user token they are role assignments made on the enterprise application.',
  },
  groups: {
    verdict: 'authz',
    what: 'Group object IDs, only when the resource app opts in. Overflows to a Graph link past the token size limit, so code that reads it must handle the overflow.',
  },
  wids: {
    verdict: 'authz',
    what: 'Tenant wide role template IDs, for example Global Administrator. Directory roles, not application roles.',
  },
  azp: {
    verdict: 'context',
    what: 'The client application that requested this token (v1.0 called it appid). Authorizing on azp alone is unsafe: pair it with idtyp equal to "app".',
  },
  azpacr: {
    verdict: 'context',
    what: 'How that client authenticated (v1.0 called it appidacr). 0 public client, 1 client secret, 2 certificate. A resource can insist on 2.',
  },
  appid: {
    verdict: 'context',
    what: 'v1.0 spelling of azp. Same claim, older token version.',
  },
  appidacr: {
    verdict: 'context',
    what: 'v1.0 spelling of azpacr. Values 0, 1 and 2 mean the same thing.',
  },

  // Authentication strength and session context
  amr: {
    verdict: 'context',
    what: 'How the user proved who they are: pwd, mfa, rsa, otp, fido, wia, ngcmfa. Present in ID tokens and in access tokens on request. It describes the sign-in, not the current moment.',
  },
  acr: {
    verdict: 'context',
    what: 'v1.0 only authentication context class. 0 means the sign-in did not meet ISO/IEC 29115. Replaced in practice by amr and acrs.',
  },
  acrs: {
    verdict: 'context',
    what: 'Authentication context class references that this session already satisfies. The claim behind Conditional Access authentication context: if the value your operation needs is missing, you raise a claims challenge instead of returning 403.',
  },
  xms_cc: {
    verdict: 'context',
    what: 'Client capabilities. Contains cp1 only if the client declared it AND the resource registered xms_cc as an optional claim. It tells the API that this client can handle a claims challenge, so the API may issue one.',
  },
  auth_time: {
    verdict: 'context',
    what: 'When the user last actually authenticated. Compare it against your own freshness requirement rather than trusting token age.',
  },
  sid: {
    verdict: 'context',
    what: 'Session ID, used for front channel sign-out.',
  },
  nonce: {
    verdict: 'protocol',
    what: 'Replay protection for the ID token. The library that requested the token checks it. Your API never should.',
  },
  at_hash: {
    verdict: 'protocol',
    what: 'Hash of the access token that came with this ID token. Checked by the client library.',
  },
  c_hash: {
    verdict: 'protocol',
    what: 'Hash of the authorization code that produced this ID token. Checked by the client library.',
  },
  tenant_region_scope: {
    verdict: 'internal',
    what: 'Region hint for the tenant. Not documented as a stable contract. Do not branch on it.',
  },
  tenant_ctry: {
    verdict: 'internal',
    what: 'Tenant country. Directory metadata, not an authorization input.',
  },

  // Internal, hands off
  aio: {
    verdict: 'internal',
    what: 'Opaque internal value used by Entra ID to re-mint tokens. Microsoft documents it as internal. Resources must not use it, log it or parse it.',
  },
  rh: {
    verdict: 'internal',
    what: 'Opaque internal value. Same rule as aio: not for you.',
  },
  xms_st: {
    verdict: 'internal',
    what: 'Internal subject type detail. Not a documented contract for resources.',
  },
  xms_tcdt: {
    verdict: 'internal',
    what: 'Tenant creation date, internal. Not an authorization input.',
  },
};

const VERDICT_LABEL = {
  authz: 'Safe for authorization',
  display: 'Display only, never authorization',
  internal: 'Internal to Entra ID, do not use',
  protocol: 'Token validation',
  context: 'Signal, only meaningful with context',
};

const NEVER_AUTHORIZE_ON = ['email', 'preferred_username', 'unique_name', 'upn', 'name'];

/**
 * Turn a decoded payload into a sorted, annotated list of rows.
 */
export function annotateClaims(payload) {
  return Object.keys(payload)
    .sort()
    .map((name) => {
      const entry = CATALOGUE[name];
      return {
        name,
        value: payload[name],
        verdict: entry ? entry.verdict : 'context',
        verdictLabel: entry ? VERDICT_LABEL[entry.verdict] : 'Not in this catalogue',
        what: entry
          ? entry.what
          : 'Not in this sample catalogue. Check the access token claims reference before you rely on it, and assume it is optional until you have proved otherwise.',
        known: Boolean(entry),
      };
    });
}

/**
 * The handful of derived answers that people actually came for.
 */
export function summarize(payload) {
  const scopes = typeof payload.scp === 'string' ? payload.scp.split(' ').filter(Boolean) : [];
  const roles = Array.isArray(payload.roles) ? payload.roles : [];
  const hasUser = scopes.length > 0;
  const appOnly = !hasUser && roles.length > 0;

  const issuedAt = typeof payload.iat === 'number' ? payload.iat : null;
  const expiresAt = typeof payload.exp === 'number' ? payload.exp : null;
  const lifetimeMinutes =
    issuedAt !== null && expiresAt !== null ? Math.round((expiresAt - issuedAt) / 60) : null;

  const present = (claim) => Object.prototype.hasOwnProperty.call(payload, claim);

  return {
    identityKey: {
      claim: 'tid + oid',
      value: payload.tid && payload.oid ? `${payload.tid}/${payload.oid}` : null,
      ok: Boolean(payload.tid && payload.oid),
      note: 'The only composite key that is unique, immutable and not administrator editable. Store this, join on this, log this.',
    },
    callerType: {
      value: appOnly ? 'app-only' : hasUser ? 'delegated' : 'unknown',
      scp: scopes,
      roles,
      note: appOnly
        ? 'No user is present. roles carries application permissions. Do not apply user consent logic or per user filtering: there is nobody to filter for.'
        : hasUser
          ? 'A user is present and the client acts on their behalf. Authorize on the intersection of what the user may do and what scp allows.'
          : 'Neither scp nor roles is present. This token grants nothing to this API. Reject it.',
    },
    appOnlyAuthorization: {
      azp: payload.azp ?? payload.appid ?? null,
      azpacr: payload.azpacr ?? payload.appidacr ?? null,
      idtyp: payload.idtyp ?? null,
      safe: payload.idtyp === 'app',
      note:
        payload.idtyp === 'app'
          ? 'idtyp is "app", so azp identifies a caller with no user behind it and can be used as an authorization key.'
          : present('idtyp')
            ? 'idtyp is present and is not "app", so this is a user token. Authorize on tid plus oid, not on azp.'
            : 'idtyp is absent. Register it as an optional claim on THIS API before authorizing anything on azp: without it you cannot tell an app-only caller from a user token.',
    },
    authenticationMethods: {
      value: Array.isArray(payload.amr) ? payload.amr : null,
      note: 'How the user authenticated at sign-in time. It is a statement about the past, not a guarantee about now.',
    },
    authenticationContext: {
      value: Array.isArray(payload.acrs) ? payload.acrs : null,
      note: 'Conditional Access authentication context already satisfied by this session. Missing value plus a sensitive operation equals a claims challenge, not a 403.',
    },
    clientCapabilities: {
      value: Array.isArray(payload.xms_cc) ? payload.xms_cc : null,
      canHandleClaimsChallenge: Array.isArray(payload.xms_cc) && payload.xms_cc.includes('cp1'),
      note: 'Emitted only when the client declared cp1 AND this API registered xms_cc as an optional claim. Both halves are required, which is why it is usually missing.',
    },
    internalClaims: {
      value: ['aio', 'rh', 'xms_st', 'xms_tcdt'].filter(present),
      note: 'Present in the token, off limits to this resource. Do not persist them, do not log them, do not branch on them.',
    },
    neverAuthorizeOn: {
      value: NEVER_AUTHORIZE_ON.filter(present),
      note: 'These are mutable, reassignable and administrator controllable. They belong in a UI label and nowhere else.',
    },
    lifetime: {
      issuedAt,
      expiresAt,
      lifetimeMinutes,
      note: 'Entra ID randomizes the default access token lifetime between 60 and 90 minutes (75 minute average) so that token refreshes do not all land on the hour. Reload this page in an hour and you will see a different number.',
    },
    version: {
      value: payload.ver ?? null,
      note: 'This sample validates v2.0 tokens only. In v2.0, aud is the API client ID GUID, appid became azp and appidacr became azpacr.',
    },
  };
}

export const claimCatalogue = CATALOGUE;
