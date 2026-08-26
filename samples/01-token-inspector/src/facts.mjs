/**
 * The verified facts this sample exists to make concrete.
 *
 * Every entry cites the Microsoft Learn page it came from. If you change a
 * statement here, change the citation with it or delete both.
 */

export const TOKEN_FACTS = [
  {
    id: 'lifetime-random',
    topic: 'Access token lifetime',
    fact: 'The default access token lifetime is a random value between 60 and 90 minutes, averaging 75 minutes. The randomization is deliberate: it stops every client in the world refreshing on the hour and spiking traffic to Entra ID.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-tokens',
  },
  {
    id: 'lifetime-no-ca',
    topic: 'Access token lifetime',
    fact: 'Tenants that do not use Conditional Access get a 2 hour default lifetime for clients such as Teams and Microsoft 365. Adding Conditional Access changes the number under you.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-tokens',
  },
  {
    id: 'no-revocation',
    topic: 'Revocation',
    fact: 'Revoking sessions does not reach an access token already in a client memory. That call invalidates refresh tokens and browser session cookies. Microsoft guidance on removing a user access says that for applications using access tokens, the user loses access when the access token expires.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-tokens',
  },
  {
    id: 'cae-lifetime',
    topic: 'Continuous access evaluation',
    fact: 'In a CAE session the access token becomes long lived, 20 to 28 hours, because revocation now happens through a signal from the resource instead of through expiry. Configurable Token Lifetime policy is not honored for CAE-aware sessions.',
    source: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation',
  },
  {
    id: 'refresh-spa',
    topic: 'Refresh tokens',
    fact: 'Refresh tokens last 90 days by default, but only 24 hours when the redirect URI is registered as type "spa". This sample IS a spa registration, so the sign-in you are looking at survives a day at most before an interactive prompt.',
    source: 'https://learn.microsoft.com/entra/identity-platform/refresh-tokens',
  },
  {
    id: 'refresh-rotation',
    topic: 'Refresh tokens',
    fact: 'Refresh tokens rotate on every use. The one your client holds now is not the one it received at sign-in, and the previous one is spent.',
    source: 'https://learn.microsoft.com/entra/identity-platform/refresh-tokens',
  },
  {
    id: 'opaque-to-clients',
    topic: 'Who validates what',
    fact: 'Clients must treat access tokens as opaque strings and must not validate them. Only the resource server validates, and only tokens meant for itself. Validating a token issued for another resource is the confused deputy problem.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-tokens',
  },
  {
    id: 'graph-opaque',
    topic: 'Who validates what',
    fact: 'Microsoft Graph access tokens use a proprietary format and cannot be validated by these rules. Pasting one into jwt.ms is sanctioned for debugging only, never as a runtime behaviour.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-tokens',
  },
  {
    id: 'identity-key',
    topic: 'Authorization keys',
    fact: 'Never use email, preferred_username, unique_name or upn for an authorization decision. They are not unique and they are administrator controllable. Use tid plus oid as a composite key.',
    source: 'https://learn.microsoft.com/entra/identity-platform/claims-validation',
  },
  {
    id: 'idtyp-required',
    topic: 'Authorization keys',
    fact: 'To authorize an app-only caller by azp you must also validate that the idtyp optional claim equals "app". Without idtyp you cannot distinguish an app-only token from a user token that happens to come from that client.',
    source: 'https://learn.microsoft.com/entra/identity-platform/claims-validation',
  },
  {
    id: 'v1-v2-claims',
    topic: 'Token versions',
    fact: 'In v2.0, aud is the client ID of the API, where v1.0 used the App ID URI. v1.0 appid maps to v2.0 azp, and v1.0 appidacr maps to v2.0 azpacr with values 0 public client, 1 client secret, 2 certificate. acr and unique_name are v1.0 only.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference',
  },
  {
    id: 'internal-claims',
    topic: 'Token versions',
    fact: 'aio and rh are internal to Entra ID. Resources must not use them for anything.',
    source: 'https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference',
  },
  {
    id: 'optional-claims-resource',
    topic: 'Optional claims',
    fact: 'Optional claims are registered on the RESOURCE application object, not the client, because access tokens are always generated from the resource manifest. It is a PATCH to /applications/{objectId} with an optionalClaims object holding idToken, accessToken and saml2Token arrays of {name, source, essential, additionalProperties}.',
    source: 'https://learn.microsoft.com/entra/identity-platform/optional-claims',
  },
  {
    id: 'xms-cc-two-halves',
    topic: 'Claims challenges',
    fact: 'xms_cc is emitted only if the client declared the cp1 capability AND the resource registered xms_cc as an optional claim. Either half missing means no claim, and an API that assumes the client cannot handle a challenge.',
    source: 'https://learn.microsoft.com/entra/identity-platform/claims-challenge',
  },
];
