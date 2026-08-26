#!/usr/bin/env bash
#
# Creates the two app registrations this sample needs.
#
# This is a prerequisite, not an azd hook. It writes to the directory, so it
# needs a directory role (Application Administrator, Cloud Application
# Administrator or Global Administrator). azd up will not do it for you and
# should not: application objects outlive the resource group.
#
# Idempotent: re-running finds the existing apps by display name and patches
# them rather than creating duplicates.
#
# Requires: az CLI (logged in with `az login --allow-no-subscriptions`).

set -euo pipefail

API_APP_NAME="${API_APP_NAME:-token-inspector-api}"
SPA_APP_NAME="${SPA_APP_NAME:-token-inspector-spa}"
SCOPE_NAME="${SCOPE_NAME:-Inspect.Read}"
# Add the deployed URL with REDIRECT_URIS="http://localhost:3000/ https://app-xxxx.azurewebsites.net/"
REDIRECT_URIS="${REDIRECT_URIS:-http://localhost:3000/}"

command -v az >/dev/null || { echo "az CLI not found." >&2; exit 1; }

TENANT_ID="$(az account show --query tenantId -o tsv)"
GRAPH="https://graph.microsoft.com/v1.0"

new_guid() {
  if command -v uuidgen >/dev/null; then
    uuidgen | tr 'A-Z' 'a-z'
  else
    python3 -c 'import uuid; print(uuid.uuid4())'
  fi
}

# Prints "appId objectId" for an app with this display name, or nothing.
find_app() {
  az ad app list --display-name "$1" --query "[0].[appId,id]" -o tsv 2>/dev/null || true
}

ensure_app() {
  local name="$1"
  local existing
  existing="$(find_app "$name")"
  if [ -n "$existing" ]; then
    echo "$existing"
    return
  fi
  az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg \
    --query "[appId,id]" -o tsv
}

echo "Tenant: $TENANT_ID"

# ---------------------------------------------------------------------------
# 1. The API app. This is the RESOURCE. Everything interesting is registered
#    here, including the optional claims, because access tokens are always
#    generated from the resource manifest, never the client one.
# ---------------------------------------------------------------------------
read -r API_APP_ID API_OBJECT_ID <<<"$(ensure_app "$API_APP_NAME")"
echo "API app:  $API_APP_NAME  appId=$API_APP_ID objectId=$API_OBJECT_ID"

# ---------------------------------------------------------------------------
# 2. The SPA app. This is the CLIENT. It gets a redirect URI of type "spa",
#    which is what enables auth code with PKCE and the CORS token endpoint,
#    and which also caps its refresh token lifetime at 24 hours.
# ---------------------------------------------------------------------------
read -r SPA_APP_ID SPA_OBJECT_ID <<<"$(ensure_app "$SPA_APP_NAME")"
echo "SPA app:  $SPA_APP_NAME  appId=$SPA_APP_ID objectId=$SPA_OBJECT_ID"

# Reuse the existing scope ID if the scope is already there, so re-running does
# not invalidate consent that has already been granted.
SCOPE_ID="$(az ad app show --id "$API_APP_ID" \
  --query "api.oauth2PermissionScopes[?value=='${SCOPE_NAME}'].id | [0]" -o tsv 2>/dev/null || true)"
if [ -z "$SCOPE_ID" ] || [ "$SCOPE_ID" = "None" ]; then
  SCOPE_ID="$(new_guid)"
fi
echo "Scope:    $SCOPE_NAME  id=$SCOPE_ID"

IDENTIFIER_URI="api://${API_APP_ID}"

# This has to be TWO patches, not one, and the reason is worth knowing.
#
# Entra validates api.preAuthorizedApplications.delegatedPermissionIds against
# the scopes that already exist on the application, not against the scopes
# being created in the same request. Send both together on a new app and it
# fails with:
#
#   Property api.preAuthorizedApplications.delegatedPermissionIds has a
#   Permission Id that cannot be found in the AppPermissions sets.
#
# It is a race, not a schema error, which is why it sometimes succeeds on a
# second attempt and why the app looks fine afterwards.
#
# Patch 1 creates the scope and everything that does not depend on it:
#
#   requestedAccessTokenVersion 2  ask for v2.0 access tokens, where aud is the
#                                  client ID GUID rather than the App ID URI
#   api.oauth2PermissionScopes     expose Inspect.Read as a delegated scope
#   optionalClaims.accessToken     xms_cc and idtyp, on the RESOURCE, which is
#                                  the only place they can be registered
#
# xms_cc still only appears if the client also declares the cp1 capability.
# The SPA in src/public/app.js does that with clientCapabilities: ['cp1'].
SCOPE_JSON="$(cat <<JSON
{
  "id": "${SCOPE_ID}",
  "value": "${SCOPE_NAME}",
  "type": "User",
  "isEnabled": true,
  "adminConsentDisplayName": "Inspect your own token",
  "adminConsentDescription": "Allows the app to call the token inspector API on behalf of the signed-in user.",
  "userConsentDisplayName": "Inspect your own token",
  "userConsentDescription": "Allows the app to show you what is inside the token issued for you."
}
JSON
)"

API_BODY="$(cat <<JSON
{
  "identifierUris": ["${IDENTIFIER_URI}"],
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [${SCOPE_JSON}]
  },
  "optionalClaims": {
    "idToken": [],
    "saml2Token": [],
    "accessToken": [
      { "name": "xms_cc", "source": null, "essential": false, "additionalProperties": [] },
      { "name": "idtyp", "source": null, "essential": false, "additionalProperties": [] }
    ]
  }
}
JSON
)"

az rest --method PATCH \
  --uri "${GRAPH}/applications/${API_OBJECT_ID}" \
  --headers "Content-Type=application/json" \
  --body "$API_BODY" >/dev/null
echo "Patched API app (1 of 2): scope, v2 access tokens, optional claims xms_cc and idtyp."

# Wait for the scope to actually be readable before anything references it.
SCOPE_VISIBLE=""
for _ in $(seq 1 10); do
  SCOPE_VISIBLE="$(az ad app show --id "$API_APP_ID" \
    --query "api.oauth2PermissionScopes[?id=='${SCOPE_ID}'].id | [0]" -o tsv 2>/dev/null || true)"
  if [ -n "$SCOPE_VISIBLE" ] && [ "$SCOPE_VISIBLE" != "None" ]; then
    break
  fi
  sleep 2
done

if [ -z "$SCOPE_VISIBLE" ] || [ "$SCOPE_VISIBLE" = "None" ]; then
  echo "  Scope ${SCOPE_ID} is not readable yet after 20 seconds. Trying the pre-authorization anyway."
fi

# Patch 2 adds the pre-authorization. The full api object is sent, including
# the scope, because PATCH replaces a complex property rather than merging
# into it, and a body carrying only preAuthorizedApplications would drop the
# scope that was just created.
PREAUTH_BODY="$(cat <<JSON
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [${SCOPE_JSON}],
    "preAuthorizedApplications": [
      {
        "appId": "${SPA_APP_ID}",
        "delegatedPermissionIds": ["${SCOPE_ID}"]
      }
    ]
  }
}
JSON
)"

PREAUTH_DONE=0
for attempt in 1 2 3 4 5; do
  if az rest --method PATCH \
    --uri "${GRAPH}/applications/${API_OBJECT_ID}" \
    --headers "Content-Type=application/json" \
    --body "$PREAUTH_BODY" >/dev/null 2>&1; then
    PREAUTH_DONE=1
    break
  fi
  echo "  Pre-authorization attempt ${attempt} did not take. Waiting for directory replication."
  sleep $((attempt * 3))
done

if [ "$PREAUTH_DONE" -eq 1 ]; then
  echo "Patched API app (2 of 2): the SPA is pre-authorized for the scope."
else
  cat <<'WARN'

Pre-authorization did not take after five attempts. This is NOT fatal.
Everything else is registered and the sample works. The only difference is
that the first sign-in shows a consent prompt for the Inspect.Read scope
instead of skipping it. Re-run this script in a few minutes to clear it.

WARN
fi

# The SPA needs the redirect URIs under "spa" (not "web"), and a declared
# dependency on the API scope.
SPA_URI_JSON="$(printf '%s\n' $REDIRECT_URIS | awk 'BEGIN{ORS=""} {printf "%s\"%s\"", (NR>1 ? "," : ""), $0}')"
SPA_BODY="$(cat <<JSON
{
  "spa": { "redirectUris": [${SPA_URI_JSON}] },
  "web": { "redirectUris": [] },
  "requiredResourceAccess": [
    {
      "resourceAppId": "${API_APP_ID}",
      "resourceAccess": [ { "id": "${SCOPE_ID}", "type": "Scope" } ]
    }
  ]
}
JSON
)"

az rest --method PATCH \
  --uri "${GRAPH}/applications/${SPA_OBJECT_ID}" \
  --headers "Content-Type=application/json" \
  --body "$SPA_BODY" >/dev/null
echo "Patched SPA app: spa redirect URIs and the required resource access."

# Service principals, so the apps show up in the tenant enterprise apps list.
#
# "az ad sp show" on a service principal that does not exist is an error rather
# than an empty result, and an existence check that errors is a bad existence
# check. Ask a question with an empty answer instead.
#
# None of this is required. Entra creates the service principal on first
# sign-in anyway. It is done here so the apps show up in Enterprise
# applications before anyone has used them, which is why every failure below
# is a warning rather than an exit.
for appId in "$API_APP_ID" "$SPA_APP_ID"; do
  SP_ID="$(az ad sp list --filter "appId eq '${appId}'" --query "[0].id" -o tsv 2>/dev/null || true)"
  if [ -n "$SP_ID" ] && [ "$SP_ID" != "None" ]; then
    echo "  Service principal already exists for ${appId}."
    continue
  fi
  if az ad sp create --id "$appId" >/dev/null 2>&1; then
    echo "  Created the service principal for ${appId}."
  else
    echo "  Could not create the service principal for ${appId}. Not fatal, Entra creates it on first sign-in."
  fi
done

cat <<EOF

Done. Feed these into azd:

  azd env set AZURE_TENANT_ID ${TENANT_ID}
  azd env set API_CLIENT_ID   ${API_APP_ID}
  azd env set SPA_CLIENT_ID   ${SPA_APP_ID}
  azd env set REQUIRED_SCOPE  ${SCOPE_NAME}

Scope requested by the SPA: api://${API_APP_ID}/${SCOPE_NAME}
Redirect URIs currently registered as type spa: ${REDIRECT_URIS}

After 'azd up', add the deployed URL as a second redirect URI:

  REDIRECT_URIS="http://localhost:3000/ \$(azd env get-value AZURE_SPA_REDIRECT_URI)" ./scripts/register-apps.sh

Use AZURE_SPA_REDIRECT_URI rather than AZURE_WEB_URI. It already carries the
trailing slash the SPA sends, and a redirect URI has to match exactly.

EOF
