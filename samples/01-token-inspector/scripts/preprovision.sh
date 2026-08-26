#!/usr/bin/env bash
# Preflight for azd up.
#
# The Bicep in this sample tolerates empty client IDs on purpose, so that
# "bicep build" and a what-if run never need real values. The cost of that is
# a deployment which succeeds and then serves an app that cannot validate a
# single token, because its audience is an empty string.
#
# This hook turns that silent failure into a loud one before anything is
# provisioned. Run scripts/register-apps.sh first, then feed the two client
# IDs into the azd environment as it tells you.

set -euo pipefail

missing=0

require() {
  local name="$1"
  local value="${!name:-}"
  if [ -z "$value" ]; then
    echo "  missing: $name"
    missing=1
  elif ! echo "$value" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
    echo "  not a GUID: $name=$value"
    missing=1
  fi
}

echo "Checking the app registrations this deployment depends on."
require API_CLIENT_ID
require SPA_CLIENT_ID

if [ "$missing" -ne 0 ]; then
  cat <<'EOF'

This sample needs two app registrations before it can deploy anything useful.
They are a separate step because creating them needs an administrator, and azd
does not have that scope.

  ./scripts/register-apps.sh
  azd env set API_CLIENT_ID <api-app-client-id>
  azd env set SPA_CLIENT_ID <spa-app-client-id>
  azd up

AZURE_TENANT_ID is optional. Left unset, the template uses the tenant azd is
signed in to.
EOF
  exit 1
fi

echo "  API_CLIENT_ID and SPA_CLIENT_ID look like GUIDs. Continuing."
