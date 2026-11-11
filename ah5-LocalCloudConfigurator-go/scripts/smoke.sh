#!/bin/sh
# Smoke test of LocalCloudConfigurator against the GoCloud through ColonyOS:
#  1. API health and operator-token check
#  2. status round trip through the cloud executor
#  3. stop and re-populate an application system (TestTranslation by default) through a ColonyOS workflow
#  4. the cloud's own smoke test as a workflow step
set -eu
cd "$(dirname -- "$0")/.."
URL=${LCC_URL:-http://127.0.0.1:8095}
TOKEN_FILE=${TOKEN_FILE:-deploy/colonyos/secrets/lcc_api_token}
SYSTEM=${SMOKE_SYSTEM:-test-translation}
BIN=./bin/LocalCloudConfigurator
auth="Authorization: Bearer $(cat "$TOKEN_FILE")"

curl -fsS "$URL/healthz" >/dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' "$URL/api/catalog")
[ "$code" = 401 ] || { echo "FAIL: API answered $code without a token" >&2; exit 1; }
echo "ok: API up, token required"

state() { curl -fsS -H "$auth" "$URL/api/status" | jq -r --arg s "$1" '.systems[] | select(.id == $s) | .state'; }
before=$(state "$SYSTEM")
echo "ok: status through ColonyOS executor ($SYSTEM: $before)"

if [ "$before" = running ]; then
  $BIN apply -url "$URL" -token-file "$TOKEN_FILE" -remove "$SYSTEM"
  [ "$(state "$SYSTEM")" = stopped ] || { echo "FAIL: $SYSTEM still running after removal" >&2; exit 1; }
  echo "ok: $SYSTEM stopped through ColonyOS"
fi
$BIN apply -url "$URL" -token-file "$TOKEN_FILE" -systems "$SYSTEM" -smoke
[ "$(state "$SYSTEM")" = running ] || { echo "FAIL: $SYSTEM not running after deployment" >&2; exit 1; }
echo "ok: $SYSTEM populated through ColonyOS; cloud smoke test passed"
echo "SMOKE PASSED"
