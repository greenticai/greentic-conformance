#!/usr/bin/env bash
# Drives a plan against the local OIDF conformance suite stack.
#
#   Usage: ci/scripts/run_conformance_plan.sh <plan-alias>
#
# <plan-alias> selects ci/plans/<alias>.config.json (or
# ci/plans/examples/<alias>.config.json as a fallback). The config JSON
# must include `oidf_plan_name` and `oidf_variant`.
#
# Required env:
#   SUITE_BASE      - e.g. https://localhost:8443
#   SUITE_API_KEY   - bearer token accepted by the suite API
#   RP_BASE_URL     - URL of the RP under test
#   ALIAS           - RP alias (defaults to greentic-rp)
#
# The script creates the plan, persists its id to reports/.last_plan_id,
# and shells out to ci/tools/run_rp_modules.py to drive each module.

set -euo pipefail

ALIAS_ARG="${1:?usage: $0 <plan-alias|config-path>}"
SUITE_BASE="${SUITE_BASE:?missing SUITE_BASE}"
SUITE_API_KEY="${SUITE_API_KEY:?missing SUITE_API_KEY}"
RP_BASE_URL="${RP_BASE_URL:?missing RP_BASE_URL}"
ALIAS="${ALIAS:-greentic-rp}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "${REPO_ROOT}/reports"
PLAN_ID_FILE="${REPO_ROOT}/reports/.last_plan_id"

# Resolve the config JSON. The argument can be either a file path
# (relative or absolute) or a short alias that maps to
# ci/plans/<alias>.config.json or ci/plans/examples/<alias>.config.json.
CONFIG_PATH=""
if [[ "$ALIAS_ARG" == *.json && -f "$ALIAS_ARG" ]]; then
  CONFIG_PATH="$ALIAS_ARG"
else
  for candidate in \
    "${REPO_ROOT}/ci/plans/${ALIAS_ARG}.config.json" \
    "${REPO_ROOT}/ci/plans/examples/${ALIAS_ARG}.config.json"; do
    if [[ -f "$candidate" ]]; then
      CONFIG_PATH="$candidate"
      break
    fi
  done
fi
if [[ -z "$CONFIG_PATH" ]]; then
  echo "[run-plan] no config found for '${ALIAS_ARG}'" >&2
  exit 2
fi
echo "[run-plan] using config ${CONFIG_PATH}"

PLAN_NAME="$(jq -r '.oidf_plan_name // empty' "$CONFIG_PATH")"
if [[ -z "$PLAN_NAME" ]]; then
  echo "[run-plan] config ${CONFIG_PATH} is missing 'oidf_plan_name'" >&2
  exit 2
fi
VARIANT_JSON="$(jq -c '.oidf_variant // {}' "$CONFIG_PATH")"

# The local suite relies on a self-signed cert; --insecure is fine for CI.
auth_header=(-H "Authorization: Bearer ${SUITE_API_KEY}")

# Patch the redirect URI to match the RP under test before sending.
TMP_CFG="$(mktemp -t rp_cfg_XXXX.json)"
trap 'rm -f "$TMP_CFG"' EXIT
jq --arg rp "$RP_BASE_URL" --arg alias "$ALIAS" \
  '.client.redirect_uri = ($rp + "/_conformance/callback")
   | .alias = $alias
   | .rp_trigger_url = ($rp + "/_conformance/start-login")' \
  "$CONFIG_PATH" > "$TMP_CFG"

create_plan() {
  local url="${SUITE_BASE%/}/api/plan?planName=${PLAN_NAME}&variant=$(jq -rR @uri <<<"$VARIANT_JSON")"
  curl --silent --show-error --insecure --fail \
    "${auth_header[@]}" \
    -H 'Content-Type: application/json' \
    -X POST \
    --data-binary @"$TMP_CFG" \
    "$url"
}

echo "[run-plan] creating plan '${PLAN_NAME}' on ${SUITE_BASE}"
plan_response="$(create_plan)" || {
  echo "[run-plan] plan creation failed" >&2
  exit 1
}

PLAN_ID="$(jq -r '.id // empty' <<<"$plan_response")"
if [[ -z "$PLAN_ID" ]]; then
  echo "[run-plan] suite did not return a plan id; raw response:" >&2
  echo "$plan_response" >&2
  exit 1
fi
echo "$PLAN_ID" > "$PLAN_ID_FILE"
echo "[run-plan] created plan ${PLAN_ID} (recorded in ${PLAN_ID_FILE})"

# Drive modules via the python helper. It honours fail-fast and returns
# a non-zero exit on any module failure.
export CONFORMANCE_ALLOWED_HOSTS="localhost,127.0.0.1,$(echo "$RP_BASE_URL" | awk -F/ '{print $3}' | cut -d: -f1)"
python3 "${REPO_ROOT}/ci/tools/run_rp_modules.py" \
  --server "$SUITE_BASE" \
  --token "$SUITE_API_KEY" \
  --alias "$ALIAS" \
  --trigger "${RP_BASE_URL}/_conformance/start-login" \
  --plan-id "$PLAN_ID" \
  --fail-fast
