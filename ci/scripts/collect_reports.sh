#!/usr/bin/env bash
# Pulls module logs and HTML reports from the local OIDF conformance
# suite into the `reports/` directory so they can be uploaded as a CI
# artifact. Always exits 0 — collection is best-effort and must not
# mask the conformance plan's own pass/fail signal.
#
# Required env:
#   SUITE_BASE     - e.g. https://localhost:8443
#   SUITE_API_KEY  - bearer token accepted by the suite API

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORTS_DIR="${REPO_ROOT}/reports"
PLAN_ID_FILE="${REPORTS_DIR}/.last_plan_id"
mkdir -p "$REPORTS_DIR"

if [[ -z "${SUITE_BASE:-}" || -z "${SUITE_API_KEY:-}" ]]; then
  echo "[collect-reports] SUITE_BASE / SUITE_API_KEY not set; nothing to collect" >&2
  exit 0
fi

if [[ ! -f "$PLAN_ID_FILE" ]]; then
  echo "[collect-reports] no plan id recorded at ${PLAN_ID_FILE}; skipping" >&2
  exit 0
fi
PLAN_ID="$(cat "$PLAN_ID_FILE")"
if [[ -z "$PLAN_ID" ]]; then
  echo "[collect-reports] empty plan id; skipping" >&2
  exit 0
fi

auth_header=(-H "Authorization: Bearer ${SUITE_API_KEY}")
plan_dir="${REPORTS_DIR}/${PLAN_ID}"
mkdir -p "$plan_dir"

echo "[collect-reports] fetching plan ${PLAN_ID} metadata"
plan_meta="${plan_dir}/plan.json"
if ! curl --silent --show-error --insecure --fail \
  "${auth_header[@]}" \
  "${SUITE_BASE%/}/api/plan/${PLAN_ID}" -o "$plan_meta"; then
  echo "[collect-reports] failed to fetch plan metadata; aborting collection" >&2
  exit 0
fi

mapfile -t module_ids < <(jq -r '.modules[]?.moduleId // .modules[]?.id // empty' "$plan_meta")
if [[ ${#module_ids[@]} -eq 0 ]]; then
  echo "[collect-reports] plan ${PLAN_ID} has no modules; skipping per-module collection" >&2
  exit 0
fi

for module_id in "${module_ids[@]}"; do
  [[ -z "$module_id" ]] && continue
  echo "[collect-reports] module ${module_id}"
  curl --silent --show-error --insecure \
    "${auth_header[@]}" \
    "${SUITE_BASE%/}/api/info/${module_id}" \
    -o "${plan_dir}/${module_id}.info.json" || true
  curl --silent --show-error --insecure \
    "${auth_header[@]}" \
    "${SUITE_BASE%/}/api/log/exporthtml/${module_id}" \
    -o "${plan_dir}/${module_id}.log.html" || true
done

echo "[collect-reports] wrote ${#module_ids[@]} module bundles to ${plan_dir}"
exit 0
