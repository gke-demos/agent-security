#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context 2>/dev/null || echo 'local')}"
AEGIS_BASE_URL="${AEGIS_BASE_URL:-http://localhost:8080}"
SESSION_ID="${SESSION_ID:-stage-session}"
LIVE_MODE="false"

for arg in "$@"; do
  if [[ "$arg" == "--live" ]]; then
    LIVE_MODE="true"
  fi
done

if [[ "$LIVE_MODE" == "true" ]]; then
  if [[ -f .env.local ]]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env.local
    set +a
  fi
  GITHUB_TARGET_REPO="${GITHUB_TARGET_REPO:-gke-demos/aegis-checkout-target}"
  GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
  echo "==> Seeding live external resources (GITHUB_TARGET_REPO=${GITHUB_TARGET_REPO}, location=${GOOGLE_CLOUD_LOCATION})"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if ! gh repo view "${GITHUB_TARGET_REPO}" >/dev/null 2>&1; then
      echo "    - Creating companion repository ${GITHUB_TARGET_REPO}"
      gh repo create "${GITHUB_TARGET_REPO}" --public --description "AegisSRE Companion Checkout Service Target Repository" || true
    fi
    echo "    - Verified companion target repository ${GITHUB_TARGET_REPO} (checkout.go, checkout_test.go, SEC-101 / PUB-202 issues)"
  fi
  if [[ -n "${GOOGLE_CLOUD_PROJECT:-}" ]] && command -v gcloud >/dev/null 2>&1; then
    echo "    - Checking Model Armor template aegis-prompt-screen in ${GOOGLE_CLOUD_PROJECT} (${GOOGLE_CLOUD_LOCATION})"
    gcloud model-armor templates describe aegis-prompt-screen \
      --project="${GOOGLE_CLOUD_PROJECT}" \
      --location="${GOOGLE_CLOUD_LOCATION}" >/dev/null 2>&1 || \
    gcloud model-armor templates create aegis-prompt-screen \
      --project="${GOOGLE_CLOUD_PROJECT}" \
      --location="${GOOGLE_CLOUD_LOCATION}" \
      --pi-and-jailbreak-filter-settings-enforcement=ENABLED \
      --pi-and-jailbreak-filter-settings-confidence-level=LOW_AND_ABOVE >/dev/null 2>&1 || true
  fi
fi

echo "==> Seeding AegisSRE Red-vs-Blue Arena fixtures (context=${KUBE_CONTEXT}, endpoint=${AEGIS_BASE_URL}, session=${SESSION_ID})"
echo "    - Resetting Alice (SecOps Lead: SEC-101, GHSA-sec-101, Gmail) and Bob (External Contractor: PUB-202 only) 3LO vaults"
echo "    - Restoring ALL_BLUE_DEFENDED security posture across all 5 Security Shields"

for PERSONA in alice bob; do
  for PROVIDER in google_gmail atlassian_jira github gcp_iam; do
    curl -sS -X POST "${AEGIS_BASE_URL%/}/api/sessions/${SESSION_ID}/oauth/grant" \
      -H "Content-Type: application/json" \
      -d "{\"persona\":\"${PERSONA}\",\"provider\":\"${PROVIDER}\"}" >/dev/null
  done
done

curl -sS -X POST "${AEGIS_BASE_URL%/}/api/sessions/${SESSION_ID}/posture" \
  -H "Content-Type: application/json" \
  -d '{
    "persona": "alice",
    "posture": {
      "promptScreenEnabled": true,
      "piiRedactorEnabled": true,
      "tokenBrokerEnabled": true,
      "stepUpAndA2UICatalogEnabled": true,
      "sandboxEgressMitmEnabled": true
    }
  }' >/dev/null

echo "==> Seeded fixtures for SEC-101, PUB-202, GHSA-sec-101, and Gmail escalations."
