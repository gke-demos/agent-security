#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context 2>/dev/null || echo 'local')}"
AEGIS_BASE_URL="${AEGIS_BASE_URL:-http://localhost:8080}"
SESSION_ID="${SESSION_ID:-stage-session}"

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
