#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo 'your-gcp-project-id')}"
LOCATION="${LOCATION:-global}"
ENGINE_ID="${GEMINI_ENTERPRISE_ENGINE_ID:-default-enterprise-engine}"
AEGIS_PUBLIC_URL="${AEGIS_PUBLIC_URL:-https://aegis.example.com}"

AGENT_CARD_URL="${AEGIS_PUBLIC_URL%/}/.well-known/agent-card.json"
A2A_RPC_URL="${AEGIS_PUBLIC_URL%/}/a2a"

echo "==> Registering AegisSRE A2A v2 Agent with Gemini Enterprise (Discovery Engine)"
echo "    Agent Card URL : ${AGENT_CARD_URL}"
echo "    A2A Endpoint   : ${A2A_RPC_URL}"
echo "    Auth Scheme    : serverSideOauth2"

ACCESS_TOKEN="$(gcloud auth print-access-token)"

curl -sS -X POST \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_ID}/locations/${LOCATION}/collections/default_collection/engines/${ENGINE_ID}/assistants/default_assistant/agents" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  -d "{
    \"displayName\": \"AegisSRE Zero-Trust Triage Orchestrator\",
    \"description\": \"Zero-trust SRE incident triage and Agent Substrate v0.5.0 gVisor sandbox remediation platform on GKE.\",
    \"a2aAgentDefinition\": {
      \"agentCardUri\": \"${AGENT_CARD_URL}\",
      \"endpointUri\": \"${A2A_RPC_URL}\",
      \"authorizationConfig\": {
        \"scheme\": \"serverSideOauth2\"
      }
    }
  }"

echo ""
echo "==> Registration request complete."
