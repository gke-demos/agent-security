#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context)}"
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo 'your-gcp-project-id')}"
REGION="${REGION:-us-central1}"

echo "==> Deploying AegisSRE Zero-Trust Agent Security Stack to context: ${KUBE_CONTEXT} (project: ${PROJECT_ID}, region: ${REGION})"

kubectl --context "${KUBE_CONTEXT}" apply -f manifests/00-namespace-and-rbac.yaml
kubectl --context "${KUBE_CONTEXT}" apply -f manifests/01-agent-substrate-v050.yaml
kubectl --context "${KUBE_CONTEXT}" apply -f manifests/02-aegis-deployment.yaml

echo "==> Waiting for deployment/aegis-sre in namespace aegis-system..."
kubectl --context "${KUBE_CONTEXT}" -n aegis-system rollout status deployment/aegis-sre --timeout=120s
echo "==> AegisSRE deployed cleanly."
