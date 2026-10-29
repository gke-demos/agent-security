#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context 2>/dev/null || echo 'default')}"
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo 'your-gcp-project-id')}"
PROJECT_NUMBER="${PROJECT_NUMBER:-$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null || echo '000000000000')}"
if [[ -z "${PROJECT_NUMBER}" ]]; then
  PROJECT_NUMBER="000000000000"
fi

ORG_ID="${ORG_ID:-$(gcloud projects get-ancestors "${PROJECT_ID}" --format='value(id,type)' 2>/dev/null | awk '$2 == "organization" {print $1; exit}' || true)}"
if [[ -z "${ORG_ID}" ]]; then
  ORG_ID="000000000000"
fi

DEFAULT_CLUSTER_LOCATION="us-central1-a"
DEFAULT_CLUSTER_NAME="aegis-gke-cluster"
if [[ "${KUBE_CONTEXT}" == gke_*_*_* ]]; then
  IFS='_' read -r _ _ ctx_loc ctx_cluster <<< "${KUBE_CONTEXT}"
  if [[ -n "${ctx_loc:-}" ]]; then
    DEFAULT_CLUSTER_LOCATION="${ctx_loc}"
  fi
  if [[ -n "${ctx_cluster:-}" ]]; then
    DEFAULT_CLUSTER_NAME="${ctx_cluster}"
  fi
fi

CLUSTER_LOCATION="${CLUSTER_LOCATION:-${DEFAULT_CLUSTER_LOCATION}}"
CLUSTER_NAME="${CLUSTER_NAME:-${DEFAULT_CLUSTER_NAME}}"
REGION="${REGION:-us-central1}"

render_manifest() {
  local file="$1"
  sed \
    -e "s|\${PROJECT_ID}|${PROJECT_ID}|g" \
    -e "s|PROJECT_ID|${PROJECT_ID}|g" \
    -e "s|\${PROJECT_NUMBER}|${PROJECT_NUMBER}|g" \
    -e "s|\${ORG_ID}|${ORG_ID}|g" \
    -e "s|\${CLUSTER_NAME}|${CLUSTER_NAME}|g" \
    -e "s|\${CLUSTER_LOCATION}|${CLUSTER_LOCATION}|g" \
    -e "s|\${REGION}|${REGION}|g" \
    "${file}"
}

echo "==> Deploying AegisSRE Zero-Trust Agent Security Stack to context: ${KUBE_CONTEXT} (project: ${PROJECT_ID}, cluster: ${CLUSTER_NAME}, location: ${CLUSTER_LOCATION}, region: ${REGION})"

render_manifest manifests/00-namespace-and-rbac.yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -
render_manifest manifests/01-agent-substrate-v050.yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -
render_manifest manifests/02-aegis-deployment.yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -
render_manifest manifests/03-gke-diy-agent-gateway.yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -

echo "==> Waiting for deployment/aegis-sre in namespace aegis-system..."
kubectl --context "${KUBE_CONTEXT}" -n aegis-system rollout status deployment/aegis-sre --timeout=120s
echo "==> AegisSRE deployed cleanly."
