#!/usr/bin/env bash
# Stand up kind + Enterprise agentgateway + Prisma AIRS adapter (+ mock AIRS).
set -euo pipefail
cd "$(dirname "$0")"
CLUSTER=airs-poc CTX=kind-airs-poc
AGW_VERSION="${AGW_VERSION:-v2026.9.1}"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY}"
AIRS_API_KEY="${AIRS_API_KEY:-mock-token}"
k(){ kubectl --context "$CTX" "$@"; }
: "${AGENTGATEWAY_LICENSE_KEY:?set AGENTGATEWAY_LICENSE_KEY (Solo Enterprise for agentgateway license)}"

kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"
k apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml >/dev/null
k delete validatingadmissionpolicybinding safe-upgrades.gateway.networking.k8s.io 2>/dev/null || true
k delete validatingadmissionpolicy safe-upgrades.gateway.networking.k8s.io 2>/dev/null || true

helm --kube-context "$CTX" upgrade -i enterprise-agentgateway-crds \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway-crds \
  -n agentgateway-system --create-namespace --version "$AGW_VERSION"
helm --kube-context "$CTX" upgrade -i enterprise-agentgateway \
  oci://us-docker.pkg.dev/solo-public/enterprise-agentgateway/charts/enterprise-agentgateway \
  -n agentgateway-system --version "$AGW_VERSION" \
  --set-string "licensing.licenseKey=${AGENTGATEWAY_LICENSE_KEY}" --wait

k create secret generic anthropic-secret -n agentgateway-system \
  --from-literal=Authorization="$ANTHROPIC_API_KEY" --dry-run=client -o yaml | k apply -f -
k create ns prisma-airs --dry-run=client -o yaml | k apply -f -
k create secret generic airs-api-key -n prisma-airs --from-literal=token="$AIRS_API_KEY" --dry-run=client -o yaml | k apply -f -
k create configmap airs-code -n prisma-airs --from-file=airs-adapter.py --from-file=mock-airs.py --dry-run=client -o yaml | k apply -f -

k apply -f manifests/airs.yaml -f manifests/gateway.yaml
k rollout restart deploy -n prisma-airs >/dev/null
k rollout status deploy/mock-airs deploy/airs-adapter -n prisma-airs --timeout=180s
k wait --for=condition=Programmed gateway/agentgateway-proxy -n agentgateway-system --timeout=180s
k rollout status deploy/agentgateway-proxy -n agentgateway-system --timeout=180s
k apply -f manifests/airs-policy.yaml
echo "Up. Run ./test.sh"
