#!/usr/bin/env bash
# Install Higress with low resources and NodePorts for the local IDC cluster.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$REPO_ROOT/artifacts/higress}"
KUBECTL="${KUBECTL:-kubectl}"
HELM="${HELM:-helm}"
VERSION="${HIGRESS_VERSION:-2.2.4}"
RELEASE="${HIGRESS_RELEASE:-higress}"
NAMESPACE="${HIGRESS_NAMESPACE:-higress-system}"
HOSTNAME="${HIGRESS_HOST:-open-card.local}"
REPO_NAME="${HIGRESS_HELM_REPO_NAME:-higress.io}"
REPO_URL="${HIGRESS_HELM_REPO_URL:-https://higress.io/helm-charts}"
VALUES_FILE="$REPO_ROOT/components/higress/values.yaml"
INGRESS_FILE="$REPO_ROOT/components/higress/ingress.yaml"

mkdir -p "$ARTIFACT_DIR"
tmpdir=""

cleanup() {
  if [[ -n $tmpdir && -d $tmpdir ]]; then
    rm -rf -- "$tmpdir"
  fi
}
capture_failure() {
  local exit_code=$?
  set +e
  "$KUBECTL" get deployment,pods,svc -n "$NAMESPACE" -o wide \
    >"$ARTIFACT_DIR/workloads-on-failure.txt" 2>&1
  "$KUBECTL" get ingressclass higress -o yaml \
    >"$ARTIFACT_DIR/ingressclass-on-failure.yaml" 2>&1
  "$KUBECTL" get ingress -n open-card-demo -o yaml \
    >"$ARTIFACT_DIR/ingress-on-failure.yaml" 2>&1
  "$KUBECTL" get events -A --sort-by=.lastTimestamp \
    >"$ARTIFACT_DIR/events-on-failure.txt" 2>&1
  cleanup
  exit "$exit_code"
}
trap capture_failure ERR
trap cleanup EXIT

for command_name in "$KUBECTL" "$HELM" openssl sed; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done

"$KUBECTL" cluster-info >"$ARTIFACT_DIR/cluster-info.txt"
"$HELM" repo add "$REPO_NAME" "$REPO_URL" --force-update \
  >"$ARTIFACT_DIR/helm-repo-add.txt"
"$HELM" repo update "$REPO_NAME" >"$ARTIFACT_DIR/helm-repo-update.txt"
printf 'chart=higress\nrelease=%s\nversion=%s\nrepo=%s\nnamespace=%s\nhost=%s\n' \
  "$RELEASE" "$VERSION" "$REPO_URL" "$NAMESPACE" "$HOSTNAME" \
  >"$ARTIFACT_DIR/version.txt"

"$HELM" upgrade --install "$RELEASE" "$REPO_NAME/higress" \
  --version "$VERSION" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --reset-values \
  --values "$VALUES_FILE" \
  --wait --timeout="${HIGRESS_HELM_TIMEOUT:-600s}" \
  >"$ARTIFACT_DIR/helm-upgrade.txt"

# Wait only for release workloads with a positive replica count. The console is
# intentionally scaled to zero in this PoC and should not block installation.
deployments="$("$KUBECTL" get deployment -n "$NAMESPACE" -o name)"
[[ -n $deployments ]] || {
  printf 'Higress release created no Deployments\n' >&2
  exit 1
}
while IFS= read -r deployment; do
  [[ -n $deployment ]] || continue
  replicas="$("$KUBECTL" get "$deployment" -n "$NAMESPACE" \
    -o jsonpath='{.spec.replicas}')"
  if [[ $replicas =~ ^[1-9][0-9]*$ ]]; then
    "$KUBECTL" rollout status "$deployment" -n "$NAMESPACE" \
      --timeout="${HIGRESS_ROLLOUT_TIMEOUT:-300s}" \
      >>"$ARTIFACT_DIR/rollouts.txt"
  fi
done <<<"$deployments"

for required_deployment in higress-controller higress-gateway; do
  "$KUBECTL" get deployment "$required_deployment" -n "$NAMESPACE" \
    >/dev/null
done

"$KUBECTL" get deployment higress-controller -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/controller.yaml"
"$KUBECTL" get deployment higress-gateway -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/gateway.yaml"
"$KUBECTL" get service higress-gateway -n "$NAMESPACE" -o yaml \
  >"$ARTIFACT_DIR/gateway-service.yaml"

# Keep the certificate in a private temporary directory only. The generated
# Secret is applied to Kubernetes, but neither key nor certificate is committed
# or retained in artifacts.
tmpdir="$(mktemp -d)"
rendered_ingress="$tmpdir/ingress.yaml"
sed "s|open-card.local|$HOSTNAME|g" "$INGRESS_FILE" >"$rendered_ingress"
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "$tmpdir/tls.key" \
  -out "$tmpdir/tls.crt" \
  -subj "/CN=$HOSTNAME" \
  -addext "subjectAltName=DNS:$HOSTNAME" \
  >"$ARTIFACT_DIR/certificate-generation.txt" 2>&1

"$KUBECTL" create namespace open-card-demo --dry-run=client -o yaml \
  | "$KUBECTL" apply -f - >"$ARTIFACT_DIR/demo-namespace-apply.txt"
"$KUBECTL" -n open-card-demo create secret tls open-card-demo-tls \
  --cert="$tmpdir/tls.crt" \
  --key="$tmpdir/tls.key" \
  --dry-run=client -o yaml \
  | "$KUBECTL" apply -f - >"$ARTIFACT_DIR/tls-secret-apply.txt"
"$KUBECTL" apply -f "$rendered_ingress" >"$ARTIFACT_DIR/ingress-apply.txt"

"$KUBECTL" get ingressclass higress -o yaml >"$ARTIFACT_DIR/ingressclass.yaml"
"$KUBECTL" get ingress -n open-card-demo -o yaml >"$ARTIFACT_DIR/ingress.yaml"
"$KUBECTL" get deployment,pods,svc -n "$NAMESPACE" -o wide \
  >"$ARTIFACT_DIR/workloads.txt"
"$KUBECTL" get events -A --sort-by=.lastTimestamp \
  >"$ARTIFACT_DIR/events.txt"

printf 'Higress %s ready; gateway replicas=1; HTTP NodePort=30080 HTTPS NodePort=30443 Host=%s\n' \
  "$VERSION" "$HOSTNAME"
