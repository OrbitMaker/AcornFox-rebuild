#!/usr/bin/env bash
set -euo pipefail

# Build the M7 0.7.0-rc.1 canonical source contract. This is a local,
# credentials-free build step: all Debian and runtime assets are explicit
# checksum-covered inputs, and no VM, service, registry, or network operation
# is performed.

version='0.7.0-rc.1'
n_minus_one='0.6.0'
repo_root=
output_root=
debs_root=
assets_root=

usage() {
  cat <<'USAGE'
Usage:
  build-m7-canonical-source.sh \
    --repo-root /absolute/Open-Card \
    --output-root /absolute/.../open-card-m7-canonical-source \
    --debs-root /absolute/verified-debs \
    --assets-root /absolute/verified-assets

The asset root must contain amd64/ and arm64/ fixed inputs plus assets.sha256;
each architecture uses the names buildkit.tar.gz, rootlesskit.tar.gz,
docker-buildx, caddy.tar.gz, and ubuntu-24.04-server-cloudimg.img.
The Debian root must contain packages.txt, debs.sha256, and debs/*.deb.
No argument permits downloading, provisioning, or overwriting an output.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) repo_root=${2:-}; shift 2 ;;
    --output-root) output_root=${2:-}; shift 2 ;;
    --debs-root) debs_root=${2:-}; shift 2 ;;
    --assets-root) assets_root=${2:-}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
done

for value in "$repo_root" "$output_root" "$debs_root" "$assets_root"; do
  [[ "$value" = /* ]] || { echo 'all paths must be absolute' >&2; exit 64; }
done
[[ -d "$repo_root" && ! -L "$repo_root" && -f "$repo_root/go.mod" ]] || { echo 'repo root is invalid' >&2; exit 64; }
[[ ! -e "$output_root" ]] || { echo 'refusing to overwrite canonical M7 output' >&2; exit 64; }
[[ -d "$debs_root" && ! -L "$debs_root" && -f "$debs_root/packages.txt" && -f "$debs_root/debs.sha256" && -d "$debs_root/debs" ]] || { echo 'verified Debian input is incomplete' >&2; exit 64; }
[[ -d "$assets_root" && ! -L "$assets_root" && -f "$assets_root/assets.sha256" ]] || { echo 'fixed asset input is incomplete' >&2; exit 64; }
for arch in amd64 arm64; do
  [[ -d "$assets_root/$arch" && ! -L "$assets_root/$arch" ]] || { echo "fixed asset architecture is missing: $arch" >&2; exit 64; }
done

repo_root=$(cd -- "$repo_root" && pwd -P)
stage_parent=$(dirname -- "$output_root")
stage_root=$(mktemp -d "$stage_parent/.open-card-m7-stage.XXXXXX")
cleanup() { rm -rf -- "$stage_root"; }
trap cleanup EXIT

build_binary() {
  local arch=$1 command=$2
  install -d -m 0750 "$stage_root/binaries/$arch"
  (
    cd "$repo_root"
    export CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local GOPROXY=off
    go build -trimpath -buildvcs=false -o "$stage_root/binaries/$arch/$command" "./cmd/$command"
  )
  chmod 0755 "$stage_root/binaries/$arch/$command"
}

for arch in amd64 arm64; do
  for command in open-card-server open-card-agent open-card-static-server open-card-secretctl open-card-security-probe open-card-imagegc; do
    build_binary "$arch" "$command"
  done
done

# The Caddy fixture is deliberately test-only. It is built only for the local
# amd64 fixture archive and is never copied into either production release.
install -d -m 0750 "$stage_root/test-only/amd64"
(
  cd "$repo_root"
  export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOPROXY=off
  go build -trimpath -buildvcs=false -o "$stage_root/test-only/amd64/open-card-caddy-fixture" ./cmd/open-card-caddy-fixture
)
chmod 0755 "$stage_root/test-only/amd64/open-card-caddy-fixture"

# M7 supplies Linux amd64 integration test binaries to the test-only archive;
# production release manifests never list them. The optional RC package is
# built when a future tests/integration/m7 or tests/integration/rc exists.
for spec in \
  'm6-ai:tests/integration/ai' \
  'm5-usage:tests/integration/usage' \
  'agent-compat:internal/agenttransport' \
  'agent-wire:api/agent/v1'; do
  name=${spec%%:*}
  package_path=${spec#*:}
  if [[ -d "$repo_root/$package_path" ]]; then
    (
      cd "$repo_root"
      export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOPROXY=off
      go test -c -tags=integration -trimpath -o "$stage_root/test-only/amd64/$name.test" "./$package_path"
    )
  fi
done
for package_path in tests/integration/m7 tests/integration/rc; do
  if [[ -d "$repo_root/$package_path" ]]; then
    name=$(basename "$package_path")
    (
      cd "$repo_root"
      export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOPROXY=off
      go test -c -tags=integration -trimpath -o "$stage_root/test-only/amd64/$name.test" "./$package_path"
    )
  fi
done

python3 "$repo_root/tools/worker/m7_canonical_bundle.py" assemble \
  --stage-root "$stage_root" \
  --repo-root "$repo_root" \
  --output-root "$output_root" \
  --debs-root "$debs_root" \
  --assets-root "$assets_root"

printf '%s\n' \
  'canonical_source=ready' \
  "version=$version" \
  "n_minus_one=$n_minus_one" \
  'architectures=linux/amd64,linux/arm64' \
  'production_caddy_fixture=excluded' \
  'test_only_fixture=bin/amd64/open-card-caddy-fixture (inside m7-fixtures.tar)' \
  'external_assets=explicit_sha256_inputs' \
  'credentials=forbidden'
