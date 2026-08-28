#!/usr/bin/env bash
set -euo pipefail

# Build only the task-scoped, credentials-free input tree consumed by
# tools/worker/assemble_guest_payload.py. This script does not provision a
# guest, alter host networking, or install packages. Debian packages must be
# supplied as an already verified explicit input rather than being silently
# downloaded from an ambient APT configuration.

usage() {
  cat <<'USAGE'
Usage:
  build-m4-canonical-source.sh \
    --repo-root /absolute/Open-Card \
    --output-root /absolute/.../clean-worker-offline-source \
    --debs-root /absolute/verified-debs \
    [--seed-assets-root /absolute/verified-assets]

`--debs-root` must contain packages.txt, debs.sha256 and a debs/ directory.
Each manifest entry is verified before it is copied. The output path must end
in `clean-worker-offline-source`; it must not already exist.
USAGE
}

repo_root=
output_root=
debs_root=
seed_assets_root=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) repo_root=${2:-}; shift 2 ;;
    --output-root) output_root=${2:-}; shift 2 ;;
    --debs-root) debs_root=${2:-}; shift 2 ;;
    --seed-assets-root) seed_assets_root=${2:-}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
done

for value in "$repo_root" "$output_root" "$debs_root"; do
  [[ "$value" = /* ]] || { echo 'all paths must be absolute' >&2; exit 64; }
done
if [[ -n "$seed_assets_root" ]]; then
  [[ "$seed_assets_root" = /* && -d "$seed_assets_root" && ! -L "$seed_assets_root" ]] || { echo 'seed assets root must be an absolute regular directory' >&2; exit 64; }
fi
[[ $(basename "$output_root") = clean-worker-offline-source ]] || { echo 'output root must end in clean-worker-offline-source' >&2; exit 64; }
[[ -d "$repo_root" && ! -L "$repo_root" && -f "$repo_root/go.mod" ]] || { echo 'repo root is invalid' >&2; exit 64; }
[[ -d "$debs_root" && ! -L "$debs_root" && -f "$debs_root/packages.txt" && -f "$debs_root/debs.sha256" && -d "$debs_root/debs" ]] || { echo 'verified deb input is incomplete' >&2; exit 64; }
[[ ! -e "$output_root" ]] || { echo 'refusing to overwrite canonical source root' >&2; exit 64; }

verify_debs() {
  local line digest path manifest_paths actual_paths
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    digest=${line%% *}
    path=${line#*  }
    [[ "$digest" =~ ^[0-9a-f]{64}$ && "$path" = debs/* && "$path" != *..* ]] || { echo 'invalid deb manifest entry' >&2; return 1; }
    [[ -f "$debs_root/$path" && ! -L "$debs_root/$path" ]] || { echo "missing verified deb: $path" >&2; return 1; }
    [[ $(sha256sum "$debs_root/$path" | awk '{print $1}') = "$digest" ]] || { echo "deb checksum mismatch: $path" >&2; return 1; }
  done <"$debs_root/debs.sha256"
  [[ -n $(find "$debs_root/debs" -maxdepth 1 -type f -name '*.deb' -print -quit) ]] || { echo 'verified deb input has no debs' >&2; return 1; }
  manifest_paths=$(mktemp)
  actual_paths=$(mktemp)
  trap 'rm -f -- "$manifest_paths" "$actual_paths"' RETURN
  awk 'NF {print $2}' "$debs_root/debs.sha256" | sort -u >"$manifest_paths"
  find "$debs_root/debs" -maxdepth 1 -type f -name '*.deb' -printf 'debs/%f\n' | sort -u >"$actual_paths"
  cmp "$manifest_paths" "$actual_paths" || { echo 'deb manifest must cover the exact downloaded package set' >&2; return 1; }
}

download() {
  local url=$1 expected=$2 destination=$3
	if [[ -e "$destination" ]]; then
	  [[ -f "$destination" && ! -L "$destination" ]] || { echo "pinned asset is not a regular file: $destination" >&2; return 1; }
	  [[ $(sha256sum "$destination" | awk '{print $1}') = "$expected" ]] || { echo "existing pinned asset checksum mismatch: $destination" >&2; return 1; }
	  return 0
	fi
  curl --fail --location --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 600 -o "$destination.part" "$url"
  [[ $(sha256sum "$destination.part" | awk '{print $1}') = "$expected" ]] || { rm -f -- "$destination.part"; echo "asset checksum mismatch: $url" >&2; return 1; }
  mv "$destination.part" "$destination"
}

verify_debs
install -d -m 0750 "$output_root/extracted" "$output_root/debs"
if [[ -n "$seed_assets_root" ]]; then
  for name in buildkit.tar.gz rootlesskit.tar.gz docker-buildx caddy.tar.gz ubuntu-24.04-server-cloudimg-amd64.img; do
    [[ -f "$seed_assets_root/$name" && ! -L "$seed_assets_root/$name" ]] || { echo "seed assets omit $name" >&2; exit 64; }
    cp -- "$seed_assets_root/$name" "$output_root/$name"
  done
fi
cp -- "$debs_root/packages.txt" "$debs_root/debs.sha256" "$output_root/"
cp -- "$debs_root"/debs/*.deb "$output_root/debs/"

(
  cd "$repo_root"
  export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  for command in open-card-server open-card-agent open-card-static-server open-card-secretctl open-card-security-probe open-card-imagegc open-card-caddy-fixture; do
    go build -trimpath -buildvcs=false -o "$output_root/$command" "./cmd/$command"
  done
)

download 'https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz' '2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af' "$output_root/buildkit.tar.gz"
download 'https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz' 'b1302b7395918266d561b9e3053771253f20761807e042ae80a1868d6e86b71c' "$output_root/rootlesskit.tar.gz"
download 'https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-amd64' '48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778' "$output_root/docker-buildx"
download 'https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz' '527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9' "$output_root/caddy.tar.gz"
download 'https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img' '6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733' "$output_root/ubuntu-24.04-server-cloudimg-amd64.img"

tar -xzf "$output_root/buildkit.tar.gz" -C "$output_root/extracted"
tar -xzf "$output_root/rootlesskit.tar.gz" -C "$output_root/extracted"
tar -xzf "$output_root/caddy.tar.gz" -C "$output_root/extracted"
for name in buildkitd buildctl buildkit-runc rootlesskit caddy; do
  source_path=$(find "$output_root/extracted" -type f -name "$name" -print -quit)
  [[ -n "$source_path" ]] || { echo "pinned asset omitted required binary: $name" >&2; exit 1; }
  if [[ "$name" = buildkit* ]]; then
    install -d -m 0750 "$output_root/extracted/bin"
    if [[ "$source_path" != "$output_root/extracted/bin/$name" ]]; then
      install -m 0755 "$source_path" "$output_root/extracted/bin/$name"
    else
      chmod 0755 "$source_path"
    fi
  else
    if [[ "$source_path" != "$output_root/extracted/$name" ]]; then
      install -m 0755 "$source_path" "$output_root/extracted/$name"
    else
      chmod 0755 "$source_path"
    fi
  fi
done
chmod 0755 "$output_root/docker-buildx"

fixture_sha=$(sha256sum "$output_root/open-card-caddy-fixture" | awk '{print $1}')
printf '{"path":"open-card-caddy-fixture","sha256":"%s","scope":"clean-worker-test-only","default_enabled":false}\n' "$fixture_sha" >"$output_root/open-card-caddy-fixture.manifest.json"

(
  cd "$output_root"
  find open-card-* extracted debs -type f -print0 | sort -z | xargs -0 sha256sum >source-manifest.sha256
  sha256sum buildkit.tar.gz rootlesskit.tar.gz docker-buildx caddy.tar.gz ubuntu-24.04-server-cloudimg-amd64.img >>source-manifest.sha256
)
chmod -R go-rwx "$output_root"
printf '%s\n' 'canonical_source=ready' 'version=0.4.0' 'external_assets=sha256_verified' 'debs=explicit_verified_input'
