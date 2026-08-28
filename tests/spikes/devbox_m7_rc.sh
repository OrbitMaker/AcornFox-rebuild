#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
host=${OPEN_CARD_DEVBOX_HOST:-ubuntu@192.168.31.64}
key=${OPEN_CARD_DEVBOX_KEY:-/Users/a007/Documents/trae_projects/效率工具/IDC节点订阅/devbox_id_ed25519}
task=/home/ubuntu/opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
uuid=fce4e26d-93b0-5128-a090-969ef73835d4
pool_path=/var/lib/libvirt/images/opencard-mvp-fa8f8eab
volume_path=$pool_path/opencard-mvp-fa8f8eab-build-worker-01.qcow2
snapshot_path=$pool_path/opencard-mvp-fa8f8eab-build-worker-01-n-minus-one-snapshot.qcow2
run_id=$(date -u +%Y%m%dT%H%M%SZ)
local_raw="$repo/artifacts/mvp/m7-runs/$run_id"
ssh_args=(-i "$key" -o BatchMode=yes -o ConnectTimeout=10)
remote_reclaim_needed=0

test -f "$key"
test ! -e "$local_raw"
mkdir -p "$local_raw"

repo_archive=$(mktemp "${TMPDIR:-/tmp}/open-card-m7-repo.XXXXXX.tar")
deb_list=$(mktemp "${TMPDIR:-/tmp}/open-card-m7-debs.XXXXXX.txt")
module_cache_archive=$(mktemp "${TMPDIR:-/tmp}/open-card-m7-gomod.XXXXXX.tar")
github_redirects=$(mktemp "${TMPDIR:-/tmp}/open-card-m7-github.XXXXXX.txt")
cleanup_local() {
  find "$repo_archive" "$deb_list" "$module_cache_archive" "$github_redirects" -maxdepth 0 -type f -delete 2>/dev/null || true
}
finish() {
  local status=$?
  set +e
  cleanup_local
  if [[ "$remote_reclaim_needed" = 1 ]]; then
    ssh "${ssh_args[@]}" "$host" "OPEN_CARD_GUEST_EXEC_TIMEOUT=120 '$task/clean-worker-guest-exec.sh' 'set -eu; export_root=/tmp/m7-failure-export; find \"\$export_root\" -depth -delete 2>/dev/null || true; install -d -m 0700 \"\$export_root\"; test ! -d /var/lib/opencard-mvp-fa8f8eab/evidence || cp -a /var/lib/opencard-mvp-fa8f8eab/evidence \"\$export_root/\"; test ! -f /var/lib/opencard-mvp-fa8f8eab/bootstrap.log || cp /var/lib/opencard-mvp-fa8f8eab/bootstrap.log \"\$export_root/\"; test ! -f /var/log/cloud-init-output.log || cp /var/log/cloud-init-output.log \"\$export_root/\"; tar -czf /tmp/m7-failure-evidence.tar.gz -C \"\$export_root\" .'" >/dev/null 2>&1
    ssh "${ssh_args[@]}" "$host" "'$task/clean-worker-guest-file-copy.py' /tmp/m7-failure-evidence.tar.gz '$task/m7-failure-evidence.tar.gz'" >/dev/null 2>&1
    scp "${ssh_args[@]}" "$host:$task/m7-failure-evidence.tar.gz" "$local_raw/" >/dev/null 2>&1
    ssh "${ssh_args[@]}" "$host" "OPEN_CARD_ALLOW_VM_LIFECYCLE=1 OPEN_CARD_RECLAIM_CONFIRMATION=reclaim-$domain '$task/clean-worker-reclaim.sh' --execute" >"$local_raw/failure-reclaim.log" 2>&1
    ssh "${ssh_args[@]}" "$host" "'$task/clean-worker-host-snapshot.sh'" >"$local_raw/failure-host-after.json" 2>/dev/null
  elif [[ "$status" != 0 ]]; then
    for name in m7-canonical-source.stdout m7-canonical-source.stderr m7-bundle-result.json m7-bundle-validation.json m7-ubuntu-gpg.log; do
      scp "${ssh_args[@]}" "$host:$task/$name" "$local_raw/" >/dev/null 2>&1 || true
    done
    ssh "${ssh_args[@]}" "$host" "set -eu
test -f '$task/.open-card-task-marker'; grep -Fxq task_id=opencard-mvp-fa8f8eab '$task/.open-card-task-marker'
for path in '$task/clean-worker-m7-repo' '$task/clean-worker-m7-canonical-source' '$task/clean-worker-m7-iso-root' '$task/m7-temp' '$task/m7-cache' '$task/m7-snapshots'; do
  if test -e \"\$path\"; then chmod -R u+rwX \"\$path\"; find \"\$path\" -depth -delete; fi
done
find '$task' -maxdepth 1 -type f \( -name 'm7-*' -o -name 'opencard-mvp-fa8f8eab-m7-*' -o -name 'opencard-mvp-fa8f8eab-build-worker-01-*.iso' \) -delete" >/dev/null 2>&1
  fi
  if [[ "$status" != 0 ]]; then
    printf '%s\n' "$status" >"$local_raw/failure.exit"
    mkdir -p "$repo/artifacts/mvp/m7-negative"
    mv "$local_raw" "$repo/artifacts/mvp/m7-negative/$run_id"
  fi
  exit "$status"
}
trap finish EXIT

(cd "$repo" && COPYFILE_DISABLE=1 tar --no-xattrs \
  --exclude=.git --exclude=.omx/state --exclude=.playwright-cli \
  --exclude=artifacts --exclude=output --exclude=node_modules --exclude=web/node_modules \
  -cf "$repo_archive" .)
GOTOOLCHAIN=auto go mod download all
module_cache_root=$(GOTOOLCHAIN=auto go env GOMODCACHE)
(cd "$module_cache_root" && COPYFILE_DISABLE=1 tar --no-xattrs -cf "$module_cache_archive" \
  github.com/jackc/pgx/v5@v5.10.0 \
  github.com/jackc/pgpassfile@v1.0.0 \
  github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761 \
  github.com/jackc/puddle/v2@v2.2.2 \
  golang.org/x/sync@v0.21.0 \
  golang.org/x/text@v0.39.0 \
  cache/download/github.com/jackc/pgx/v5/@v \
  cache/download/github.com/jackc/pgpassfile/@v \
  cache/download/github.com/jackc/pgservicefile/@v \
  cache/download/github.com/jackc/puddle/v2/@v \
  cache/download/github.com/davecgh/go-spew/@v \
  cache/download/github.com/kr/pretty/@v \
  cache/download/github.com/pmezard/go-difflib/@v \
  cache/download/github.com/stretchr/objx/@v \
  cache/download/github.com/stretchr/testify/@v \
  cache/download/golang.org/x/mod/@v \
  cache/download/golang.org/x/sync/@v \
  cache/download/golang.org/x/text/@v \
  cache/download/golang.org/x/tools/@v \
  cache/download/gopkg.in/check.v1/@v \
  cache/download/gopkg.in/yaml.v3/@v)
sed -n '1,145p' "$repo/artifacts/mvp/m4-raw-final/canonical-0.4.0/guest/bootstrap.log" \
  | sed -n 's#^debs/\(.*\.deb\): OK$#\1#p' >"$deb_list"
test "$(wc -l <"$deb_list" | tr -d ' ')" = 140
while IFS='|' read -r url expected relative; do
  redirect=$(curl --fail --silent --show-error -D - -o /dev/null "$url" | sed -n 's/^[Ll]ocation: //p' | tr -d '\r' | tail -1)
  case "$redirect" in https://release-assets.githubusercontent.com/*) ;; *) exit 65 ;; esac
  printf '%s|%s|%s\n' "$relative" "$expected" "$(printf '%s' "$redirect" | base64 | tr -d '\n')" >>"$github_redirects"
done <<'GITHUB_ASSETS'
https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-amd64.tar.gz|2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af|amd64/buildkit.tar.gz
https://github.com/moby/buildkit/releases/download/v0.32.2/buildkit-v0.32.2.linux-arm64.tar.gz|9e8f46bf309ec0ab262967be5538a4dbe06be756a82621f98253933bac5dcf92|arm64/buildkit.tar.gz
https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-x86_64.tar.gz|b1302b7395918266d561b9e3053771253f20761807e042ae80a1868d6e86b71c|amd64/rootlesskit.tar.gz
https://github.com/rootless-containers/rootlesskit/releases/download/v3.1.0/rootlesskit-aarch64.tar.gz|42d1c22a34be7bb458f9ae7363d68dd05d553422d95392b44d0be7fa1fd76bf0|arm64/rootlesskit.tar.gz
https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-amd64|48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778|amd64/docker-buildx
https://github.com/docker/buildx/releases/download/v0.36.1/buildx-v0.36.1.linux-arm64|5d0cafd9d16afe1a0f0d9529885344ace2cc99efdd531b6c783c5455a6001569|arm64/docker-buildx
https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz|527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9|amd64/caddy.tar.gz
https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_arm64.tar.gz|52d42ae12b3462097e9868da6dfed3c9648ae12edd3b3638102312af84cb6904|arm64/caddy.tar.gz
GITHUB_ASSETS
test "$(wc -l <"$github_redirects" | tr -d ' ')" = 8

ssh "${ssh_args[@]}" "$host" "set -eu
test -f '$task/.open-card-task-marker'
grep -Fxq task_id=opencard-mvp-fa8f8eab '$task/.open-card-task-marker'
! sudo virsh dominfo '$domain' >/dev/null 2>&1
! sudo virsh pool-info opencard-mvp-fa8f8eab-build-workers >/dev/null 2>&1
! sudo virsh net-info opencard-mvp-fa8f8eab-build-isolated >/dev/null 2>&1
sudo test ! -e '$pool_path'
for path in '$task/clean-worker-m7-repo' '$task/clean-worker-m7-canonical-source' '$task/clean-worker-m7-iso-root' '$task/m7-temp' '$task/m7-cache' '$task/m7-snapshots'; do
  if test -e \"\$path\"; then chmod -R u+rwX \"\$path\"; find \"\$path\" -depth -delete; fi
done
if ! test -f '$task/clean-worker-m7-assets/assets.sha256' || ! (cd '$task/clean-worker-m7-assets' && sha256sum -c assets.sha256 >/dev/null 2>&1); then
  test ! -e '$task/clean-worker-m7-assets' || find '$task/clean-worker-m7-assets' -depth -delete
fi
if ! test -f '$task/clean-worker-m7-debs/debs.sha256' || ! (cd '$task/clean-worker-m7-debs' && sha256sum -c debs.sha256 >/dev/null 2>&1); then
  test ! -e '$task/clean-worker-m7-debs' || find '$task/clean-worker-m7-debs' -depth -delete
fi
find '$task' -maxdepth 1 -type f \( -name 'm7-*' -o -name 'opencard-mvp-fa8f8eab-m7-*' -o -name 'opencard-mvp-fa8f8eab-build-worker-01-*.iso' \) -delete
mkdir -p '$task/m7-temp'"
scp "${ssh_args[@]}" "$repo_archive" "$host:$task/m7-temp/repo.tar"
scp "${ssh_args[@]}" "$deb_list" "$host:$task/m7-temp/deb-files.txt"
scp "${ssh_args[@]}" "$module_cache_archive" "$host:$task/m7-temp/gomod.tar"
scp "${ssh_args[@]}" "$github_redirects" "$host:$task/m7-temp/github-assets.txt"

ssh "${ssh_args[@]}" "$host" 'bash -s' <<'REMOTE_PREPARE'
set -euo pipefail
umask 077
task=/home/ubuntu/opencard-mvp-fa8f8eab
repo=$task/clean-worker-m7-repo
assets=$task/clean-worker-m7-assets
debs=$task/clean-worker-m7-debs
canonical=$task/clean-worker-m7-canonical-source
iso_root=$task/clean-worker-m7-iso-root
pool_path=/var/lib/libvirt/images/opencard-mvp-fa8f8eab
test -f "$task/.open-card-task-marker"
mkdir -p "$repo" "$assets/amd64" "$assets/arm64" "$debs/debs" "$iso_root"
tar -xf "$task/m7-temp/repo.tar" -C "$repo"
test -f "$repo/go.mod" -a -d "$repo/web/dist"

download() {
  local url=$1 expected=$2 target=$3
  if [[ -f "$target" && ! -L "$target" ]] && printf '%s  %s\n' "$expected" "$target" | sha256sum -c - >/dev/null 2>&1; then
    return 0
  fi
  curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --retry 5 --retry-delay 2 --output "$target.part" -- "$url"
  printf '%s  %s\n' "$expected" "$target.part" | sha256sum -c -
  mv "$target.part" "$target"
  chmod 0644 "$target"
}
download_jobs=()
queue_download() { download "$1" "$2" "$3" & download_jobs+=("$!"); }
while IFS='|' read -r relative expected encoded_url; do
  url=$(printf '%s' "$encoded_url" | base64 -d)
  case "$url" in https://release-assets.githubusercontent.com/*) ;; *) exit 65 ;; esac
  queue_download "$url" "$expected" "$assets/$relative"
done <"$task/m7-temp/github-assets.txt"
queue_download https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img 6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733 "$assets/amd64/ubuntu-24.04-server-cloudimg.img"
queue_download https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img 4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa "$assets/arm64/ubuntu-24.04-server-cloudimg.img"
for job in "${download_jobs[@]}"; do wait "$job"; done
(cd "$assets" && find amd64 arm64 -type f -print0 | sort -z | xargs -0 sha256sum >assets.sha256)

# Go is task-local build tooling only. It never replaces the shared host Go
# installation and is removed with m7-temp during exact reclaim.
download https://dl.google.com/go/go1.25.13.linux-amd64.tar.gz 39042a078ea9ceebe3ecda4a7188f0f5b96e14a071d27923ba7f40b456e85ae3 "$task/m7-temp/go1.25.13.linux-amd64.tar.gz"
mkdir -p "$task/m7-temp/go-toolchain"
tar -xzf "$task/m7-temp/go1.25.13.linux-amd64.tar.gz" -C "$task/m7-temp/go-toolchain"
test "$($task/m7-temp/go-toolchain/go/bin/go version)" = 'go version go1.25.13 linux/amd64'
export PATH="$task/m7-temp/go-toolchain/go/bin:$PATH"
export GOMODCACHE="$task/m7-cache/gomod"
mkdir -p "$GOMODCACHE"
tar --no-same-permissions --delay-directory-restore -xf "$task/m7-temp/gomod.tar" -C "$GOMODCACHE"
(cd "$repo" && GOTOOLCHAIN=local GOPROXY="file://$GOMODCACHE/cache/download" go mod download all && GOTOOLCHAIN=local GOPROXY=off go mod verify >"$task/m7-go-mod-verify.log")

deb_jobs=()
download_deb() {
  local filename=$1 package rest version
  [[ "$filename" =~ ^[A-Za-z0-9.+%-]+_[A-Za-z0-9.+:%~+-]+_(all|amd64)\.deb$ ]]
  package=${filename%%_*}
  rest=${filename#*_}; version=${rest%_*}; version=${version//%3a/:}
  [[ -f "$debs/debs/$filename" && ! -L "$debs/debs/$filename" ]] || (cd "$debs/debs" && apt-get download "$package=$version" >/dev/null)
  test -f "$debs/debs/$filename"
}
while IFS= read -r filename; do
  download_deb "$filename" & deb_jobs+=("$!")
  if (( ${#deb_jobs[@]} == 8 )); then
    for job in "${deb_jobs[@]}"; do wait "$job"; done
    deb_jobs=()
  fi
done <"$task/m7-temp/deb-files.txt"
for job in "${deb_jobs[@]}"; do wait "$job"; done
cp "$task/m7-temp/deb-files.txt" "$debs/packages.txt"
(cd "$debs" && find debs -type f -name '*.deb' -print0 | sort -z | xargs -0 sha256sum >debs.sha256)
test "$(find "$debs/debs" -type f -name '*.deb' | wc -l)" = 140

bash "$repo/scripts/mvp/build-m7-canonical-source.sh" \
  --repo-root "$repo" --output-root "$canonical" --debs-root "$debs" --assets-root "$assets" \
  >"$task/m7-canonical-source.stdout" 2>"$task/m7-canonical-source.stderr"
(cd "$canonical" && sha256sum -c bundle-manifest.sha256)

bundle=$task/opencard-mvp-fa8f8eab-m7-offline-bundle.tar
python3 "$repo/tools/worker/offline_bundle.py" build --output "$bundle" \
  --input "payload/debs.tar=$canonical/debs.tar" \
  --input "payload/releases.tar=$canonical/releases.tar" \
  --input "payload/migrations.tar=$canonical/migrations.tar" \
  --input "payload/g7-scripts.tar=$canonical/g7-scripts.tar" \
  --input "payload/manifest.json=$canonical/manifest.json" \
  --input "payload/bundle-manifest.sha256=$canonical/bundle-manifest.sha256" \
  --input "payload/sbom.spdx.json=$canonical/sbom.spdx.json" \
  --input "payload/supply-chain.json=$canonical/supply-chain.json" \
  --input "payload/clean-worker-bootstrap.sh=$repo/scripts/mvp/clean-worker-bootstrap.sh" \
  --input "payload/offline_bundle.py=$repo/tools/worker/offline_bundle.py" \
  >"$task/m7-bundle-result.json"
python3 "$repo/tools/worker/offline_bundle.py" validate --archive "$bundle" >"$task/m7-bundle-validation.json"

cp "$bundle" "$iso_root/offline-bundle.tar"
cp "$canonical/m7-fixtures.tar" "$iso_root/m7-fixtures.tar"
cp "$repo/tools/worker/offline_bundle.py" "$repo/scripts/mvp/clean-worker-bootstrap.sh" "$iso_root/"
(cd "$iso_root" && sha256sum offline-bundle.tar m7-fixtures.tar offline_bundle.py clean-worker-bootstrap.sh >offline-bundle.sha256)
genisoimage -quiet -volid OPENCARD_BUNDLE -joliet -rock -o "$task/opencard-mvp-fa8f8eab-build-worker-01-offline.iso" "$iso_root"

curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
  --output "$task/m7-temp/SHA256SUMS" https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS
curl --fail --location --proto '=https' --output "$task/m7-temp/SHA256SUMS.gpg" https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS.gpg
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg "$task/m7-temp/SHA256SUMS.gpg" "$task/m7-temp/SHA256SUMS" >"$task/m7-ubuntu-gpg.log" 2>&1
grep -F '6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733 *ubuntu-24.04-server-cloudimg-amd64.img' "$task/m7-temp/SHA256SUMS"
grep -F '4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa *ubuntu-24.04-server-cloudimg-arm64.img' "$task/m7-temp/SHA256SUMS"
cp "$assets/amd64/ubuntu-24.04-server-cloudimg.img" "$task/m7-temp/ubuntu-24.04-server-cloudimg-amd64.img"

cloud-localds --network-config="$repo/deploy/worker/cloud-init-network-config.yaml" \
  "$task/opencard-mvp-fa8f8eab-build-worker-01-seed.iso" \
  "$repo/deploy/worker/cloud-init-m7-user-data.yaml" "$repo/deploy/worker/cloud-init-meta-data.yaml"

for script in provision-clean-worker.sh clean-worker-reclaim.sh clean-worker-guest-exec.sh clean-worker-host-snapshot.sh; do
  install -m 0750 "$repo/scripts/mvp/$script" "$task/$script"
done
install -m 0750 "$repo/scripts/mvp/clean-worker-guest-file-copy.py" "$task/clean-worker-guest-file-copy.py"
"$task/clean-worker-host-snapshot.sh" >"$task/m7-host-before-create.json"

sudo install -d -m 0750 -o root -g libvirt-qemu "$pool_path"
cat >"$task/m7-temp/pool-marker" <<'EOF'
task_id=opencard-mvp-fa8f8eab
domain=opencard-mvp-fa8f8eab-build-worker-01
domain_uuid=fce4e26d-93b0-5128-a090-969ef73835d4
network=opencard-mvp-fa8f8eab-build-isolated
network_uuid=03f91824-e5c9-5655-ac06-fec291e81c93
EOF
sudo install -m 0640 -o root -g libvirt-qemu "$task/m7-temp/pool-marker" "$pool_path/.open-card-task-marker"
sudo install -m 0640 -o root -g libvirt-qemu "$task/m7-temp/ubuntu-24.04-server-cloudimg-amd64.img" "$pool_path/ubuntu-24.04-server-cloudimg-amd64.img"
sudo install -m 0640 -o root -g libvirt-qemu "$task/opencard-mvp-fa8f8eab-build-worker-01-seed.iso" "$pool_path/opencard-mvp-fa8f8eab-build-worker-01-seed.iso"
sudo install -m 0640 -o root -g libvirt-qemu "$task/opencard-mvp-fa8f8eab-build-worker-01-offline.iso" "$pool_path/opencard-mvp-fa8f8eab-build-worker-01-offline.iso"
REMOTE_PREPARE

ssh "${ssh_args[@]}" "$host" "OPEN_CARD_ALLOW_VM_LIFECYCLE=1 OPEN_CARD_PROVISION_CONFIRMATION=provision-$domain '$task/provision-clean-worker.sh'" | tee "$local_raw/provision.log"
remote_reclaim_needed=1

guest_exec() {
  ssh "${ssh_args[@]}" "$host" "OPEN_CARD_GUEST_EXEC_TIMEOUT=${OPEN_CARD_GUEST_EXEC_TIMEOUT:-1800} '$task/clean-worker-guest-exec.sh' $(printf %q "$1")"
}
wait_guest() {
  for _ in $(seq 1 300); do
    if ssh "${ssh_args[@]}" "$host" "sudo virsh qemu-agent-command '$domain' '{\"execute\":\"guest-ping\"}' >/dev/null 2>&1"; then return 0; fi
    sleep 2
  done
  return 1
}
reboot_guest() {
  local before after=
  before=$(guest_exec 'cat /proc/sys/kernel/random/boot_id')
  ssh "${ssh_args[@]}" "$host" "sudo virsh reboot '$domain' --mode agent >/dev/null"
  for _ in $(seq 1 300); do
    if wait_guest; then
      after=$(guest_exec 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
      [[ -n "$after" && "$after" != "$before" ]] && return 0
    fi
    sleep 1
  done
  return 1
}
restore_n_minus_one() {
  ssh "${ssh_args[@]}" "$host" "set -eu
sudo virsh shutdown '$domain' --mode agent >/dev/null
for i in \$(seq 1 60); do test \"\$(sudo virsh domstate '$domain')\" = 'shut off' && break; sleep 1; done
test \"\$(sudo virsh domstate '$domain')\" = 'shut off'
sudo cp --reflink=auto '$snapshot_path' '$volume_path.part'
sudo chown libvirt-qemu:libvirt-qemu '$volume_path.part'; sudo chmod 0640 '$volume_path.part'
sudo mv '$volume_path.part' '$volume_path'
sudo virsh start '$domain' >/dev/null"
  wait_guest
  guest_exec 'test -f /var/lib/opencard-mvp-fa8f8eab/bootstrap-complete; test "$(readlink /opt/open-card/current)" = releases/release-0.6.0'
}
export_round() {
  local round=$1
  guest_exec "tar -czf /tmp/m7-round-$round.tar.gz -C /var/lib/opencard-mvp-fa8f8eab/evidence m7-upgrade-$round"
  ssh "${ssh_args[@]}" "$host" "'$task/clean-worker-guest-file-copy.py' /tmp/m7-round-$round.tar.gz '$task/m7-round-$round.tar.gz' >/dev/null"
  scp "${ssh_args[@]}" "$host:$task/m7-round-$round.tar.gz" "$local_raw/"
}

wait_guest
guest_exec 'for i in $(seq 1 600); do test -f /var/lib/opencard-mvp-fa8f8eab/bootstrap-complete && exit 0; sleep 1; done; tail -200 /var/log/cloud-init-output.log; exit 1' | tee "$local_raw/bootstrap-complete.log"
ssh "${ssh_args[@]}" "$host" "set -eu
sudo virsh shutdown '$domain' --mode agent >/dev/null
for i in \$(seq 1 60); do test \"\$(sudo virsh domstate '$domain')\" = 'shut off' && break; sleep 1; done
test \"\$(sudo virsh domstate '$domain')\" = 'shut off'
sudo cp --reflink=auto '$volume_path' '$snapshot_path'
sudo chown libvirt-qemu:libvirt-qemu '$snapshot_path'; sudo chmod 0640 '$snapshot_path'
sudo virsh start '$domain' >/dev/null"
wait_guest

for round in 1 2 3; do
  if [[ "$round" != 1 ]]; then restore_n_minus_one; fi
  guest_exec "bash /opt/opencard-offline/outer/payload/tests/spikes/clean_worker_m7_upgrade_guest.sh $round" \
    >"$local_raw/upgrade-round-$round.stdout" 2>"$local_raw/upgrade-round-$round.stderr"
  export_round "$round"
done

guest_exec 'bash /opt/opencard-offline/outer/payload/tests/spikes/clean_worker_m7_rc_guest.sh' \
  >"$local_raw/rc.stdout" 2>"$local_raw/rc.stderr"
for round in 1 2 3; do
  reboot_guest
  guest_exec "bash /opt/opencard-offline/outer/payload/tests/spikes/clean_worker_m7_post_reboot_guest.sh $round" \
    >"$local_raw/reboot-round-$round.stdout" 2>"$local_raw/reboot-round-$round.stderr"
done

guest_exec 'tar -czf /tmp/m7-final-evidence.tar.gz -C /var/lib/opencard-mvp-fa8f8eab evidence m7-final-complete m7-pre-reboot-complete'
ssh "${ssh_args[@]}" "$host" "'$task/clean-worker-guest-file-copy.py' /tmp/m7-final-evidence.tar.gz '$task/m7-final-evidence.tar.gz' >/dev/null"
scp "${ssh_args[@]}" "$host:$task/m7-final-evidence.tar.gz" "$local_raw/"
ssh "${ssh_args[@]}" "$host" "tar -czf '$task/m7-supply-evidence.tar.gz' -C '$task/clean-worker-m7-canonical-source' manifest.json bundle-manifest.sha256 source-manifest.sha256 sbom.spdx.json supply-chain.json compatibility.json summary.json"
scp "${ssh_args[@]}" "$host:$task/m7-supply-evidence.tar.gz" "$local_raw/"
scp "${ssh_args[@]}" "$host:$task/m7-host-before-create.json" "$local_raw/host-before.json"

ssh "${ssh_args[@]}" "$host" "OPEN_CARD_ALLOW_VM_LIFECYCLE=1 OPEN_CARD_RECLAIM_CONFIRMATION=reclaim-$domain '$task/clean-worker-reclaim.sh' --execute" | tee "$local_raw/reclaim.log"
remote_reclaim_needed=0
ssh "${ssh_args[@]}" "$host" "'$task/clean-worker-host-snapshot.sh'" >"$local_raw/host-after.json"
cmp "$local_raw/host-before.json" "$local_raw/host-after.json"
ssh "${ssh_args[@]}" "$host" "set -eu
! sudo virsh dominfo '$domain' >/dev/null 2>&1
! sudo virsh pool-info opencard-mvp-fa8f8eab-build-workers >/dev/null 2>&1
! sudo virsh net-info opencard-mvp-fa8f8eab-build-isolated >/dev/null 2>&1
sudo test ! -e '$pool_path'
test ! -e '$task/clean-worker-m7-repo'
test ! -e '$task/clean-worker-m7-canonical-source'
test ! -e '$task/clean-worker-m7-assets'
test ! -e '$task/clean-worker-m7-debs'
test ! -e '$task/clean-worker-m7-iso-root'
test ! -e '$task/m7-temp'"

(cd "$local_raw" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 shasum -a 256 >manifest.sha256)
mkdir -p "$repo/artifacts/mvp/m7-raw-final"
final_raw="$repo/artifacts/mvp/m7-raw-final/$run_id"
mv "$local_raw" "$final_raw"
printf 'M7_CANONICAL_VM_RUN=PASS\nM7_HOST_RECLAIM=PASS\nraw_evidence=%s\n' "$final_raw"
