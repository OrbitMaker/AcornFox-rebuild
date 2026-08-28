#!/usr/bin/env bash
set -euo pipefail
umask 077

round=${1:?reboot round is required}
[[ "$round" =~ ^[123]$ ]]
domain=opencard-mvp-fa8f8eab-build-worker-01
offline=/opt/opencard-offline
state=/var/lib/opencard-mvp-fa8f8eab
evidence="$state/evidence/m7-reboot-$round"
install_env=(OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain")

record_failure() {
  local status=$? line=${BASH_LINENO[0]:-unknown}
  trap - ERR
  printf '{"status":%s,"line":"%s","round":%s}\n' "$status" "$line" "$round" >"$evidence/failure.json"
  exit "$status"
}
trap record_failure ERR

test "$(id -u)" -eq 0
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test -f "$state/m7-pre-reboot-complete"
test "$(readlink /opt/open-card/current)" = releases/release-0.7.0-rc.1
install -d -m 0750 "$evidence"

for service in docker containerd postgresql open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-enabled "$service")" = enabled
  for _ in $(seq 1 200); do [[ "$(systemctl is-active "$service" 2>/dev/null || true)" = active ]] && break; sleep 0.1; done
  test "$(systemctl is-active "$service")" = active
done
for _ in $(seq 1 200); do curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS http://127.0.0.1:8080/readyz >/dev/null
curl -fsS http://127.0.0.1:2019/config/ >"$evidence/caddy-config-after-reboot.json"
db_password=$(cat /etc/open-card/postgres-password)
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
test "$(psql "$database_url" -X -Aqt -c 'SELECT count(*) FROM schema_migrations')" = 21
test "$(psql "$database_url" -X -Aqt -c 'SELECT value FROM m7_restore_sentinel WHERE id=1')" = before-backup
test "$(cat /etc/open-card/m7-restore-sentinel)" = m7-config-before-backup
test "$(cat /var/lib/open-card/m7-restore-sentinel)" = m7-data-before-backup

systemctl status open-card-server open-card-agent open-card-buildkit open-card-caddy postgresql --no-pager >"$evidence/systemd-status.txt"
docker ps --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.ID}} {{.Names}} {{.Status}}' >"$evidence/runtime-containers.txt"
psql "$database_url" -X -Aqt -F '|' -c "SELECT state,count(*) FROM deployments GROUP BY state ORDER BY state" >"$evidence/deployments.tsv"
printf '{"round":%s,"release":"0.7.0-rc.1","schema_migrations":21,"services_autostart":true,"database_restore_persisted":true}\n' "$round" >"$evidence/result.json"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
touch "$state/m7-reboot-$round-complete"

if [[ "$round" != 3 ]]; then
  printf 'M7_REBOOT_ROUND_%s=PASS\n' "$round"
  exit 0
fi

# Remove the explicitly test-only route failure fixture before evaluating the
# production uninstall footprint. It was never part of the release manifest.
systemctl disable --now open-card-caddy-fixture.service >/dev/null 2>&1 || true
find /etc/systemd/system -maxdepth 1 -type f -name open-card-caddy-fixture.service -delete
systemctl daemon-reload

docker volume ls --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.Name}}' | sort >"$evidence/volumes-before-uninstall.txt"
find /var/lib/open-card -path /var/lib/open-card/backups -prune -o -type f -print0 | sort -z | xargs -0 sha256sum >"$evidence/data-before-uninstall.sha256"
# This is an asserted negative path. ERR traps fire even while errexit is
# disabled, so suspend only the diagnostic trap for this one command, capture
# its status, and restore fail-fast diagnostics immediately afterward.
trap - ERR
set +e
env "${install_env[@]}" "$offline/g7/uninstall.sh" --root / --purge --confirm WRONG >"$evidence/wrong-purge-token.log" 2>&1
wrong_purge_status=$?
set -e
trap record_failure ERR
test "$wrong_purge_status" -ne 0
test -d /var/lib/open-card

for container in $(docker ps -q --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab); do docker stop "$container" >/dev/null; done
for replay in 1 2; do
  env "${install_env[@]}" "$offline/g7/uninstall.sh" --root / >"$evidence/uninstall-$replay.log"
done
test ! -e /opt/open-card
test ! -e /etc/open-card
test -d /var/lib/open-card
test -d /var/lib/open-card/evidence
test ! -e /var/lib/open-card-buildkit-state.img
test ! -e /var/lib/open-card-buildkit
test ! -e /var/lib/open-card-agent
test ! -e /var/lib/open-card-caddy
test ! -e /etc/buildkit/buildkitd.toml
test ! -e /etc/apparmor.d/opencard-rootlesskit
! grep -Fq '/var/lib/open-card-buildkit-state.img /var/lib/open-card-buildkit ext4' /etc/fstab
test -f "$state/evidence/m4-real/manifest.sha256"
docker volume ls --filter label=open-card.task-prefix=opencard-mvp-fa8f8eab --format '{{.Name}}' | sort >"$evidence/volumes-after-uninstall.txt"
cmp "$evidence/volumes-before-uninstall.txt" "$evidence/volumes-after-uninstall.txt"

# Docker proxy and systemd cgroup teardown can settle just after stop returns.
# Wait only for this guest's explicitly managed units, executable paths and
# task ports, then persist the independent observations used by the assertions.
for _ in $(seq 1 100); do
  units_active=0
  for service in open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-caddy-fixture; do
    [[ "$(systemctl is-active "$service" 2>/dev/null || true)" != active ]] || units_active=1
  done
  managed_processes=$(pgrep -fa '/opt/open-card/(current|releases/[^/]+)/bin/(open-card-server|open-card-agent|open-card-static-server|open-card-caddy-fixture|buildkitd|buildctl|rootlesskit|caddy)( |$)' || true)
  managed_listeners=$(ss -lntp | grep -E ':(8080|8092|18481|2019|2020)\b' || true)
  [[ "$units_active" = 0 && -z "$managed_processes" && -z "$managed_listeners" ]] && break
  sleep 0.1
done
{
  for service in open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-caddy-fixture; do
    printf '%s active=%s enabled=%s\n' "$service" \
      "$(systemctl is-active "$service" 2>/dev/null || true)" \
      "$(systemctl is-enabled "$service" 2>/dev/null || true)"
  done
} >"$evidence/post-uninstall-units.txt"
printf '%s\n' "$managed_processes" >"$evidence/post-uninstall-processes.txt"
printf '%s\n' "$managed_listeners" >"$evidence/post-uninstall-listeners.txt"
for service in open-card-server open-card-agent open-card-buildkit open-card-caddy open-card-caddy-fixture; do
  test "$(systemctl is-active "$service" 2>/dev/null || true)" != active
  test "$(systemctl is-enabled "$service" 2>/dev/null || true)" != enabled
done
test -z "$managed_processes"
test -z "$managed_listeners"
printf '%s\n' \
  'M7_REBOOT_ROUND_3=PASS' \
  'M7_UNINSTALL_DEFAULT_PRESERVE=PASS' \
  'M7_UNINSTALL_REPLAY=PASS' \
  'M7_PURGE_WRONG_CONFIRMATION=REJECTED' >"$evidence/final-markers.txt"
(cd "$evidence" && find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >manifest.sha256)
touch "$state/m7-final-complete"
cat "$evidence/final-markers.txt"
