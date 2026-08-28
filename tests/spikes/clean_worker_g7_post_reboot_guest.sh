#!/usr/bin/env bash
set -euo pipefail

domain=opencard-mvp-fa8f8eab-build-worker-01
offline=/opt/opencard-offline
evidence=/var/lib/opencard-mvp-fa8f8eab/evidence/g7
wait_url() {
  local url=$1
  for _ in $(seq 1 100); do curl -fsS "$url" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}
test "$(cat /etc/opencard-mvp-fa8f8eab-clean-worker)" = "$domain"
test -f /var/lib/opencard-mvp-fa8f8eab/g7-pre-reboot-complete
test "$(readlink /opt/open-card/current)" = releases/release-0.2.0
for service in docker containerd postgresql open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-enabled "$service")" = enabled
  for _ in $(seq 1 100); do
    [[ "$(systemctl is-active "$service" 2>/dev/null || true)" = active ]] && break
    sleep 0.1
  done
  test "$(systemctl is-active "$service")" = active
done
test "$(systemctl is-enabled qemu-guest-agent)" = static
for _ in $(seq 1 100); do
  [[ "$(systemctl is-active qemu-guest-agent 2>/dev/null || true)" = active ]] && break
  sleep 0.1
done
test "$(systemctl is-active qemu-guest-agent)" = active
wait_url http://127.0.0.1:8080/readyz
wait_url http://127.0.0.1:18481/readyz
db_password=$(cat /etc/open-card/postgres-password)
database_url="postgresql://opencard:$db_password@127.0.0.1:5432/opencard?sslmode=disable"
test "$(psql "$database_url" -Atc "SELECT value FROM g7_restore_sentinel WHERE id=1")" = before-backup

systemctl restart open-card-server.service open-card-agent.service open-card-buildkit.service open-card-caddy.service
for service in open-card-server open-card-agent open-card-buildkit open-card-caddy; do test "$(systemctl is-active "$service")" = active; done
env OPEN_CARD_ALLOW_SYSTEM_ROOT=1 OPEN_CARD_SYSTEM_ROOT_CONFIRMATION="$domain" \
  "$offline/g7/uninstall.sh" --root / >"$evidence/uninstall.log"
test -d /var/lib/open-card
test -f /var/lib/opencard-mvp-fa8f8eab/evidence/s2/positive.oci.sha256
test ! -e /opt/open-card
for unit in open-card-server open-card-agent open-card-buildkit open-card-caddy; do
  test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" != enabled
  test "$(systemctl is-active "$unit" 2>/dev/null || true)" != active
done
touch /var/lib/opencard-mvp-fa8f8eab/g7-post-reboot-complete
printf '%s\n' \
  'g7_post_reboot=PASS' \
  'autostart_after_guest_reboot=PASS' \
  'service_restart_after_reboot=PASS' \
  'postgres_restore_persisted=PASS' \
  'uninstall_preserved_data_and_evidence=PASS'
