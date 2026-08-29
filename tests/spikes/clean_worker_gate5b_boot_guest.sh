#!/usr/bin/env bash
# Runs only inside the disposable Gate5B boot-graph guest.  It installs the
# canonical boot barrier artifacts verbatim, then supplies harmless unit names
# whose only observable action is creating files under the task state root.
set -Eeuo pipefail
umask 077

phase=${1:?phase is required: initial|post-reboot}
[[ "$phase" == initial || "$phase" == post-reboot ]]

prefix=${OPEN_CARD_G5B_BOOT_PREFIX:-opencard-g5b-20260830-a01}
[[ "$prefix" =~ ^opencard-g5b-[0-9]{8}-a[0-9]{2}$ ]]
source_root=${OPEN_CARD_G5B_BOOT_SOURCE_ROOT:-/home/ubuntu/g5b-source}
state=/var/lib/$prefix
evidence=$state/evidence
marker=/var/lib/open-card/upgrade-in-progress
safe=open-card-upgrade-safe.target
recover=open-card-upgrade-recover.service
finalize=open-card-upgrade-finalize.service
units=(open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service open-card-edge.service)

[[ "$(id -u)" -eq 0 ]]
[[ -d "$source_root/systemd" && ! -L "$source_root/systemd" ]]
install -d -o root -g root -m 0700 "$state" "$evidence" /opt/open-card/upgrade-tools /var/lib/open-card
printf '%s\n' "$prefix" >"$state/.open-card-task-marker"
chmod 0600 "$state/.open-card-task-marker"

diagnose_failure() {
  local status=$?
  trap - ERR
  printf 'guest_phase=%s failed_status=%s\n' "$phase" "$status" >&2
  for file in "$evidence"/systemd-analyze-verify.txt "$evidence"/prepare-failure-start.txt; do
    [[ -f "$file" ]] && tail -80 "$file" >&2 || true
  done
  exit "$status"
}
trap diagnose_failure ERR

record_unit_states() {
  local label=$1 unit
  {
    printf 'label=%s\n' "$label"
    for unit in "$recover" "$safe" "$finalize" "${units[@]}"; do
      printf '%s active=%s result=%s requires=%s wants=%s before=%s\n' "$unit" \
        "$(systemctl show --value -p ActiveState "$unit")" \
        "$(systemctl show --value -p Result "$unit")" \
        "$(systemctl show --value -p Requires "$unit")" \
        "$(systemctl show --value -p Wants "$unit")" \
        "$(systemctl show --value -p Before "$unit")"
    done
  } >>"$evidence/systemctl-states.txt"
}

stop_business() {
  systemctl stop "${units[@]}" "$safe" "$finalize" "$recover" >/dev/null 2>&1 || true
  rm -rf "$state/business"
  install -d -o root -g root -m 0700 "$state/business"
}

assert_inactive_business() {
  local unit
  for unit in "${units[@]}"; do
    [[ "$(systemctl show --value -p ActiveState "$unit")" != active ]] || {
      echo "$unit unexpectedly active" >&2
      return 1
    }
  done
}

install_fixture() {
  local file
  for file in open-card-upgrade-recover.service open-card-upgrade-safe.target open-card-upgrade-finalize.service; do
    install -o root -g root -m 0644 "$source_root/systemd/$file" "/etc/systemd/system/$file"
    cmp "$source_root/systemd/$file" "/etc/systemd/system/$file"
  done
  install -d -o root -g root -m 0755 /etc/systemd/system/open-card-edge.service.d
  install -o root -g root -m 0644 "$source_root/systemd/open-card-edge.service.d/10-upgrade-marker.conf" \
    /etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf
  cmp "$source_root/systemd/open-card-edge.service.d/10-upgrade-marker.conf" \
    /etc/systemd/system/open-card-edge.service.d/10-upgrade-marker.conf

  cat >/opt/open-card/upgrade-tools/open-card-upgrade <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
state=/var/lib/opencard-g5b-20260830-a01
marker=/var/lib/open-card/upgrade-in-progress
case "${1:-}" in
  recover-prepare)
    [[ "${2:-}" == --pending && -f "$marker" ]] || exit 64
    case "$(cat "$state/prepare-mode")" in
      success) touch "$state/prepare-ok" ;;
      fail) echo prepare_failed >&2; exit 71 ;;
      *) exit 65 ;;
    esac
    ;;
  recover-finalize)
    [[ "${2:-}" == --pending && -f "$marker" && -f "$state/prepare-ok" ]] || exit 64
    case "$(cat "$state/finalize-mode")" in
      success) rm -f "$marker"; touch "$state/finalize-ok" ;;
      fail) echo finalize_failed >&2; exit 72 ;;
      *) exit 65 ;;
    esac
    ;;
  *) exit 64 ;;
esac
EOF
  chmod 0755 /opt/open-card/upgrade-tools/open-card-upgrade

  local unit name
  for unit in "${units[@]}"; do
    name=${unit%.service}
    cat >"/etc/systemd/system/$unit" <<EOF
[Unit]
Description=Gate5B isolated boot graph dummy $name
Requires=$safe
After=$safe

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/touch $state/business/$name.started

[Install]
WantedBy=multi-user.target
EOF
  done
  systemctl daemon-reload
  systemctl enable "$safe" "${units[@]}" >/dev/null
}

verify_graph() {
  systemd-analyze verify \
    /etc/systemd/system/open-card-upgrade-recover.service \
    /etc/systemd/system/open-card-upgrade-safe.target \
    /etc/systemd/system/open-card-upgrade-finalize.service \
    /etc/systemd/system/open-card-buildkit.service \
    /etc/systemd/system/open-card-caddy.service \
    /etc/systemd/system/open-card-server.service \
    /etc/systemd/system/open-card-agent.service \
    /etc/systemd/system/open-card-edge.service \
    >"$evidence/systemd-analyze-verify.txt" 2>&1
  systemd-analyze dot "$safe" "$recover" "$finalize" "${units[@]}" >"$evidence/systemd-graph.dot"
  test -L /etc/systemd/system/open-card-edge.service.requires/open-card-upgrade-safe.target
  for unit in open-card-buildkit.service open-card-caddy.service open-card-server.service open-card-agent.service; do
    test -L "/etc/systemd/system/$unit.requires/open-card-upgrade-safe.target"
  done
  grep -Fq 'open-card-upgrade-recover.service' < <(systemctl show --value -p Requires "$safe")
  grep -Fq 'open-card-upgrade-finalize.service' < <(systemctl show --value -p Wants "$safe")
  for unit in "${units[@]}" "$finalize"; do
    grep -Fq "$unit" < <(systemctl show --value -p Before "$safe")
  done
}

initial() {
  install_fixture
  verify_graph

  # No marker: the condition-gated helpers are skipped and the safe target
  # permits every benign business unit to start.
  stop_business
  rm -f "$marker" "$state/prepare-ok" "$state/finalize-ok"
  printf 'success\n' >"$state/prepare-mode"
  printf 'success\n' >"$state/finalize-mode"
  systemctl start "$safe" "${units[@]}"
  for unit in "${units[@]}"; do systemctl is-active --quiet "$unit"; done
  [[ ! -e "$marker" ]]
  record_unit_states marker_absent

  # Prepare failure is a required dependency failure; no business unit may
  # become active and the marker remains authoritative.
  stop_business
  printf 'txn-prepare-fail\n' >"$marker"
  printf 'fail\n' >"$state/prepare-mode"
  printf 'success\n' >"$state/finalize-mode"
  set +e
  systemctl start "$safe" >"$evidence/prepare-failure-start.txt" 2>&1
  prepare_status=$?
  set -e
  [[ $prepare_status -ne 0 ]]
  [[ -f "$marker" ]]
  assert_inactive_business
  record_unit_states prepare_failure

  # Finalizer is intentionally a Wants dependency.  Its failure preserves the
  # marker and blocks the Edge through the canonical marker drop-in.
  stop_business
  systemctl reset-failed "$recover" "$safe" "$finalize" || true
  printf 'txn-finalize-fail\n' >"$marker"
  printf 'success\n' >"$state/prepare-mode"
  printf 'fail\n' >"$state/finalize-mode"
  systemctl start "$safe"
  for _ in $(seq 1 100); do
    [[ "$(systemctl show --value -p ActiveState "$finalize")" != activating ]] && break
    sleep 0.1
  done
  [[ -f "$marker" ]]
  [[ "$(systemctl show --value -p ActiveState open-card-edge.service)" != active ]]
  record_unit_states finalizer_failure

  # A successful terminal fixture removes the marker.  Starting the Edge only
  # after that durable terminal action proves the real drop-in condition opens.
  stop_business
  systemctl reset-failed "$recover" "$safe" "$finalize" || true
  printf 'txn-terminal-success\n' >"$marker"
  printf 'success\n' >"$state/prepare-mode"
  printf 'success\n' >"$state/finalize-mode"
  rm -f "$state/prepare-ok" "$state/finalize-ok"
  systemctl start "$safe"
  for _ in $(seq 1 100); do [[ ! -f "$marker" ]] && break; sleep 0.1; done
  [[ ! -f "$marker" && -f "$state/finalize-ok" ]]
  systemctl start open-card-edge.service
  systemctl is-active --quiet open-card-edge.service
  record_unit_states terminal_success

  # The reboot case deliberately leaves a failed prepare marker.  The host
  # reboots the VM; post-reboot asserts systemd's actual boot transaction.
  stop_business
  systemctl reset-failed "$recover" "$safe" "$finalize" || true
  printf 'txn-reboot-prepare-fail\n' >"$marker"
  printf 'fail\n' >"$state/prepare-mode"
  printf 'success\n' >"$state/finalize-mode"
  rm -f "$state/prepare-ok" "$state/finalize-ok"
  printf 'initial=PASS\n' >"$evidence/initial-result.txt"
}

post_reboot() {
  [[ -f "$marker" ]]
  [[ "$(cat "$state/prepare-mode")" == fail ]]
  systemctl is-failed --quiet "$recover"
  [[ "$(systemctl show --value -p ActiveState "$safe")" != active ]]
  assert_inactive_business
  [[ "$(systemctl show --value -p ActiveState open-card-edge.service)" != active ]]
  record_unit_states reboot_marker_prepare_failure
  journalctl -b --no-pager -u "$recover" -u "$safe" -u "$finalize" -u open-card-edge.service \
    >"$evidence/reboot-journal.txt"
  systemctl status --no-pager "$recover" "$safe" "$finalize" "${units[@]}" \
    >"$evidence/reboot-systemctl-status.txt" 2>&1 || true
  {
    printf 'guest_os=%s\n' "$(. /etc/os-release; printf %s "$PRETTY_NAME")"
    printf 'arch=%s\n' "$(uname -m)"
    printf 'memory_mib=%s\n' "$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
    printf 'vcpus=%s\n' "$(nproc)"
    printf 'initial=PASS\n'
    printf 'reboot_marker_prepare_failure=PASS\n'
    printf 'public_listeners=none\n'
  } >"$evidence/summary.txt"
}

case "$phase" in
  initial) initial ;;
  post-reboot) post_reboot ;;
esac
