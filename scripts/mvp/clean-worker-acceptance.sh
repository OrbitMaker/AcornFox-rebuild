#!/usr/bin/env bash
set -euo pipefail

mode="${1:---dry-run}"
task_id="${OPEN_CARD_TASK_ID:-opencard-mvp-fa8f8eab}"
workspace="${OPEN_CARD_WORKER_WORKSPACE:-/var/lib/opencard-mvp-fa8f8eab/workspace}"
expected_memory="${OPEN_CARD_EXPECTED_MEMORY_MAX:-536870912}"
expected_cpu="${OPEN_CARD_EXPECTED_CPU_MAX:-50000 100000}"

test "$task_id" = "opencard-mvp-fa8f8eab"
case "$workspace" in
  /var/lib/opencard-mvp-fa8f8eab/*) ;;
  *) echo "workspace must stay inside the task prefix" >&2; exit 64 ;;
esac

if [[ "$mode" == "--dry-run" ]]; then
  printf '%s\n' \
    "mode=dry-run" \
    "workspace=$workspace" \
    "expected_memory_max=$expected_memory" \
    "expected_cpu_max=$expected_cpu" \
    "checks=memory,cpu,metadata,timeout,workspace,socket,privilege"
  exit 0
fi
if [[ "$mode" != "--execute-inside-approved-worker" ]]; then
  echo "unsupported acceptance mode" >&2
  exit 64
fi
test -f /etc/opencard-mvp-fa8f8eab-clean-worker
test "$(cat /sys/fs/cgroup/memory.max)" = "$expected_memory"
test "$(cat /sys/fs/cgroup/cpu.max)" = "$expected_cpu"
test ! -e /var/run/docker.sock
test ! -e /host
if curl --connect-timeout 2 --max-time 3 --fail http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
  echo "metadata endpoint unexpectedly reachable" >&2
  exit 1
fi
test -d "$workspace"
printf '%s\n' 'clean_worker_acceptance=PASS'
