#!/usr/bin/env bash

# SSH helpers. They deliberately require BatchMode and passwordless sudo so a
# deployment cannot hang waiting for an unattended password prompt.

if [[ -n ${OPENCARD_SSH_LOADED:-} ]]; then
  return 0
fi
OPENCARD_SSH_LOADED=1

OC_SSH_ARGS=(
  -o BatchMode=yes
  -o ConnectTimeout="${SSH_CONNECT_TIMEOUT}"
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking="${SSH_STRICT_HOST_KEY_CHECKING}"
)

oc_ssh() {
  local host=${1:?host required}
  shift
  local key
  local user=$SSH_USER
  key="$(oc_ssh_key_for_host "$host")"
  if [[ $host != "$DEV_HOST" && $host != "$TEST_HOST" ]]; then
    user=$VM_SSH_USER
  fi
  if [[ -n $key ]]; then
    ssh -n "${OC_SSH_ARGS[@]}" -i "$key" "${user}@${host}" "$@"
  else
    ssh -n "${OC_SSH_ARGS[@]}" "${user}@${host}" "$@"
  fi
}

oc_ssh_root() {
  local host=${1:?host required}
  shift
  oc_ssh "$host" sudo -n "$@"
}

oc_ssh_root_script() {
  local host=${1:?host required}
  shift
  local key
  local user=$SSH_USER
  key="$(oc_ssh_key_for_host "$host")"
  if [[ $host != "$DEV_HOST" && $host != "$TEST_HOST" ]]; then
    user=$VM_SSH_USER
  fi
  if [[ -n $key ]]; then
    ssh "${OC_SSH_ARGS[@]}" -i "$key" "${user}@${host}" sudo -n bash -s -- "$@"
  else
    ssh "${OC_SSH_ARGS[@]}" "${user}@${host}" sudo -n bash -s -- "$@"
  fi
}

oc_wait_ssh() {
  local host=${1:?host required}
  local attempts=${2:-60}
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if oc_ssh "$host" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}
