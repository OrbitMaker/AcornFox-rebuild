#!/usr/bin/env bash

# Shared shell helpers. This file is sourced by the stage scripts and is not
# intended to be executed directly.

if [[ -n ${OPENCARD_COMMON_LOADED:-} ]]; then
  return 0
fi
OPENCARD_COMMON_LOADED=1

oc_die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

oc_warn() {
  printf 'WARN: %s\n' "$*" >&2
}

oc_info() {
  printf 'INFO: %s\n' "$*"
}

oc_have() {
  command -v "$1" >/dev/null 2>&1
}

oc_require_commands() {
  local command_name
  for command_name in "$@"; do
    oc_have "$command_name" || oc_die "required local command is missing: $command_name"
  done
}

oc_sha256() {
  if oc_have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

oc_b64() {
  printf '%s' "$1" | base64 | tr -d '\n'
}
