#!/usr/bin/env bash
set -euo pipefail

[[ $(hostname) = acornfox-afb-build-03b-product-p2-20260905 ]] || exit 23

readonly policy='/etc/acornfox/acornfox-controlled-egress-policy-v1.json'
readonly policy_nft='/etc/acornfox/acornfox-p0-policy.nft'
readonly expected_digest='6deae056bad3b82599282a49c65c3cb8080ab2956fd45cdf64249959c4862ebd'

die() { printf '%s\n' "acornfox-p0-policy: $*" >&2; exit 23; }
actual_digest() { sha256sum "$policy" | awk '{print $1}'; }

[[ ${1:-} = apply || ${1:-} = check || ${1:-} = counters ]] || die 'usage: apply|check|counters'
[[ -r "$policy" && -r "$policy_nft" ]] || die 'policy inputs missing'
[[ $(actual_digest) = "$expected_digest" ]] || die 'policy digest mismatch'

case "$1" in
  apply)
    /usr/sbin/nft list table inet acornfox_p0 >/dev/null 2>&1 && /usr/sbin/nft delete table inet acornfox_p0 || true
    /usr/sbin/nft -c -f "$policy_nft"
    /usr/sbin/nft -f "$policy_nft"
    /usr/sbin/nft list table inet acornfox_p0 >/dev/null
    ;;
  check)
    /usr/sbin/nft list table inet acornfox_p0 >/dev/null
    ;;
  counters)
    /usr/sbin/nft -a list table inet acornfox_p0
    ;;
esac
