#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
output=$(mktemp -d /private/tmp/acornfox-macos-tests.XXXXXX)
trap 'rm -rf "$output"' EXIT
sources=()
for source in desktop/macos/Sources/*.swift; do
  [[ $source == */main.swift ]] || sources+=("$source")
done
sources+=(desktop/macos/Tests/FixtureSupport.swift)
all_tests=(DiskPreparerTests EFIPreparerTests SeedPreparerTests LoopbackForwarderTests ProvisioningTests GracefulStopTests NetworkIdentityTests InstalledInstanceTests SSHPathDiagnosticsTests NativeInstanceProvisionerTests InitialBootstrapSessionTests)
if [[ $# -gt 0 ]]; then
  selected_tests=()
  for arg in "$@"; do
    matched=false
    for t in "${all_tests[@]}"; do
      if [[ "$arg" == "$t" ]]; then
        matched=true
        selected_tests+=("$arg")
        break
      fi
    done
    if [[ "$matched" != true ]]; then
      echo "Unknown test: $arg" >&2
      exit 1
    fi
  done
else
  selected_tests=("${all_tests[@]}")
fi

for test in "${selected_tests[@]}"; do
  xcrun swiftc -parse-as-library -target arm64-apple-macos13.0 -framework CryptoKit -framework Network -framework Virtualization "${sources[@]}" "desktop/macos/Tests/$test.swift" -o "$output/$test"
  "$output/$test"
done

if [[ $# -eq 0 ]]; then
  PYTHONDONTWRITEBYTECODE=1 python3 desktop/macos/Tests/manifest_tests.py
  PYTHONDONTWRITEBYTECODE=1 python3 desktop/macos/Tests/guest_resume_tests.py
  PYTHONDONTWRITEBYTECODE=1 python3 desktop/macos/Tests/helper_contract_tests.py
  xcrun swiftc -parse-as-library -target arm64-apple-macos13.0 -framework AppKit -framework CryptoKit -framework Network -framework Virtualization desktop/macos/Sources/*.swift -o "$output/AcornFox"
  bash -n desktop/macos/build-app.sh
fi
