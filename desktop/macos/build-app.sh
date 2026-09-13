#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'usage: build-app.sh --resource-root DIR --base-gzip FILE --base-gzip-sha256 HEX --base-raw-sha256 HEX --base-raw-bytes BYTES --candidate-dir DIR --candidate-binding-sha256 HEX --output DIR'
}

[[ $# -eq 16 ]] || { usage >&2; exit 2; }
[[ $1 == --resource-root && $3 == --base-gzip && $5 == --base-gzip-sha256 && $7 == --base-raw-sha256 && $9 == --base-raw-bytes && ${11} == --candidate-dir && ${13} == --candidate-binding-sha256 && ${15} == --output ]] || { usage >&2; exit 2; }
resource_root=$2; base_gzip=$4; base_gzip_sha=$6; base_raw_sha=$8; base_raw_bytes=${10}; candidate_dir=${12}; binding_sha=${14}; output=${16}
[[ -d $resource_root && -f $base_gzip && -d $candidate_dir && $base_gzip_sha =~ ^[0-9a-f]{64}$ && $base_raw_sha =~ ^[0-9a-f]{64}$ && $binding_sha =~ ^[0-9a-f]{64}$ && $base_raw_bytes =~ ^[0-9]+$ ]] || { printf '%s\n' 'AcornFox build: resource input is invalid' >&2; exit 23; }
[[ $(shasum -a 256 "$base_gzip" | awk '{print $1}') == "$base_gzip_sha" ]] || { printf '%s\n' 'AcornFox build: base image digest mismatch' >&2; exit 23; }
[[ $(find "$candidate_dir" -maxdepth 1 -type f | wc -l | tr -d ' ') == 6 ]] || { printf '%s\n' 'AcornFox build: expected six candidate files' >&2; exit 23; }

app="$output/AcornFox.app"
[[ ! -e $app ]] || { printf '%s\n' 'AcornFox build: output package already exists' >&2; exit 23; }
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$base_gzip" "$app/Contents/Resources/base.raw.gz"
cp -R "$candidate_dir" "$app/Contents/Resources/candidate"
GOOS=linux GOARCH=arm64 go build -trimpath -o "$app/Contents/Resources/acornfox-guest-bridge" ./cmd/acornfox-guest-bridge
python3 desktop/macos/generate-manifest.py "$app/Contents/Resources" "$base_raw_sha" "$base_raw_bytes" "$binding_sha"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>AcornFox</string><key>CFBundleIdentifier</key><string>com.acornfox.local</string><key>CFBundleName</key><string>AcornFox</string><key>LSMinimumSystemVersion</key><string>13.0</string></dict></plist>
PLIST
cat > "$output/AcornFox.entitlements" <<'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>
ENTITLEMENTS
xcrun swiftc -parse-as-library -target arm64-apple-macos13.0 -framework AppKit -framework CryptoKit -framework Network -framework Virtualization desktop/macos/Sources/*.swift -o "$app/Contents/MacOS/AcornFox"
codesign --force --sign - --entitlements "$output/AcornFox.entitlements" "$app"
printf '%s\n' "AcornFox build: ad-hoc package created at $app"
