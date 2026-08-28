#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${SPIKE_OUTPUT_DIR:-artifacts/mvp/m0/SPIKE-S0-GO}"
PORT="${OPEN_CARD_SPIKE_PORT:-18482}"
mkdir -p "$OUTPUT_DIR"

if [[ -n "$(gofmt -l cmd internal api/agent/v1)" ]]; then
  echo "Go sources are not formatted" >&2
  exit 1
fi

packages="$(go list ./... | grep -v '/web/')"
# Package import paths cannot contain whitespace; intentional word splitting
# keeps this compatible with the Bash 3.2 shipped on macOS.
# shellcheck disable=SC2086
go test -count=1 $packages
# shellcheck disable=SC2086
go test -race -count=1 $packages
# shellcheck disable=SC2086
go vet $packages

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$OUTPUT_DIR/open-card-server-linux-amd64" ./cmd/open-card-server
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$OUTPUT_DIR/open-card-server-linux-arm64" ./cmd/open-card-server
go build -trimpath -o "$OUTPUT_DIR/open-card-server-host" ./cmd/open-card-server

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "spike port $PORT is already occupied" >&2
  exit 1
fi

start_ns="$(python3 -c 'import time; print(time.time_ns())')"
OPEN_CARD_SERVER_ADDR="127.0.0.1:$PORT" "$OUTPUT_DIR/open-card-server-host" >"$OUTPUT_DIR/server.stdout.log" 2>"$OUTPUT_DIR/server.stderr.log" &
server_pid=$!
cleanup() {
  kill "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null; then
    break
  fi
  sleep 0.05
done
curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null
ready_ns="$(python3 -c 'import time; print(time.time_ns())')"
cold_ms=$(( (ready_ns - start_ns) / 1000000 ))
if (( cold_ms > 3000 )); then
  echo "cold start exceeded 3000ms: ${cold_ms}ms" >&2
  exit 1
fi

request_pids=()
for i in $(seq 1 20); do
  curl -fsS -X POST -H 'content-type: application/json' \
    -d "{\"name\":\"concurrent-$i\"}" \
    "http://127.0.0.1:$PORT/api/v1/applications" >/dev/null &
  request_pids+=("$!")
done
for request_pid in "${request_pids[@]}"; do
  wait "$request_pid"
done
application_count="$(curl -fsS "http://127.0.0.1:$PORT/api/v1/applications" | jq '.items | length')"
if [[ "$application_count" != 20 ]]; then
  echo "expected 20 applications, got $application_count" >&2
  exit 1
fi

rss_kib="$(ps -o rss= -p "$server_pid" | tr -d ' ')"
if [[ -z "$rss_kib" || "$rss_kib" -gt 204800 ]]; then
  echo "idle RSS exceeded 200MiB: ${rss_kib:-unknown} KiB" >&2
  exit 1
fi

printf '%s\n' \
  "go_version=$(go version)" \
  'linux_amd64_build=ok' \
  'linux_arm64_build=ok' \
  'race=ok' \
  'vet=ok' \
  "cold_start_ms=$cold_ms" \
  "idle_rss_kib=$rss_kib" \
  "concurrent_crud_count=$application_count"
