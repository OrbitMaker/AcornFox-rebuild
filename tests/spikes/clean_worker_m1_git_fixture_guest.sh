#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/opencard-mvp-fa8f8eab/git-fixture
install -d -m 0750 "$root/source" "$root/www"
if [[ ! -f "$root/ca.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj '/CN=Open Card M1 Git Fixture CA' -keyout "$root/ca.key" -out "$root/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -sha256 -nodes -subj '/CN=git.opencard.test' -keyout "$root/server.key" -out "$root/server.csr" >/dev/null 2>&1
  printf '%s\n' 'subjectAltName=DNS:git.opencard.test,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' >"$root/server.ext"
  openssl x509 -req -sha256 -days 1 -in "$root/server.csr" -CA "$root/ca.crt" -CAkey "$root/ca.key" -CAcreateserial -extfile "$root/server.ext" -out "$root/server.crt" >/dev/null 2>&1
fi
install -m 0644 "$root/ca.crt" /usr/local/share/ca-certificates/opencard-mvp-fa8f8eab-git-fixture.crt
update-ca-certificates >/dev/null
grep -Fq '127.0.0.1 git.opencard.test' /etc/hosts || printf '%s\n' '127.0.0.1 git.opencard.test' >>/etc/hosts

git -C "$root/source" init -q -b main
git -C "$root/source" config user.name 'Open Card Fixture'
git -C "$root/source" config user.email 'fixture@opencard.invalid'
cp /opt/open-card/current/bin/open-card-static-server "$root/source/open-card-static-server"
chmod 0755 "$root/source/open-card-static-server"
printf '%s\n' '<!doctype html><title>Open Card M1 Git</title><h1>git-dockerfile-proof</h1>' >"$root/source/index.html"
cat >"$root/source/Dockerfile" <<'EOF'
FROM scratch
COPY --chmod=0555 open-card-static-server /open-card-static-server
COPY --chown=65532:65532 index.html /www/index.html
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/open-card-static-server","-root","/www","-listen",":8080"]
EOF
git -C "$root/source" add Dockerfile index.html open-card-static-server
git -C "$root/source" commit -q -m 'M1 deterministic Dockerfile fixture'
commit=$(git -C "$root/source" rev-parse HEAD)
git clone -q --bare "$root/source" "$root/www/m1.git"
git --git-dir="$root/www/m1.git" update-server-info
cat >"$root/https_server.py" <<'PY'
import http.server, os, ssl
os.chdir('/var/lib/opencard-mvp-fa8f8eab/git-fixture/www')
server=http.server.ThreadingHTTPServer(('127.0.0.1',443),http.server.SimpleHTTPRequestHandler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/var/lib/opencard-mvp-fa8f8eab/git-fixture/server.crt','/var/lib/opencard-mvp-fa8f8eab/git-fixture/server.key')
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
PY
systemctl stop opencard-mvp-fa8f8eab-git-fixture.service 2>/dev/null || true
systemd-run --quiet --unit=opencard-mvp-fa8f8eab-git-fixture --service-type=simple --property=Restart=no --property=PrivateTmp=yes /usr/bin/python3 "$root/https_server.py"
for _ in $(seq 1 30); do
  curl -fsS https://git.opencard.test/m1.git/HEAD >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS https://git.opencard.test/m1.git/HEAD >/dev/null
printf 'git_fixture_commit=%s\n' "$commit"
