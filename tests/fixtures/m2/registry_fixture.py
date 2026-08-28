#!/usr/bin/env python3
"""Small deterministic OCI Distribution fixture for the M2 clean worker.

It intentionally implements only the read/resolve path used by the test.  It
is loopback-only, has no push endpoint, and never logs the Basic-auth token.
The generated manifests and layers are ordinary OCI objects so an ImageStore
can fetch and verify them by digest rather than trusting the source tag.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import socketserver
import tarfile
import tempfile
import threading
import time
from typing import Any


OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def layer_bytes(binary: pathlib.Path, marker: str) -> tuple[bytes, str]:
    with tempfile.NamedTemporaryFile(prefix="opencard-m2-layer-", suffix=".tar", delete=False) as handle:
        name = handle.name
    try:
        with tarfile.open(name, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for directory in ("var/", "var/lib/", "var/lib/opencard/", "var/lib/opencard/data/"):
                directory_info = tarfile.TarInfo(directory)
                directory_info.type = tarfile.DIRTYPE
                directory_info.mode = 0o750
                directory_info.uid = 65532
                directory_info.gid = 65532
                directory_info.mtime = 0
                archive.addfile(directory_info)
            info = tarfile.TarInfo("open-card-static-server")
            payload = binary.read_bytes()
            info.size = len(payload)
            info.mode = 0o755
            info.uid = 65532
            info.gid = 65532
            info.mtime = 0
            archive.addfile(info, __import__("io").BytesIO(payload))
            marker_bytes = (marker + "\n").encode("utf-8")
            marker_info = tarfile.TarInfo("www/index.html")
            marker_info.size = len(marker_bytes)
            marker_info.mode = 0o644
            marker_info.uid = 65532
            marker_info.gid = 65532
            marker_info.mtime = 0
            archive.addfile(marker_info, __import__("io").BytesIO(marker_bytes))
        raw = pathlib.Path(name).read_bytes()
        return gzip.compress(raw, mtime=0), digest(raw)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


class RegistryState:
    def __init__(self, root: pathlib.Path, binary: pathlib.Path, token: str, control_token: str) -> None:
        self.root = root
        self.binary = binary
        self.token = token
        self.control_token = control_token
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict[str, Any]] = {}
        self.tags: dict[tuple[str, str], str] = {}
        self.private: set[str] = set()
        self._build()

    def _build_image(self, repository: str, marker: str, private: bool) -> str:
        layer, diff_id = layer_bytes(self.binary, marker)
        layer_digest = digest(layer)
        # A deterministic config is enough for registry resolution and OCI
        # verification.  The layer is a normal scratch rootfs layer.
        entrypoint = ["/open-card-static-server", "-root", "/www", "-listen", ":8080"]
        if repository == "opencard/m2/db":
            entrypoint.extend(
                [
                    "-state-file",
                    "/var/lib/opencard/data/m2-volume-canary",
                    "-state-content",
                    "M2-VOLUME-CANARY-V1",
                ]
            )
        config = json_bytes(
            {
                "architecture": "amd64",
                "config": {
                    "Entrypoint": entrypoint,
                    "Env": [],
                    "User": "65532:65532",
                    "WorkingDir": "/",
                },
                "created": "1970-01-01T00:00:00Z",
                "os": "linux",
                "rootfs": {"diff_ids": [diff_id], "type": "layers"},
            }
        )
        config_digest = digest(config)
        manifest = json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": len(config)},
                "layers": [{"mediaType": OCI_LAYER, "digest": layer_digest, "size": len(layer)}],
            }
        )
        manifest_digest = digest(manifest)
        self.blobs[layer_digest] = layer
        self.blobs[config_digest] = config
        self.blobs[manifest_digest] = manifest
        self.manifests[manifest_digest] = json.loads(manifest.decode("utf-8"))
        self.tags[(repository, "stable")] = manifest_digest
        self.tags[(repository, "v1")] = manifest_digest
        if private:
            self.private.add(repository)
        return manifest_digest

    def _build(self) -> None:
        self._build_image("opencard/m2/public", "M2-REGISTRY-PUBLIC-V1", False)
        self._build_image("opencard/m2/public-v2", "M2-REGISTRY-PUBLIC-V2", False)
        self._build_image("opencard/m2/private", "M2-REGISTRY-PRIVATE-V1", True)
        self._build_image("opencard/m2/db", "M2-REGISTRY-DB", True)
        self._build_image("opencard/m2/api", "M2-REGISTRY-API", True)

    def write_map(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        value = {
            "schema": "m2-registry-fixture-v1",
            "repositories": {
                repository: {tag: digest_value for (repo, tag), digest_value in self.tags.items() if repo == repository}
                for repository in sorted({repo for repo, _ in self.tags})
            },
            "private_repositories": sorted(self.private),
            "platform": {"os": "linux", "architecture": "amd64"},
        }
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(path, 0o640)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OpenCardM2Registry/1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Never write request headers: Authorization is intentionally absent
        # from all fixture logs.
        return

    @property
    def state(self) -> RegistryState:
        return self.server.state  # type: ignore[attr-defined]

    def _authorized(self, repository: str) -> bool:
        if repository not in self.state.private:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except Exception:
            return False
        return decoded == "fixture:" + self.state.token

    def _json(self, status: int, value: Any) -> None:
        payload = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _blob(self, status: int, payload: bytes, media_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Docker-Content-Digest", digest(payload))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _head_blob(self, status: int, payload: bytes, media_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Docker-Content-Digest", digest(payload))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/v2/" or self.path == "/v2":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        prefix = "/v2/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        path = self.path[len(prefix) :]
        if "/manifests/" in path:
            repository, reference = path.split("/manifests/", 1)
            if not self._authorized(repository):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="opencard-m2-registry"')
                self.end_headers()
                return
            manifest_digest = reference if reference.startswith("sha256:") else self.state.tags.get((repository, reference), "")
            payload = self.state.blobs.get(manifest_digest)
            if payload is None:
                self.send_error(404)
                return
            self._head_blob(200, payload, OCI_MANIFEST)
            return
        if "/blobs/" in path:
            repository, blob_digest = path.split("/blobs/", 1)
            if not self._authorized(repository):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="opencard-m2-registry"')
                self.end_headers()
                return
            payload = self.state.blobs.get(blob_digest)
            if payload is None:
                self.send_error(404)
                return
            self._head_blob(200, payload, OCI_LAYER if payload.startswith(b"\x1f\x8b") else OCI_CONFIG)
            return
        self.send_error(404)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v2/" or self.path == "/v2":
            self._json(200, {})
            return
        prefix = "/v2/"
        if not self.path.startswith(prefix):
            self._json(404, {"errors": [{"code": "NAME_UNKNOWN", "message": "unknown endpoint"}]})
            return
        path = self.path[len(prefix) :]
        if "/manifests/" in path:
            repository, reference = path.split("/manifests/", 1)
            if not self._authorized(repository):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="opencard-m2-registry"')
                self.end_headers()
                return
            manifest_digest = reference if reference.startswith("sha256:") else self.state.tags.get((repository, reference), "")
            if not manifest_digest or manifest_digest not in self.state.blobs:
                self._json(404, {"errors": [{"code": "MANIFEST_UNKNOWN", "message": "manifest not found"}]})
                return
            self._blob(200, self.state.blobs[manifest_digest], OCI_MANIFEST)
            return
        if "/blobs/" in path:
            repository, blob_digest = path.split("/blobs/", 1)
            if not self._authorized(repository):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="opencard-m2-registry"')
                self.end_headers()
                return
            payload = self.state.blobs.get(blob_digest)
            if payload is None:
                self._json(404, {"errors": [{"code": "BLOB_UNKNOWN", "message": "blob not found"}]})
                return
            media_type = OCI_LAYER if payload.startswith(b"\x1f\x8b") else OCI_CONFIG
            self._blob(200, payload, media_type)
            return
        self._json(404, {"errors": [{"code": "NAME_UNKNOWN", "message": "unknown endpoint"}]})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/__control/move-tag":
            self._json(404, {"error": "control endpoint not found"})
            return
        if self.client_address[0] not in {"127.0.0.1", "::1"} or self.headers.get("X-Open-Card-Fixture") != self.state.control_token:
            self._json(403, {"error": "fixture control authorization failed"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            value = json.loads(self.rfile.read(length))
            repository = str(value["repository"])
            tag = str(value["tag"])
            target = str(value["target"])
            if repository in self.state.private or not target.startswith("sha256:") or target not in self.state.blobs:
                raise ValueError("invalid tag move")
            self.state.tags[(repository, tag)] = target
        except Exception:
            self._json(400, {"error": "invalid tag move"})
            return
        self._json(200, {"repository": repository, "tag": tag, "digest": target})


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, help="127.0.0.1:port")
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--control-token-file", required=True)
    parser.add_argument("--static-binary", required=True)
    args = parser.parse_args()
    host, port_text = args.listen.rsplit(":", 1)
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("registry fixture must bind loopback")
    root = pathlib.Path(args.data_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    binary = pathlib.Path(args.static_binary).resolve()
    if not binary.is_file() or not os.access(binary, os.R_OK):
        raise SystemExit("canonical static server binary is required")
    token = pathlib.Path(args.token_file).read_text(encoding="utf-8").strip()
    control_token = pathlib.Path(args.control_token_file).read_text(encoding="utf-8").strip()
    if len(token) < 24 or len(control_token) < 24 or any(char in token + control_token for char in "\r\n\x00"):
        raise SystemExit("fixture token is invalid")
    state = RegistryState(root, binary, token, control_token)
    map_path = root / "registry-map.json"
    state.write_map(map_path)
    server = ThreadingServer((host, int(port_text)), Handler)
    server.state = state  # type: ignore[attr-defined]
    ready = pathlib.Path(args.ready_file)
    ready.write_text(json.dumps({"listen": args.listen, "map": str(map_path)}) + "\n", encoding="utf-8")
    os.chmod(ready, 0o640)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.shutdown()
        server.server_close()
        try:
            ready.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
