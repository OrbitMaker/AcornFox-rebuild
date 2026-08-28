#!/usr/bin/env python3
import http.server
import os
import ssl
import subprocess
import urllib.parse

ROOT = "/var/lib/opencard-mvp-fa8f8eab/git-fixture/www"
BACKEND = "/usr/lib/git-core/git-http-backend"


class GitHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.serve_git()

    def do_POST(self):
        self.serve_git()

    def serve_git(self):
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        env = {
            "PATH": "/usr/bin:/bin",
            "GIT_PROJECT_ROOT": ROOT,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_ADDR": self.client_address[0],
            "SERVER_PROTOCOL": self.protocol_version,
        }
        result = subprocess.run([BACKEND], input=body, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, check=False)
        head, separator, payload = result.stdout.partition(b"\r\n\r\n")
        line_separator = "\r\n"
        if not separator:
            head, separator, payload = result.stdout.partition(b"\n\n")
            line_separator = "\n"
        if not separator:
            self.send_error(500)
            return
        status = 200
        headers = []
        for line in head.decode("latin-1").split(line_separator):
            name, value = line.split(":", 1)
            if name.lower() == "status":
                status = int(value.strip().split()[0])
            else:
                headers.append((name.strip(), value.strip()))
        self.send_response(status)
        has_length = False
        for name, value in headers:
            self.send_header(name, value)
            has_length = has_length or name.lower() == "content-length"
        if not has_length:
            self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), GitHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    "/var/lib/opencard-mvp-fa8f8eab/git-fixture/server.crt",
    "/var/lib/opencard-mvp-fa8f8eab/git-fixture/server.key",
)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
