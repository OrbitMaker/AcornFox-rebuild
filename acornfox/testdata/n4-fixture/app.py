"""HTTP fixture for N4 acceptance. Never print connection URLs or passwords."""
import json
import os
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

MARKER = Path("/data/n4-marker")


def database(action=None, value=None):
    raw = os.getenv("DATABASE_URL")
    if not raw:
        return None
    url = urlparse(raw)
    kwargs = dict(user=unquote(url.username), password=unquote(url.password),
                  host=url.hostname, port=url.port, database=url.path.lstrip("/"))
    if url.scheme in ("postgres", "postgresql"):
        import pg8000.dbapi
        conn = pg8000.dbapi.connect(**kwargs, timeout=5)
        kind = "postgres"
        upsert = "INSERT INTO n4_marker VALUES (1, %s) ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value"
    elif url.scheme == "mysql":
        import pymysql
        # TLS permits MySQL's default caching_sha2_password without RSA helpers.
        conn = pymysql.connect(**kwargs, connect_timeout=5,
                               ssl={"check_hostname": False})
        kind = "mysql"
        upsert = "INSERT INTO n4_marker VALUES (1, %s) ON DUPLICATE KEY UPDATE value=VALUES(value)"
    else:
        raise ValueError("unsupported database scheme")
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1")
        result = dict(kind=kind, ready=cur.fetchone()[0] == 1)
        if action in ("write", "read"):
            cur.execute("CREATE TABLE IF NOT EXISTS n4_marker (id INTEGER PRIMARY KEY, value VARCHAR(128))")
            if action == "write":
                cur.execute(upsert, (value,))
            cur.execute("SELECT value FROM n4_marker WHERE id=1")
            row = cur.fetchone()
            result["marker"] = row[0] if row else None
            conn.commit()
        return result
    finally:
        conn.close()


def redis_state(action=None, value=None):
    raw = os.getenv("REDIS_URL")
    if not raw:
        return None
    import redis
    with redis.Redis.from_url(raw, socket_connect_timeout=5, socket_timeout=5,
                              decode_responses=True) as conn:
        result = dict(ready=bool(conn.ping()))
        if action == "write":
            conn.set("n4-marker", value)
        if action in ("read", "write"):
            result["marker"] = conn.get("n4-marker")
        return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        url = urlparse(self.path)
        value = parse_qs(url.query).get("value", ["n4-marker"])[0][:128]
        try:
            if url.path == "/write":
                MARKER.parent.mkdir(parents=True, exist_ok=True)
                MARKER.write_text(value)
            if url.path == "/busy":
                until = time.monotonic() + 2
                while time.monotonic() < until:
                    sum(i * i for i in range(1000))
            if url.path == "/emit-secret":
                # Only a synthetic value set by the acceptance driver is logged.
                print("n4-log-secret=" + os.getenv("N4_SYNTHETIC_SECRET", "unset"), flush=True)
            action = url.path.removeprefix("/db/") if url.path.startswith("/db/") else None
            result = dict(ok=True, file=MARKER.read_text() if MARKER.exists() else None,
                          database=database(action, value), redis=redis_state(action, value))
            status = 200
        except Exception as error:
            # Exception messages can include DSNs. Only expose the error class.
            result, status = dict(ok=False, error=type(error).__name__), 503
        raw = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def heartbeat():
    while True:
        print("n4-repeat", flush=True)
        time.sleep(1)


threading.Thread(target=heartbeat, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
