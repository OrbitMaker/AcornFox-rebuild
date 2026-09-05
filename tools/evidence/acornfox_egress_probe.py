#!/usr/bin/env python3
import json
from pathlib import Path
import socket
import ssl
import struct
import sys


def counter_totals(document):
    counts = {}
    for entry in document["nftables"]:
        rule = entry.get("rule", {})
        label = rule.get("comment")
        if label:
            counts[label] = counts.get(label, 0) + sum(item.get("counter", {}).get("packets", 0) for item in rule["expr"])
    return counts


def verify_counter_evidence(probes, initial, final):
    required = {
        "dns_udp_allowed": "dns_udp_allowed", "dns_tcp_allowed": "dns_tcp_allowed",
        "public_http_allowed": "public_web_allowed", "public_https_allowed": "public_web_allowed",
        "metadata_denied": "metadata_denied", "private_lan_denied": "private_or_special_ipv4_denied",
        "cgnat_denied": "private_or_special_ipv4_denied", "loopback_denied": "loopback_denied",
        "public_port22_denied": "other_egress_denied", "ipv6_denied": "ipv6_denied",
        "unexpected_dns_udp_denied": "unexpected_dns_udp_denied", "unexpected_dns_tcp_denied": "unexpected_dns_tcp_denied",
    }
    names = [p["name"] for p in probes]
    if len(set(names)) != len(names) or set(names) != set(required) | {"resolved_public_ipv4"} or not all(p["ok"] is True for p in probes):
        raise ValueError("probe matrix is incomplete or failed")
    before, after = counter_totals(initial), counter_totals(final)
    for probe, counter in required.items():
        if after.get(counter, 0) <= before.get(counter, 0):
            raise ValueError(probe + " has no corresponding kernel counter increase")
    return {"status": "PASS", "probes": len(probes), "counter_increments": {c: after[c] - before.get(c, 0) for c in sorted(set(required.values()))}}


def result(name, ok, **details):
    print(json.dumps({"name": name, "ok": bool(ok), **details}, sort_keys=True), flush=True)
    return bool(ok)


def receive_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ValueError("truncated_dns_response")
        chunks.extend(part)
    return bytes(chunks)


def dns_query(resolver, tcp=False):
    txid = b"\xaf\xb0"
    question = b"\x08registry\x05npmjs\x03org\x00\x00\x01\x00\x01"
    packet = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    try:
        if tcp:
            with socket.create_connection((resolver, 53), 4) as sock:
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                size = struct.unpack("!H", receive_exact(sock, 2))[0]
                body = receive_exact(sock, size)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(4)
                sock.sendto(packet, (resolver, 53))
                body, _ = sock.recvfrom(2048)
        if len(body) < 12 or body[:2] != txid or body[3] & 0x0F:
            return False, None, "invalid_dns_response"
        return True, body, "ok"
    except Exception as exc:
        return False, None, type(exc).__name__


def answer_ipv4(body):
    if not body:
        return None
    offset = 12
    while body[offset] != 0:
        offset += body[offset] + 1
    offset += 5
    answers = struct.unpack("!H", body[6:8])[0]
    for _ in range(answers):
        if body[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while body[offset] != 0:
                offset += body[offset] + 1
            offset += 1
        kind, _, _, length = struct.unpack("!HHIH", body[offset:offset + 10])
        offset += 10
        data = body[offset:offset + length]
        offset += length
        if kind == 1 and length == 4:
            return socket.inet_ntoa(data)
    return None


def http_probe(ip, port, tls=False):
    try:
        with socket.create_connection((ip, port), 5) as raw:
            sock = raw
            if tls:
                sock = ssl.create_default_context().wrap_socket(raw, server_hostname="registry.npmjs.org")
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n")
            line = sock.recv(80).split(b"\r\n", 1)[0]
            return line.startswith(b"HTTP/"), line.decode("ascii", "replace")[:80]
    except Exception as exc:
        return False, type(exc).__name__


def denied_ipv4(name, ip, port):
    try:
        with socket.create_connection((ip, port), 3):
            return result(name, False, endpoint=f"{ip}:{port}", outcome="connected")
    except Exception as exc:
        return result(name, True, endpoint=f"{ip}:{port}", outcome=type(exc).__name__)


def denied_ipv6():
    ip = "::1"
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, 443, 0, 0))
        return result("ipv6_denied", False, endpoint=f"[{ip}]:443", outcome="connected")
    except Exception as exc:
        return result("ipv6_denied", True, endpoint=f"[{ip}]:443", outcome=type(exc).__name__)


def main():
    ok_udp, udp_body, udp_reason = dns_query("1.1.1.1", tcp=False)
    ok_tcp, _, tcp_reason = dns_query("1.0.0.1", tcp=True)
    success = result("dns_udp_allowed", ok_udp, resolver="1.1.1.1:53", outcome=udp_reason)
    success &= result("dns_tcp_allowed", ok_tcp, resolver="1.0.0.1:53", outcome=tcp_reason)
    resolved = answer_ipv4(udp_body)
    success &= result("resolved_public_ipv4", resolved is not None, value=resolved or "none")
    if resolved:
        http_ok, http_outcome = http_probe(resolved, 80)
        https_ok, https_outcome = http_probe(resolved, 443, tls=True)
        success &= result("public_http_allowed", http_ok, endpoint=f"{resolved}:80", outcome=http_outcome)
        success &= result("public_https_allowed", https_ok, endpoint=f"{resolved}:443", outcome=https_outcome)
    else:
        success = False
    
    success &= denied_ipv4("metadata_denied", "169.254.169.254", 80)
    success &= denied_ipv4("private_lan_denied", "192.168.122.1", 80)
    success &= denied_ipv4("loopback_denied", "127.0.0.1", 22)
    success &= denied_ipv4("public_port22_denied", "1.1.1.1", 22)
    success &= denied_ipv4("unexpected_dns_tcp_denied", "8.8.8.8", 53)
    other_dns, _, reason = dns_query("8.8.8.8")
    success &= result("unexpected_dns_udp_denied", not other_dns, outcome=reason)
    success &= denied_ipv4("cgnat_denied", "100.64.0.1", 443)
    success &= denied_ipv6()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--verify-counters":
        probes = [json.loads(line) for line in Path(sys.argv[2]).read_text().splitlines()]
        initial = json.loads(Path(sys.argv[3]).read_text())
        final = json.loads(Path(sys.argv[4]).read_text())
        print(json.dumps(verify_counter_evidence(probes, initial, final), sort_keys=True))
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: acornfox_egress_probe.py [--verify-counters PROBES INITIAL FINAL]")
