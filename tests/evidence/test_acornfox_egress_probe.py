import importlib.util
import pathlib
import socket
import struct
import unittest
from unittest.mock import patch


path = pathlib.Path(__file__).parents[2] / "tools/evidence/acornfox_egress_probe.py"
spec = importlib.util.spec_from_file_location("acornfox_egress_probe", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Datagram:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, value):
        pass

    def sendto(self, packet, address):
        self.packet = packet

    def recvfrom(self, size):
        self.assert_packet()
        response = self.packet[:2] + b"\x81\x80" + self.packet[4:]
        return response, ("1.1.1.1", 53)

    def assert_packet(self):
        assert self.packet[:12] == struct.pack("!HHHHHH", 0xAFB0, 0x0100, 1, 0, 0, 0)
        assert self.packet[12:] == b"\x08registry\x05npmjs\x03org\0\0\x01\0\x01"


class Stream(Datagram):
    def sendall(self, packet):
        size = struct.unpack("!H", packet[:2])[0]
        self.packet = packet[2:]
        assert size == len(self.packet)
        self.assert_packet()
        self.response = packet[:2] + self.packet[:2] + b"\x81\x80" + self.packet[4:]

    def recv(self, size):
        # TCP does not promise a complete length prefix or frame per read.
        result, self.response = self.response[:1], self.response[1:]
        return result


class ProbeWireTest(unittest.TestCase):
    def test_connection_errors_without_kernel_denials_cannot_pass(self):
        names = ["dns_udp_allowed", "dns_tcp_allowed", "resolved_public_ipv4", "public_http_allowed", "public_https_allowed", "metadata_denied", "private_lan_denied", "cgnat_denied", "loopback_denied", "public_port22_denied", "ipv6_denied", "unexpected_dns_udp_denied", "unexpected_dns_tcp_denied"]
        rows = [{"name": name, "ok": True} for name in names]
        with self.assertRaisesRegex(ValueError, "no corresponding kernel"):
            probe.verify_counter_evidence(rows, {"nftables": []}, {"nftables": []})

    def test_dns_udp_sends_binary_wire_format(self):
        with patch.object(socket, "socket", return_value=Datagram()):
            self.assertTrue(probe.dns_query("1.1.1.1")[0])

    def test_dns_tcp_accepts_fragmented_wire_response(self):
        with patch.object(socket, "create_connection", return_value=Stream()):
            self.assertTrue(probe.dns_query("1.0.0.1", tcp=True)[0])

    def test_truncated_tcp_response_is_failure(self):
        stream = Stream()
        stream.recv = lambda size: b""
        with patch.object(socket, "create_connection", return_value=stream):
            self.assertFalse(probe.dns_query("1.0.0.1", tcp=True)[0])

    def test_http_uses_actual_crlf(self):
        stream = Datagram()
        sent = []
        stream.sendall = sent.append
        stream.recv = lambda size: b"HTTP/1.1 200 OK\r\n"
        with patch.object(socket, "create_connection", return_value=stream):
            self.assertTrue(probe.http_probe("1.1.1.1", 80)[0])
        self.assertEqual(sent, [b"HEAD / HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n"])


if __name__ == "__main__":
    unittest.main()
