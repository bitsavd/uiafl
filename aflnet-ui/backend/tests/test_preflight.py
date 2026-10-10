import socket
import threading
import unittest
from unittest.mock import patch

from app.preflight import preflight, probe_tcp, probe_udp
from app.protocols import PROTOCOL_GROUPS


class PreflightTests(unittest.TestCase):
    def test_every_protocol_returns_structured_checks(self):
        for group in PROTOCOL_GROUPS:
            for entry in group['protocols']:
                with self.subTest(protocol=entry['id']):
                    transport = 'udp' if 'UDP' in entry['transport'] else 'tcp'
                    result = preflight(entry['id'], '127.0.0.1', 49152, transport)
                    names = {item['name'] for item in result['checks']}
                    self.assertTrue({'检测引擎', '测试种子', '传输协议', '本地目标程序', '本地端口', '协议响应'} <= names)
                    self.assertTrue(all(item['status'] in {'pass', 'fail', 'warning'} for item in result['checks']))

    def test_occupied_local_port_blocks_readiness(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            result = preflight('MODBUS', '127.0.0.1', listener.getsockname()[1], 'tcp')
        self.assertEqual(next(item for item in result['checks'] if item['name'] == '本地端口')['status'], 'fail')
        self.assertFalse(result['ok'])

    def test_missing_configuration_is_not_marked_ready(self):
        result = preflight('SNMP', '127.0.0.1', 49152, 'udp')
        self.assertFalse(result['ok'])
        self.assertEqual(next(item for item in result['checks'] if item['name'] == '测试种子')['status'], 'fail')

    def test_transport_mismatch(self):
        result = preflight('MODBUS', '127.0.0.1', 49152, 'udp')
        self.assertEqual(next(item for item in result['checks'] if item['name'] == '传输协议')['status'], 'fail')

    def test_modbus_fragmented_response(self):
        client, server = socket.socketpair()
        errors = []

        def respond():
            try:
                with server:
                    request = server.recv(12)
                    self.assertEqual(request, bytes.fromhex('000100000006010300000001'))
                    for byte in bytes.fromhex('0001000000050103020001'):
                        server.sendall(bytes([byte]))
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=respond)
        worker.start()
        with client:
            client.settimeout(2)
            self.assertEqual(probe_tcp(client, 'MODBUS', '127.0.0.1')[0], 'pass')
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)

    def test_tcp_connection_does_not_prove_protocol(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall(b'HTTP/1.1 200 OK\r\n')
            self.assertEqual(probe_tcp(client, 'SSH', '127.0.0.1')[0], 'warning')

    def test_udp_without_probe_is_unverified(self):
        self.assertEqual(probe_udp([], 'SNMP')[0], 'warning')

    def test_dns_failure_is_reported(self):
        with patch('app.preflight.socket.getaddrinfo', side_effect=socket.gaierror()):
            result = preflight('MQTT', 'device.invalid', 1883, 'tcp')
        self.assertFalse(result['ok'])
        self.assertEqual(result['checks'][-1]['name'], '目标地址')


if __name__ == '__main__':
    unittest.main()
