import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


class ModbusStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='modbus-stream-test-')
        cls.binary = Path(cls.directory.name) / 'server'
        source = Path(__file__).with_name('modbus_tcp_server.c')
        subprocess.run(['cc', '-O0', '-Wall', '-Wextra', str(source), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            self.port = reserved.getsockname()[1]
        self.process = subprocess.Popen([str(self.binary), str(self.port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_server)
        for _ in range(50):
            try:
                self.connection = socket.create_connection(('127.0.0.1', self.port), timeout=.2)
                self.connection.settimeout(2)
                self.addCleanup(self.connection.close)
                return
            except OSError:
                time.sleep(.02)
        self.fail('Server failed to start')

    def stop_server(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def request(self, transaction=1):
        return struct.pack('!HHHBBHH', transaction, 0, 6, 1, 3, 0, 1)

    def response(self, transaction=1):
        return struct.pack('!HHHBBB H', transaction, 0, 5, 1, 3, 2, 0)

    def read(self, length):
        data = b''
        while len(data) < length:
            part = self.connection.recv(length - len(data))
            if not part:
                break
            data += part
        return data

    def test_all_frame_split_positions(self):
        request = self.request()
        for split in range(1, len(request)):
            self.connection.sendall(request[:split])
            time.sleep(.01)
            self.connection.sendall(request[split:])
            self.assertEqual(self.read(11), self.response())

    def test_byte_by_byte(self):
        for byte in self.request():
            self.connection.sendall(bytes([byte]))
            time.sleep(.01)
        self.assertEqual(self.read(11), self.response())

    def test_many_coalesced_requests(self):
        self.connection.sendall(b''.join(self.request(i) for i in range(32)))
        self.assertEqual(self.read(32 * 11), b''.join(self.response(i) for i in range(32)))

    def test_complete_frame_then_partial_frame(self):
        self.connection.sendall(self.request(1) + self.request(2)[:5])
        self.assertEqual(self.read(11), self.response(1))
        self.connection.sendall(self.request(2)[5:])
        self.assertEqual(self.read(11), self.response(2))

    def test_truncated_frame_does_not_generate_response(self):
        self.connection.sendall(self.request()[:-1])
        self.connection.shutdown(socket.SHUT_WR)
        self.assertEqual(self.read(11), b'')

    def test_invalid_lengths_close_connection(self):
        self.connection.sendall(struct.pack('!HHHB', 1, 0, 65535, 1))
        self.assertEqual(self.read(11), b'')


if __name__ == '__main__':
    unittest.main()
