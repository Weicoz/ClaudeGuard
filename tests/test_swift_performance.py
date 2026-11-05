"""Probe the real native network path against loopback fixtures only."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift compiler required')
class SwiftPerformanceTests(unittest.TestCase):
    def test_probe_reuse_hedging_and_transport_isolation(self):
        counts = Counter()
        headers = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                counts[self.path] += 1
                headers.append(self.headers.get('Connection'))
                if self.path == '/slow':
                    time.sleep(0.8)
                body = b'x' * 65536 if self.path == '/oversized' else (b'invalid' if self.path == '/invalid' else b'203.0.113.10')
                self.send_response(503 if self.path == '/error' else 200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        source = (Path(__file__).resolve().parents[1] / 'src/main.swift').read_text()
        source = source.split('\n// MARK: - Entry point')[0]
        harness = r'''
class FakeSTUN: AppDelegate {
    var queries = 0
    override func stunQuery(host: String, port: UInt16, completion: @escaping (String?) -> Void) -> NWConnection? {
        queries += 1
        completion("203.0.113.10")
        return nil
    }
}
let native = FakeSTUN()
native.eventLogPath = CommandLine.arguments[2]
let base = CommandLine.arguments[1]
precondition(native.resolvePublicIP(deadline: 1, mode: "stun") == "203.0.113.10")
precondition(native.queries == 3 && native.httpSession == nil, "STUN created an unused HTTP session")
native.httpServices = [base + "/good", base + "/unused"]
precondition(native.resolvePublicIP(deadline: 1, mode: "http") == "203.0.113.10")
let first = native.httpSession!
precondition(native.resolvePublicIP(deadline: 1, mode: "http") == "203.0.113.10")
precondition(native.httpSession === first, "Healthy polls recreated the HTTP session")
precondition(native.queries == 3, "HTTP silently queried STUN")
native.policyConfig["http_proxy"] = "http://127.0.0.1:9"
let proxied = native.sessionForHTTPProbe(deadline: 1)
precondition(proxied !== first, "Proxy change reused the old session")
precondition(proxied.configuration.connectionProxyDictionary?["HTTPPort"] as? Int == 9)
native.policyConfig = [:]
native.preferredHTTPService = nil
native.httpServices = [base + "/slow", base + "/fallback"]
let started = Date()
precondition(native.resolvePublicIP(deadline: 1, mode: "http") == "203.0.113.10")
precondition(Date().timeIntervalSince(started) < 0.75, "Slow primary delayed fallback")
precondition(native.preferredHTTPService == base + "/fallback")
precondition(native.resolvePublicIP(deadline: 1, mode: "http") == "203.0.113.10")
native.httpServices = [base + "/error", base + "/invalid"]
precondition(native.resolvePublicIP(deadline: 0.4, mode: "http") == nil, "HTTP errors or malformed IPs allowed")
native.httpServices = [base + "/oversized"]
precondition(native.resolvePublicIP(deadline: 0.4, mode: "http") == nil, "Oversized provider response accepted")
native.httpSession?.invalidateAndCancel()
print("Native performance checks passed")
'''
        with tempfile.TemporaryDirectory() as directory, ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                main = Path(directory) / 'main.swift'
                executable = Path(directory) / 'check'
                main.write_text(source + harness)
                subprocess.run(['swiftc', '-O', str(main), '-o', str(executable)], check=True, capture_output=True, text=True, timeout=60)
                result = subprocess.run([str(executable), f'http://127.0.0.1:{server.server_port}', str(Path(directory) / 'events.jsonl')], check=True, capture_output=True, text=True, timeout=10)
                self.assertIn('Native performance checks passed', result.stdout)
                self.assertEqual(counts, {'/good': 2, '/slow': 1, '/fallback': 2, '/error': 1, '/invalid': 1, '/oversized': 1})
                self.assertEqual(set(headers), {'close'})
            finally:
                server.shutdown()
                thread.join(timeout=3)
