import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from scanner import run_chain
from template_method import build_probe, check


class TemplateMethodTests(unittest.TestCase):
    def test_payload_vectors_from_original_javascript(self):
        # Golden length/checksum vectors produced by evaluating the original
        # upstream JavaScript builder, not by the Python implementation.
        vectors = [(1, 4000, 1048575, 2485031725),
                   (8, 1020, 8388605, 16116417),
                   (20, 1020, 20971517, 4227197633)]
        for mib, parts, length, checksum in vectors:
            body = build_probe(mib, parts)
            self.assertEqual(len(body), length)
            value = 2166136261
            for byte in body:
                value = ((value ^ byte) * 16777619) & 0xffffffff
            self.assertEqual(value, checksum)

    def test_memory_signature_is_only_ambiguous(self):
        with patch('template_method.exchange', side_effect=[
            {'http_status': 200}, {'http_status': 500, 'memory_error_signature': True}]):
            r = check('http://127.0.0.1:8080/')
        self.assertEqual(r['kind'], 'ambiguous_runtime_anomaly')
        self.assertEqual(r['request_count'], 2)
        self.assertFalse(r['rce_confirmed'])

    def test_rejection_is_inconclusive(self):
        for status in (403, 413, 429, 302):
            with patch('template_method.exchange', side_effect=[{'http_status': 200}, {'http_status': status}]):
                self.assertEqual(check('http://127.0.0.1:8080/')['kind'], 'inconclusive')

    def test_nonhealthy_control_stops_before_probe(self):
        with patch('template_method.exchange', return_value={'http_status': 503}) as send:
            r = check('http://127.0.0.1:8080/')
        self.assertEqual(r['request_count'], 1)
        self.assertEqual(send.call_count, 1)

    def test_fixed_banner_stops_after_first_probe(self):
        with patch('template_method.exchange', return_value={'http_status': 200, 'version': '8.3.36'}):
            r = check('http://127.0.0.1:8080/')
        self.assertEqual(r['request_count'], 2)
        self.assertEqual(r['kind'], 'version_only')

    def test_hidden_version_no_signal_is_not_patched(self):
        with patch('template_method.exchange', return_value={'http_status': 200}):
            r = check('http://127.0.0.1:8080/')
        self.assertEqual(r['kind'], 'no_signal')
        self.assertEqual(r['request_count'], 4)

    def test_transport_failure_is_not_cve_proof(self):
        with patch('template_method.exchange', side_effect=[{'http_status': 200}, {'error': 'TimeoutError'}]):
            self.assertEqual(check('http://127.0.0.1:8080/')['kind'], 'inconclusive')

    def test_correlated_methods_do_not_vote(self):
        with patch('scanner.scan', return_value={'target': 'http://localhost:8080/', 'status': 'unknown', 'http_status': 200}), \
             patch('scanner.run_template', return_value=[{'kind': 'ambiguous_runtime_anomaly'}]), \
             patch('scanner.run_active', return_value=[{'kind': 'ambiguous_runtime_anomaly'}]):
            r = run_chain('http://localhost:8080/', ['http://localhost:8080'], 'lab',
                          active_script='mocked', active_methods=('template', 'assetnote'), profile='lab')
        self.assertEqual(r['methods_enabled'], 3)
        self.assertEqual(r['findings'][0]['status'], 'suspicious_behavior')
        self.assertFalse(r['findings'][0]['rce_confirmed'])
        self.assertEqual(len(r['recovery_checks']), 2)

    def test_failed_recovery_stops_second_method(self):
        with patch('scanner.scan', side_effect=[
            {'target': 'http://localhost:8080/', 'status': 'unknown', 'http_status': 200},
            {'target': 'http://localhost:8080/', 'status': 'error'}]), \
             patch('scanner.run_template', return_value=[{'kind': 'inconclusive'}]), \
             patch('scanner.run_active') as second:
            r = run_chain('http://localhost:8080/', ['http://localhost:8080'], 'lab',
                          active_script='mocked', active_methods=('template', 'assetnote'), profile='lab')
        second.assert_not_called()
        self.assertTrue(r['active_stopped_after_recovery_failure'])


class NativeCLIIntegration(unittest.TestCase):
    def test_full_cli_without_nuclei_or_third_party_dependencies(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def respond(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8.3.36')
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'OK')
            def do_GET(self):
                requests.append('GET')
                self.respond()
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                if size > 21 * 1048576:
                    self.send_error(413)
                    return
                self.rfile.read(size)
                requests.append('POST')
                self.respond()
            def log_message(self, *args):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                proc = subprocess.run([sys.executable, '-S', str(Path(__file__).with_name('scanner.py')),
                    '--url', base + '/index.php', '--allow-origin', base,
                    '--authorization-ref', 'synthetic-lab', '--profile', 'lab', '--active', '--active-method', 'template'],
                    capture_output=True, text=True, timeout=20, check=True)
                report = json.loads(proc.stdout)
                self.assertEqual(requests, ['GET', 'POST', 'POST', 'GET'])
                self.assertEqual(report['methods_enabled'], 2)
                self.assertEqual(report['findings'][0]['status'], 'fix_level_advertised')
                self.assertEqual(report['active_evidence'][0]['request_count'], 2)
                self.assertGreaterEqual(report['timing']['total_elapsed_seconds'], 0)
            finally:
                server.shutdown()
                t.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)
