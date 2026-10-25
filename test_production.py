import json
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from php_version import scan
from scanner import run_chain

TARGET = 'https://audit.example.com/application/'
ORIGIN = 'https://audit.example.com'


class ProductionTests(unittest.TestCase):
    def test_real_domain_url_is_supported_without_localhost_requirement(self):
        with patch('scanner.scan', return_value={'target': TARGET, 'http_status': 200,
                   'status': 'potentially_affected', 'version': '8.3.35'}), \
             patch('scanner.run_template') as native, patch('scanner.run_active') as upstream:
            result = run_chain(TARGET, [ORIGIN], 'approved-vapt-engagement')
        self.assertEqual(result['profile'], 'production')
        self.assertEqual(result['findings'][0]['status'], 'potentially_affected')
        native.assert_not_called()
        upstream.assert_not_called()

    def test_active_production_blocked_before_network_without_opt_in(self):
        with patch('scanner.scan') as network:
            with self.assertRaisesRegex(ValueError, 'allow-disruptive'):
                run_chain(TARGET, [ORIGIN], 'approved-vapt', active_methods=('template',))
            network.assert_not_called()

    def test_explicit_approved_production_active_opt_in(self):
        with patch('scanner.scan', return_value={'target': TARGET, 'http_status': 200, 'status': 'unknown'}), \
             patch('scanner.run_template', return_value=[{'kind': 'no_signal'}]) as active:
            r = run_chain(TARGET, [ORIGIN], 'approved-disruptive-test',
                          active_methods=('template',), allow_disruptive=True)
        active.assert_called_once_with(TARGET, 5, False)
        self.assertTrue(r['disruptive_testing_opt_in'])
        self.assertEqual(r['findings'][0]['status'], 'inconclusive')

    def test_blocked_and_failed_routes_are_not_reported_patched(self):
        cases = [(301, 'redirect_not_followed'), (401, 'authentication_or_access_restricted'),
                 (403, 'authentication_or_access_restricted'), (429, 'rate_limited'),
                 (404, 'route_not_found'), (502, 'server_or_gateway_error')]
        for status, label in cases:
            with self.subTest(status=status), patch('scanner.scan', return_value={
                'target': TARGET, 'http_status': status, 'status': 'unknown'}):
                r = run_chain(TARGET, [ORIGIN], 'approved-vapt')
                self.assertEqual(r['coverage'][0]['access_observation'], label)
                self.assertEqual(r['findings'][0]['status'], 'inconclusive')

    def test_cli_production_active_requires_opt_in(self):
        p = subprocess.run([sys.executable, str(Path(__file__).with_name('scanner.py')),
            '--url', TARGET, '--allow-origin', ORIGIN, '--authorization-ref', 'approved-vapt',
            '--active'], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn('--allow-disruptive', p.stderr)

    def test_default_profile_sends_only_get_and_keeps_cookie_secret_out_of_report(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append('GET')
                self.send_response(403)
                self.send_header('Set-Cookie', 'PHPSESSID=DO_NOT_STORE_THIS; HttpOnly')
                self.end_headers()
            def do_POST(self):
                requests.append('POST')
                self.send_error(500)
            def log_message(self, *args):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                result = run_chain(base + '/', [base], 'production-fixture')
                self.assertEqual(requests, ['GET'])
                self.assertEqual(result['findings'][0]['status'], 'inconclusive')
                self.assertNotIn('DO_NOT_STORE_THIS', json.dumps(result))
            finally:
                server.shutdown()
                t.join()

    def _self_signed_server(self, tmp):
        """Start a throwaway HTTPS server with a self-signed cert that advertises
        a vulnerable PHP banner. Returns (server, thread, base_url)."""
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8.5.10')
                self.end_headers()
            def log_message(self, *args):
                pass
        cert, key = Path(tmp) / 'cert.pem', Path(tmp) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f'https://127.0.0.1:{server.server_port}'

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for the self-signed TLS fixture')
    def test_untrusted_https_certificate_is_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, t, base = self._self_signed_server(tmp)
            try:
                r = scan(base + '/', [base], 'tls-fixture')
                self.assertEqual(r['status'], 'error')
                self.assertEqual(r['reason'], 'URLError')  # backward-compatible field
                self.assertEqual(r['error_stage'], 'tls_handshake')
                self.assertEqual(r['tls_verification'], 'enabled')
                self.assertIn('--insecure-tls', r['tls_hint'])
            finally:
                server.shutdown()
                t.join()

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for the self-signed TLS fixture')
    def test_insecure_tls_opt_in_accepts_self_signed_and_assesses_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, t, base = self._self_signed_server(tmp)
            try:
                r = scan(base + '/', [base], 'tls-fixture', insecure_tls=True)
                self.assertEqual(r['http_status'], 200)
                self.assertEqual(r['tls_verification'], 'disabled')
                self.assertEqual(r['observed_versions'], ['8.5.10'])
                self.assertEqual(r['status'], 'potentially_affected')
            finally:
                server.shutdown()
                t.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)
