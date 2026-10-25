"""Run the real upstream scanner against a synthetic local HTTP service."""
import importlib.util
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scanner import run_chain


@unittest.skipUnless(importlib.util.find_spec('h11') and importlib.util.find_spec('tqdm'),
                     'Install requirements-active.txt for real upstream integration test')
class ActiveIntegration(unittest.TestCase):
    def run_synthetic(self, methods=()):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def respond(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8.3.36')
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'OK')
            def do_GET(self):
                requests.append(('GET', 0))
                self.respond()
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                if size > 21 * 1024 * 1024:
                    self.send_error(413)
                    return
                self.rfile.read(size)
                requests.append(('POST', size))
                self.respond()
            def log_message(self, *args):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                report = run_chain(base + '/index.php', [base], 'synthetic-fixture', timeout=5,
                    active_script=Path(__file__).parent / 'vendor' / 'assetnote_scanner.py',
                    active_methods=methods, profile='lab')
                self.assertEqual(report['active_evidence'][0]['kind'], 'version_only')
                self.assertEqual(report['findings'][0]['status'], 'fix_level_advertised')
                expected = ['GET', 'POST', 'POST', 'GET']
                if methods == ('template', 'assetnote'):
                    expected += ['POST', 'POST', 'GET']
                    self.assertEqual(report['methods_enabled'], 3)
                    self.assertEqual([x['method'] for x in report['active_evidence']], ['template', 'assetnote'])
                self.assertEqual([x[0] for x in requests], expected)
                self.assertFalse(report['findings'][0]['rce_confirmed'])
            finally:
                server.shutdown()
                t.join()

    def test_real_upstream_subprocess(self):
        self.run_synthetic()

    def test_both_real_engines_in_one_chain(self):
        self.run_synthetic(('template', 'assetnote'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
