import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from scanner import run_chain
from template_method import check, exchange


def _serve(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f'http://127.0.0.1:{server.server_port}'


class ActiveDiagnostics(unittest.TestCase):
    def test_control_redirect_records_location_and_marks_endpoint_unsuitable(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(303)
                self.send_header('Location', '/dashboard')
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *args):
                pass
        server, t, base = _serve(Handler)
        try:
            out = check(base + '/login', timeout=5)
            self.assertEqual(out['kind'], 'inconclusive')
            self.assertEqual(out['control_status'], 303)
            self.assertEqual(out['redirect_location'], '/dashboard')
            self.assertIn('endpoint', out['endpoint_suitability'].lower())
            self.assertEqual(out['request_count'], 1)  # stopped after the control
        finally:
            server.shutdown()
            t.join()

    def test_read_timeout_is_classified_as_timeout_stage(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                time.sleep(2)  # exceed the 1s client timeout
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *args):
                pass
        server, t, base = _serve(Handler)
        try:
            record = exchange(base + '/', b'--x\n', 'x', timeout=1)
            self.assertIn('error', record)
            self.assertEqual(record['error_stage'], 'timeout')
            self.assertEqual(record['timeout_category'], 'socket_timeout')
        finally:
            server.shutdown()
            t.join()

    def test_verdict_summary_separates_version_from_active(self):
        passive = {'target': 'https://lab.test/login', 'http_status': 200,
                   'status': 'potentially_affected'}
        template = [{'kind': 'inconclusive', 'control_status': 303,
                     'redirect_location': '/dashboard'}]
        with patch('scanner.scan', return_value=passive), \
             patch('scanner.run_template', return_value=template):
            report = run_chain('https://lab.test/login', ['https://lab.test'],
                               'unit-ref', active_methods=('template',), profile='lab')
        summary = report['verdict_summary']
        self.assertEqual(summary['version_assessment'], 'potentially_affected')
        self.assertEqual(summary['active_assessment'], 'inconclusive')
        self.assertTrue(summary['active_executed'])
        self.assertEqual(summary['overall_status'], 'potentially_affected')
        self.assertFalse(summary['rce_confirmed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
